//! Cheap pre-authentication admission control.
//!
//! Sits between the identity layer and the rune auth layer so that a client
//! presenting a valid certificate but invalid runes cannot turn every request
//! into a `check_rune` call against CLN. The budget is keyed by certificate
//! fingerprint and never touches the backend.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use redis::aio::MultiplexedConnection;
use tonic::Status;
use tower::{Layer, Service};

use crate::grpc::interceptors::auth_layer::status_response;
use crate::grpc::interceptors::identity::{remote_addr_from_extensions, ClientIdentity};
use crate::grpc::interceptors::rate_limiter::{
    check_rate_limit_with_fallback, InMemoryRateLimiter, RateLimitPolicy,
};
use crate::grpc::limits::Limits;

/// Tower layer enforcing a coarse request budget before any authorization or
/// backend interaction.
#[derive(Clone)]
pub struct AdmissionLayer {
    redis_cm: Option<MultiplexedConnection>,
    fallback: Arc<InMemoryRateLimiter>,
    policy: RateLimitPolicy,
}

impl AdmissionLayer {
    pub fn new(
        redis_cm: Option<MultiplexedConnection>,
        fallback: Arc<InMemoryRateLimiter>,
        limits: &Limits,
    ) -> Self {
        Self {
            redis_cm,
            fallback,
            policy: RateLimitPolicy {
                limit: limits.preauth_limit,
                window_seconds: limits.preauth_window_seconds,
            },
        }
    }
}

impl<S> Layer<S> for AdmissionLayer {
    type Service = AdmissionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AdmissionService {
            inner,
            redis_cm: self.redis_cm.clone(),
            fallback: self.fallback.clone(),
            policy: self.policy,
        }
    }
}

#[derive(Clone)]
pub struct AdmissionService<S> {
    inner: S,
    redis_cm: Option<MultiplexedConnection>,
    fallback: Arc<InMemoryRateLimiter>,
    policy: RateLimitPolicy,
}

impl<S> Service<http::Request<tonic::body::Body>> for AdmissionService<S>
where
    S: Service<http::Request<tonic::body::Body>, Response = http::Response<tonic::body::Body>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = S::Response;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
        let Some(identity) = req.extensions().get::<ClientIdentity>().cloned() else {
            return Box::pin(async move {
                Ok(status_response(Status::unauthenticated(
                    "Client certificate required",
                )))
            });
        };

        let path = req.uri().path().to_string();
        let key = format!("admit:{}", identity.fingerprint_sha256);
        let remote_addr = remote_addr_from_extensions(req.extensions());
        let redis_cm = self.redis_cm.clone();
        let fallback = self.fallback.clone();
        let policy = self.policy;
        let mut inner = self.inner.clone();

        Box::pin(async move {
            if !check_rate_limit_with_fallback(&redis_cm, &fallback, &key, policy).await {
                tracing::warn!(
                    fingerprint = %identity.fingerprint_sha256,
                    claimed_client_id = identity.claimed_client_id.as_deref().unwrap_or("-"),
                    remote_addr = ?remote_addr,
                    limit = policy.limit,
                    window_seconds = policy.window_seconds,
                    "Pre-authentication rate limit exceeded"
                );
                return Ok(status_response(Status::resource_exhausted(
                    "Too many requests; retry later",
                )));
            }

            let started = std::time::Instant::now();
            let result = inner.call(req).await;
            tracing::debug!(
                fingerprint = %identity.fingerprint_sha256,
                claimed_client_id = identity.claimed_client_id.as_deref().unwrap_or("-"),
                remote_addr = ?remote_addr,
                path = %path,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "Request admitted"
            );
            result.map_err(Into::into)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
    use http_body_util::Full;

    #[derive(Clone)]
    struct CountingService {
        calls: Arc<AtomicUsize>,
    }

    impl Service<http::Request<tonic::body::Body>> for CountingService {
        type Response = http::Response<tonic::body::Body>;
        type Error = Box<dyn std::error::Error + Send + Sync>;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: http::Request<tonic::body::Body>) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Ok(http::Response::new(tonic::body::Body::new(Full::new(
                    Bytes::new(),
                ))))
            })
        }
    }

    fn limits_with_budget(limit: u32) -> Limits {
        Limits {
            preauth_limit: limit,
            preauth_window_seconds: 3600,
            ..Limits::default()
        }
    }

    fn request(fingerprint: Option<&str>) -> http::Request<tonic::body::Body> {
        let mut req = http::Request::new(tonic::body::Body::new(Full::new(Bytes::new())));
        if let Some(fingerprint) = fingerprint {
            req.extensions_mut()
                .insert(ClientIdentity::new(fingerprint));
        }
        req
    }

    fn service_with(limit: u32) -> (AdmissionService<CountingService>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = CountingService {
            calls: calls.clone(),
        };
        let service =
            AdmissionLayer::new(None, InMemoryRateLimiter::new(), &limits_with_budget(limit))
                .layer(inner);
        (service, calls)
    }

    #[tokio::test]
    async fn allows_up_to_budget_then_rejects() {
        let (mut service, calls) = service_with(2);

        for _ in 0..2 {
            let response = service
                .call(request(Some("cert-a")))
                .await
                .expect("must return a gRPC response");
            assert!(response.headers().get("grpc-status").is_none());
        }

        let rejected = service.call(request(Some("cert-a"))).await.unwrap();
        assert_eq!(rejected.headers().get("grpc-status").unwrap(), "8");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "rejected request must not reach the inner service"
        );
    }

    #[tokio::test]
    async fn budgets_are_per_fingerprint() {
        let (mut service, calls) = service_with(1);

        let first = service.call(request(Some("cert-a"))).await.unwrap();
        assert!(first.headers().get("grpc-status").is_none());
        let exhausted = service.call(request(Some("cert-a"))).await.unwrap();
        assert_eq!(exhausted.headers().get("grpc-status").unwrap(), "8");

        let other = service.call(request(Some("cert-b"))).await.unwrap();
        assert!(other.headers().get("grpc-status").is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn missing_identity_is_rejected() {
        let (mut service, calls) = service_with(10);

        let response = service.call(request(None)).await.unwrap();
        assert_eq!(response.headers().get("grpc-status").unwrap(), "16");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// Bounded adversarial load: 10 000 requests rotating 10 certificates and
    /// 10 000 distinct `x-client-id` claims must consume exactly the per
    /// certificate budget and grow the limiter state by at most 10 buckets.
    #[tokio::test]
    async fn bounded_load_with_spoofed_claims_stays_bounded() {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = CountingService {
            calls: calls.clone(),
        };
        let fallback = InMemoryRateLimiter::new();
        let mut service =
            AdmissionLayer::new(None, fallback.clone(), &limits_with_budget(100)).layer(inner);

        let mut admitted = 0usize;
        for i in 0..10_000 {
            let fingerprint = format!("cert-{:02}", i % 10);
            let mut req = request(Some(fingerprint.as_str()));
            req.headers_mut()
                .insert("x-client-id", format!("claim-{i}").parse().unwrap());
            let response = service.call(req).await.unwrap();
            if response.headers().get("grpc-status").is_none() {
                admitted += 1;
            }
        }

        assert_eq!(admitted, 1_000, "10 certificates x 100 budget");
        assert_eq!(calls.load(Ordering::SeqCst), 1_000);
        assert_eq!(
            fallback.tracked_keys().await,
            10,
            "spoofed claims must not create additional buckets"
        );
    }

    /// GCOB-003 regression: after the pre-auth budget is exhausted, invalid
    /// runes never reach the inner (auth) service, hence never reach CLN.
    #[tokio::test]
    async fn preauth_budget_caps_backend_attempts() {
        let (mut service, calls) = service_with(10);

        for i in 0..100 {
            let response = service.call(request(Some("cert-a"))).await.unwrap();
            let status = response
                .headers()
                .get("grpc-status")
                .map(|v| v.to_str().unwrap());
            if i < 10 {
                assert!(status.is_none(), "request {i} must pass admission");
            } else {
                assert_eq!(status, Some("8"), "request {i} must be cut pre-auth");
            }
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            10,
            "backend attempts must equal the pre-auth budget, not the request count"
        );
    }
}
