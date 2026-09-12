use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use redis::aio::MultiplexedConnection;
use tonic::Status;
use tower::{Layer, Service};

use crate::grpc::interceptors::auth_layer::{rune_method_for_path, status_response};
use crate::grpc::interceptors::identity::{remote_addr_from_extensions, ClientIdentity};
use crate::grpc::interceptors::rate_limiter::{
    check_rate_limit_with_fallback, policy_for_method, InMemoryRateLimiter,
};

/// Tower layer that enforces per-method rate limits before the service runs.
///
/// Runs after the auth layer (auth wraps this one), so only authenticated
/// requests consume quota. The budget key is derived from the mTLS client
/// certificate fingerprint, never from client-supplied headers, so renaming
/// `x-client-id` cannot mint additional budgets. Streams are limited at
/// subscription creation: the request that opens the stream is what gets
/// counted, not each event.
#[derive(Clone)]
pub struct RateLimitLayer {
    redis_cm: Option<MultiplexedConnection>,
    fallback: Arc<InMemoryRateLimiter>,
}

impl RateLimitLayer {
    pub fn new(
        redis_cm: Option<MultiplexedConnection>,
        fallback: Arc<InMemoryRateLimiter>,
    ) -> Self {
        Self { redis_cm, fallback }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            redis_cm: self.redis_cm.clone(),
            fallback: self.fallback.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    redis_cm: Option<MultiplexedConnection>,
    fallback: Arc<InMemoryRateLimiter>,
}

impl<S> Service<http::Request<tonic::body::Body>> for RateLimitService<S>
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
        let path = req.uri().path().to_string();

        // Methods without a policy (or unknown paths) pass through untouched.
        let method = match rune_method_for_path(&path) {
            Some(method) => method,
            None => {
                let mut inner = self.inner.clone();
                return Box::pin(async move { inner.call(req).await.map_err(Into::into) });
            }
        };
        let Some(policy) = policy_for_method(method) else {
            let mut inner = self.inner.clone();
            return Box::pin(async move { inner.call(req).await.map_err(Into::into) });
        };

        // Defense in depth: the identity layer rejects certificate-less
        // requests before this layer, but a missing identity must never be
        // treated as a fresh budget.
        let Some(identity) = req.extensions().get::<ClientIdentity>().cloned() else {
            return Box::pin(async move {
                Ok(status_response(Status::unauthenticated(
                    "Client certificate required",
                )))
            });
        };

        // Independent budget per method and certificate fingerprint.
        let key = format!("{method}:{}", identity.fingerprint_sha256);
        let remote_addr = remote_addr_from_extensions(req.extensions());
        let redis_cm = self.redis_cm.clone();
        let fallback = self.fallback.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            if !check_rate_limit_with_fallback(&redis_cm, &fallback, &key, policy).await {
                tracing::warn!(
                    fingerprint = %identity.fingerprint_sha256,
                    claimed_client_id = identity.claimed_client_id.as_deref().unwrap_or("-"),
                    remote_addr = ?remote_addr,
                    method = %method,
                    limit = policy.limit,
                    window_seconds = policy.window_seconds,
                    "Rate limit exceeded"
                );
                return Ok(status_response(Status::resource_exhausted(format!(
                    "Rate limit exceeded for '{method}' ({} per {}s)",
                    policy.limit, policy.window_seconds
                ))));
            }
            inner.call(req).await.map_err(Into::into)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
    use http_body_util::Full;

    use crate::grpc::interceptors::auth::CLIENT_ID_HEADER;

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

    fn counting_service() -> (CountingService, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            CountingService {
                calls: calls.clone(),
            },
            calls,
        )
    }

    fn request(path: &str, fingerprint: Option<&str>) -> http::Request<tonic::body::Body> {
        let mut req = http::Request::new(tonic::body::Body::new(Full::new(Bytes::new())));
        *req.uri_mut() = path.parse().unwrap();
        if let Some(fingerprint) = fingerprint {
            req.extensions_mut()
                .insert(ClientIdentity::new(fingerprint));
        }
        req
    }

    fn with_claim(
        mut req: http::Request<tonic::body::Body>,
        claim: &str,
    ) -> http::Request<tonic::body::Body> {
        req.headers_mut()
            .insert(CLIENT_ID_HEADER, claim.parse().unwrap());
        req
    }

    #[tokio::test]
    async fn payment_limit_blocks_after_three_requests() {
        let (inner, calls) = counting_service();
        let mut service = RateLimitLayer::new(None, InMemoryRateLimiter::new()).layer(inner);

        for _ in 0..3 {
            assert!(service
                .call(request("/cln.NodeServices/Xpay", Some("cert-a")))
                .await
                .is_ok());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        let response = service
            .call(request("/cln.NodeServices/Xpay", Some("cert-a")))
            .await
            .expect("rate limit must produce a gRPC response, not a transport error");
        assert_eq!(response.headers().get("grpc-status").unwrap(), "8");
        assert_eq!(calls.load(Ordering::SeqCst), 3, "inner must not be called");
    }

    #[tokio::test]
    async fn missing_identity_is_rejected() {
        let (inner, calls) = counting_service();
        let mut service = RateLimitLayer::new(None, InMemoryRateLimiter::new()).layer(inner);

        let response = service
            .call(request("/cln.NodeServices/Xpay", None))
            .await
            .unwrap();
        assert_eq!(response.headers().get("grpc-status").unwrap(), "16");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn methods_have_independent_budgets() {
        let (inner, _calls) = counting_service();
        let mut service = RateLimitLayer::new(None, InMemoryRateLimiter::new()).layer(inner);

        for _ in 0..3 {
            service
                .call(request("/cln.NodeServices/Xpay", Some("cert-a")))
                .await
                .unwrap();
        }
        let blocked = service
            .call(request("/cln.NodeServices/Xpay", Some("cert-a")))
            .await
            .unwrap();
        assert_eq!(blocked.headers().get("grpc-status").unwrap(), "8");

        // A different method for the same client still has its own budget.
        let allowed = service
            .call(request("/cln.NodeServices/Getinfo", Some("cert-a")))
            .await
            .unwrap();
        assert!(allowed.headers().get("grpc-status").is_none());
    }

    #[tokio::test]
    async fn unlimited_path_passes_through() {
        let (inner, calls) = counting_service();
        let mut service = RateLimitLayer::new(None, InMemoryRateLimiter::new()).layer(inner);

        let response = service
            .call(request("/cln.NodeServices/UnknownRpc", None))
            .await
            .unwrap();
        assert!(response.headers().get("grpc-status").is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// GCOB-001 regression: one certificate cannot mint budgets by renaming
    /// the `x-client-id` header.
    #[tokio::test]
    async fn spoofed_client_id_claims_share_one_budget() {
        let (inner, calls) = counting_service();
        let mut service = RateLimitLayer::new(None, InMemoryRateLimiter::new()).layer(inner);

        for i in 0..3 {
            let req = with_claim(
                request("/cln.NodeServices/Xpay", Some("cert-a")),
                &format!("attacker-{i:06}"),
            );
            let response = service.call(req).await.unwrap();
            assert!(response.headers().get("grpc-status").is_none());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        for i in 3..20 {
            let req = with_claim(
                request("/cln.NodeServices/Xpay", Some("cert-a")),
                &format!("attacker-{i:06}"),
            );
            let response = service.call(req).await.unwrap();
            assert_eq!(
                response.headers().get("grpc-status").unwrap(),
                "8",
                "claim {i} must not create a new budget"
            );
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "only the certificate budget may be consumed"
        );
    }

    #[tokio::test]
    async fn different_fingerprints_have_independent_budgets() {
        let (inner, calls) = counting_service();
        let mut service = RateLimitLayer::new(None, InMemoryRateLimiter::new()).layer(inner);

        for _ in 0..3 {
            service
                .call(request("/cln.NodeServices/Xpay", Some("cert-a")))
                .await
                .unwrap();
        }
        let blocked = service
            .call(request("/cln.NodeServices/Xpay", Some("cert-a")))
            .await
            .unwrap();
        assert_eq!(blocked.headers().get("grpc-status").unwrap(), "8");

        let other = service
            .call(request("/cln.NodeServices/Xpay", Some("cert-b")))
            .await
            .unwrap();
        assert!(other.headers().get("grpc-status").is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }
}
