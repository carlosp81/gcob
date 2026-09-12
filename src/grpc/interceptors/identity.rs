//! Canonical client identity derived from the mTLS handshake.
//!
//! The rate limiter must never trust client-supplied identifiers. Every
//! request that reaches the admission layers carries a [`ClientIdentity`]
//! extracted from the TLS peer certificate, so renaming the `x-client-id`
//! header cannot mint new budgets.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use sha2::{Digest, Sha256};
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tonic::Status;
use tower::{Layer, Service};

use crate::grpc::interceptors::auth::CLIENT_ID_HEADER;
use crate::grpc::interceptors::auth_layer::status_response;

/// Identity of the authenticated TLS peer.
///
/// `fingerprint_sha256` is the SHA-256 of the leaf certificate DER and is the
/// only field used for security decisions. `claimed_client_id` is the
/// client-supplied `x-client-id` header kept for audit purposes only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    pub fingerprint_sha256: String,
    pub claimed_client_id: Option<String>,
}

impl ClientIdentity {
    pub fn new(fingerprint_sha256: impl Into<String>) -> Self {
        Self {
            fingerprint_sha256: fingerprint_sha256.into(),
            claimed_client_id: None,
        }
    }
}

/// SHA-256 of a DER certificate, hex encoded.
pub fn fingerprint_from_der(der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der);
    hex::encode(hasher.finalize())
}

/// Resolve the client identity from request extensions.
///
/// Prefers an identity already hydrated by an outer layer (also used by
/// tests) and otherwise derives it from the TLS peer certificate.
pub fn identity_from_extensions(extensions: &http::Extensions) -> Option<ClientIdentity> {
    if let Some(identity) = extensions.get::<ClientIdentity>() {
        return Some(identity.clone());
    }

    let certs = extensions
        .get::<TlsConnectInfo<TcpConnectInfo>>()?
        .peer_certs()?;
    let leaf = certs.first()?;

    Some(ClientIdentity {
        fingerprint_sha256: fingerprint_from_der(leaf.as_ref()),
        claimed_client_id: None,
    })
}

/// Remote address of the peer, from either the TLS or plain connection info.
pub fn remote_addr_from_extensions(extensions: &http::Extensions) -> Option<SocketAddr> {
    if let Some(info) = extensions.get::<TcpConnectInfo>() {
        return info.remote_addr();
    }
    extensions
        .get::<TlsConnectInfo<TcpConnectInfo>>()?
        .get_ref()
        .remote_addr()
}

// --- Layer ---

/// Outermost layer: hydrates [`ClientIdentity`] from the TLS session and
/// rejects connections that present no client certificate.
#[derive(Clone, Copy, Default)]
pub struct ClientIdentityLayer;

impl ClientIdentityLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for ClientIdentityLayer {
    type Service = ClientIdentityService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ClientIdentityService { inner }
    }
}

#[derive(Clone)]
pub struct ClientIdentityService<S> {
    inner: S,
}

impl<S> Service<http::Request<tonic::body::Body>> for ClientIdentityService<S>
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

    fn call(&mut self, mut req: http::Request<tonic::body::Body>) -> Self::Future {
        let mut identity = match identity_from_extensions(req.extensions()) {
            Some(identity) => identity,
            None => {
                tracing::warn!("Rejected request without a client certificate");
                return Box::pin(async move {
                    Ok(status_response(Status::unauthenticated(
                        "Client certificate required",
                    )))
                });
            }
        };

        if identity.claimed_client_id.is_none() {
            identity.claimed_client_id = req
                .headers()
                .get(CLIENT_ID_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
                .filter(|s| !s.is_empty());
        }
        req.extensions_mut().insert(identity);

        let mut inner = self.inner.clone();
        Box::pin(async move { inner.call(req).await.map_err(Into::into) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

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

    fn request() -> http::Request<tonic::body::Body> {
        http::Request::new(tonic::body::Body::new(Full::new(Bytes::new())))
    }

    #[test]
    fn fingerprint_matches_known_value() {
        // echo -n gcob-test-cert | sha256sum
        assert_eq!(
            fingerprint_from_der(b"gcob-test-cert"),
            "9d28eb1c7b65fcafb1a6c96992108680cdb551dc43a455a51c18bf26fec711b0"
        );
    }

    #[test]
    fn fingerprint_from_rcgen_certificate_is_stable() {
        let key = rcgen::generate_simple_self_signed(vec!["client.test".to_string()]).unwrap();
        let der = key.cert.der().clone();
        let first = fingerprint_from_der(der.as_ref());
        let second = fingerprint_from_der(der.as_ref());
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn identity_from_empty_extensions_is_none() {
        let extensions = http::Extensions::new();
        assert_eq!(identity_from_extensions(&extensions), None);
    }

    #[test]
    fn existing_identity_extension_is_reused() {
        let mut extensions = http::Extensions::new();
        extensions.insert(ClientIdentity::new("cert-a"));
        let identity = identity_from_extensions(&extensions).unwrap();
        assert_eq!(identity.fingerprint_sha256, "cert-a");
    }

    #[tokio::test]
    async fn rejects_requests_without_certificate() {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = CountingService {
            calls: calls.clone(),
        };
        let mut service = ClientIdentityLayer::new().layer(inner);

        let response = service.call(request()).await.unwrap();
        assert_eq!(response.headers().get("grpc-status").unwrap(), "16");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn passes_through_and_hydrates_claim() {
        let seen: Arc<tokio::sync::Mutex<Option<ClientIdentity>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let seen_clone = seen.clone();

        let inner = tower::service_fn(move |req: http::Request<tonic::body::Body>| {
            let seen = seen_clone.clone();
            async move {
                *seen.lock().await = req.extensions().get::<ClientIdentity>().cloned();
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(http::Response::new(
                    tonic::body::Body::new(Full::new(Bytes::new())),
                ))
            }
        });

        let mut service = ClientIdentityLayer::new().layer(inner);
        let mut req = request();
        req.extensions_mut().insert(ClientIdentity::new("cert-a"));
        req.headers_mut()
            .insert(CLIENT_ID_HEADER, "crm-01".parse().unwrap());

        let response = service.call(req).await.unwrap();
        assert!(response.headers().get("grpc-status").is_none());

        let identity = seen.lock().await.clone().expect("identity hydrated");
        assert_eq!(identity.fingerprint_sha256, "cert-a");
        assert_eq!(identity.claimed_client_id.as_deref(), Some("crm-01"));
    }

    #[tokio::test]
    async fn empty_claim_header_is_not_recorded() {
        let seen: Arc<tokio::sync::Mutex<Option<ClientIdentity>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let seen_clone = seen.clone();

        let inner = tower::service_fn(move |req: http::Request<tonic::body::Body>| {
            let seen = seen_clone.clone();
            async move {
                *seen.lock().await = req.extensions().get::<ClientIdentity>().cloned();
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(http::Response::new(
                    tonic::body::Body::new(Full::new(Bytes::new())),
                ))
            }
        });

        let mut service = ClientIdentityLayer::new().layer(inner);
        let mut req = request();
        req.extensions_mut().insert(ClientIdentity::new("cert-a"));
        req.headers_mut()
            .insert(CLIENT_ID_HEADER, "".parse().unwrap());

        service.call(req).await.unwrap();
        let identity = seen.lock().await.clone().unwrap();
        assert_eq!(identity.claimed_client_id, None);
    }

    #[test]
    fn remote_addr_from_empty_extensions_is_none() {
        let extensions = http::Extensions::new();
        assert_eq!(remote_addr_from_extensions(&extensions), None);
    }
}
