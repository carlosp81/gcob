use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use prost::Message;
use tonic::Status;
use tower::{Layer, Service};
use zeroize::Zeroizing;

use crate::cln::client::ClnClient;
use crate::cln::cln_api;

use super::auth::{validate_rune, RUNE_HEADER};

/// Maximum accepted rune length. Real CLN runes are far shorter; anything
/// larger is rejected before it can be copied into a backend request.
pub(crate) const MAX_RUNE_LEN: usize = 4096;

/// Characters allowed in a rune header value: the base64url alphabet plus the
/// separators used by CLN rune restrictions (`/`, `=`, `&`, `|`, `,`, `.`,
/// `:`, `+`). Anything else can never be a valid rune.
fn is_valid_rune_charset(rune: &str) -> bool {
    !rune.is_empty()
        && rune.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'_' | b'=' | b'/' | b'+' | b'&' | b'|' | b',' | b'.' | b':'
                )
        })
}

// --- Path → CLN method name mapping ---

pub(crate) fn rune_method_for_path(path: &str) -> Option<&'static str> {
    match path {
        "/cln.NodeServices/Invoice" => Some("invoice"),
        "/cln.NodeServices/Getinfo" => Some("getinfo"),
        "/cln.NodeServices/Xpay" => Some("xpay"),
        "/cln.NodeServices/InvoiceStream" => Some("invoice"),
        "/cln.NodeServices/XpayStreamWatch" => Some("xpay"),
        "/cln.NodeServices/XpayStream" => Some("xpay_stream"),
        "/cln.NodeServices/InvoiceWatch" => Some("invoice_watch"),
        "/cln.NodeServices/WatchChannels" => Some("watch_channels"),
        "/cln.NodeServices/WatchPeers" => Some("watch_peers"),
        "/cln.NodeServices/WatchSystem" => Some("watch_system"),
        _ => None,
    }
}

/// Convert a gRPC status into an HTTP response so the stream is not reset.
///
/// Returning `Err` from the tower service is treated by hyper as a fatal
/// connection error (`RST_STREAM`), which the client reports as
/// "h2 protocol error" instead of the real gRPC status.
pub(crate) fn status_response(status: Status) -> http::Response<tonic::body::Body> {
    tracing::warn!(
        code = ?status.code(),
        message = %status.message(),
        "gRPC request rejected"
    );
    status.into_http()
}

fn unauthenticated_response(message: &str) -> http::Response<tonic::body::Body> {
    status_response(Status::unauthenticated(message))
}

// --- Protobuf param extraction for rune validation ---

fn extract_params_for_path(path: &str, body: &[u8]) -> Vec<String> {
    match path {
        "/cln.NodeServices/Invoice" => {
            let req = cln_api::InvoiceRequest::decode(body).unwrap_or_default();
            let amount = req
                .amount_msat
                .and_then(|a| a.value)
                .map(|v| match v {
                    cln_api::amount_or_any::Value::Amount(a) => a.msat.to_string(),
                    cln_api::amount_or_any::Value::Any(_) => "any".to_string(),
                })
                .unwrap_or_default();
            vec![amount, req.label, req.description]
        }
        "/cln.NodeServices/Xpay" => {
            let req = cln_api::XpayRequest::decode(body).unwrap_or_default();
            let amount = req
                .amount_msat
                .map(|a| a.msat.to_string())
                .unwrap_or_default();
            vec![req.invstring, amount]
        }
        // Getinfo, InvoiceStream, XpayStreamWatch, XpayStream, InvoiceWatch,
        // WatchChannels, WatchPeers, WatchSystem have no params for rune validation
        _ => vec![],
    }
}

/// Read the request body up to `max_bytes`.
///
/// The limit is enforced while streaming so an oversized body is rejected
/// before it is materialized or sent to CLN for rune validation.
async fn read_body_limited(
    mut body: tonic::body::Body,
    max_bytes: usize,
    path: &str,
) -> Result<Bytes, Status> {
    use http_body_util::BodyExt;

    let mut buf: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| {
            tracing::warn!(path = %path, error = %e, "Failed to read request body");
            Status::internal("Failed to read request body")
        })?;
        if let Some(data) = frame.data_ref() {
            if buf.len().saturating_add(data.len()) > max_bytes {
                tracing::warn!(
                    path = %path,
                    max_body_bytes = max_bytes,
                    "Request body exceeds the configured limit"
                );
                return Err(Status::resource_exhausted(format!(
                    "Request body exceeds the {max_bytes} byte limit"
                )));
            }
            buf.extend_from_slice(data);
        }
    }
    Ok(Bytes::from(buf))
}

// --- Layer ---

#[derive(Clone)]
pub struct AuthLayer {
    client: Arc<ClnClient>,
    max_body_bytes: usize,
}

impl AuthLayer {
    pub fn new(client: Arc<ClnClient>, max_body_bytes: usize) -> Self {
        Self {
            client,
            max_body_bytes,
        }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            client: self.client.clone(),
            max_body_bytes: self.max_body_bytes,
        }
    }
}

// --- Service ---

#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    client: Arc<ClnClient>,
    max_body_bytes: usize,
}

impl<S> Service<http::Request<tonic::body::Body>> for AuthService<S>
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

        // Extract the rune from gRPC metadata headers. A duplicate header is
        // ambiguous (proxies and clients may disagree on which value counts),
        // and malformed values can never be valid: both are rejected here,
        // before any backend interaction. The accepted value is held in a
        // `Zeroizing` buffer so it is wiped when the request completes.
        let mut values = req.headers().get_all(RUNE_HEADER).iter();
        let first = values.next();
        if values.next().is_some() {
            return Box::pin(async move {
                Ok(unauthenticated_response(
                    "Multiple Rune headers are not allowed",
                ))
            });
        }

        let rune = match first {
            Some(value) => match value.to_str() {
                Ok(value)
                    if !value.is_empty()
                        && value.len() <= MAX_RUNE_LEN
                        && is_valid_rune_charset(value) =>
                {
                    Zeroizing::new(value.to_string())
                }
                _ => {
                    return Box::pin(
                        async move { Ok(unauthenticated_response("Invalid Rune header")) },
                    );
                }
            },
            None => {
                let msg = format!(
                    "Missing or empty Rune header '{}'. Provide a valid Rune for authentication.",
                    RUNE_HEADER
                );
                return Box::pin(async move { Ok(unauthenticated_response(&msg)) });
            }
        };

        // Map gRPC path to CLN method name
        let method = match rune_method_for_path(&path) {
            Some(m) => m,
            None => {
                let msg = format!("Unknown gRPC path: {}", path);
                return Box::pin(async move { Ok(unauthenticated_response(&msg)) });
            }
        };

        let client = self.client.clone();
        let max_body_bytes = self.max_body_bytes;
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Split request to read body
            let (parts, body) = req.into_parts();

            // Read body bytes for protobuf decoding, bounded before any CLN
            // interaction so oversized requests cannot allocate arbitrarily.
            let body_bytes = match read_body_limited(body, max_body_bytes, &path).await {
                Ok(bytes) => bytes,
                Err(status) => return Ok(status_response(status)),
            };

            // Extract params from protobuf body
            let params = extract_params_for_path(&path, &body_bytes);

            // Async rune validation via CLN check_rune (now with params). A
            // rejected rune is a gRPC status response; returning Err here would
            // reset the HTTP/2 stream and hide the real error from the client.
            if let Err(status) = validate_rune(&client, &rune, method, params).await {
                return Ok(status_response(status));
            }

            tracing::info!(path = %path, method = %method, "Rune validated - request allowed through");

            // Reconstruct request with original body bytes as tonic::body::Body
            let body = tonic::body::Body::new(http_body_util::Full::new(body_bytes));
            let req = http::Request::from_parts(parts, body);

            inner.call(req).await.map_err(Into::into)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tower::service_fn;

    #[test]
    fn method_mapping_all_rpc_paths() {
        assert_eq!(
            rune_method_for_path("/cln.NodeServices/Invoice"),
            Some("invoice")
        );
        assert_eq!(
            rune_method_for_path("/cln.NodeServices/Getinfo"),
            Some("getinfo")
        );
        assert_eq!(rune_method_for_path("/cln.NodeServices/Xpay"), Some("xpay"));
        assert_eq!(
            rune_method_for_path("/cln.NodeServices/InvoiceStream"),
            Some("invoice")
        );
        assert_eq!(
            rune_method_for_path("/cln.NodeServices/XpayStreamWatch"),
            Some("xpay")
        );
        assert_eq!(
            rune_method_for_path("/cln.NodeServices/XpayStream"),
            Some("xpay_stream")
        );
        assert_eq!(
            rune_method_for_path("/cln.NodeServices/InvoiceWatch"),
            Some("invoice_watch")
        );
        assert_eq!(
            rune_method_for_path("/cln.NodeServices/WatchChannels"),
            Some("watch_channels")
        );
        assert_eq!(
            rune_method_for_path("/cln.NodeServices/WatchPeers"),
            Some("watch_peers")
        );
        assert_eq!(
            rune_method_for_path("/cln.NodeServices/WatchSystem"),
            Some("watch_system")
        );
    }

    #[test]
    fn unknown_path_returns_none() {
        assert_eq!(rune_method_for_path("/cln.NodeServices/UnknownRpc"), None);
        assert_eq!(rune_method_for_path("/"), None);
        assert_eq!(rune_method_for_path(""), None);
    }

    #[test]
    fn rune_header_constant_is_lowercase() {
        assert_eq!(RUNE_HEADER, "x-rune");
    }

    #[test]
    fn extract_params_invoice_basic() {
        let req = cln_api::InvoiceRequest {
            amount_msat: Some(cln_api::AmountOrAny {
                value: Some(cln_api::amount_or_any::Value::Amount(cln_api::Amount {
                    msat: 50000,
                })),
            }),
            label: "test-label".to_string(),
            description: "test-desc".to_string(),
            ..Default::default()
        };
        let mut body = Vec::new();
        req.encode(&mut body).unwrap();

        let params = extract_params_for_path("/cln.NodeServices/Invoice", &body);
        assert_eq!(params, vec!["50000", "test-label", "test-desc"]);
    }

    #[test]
    fn extract_params_invoice_any_amount() {
        let req = cln_api::InvoiceRequest {
            amount_msat: Some(cln_api::AmountOrAny {
                value: Some(cln_api::amount_or_any::Value::Any(true)),
            }),
            label: "any-label".to_string(),
            description: "any-desc".to_string(),
            ..Default::default()
        };
        let mut body = Vec::new();
        req.encode(&mut body).unwrap();

        let params = extract_params_for_path("/cln.NodeServices/Invoice", &body);
        assert_eq!(params, vec!["any", "any-label", "any-desc"]);
    }

    #[test]
    fn extract_params_xpay() {
        let req = cln_api::XpayRequest {
            invstring: "lnbc1...".to_string(),
            amount_msat: Some(cln_api::Amount { msat: 100000 }),
            ..Default::default()
        };
        let mut body = Vec::new();
        req.encode(&mut body).unwrap();

        let params = extract_params_for_path("/cln.NodeServices/Xpay", &body);
        assert_eq!(params, vec!["lnbc1...", "100000"]);
    }

    #[test]
    fn extract_params_getinfo_returns_empty() {
        let params = extract_params_for_path("/cln.NodeServices/Getinfo", &[]);
        assert!(params.is_empty());
    }

    #[test]
    fn extract_params_unknown_path_returns_empty() {
        let params = extract_params_for_path("/cln.NodeServices/UnknownRpc", &[]);
        assert!(params.is_empty());
    }

    #[test]
    fn extract_params_malformed_body_returns_empty_or_default() {
        let params = extract_params_for_path("/cln.NodeServices/Invoice", b"invalid");
        // decode fails, returns default InvoiceRequest
        assert_eq!(params.len(), 3);
        assert_eq!(params[0], ""); // amount defaults to ""
        assert_eq!(params[1], ""); // label defaults to ""
        assert_eq!(params[2], ""); // description defaults to ""
    }

    // --- AuthLayer rejection response tests ---

    #[test]
    fn unauthenticated_response_has_status_16() {
        let resp = unauthenticated_response("test message");
        // into_http() returns HTTP 200; gRPC status is in the body (grpc-status header)
        // The actual gRPC status code is embedded in the response body
        assert_eq!(resp.status(), 200); // HTTP status is 200
                                        // The gRPC status is in the grpc-status header
        let grpc_status = resp.headers().get("grpc-status");
        assert!(grpc_status.is_some(), "Should have grpc-status header");
    }

    #[test]
    fn unauthenticated_response_has_grpc_content_type() {
        let resp = unauthenticated_response("test");
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/grpc"
        );
    }

    #[test]
    fn rune_method_for_path_all_10_rpc_methods() {
        // Verify all 10 RPC methods are mapped
        let paths = vec![
            "/cln.NodeServices/Invoice",
            "/cln.NodeServices/Getinfo",
            "/cln.NodeServices/Xpay",
            "/cln.NodeServices/InvoiceStream",
            "/cln.NodeServices/XpayStreamWatch",
            "/cln.NodeServices/XpayStream",
            "/cln.NodeServices/InvoiceWatch",
            "/cln.NodeServices/WatchChannels",
            "/cln.NodeServices/WatchPeers",
            "/cln.NodeServices/WatchSystem",
        ];
        for path in paths {
            assert!(
                rune_method_for_path(path).is_some(),
                "Path should be mapped: {}",
                path
            );
        }
    }

    #[test]
    fn rune_method_for_path_returns_correct_method_names() {
        assert_eq!(
            rune_method_for_path("/cln.NodeServices/Invoice"),
            Some("invoice")
        );
        assert_eq!(rune_method_for_path("/cln.NodeServices/Xpay"), Some("xpay"));
        assert_eq!(
            rune_method_for_path("/cln.NodeServices/XpayStream"),
            Some("xpay_stream")
        );
        assert_eq!(
            rune_method_for_path("/cln.NodeServices/InvoiceWatch"),
            Some("invoice_watch")
        );
    }

    #[test]
    fn extract_params_invoice_empty_body() {
        let params = extract_params_for_path("/cln.NodeServices/Invoice", &[]);
        assert_eq!(params, vec!["", "", ""]);
    }

    #[test]
    fn extract_params_xpay_empty_body() {
        let params = extract_params_for_path("/cln.NodeServices/Xpay", &[]);
        assert_eq!(params, vec!["", ""]);
    }

    #[tokio::test]
    async fn rejected_rune_returns_grpc_status_instead_of_transport_error() {
        // Lazy channel to a closed port: check_rune fails fast, and the layer
        // must translate it into a gRPC response (status 16), never a tower Err
        // that would reset the HTTP/2 stream.
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        let client = Arc::new(ClnClient {
            inner: cln_api::node_client::NodeClient::new(channel),
            node_id: "test-node".to_string(),
        });

        let mut service = AuthLayer::new(client, 262_144).layer(service_fn(
            |_req: http::Request<tonic::body::Body>| async {
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(http::Response::new(
                    tonic::body::Body::new(http_body_util::Full::new(Bytes::new())),
                ))
            },
        ));

        let mut req = http::Request::new(tonic::body::Body::new(http_body_util::Full::new(
            Bytes::new(),
        )));
        req.headers_mut()
            .insert(RUNE_HEADER, "blacklisted-rune".parse().unwrap());
        *req.uri_mut() = "/cln.NodeServices/Getinfo".parse().unwrap();

        let response = service
            .call(req)
            .await
            .expect("a rejected rune must produce a gRPC response, not a transport error");
        assert_eq!(response.headers().get("grpc-status").unwrap(), "16");
    }

    // --- Body size limit tests (GCOB-007) ---

    fn lazy_client() -> Arc<ClnClient> {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        Arc::new(ClnClient {
            inner: cln_api::node_client::NodeClient::new(channel),
            node_id: "test-node".to_string(),
        })
    }

    fn auth_request(path: &str, body: Bytes) -> http::Request<tonic::body::Body> {
        let mut req = http::Request::new(tonic::body::Body::new(http_body_util::Full::new(body)));
        req.headers_mut()
            .insert(RUNE_HEADER, "some-rune".parse().unwrap());
        *req.uri_mut() = path.parse().unwrap();
        req
    }

    #[derive(Clone)]
    struct CountingService {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Service<http::Request<tonic::body::Body>> for CountingService {
        type Response = http::Response<tonic::body::Body>;
        type Error = Box<dyn std::error::Error + Send + Sync>;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: http::Request<tonic::body::Body>) -> Self::Future {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async {
                Ok(http::Response::new(tonic::body::Body::new(
                    http_body_util::Full::new(Bytes::new()),
                )))
            })
        }
    }

    fn counting_inner() -> (CountingService, Arc<std::sync::atomic::AtomicUsize>) {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (
            CountingService {
                calls: calls.clone(),
            },
            calls,
        )
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_before_any_backend_call() {
        let (inner, calls) = counting_inner();
        let mut service = AuthLayer::new(lazy_client(), 16).layer(inner);

        let response = service
            .call(auth_request(
                "/cln.NodeServices/Getinfo",
                Bytes::from_static(&[0u8; 32]),
            ))
            .await
            .expect("must return a gRPC response");

        assert_eq!(response.headers().get("grpc-status").unwrap(), "8");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "inner service must never see an oversized request"
        );
    }

    #[tokio::test]
    async fn chunked_body_over_limit_is_rejected_while_streaming() {
        use http_body_util::StreamBody;
        use std::convert::Infallible;

        let chunks = tokio_stream::iter(vec![
            Ok::<_, Infallible>(http_body::Frame::data(Bytes::from_static(&[0u8; 10]))),
            Ok::<_, Infallible>(http_body::Frame::data(Bytes::from_static(&[0u8; 10]))),
        ]);
        let body = tonic::body::Body::new(StreamBody::new(chunks));

        let (inner, calls) = counting_inner();
        let mut service = AuthLayer::new(lazy_client(), 16).layer(inner);

        let mut req = http::Request::new(body);
        req.headers_mut()
            .insert(RUNE_HEADER, "some-rune".parse().unwrap());
        *req.uri_mut() = "/cln.NodeServices/Getinfo".parse().unwrap();

        let response = service.call(req).await.unwrap();
        assert_eq!(response.headers().get("grpc-status").unwrap(), "8");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn body_at_limit_reaches_rune_check() {
        let (inner, _calls) = counting_inner();
        let mut service = AuthLayer::new(lazy_client(), 16).layer(inner);

        let response = service
            .call(auth_request(
                "/cln.NodeServices/Getinfo",
                Bytes::from_static(&[0u8; 16]),
            ))
            .await
            .unwrap();

        // Passed the size gate; the unreachable CLN produces status 16.
        assert_eq!(response.headers().get("grpc-status").unwrap(), "16");
    }

    #[tokio::test]
    async fn body_under_limit_reaches_rune_check() {
        let (inner, _calls) = counting_inner();
        let mut service = AuthLayer::new(lazy_client(), 16).layer(inner);

        let response = service
            .call(auth_request(
                "/cln.NodeServices/Getinfo",
                Bytes::from_static(&[0u8; 8]),
            ))
            .await
            .unwrap();
        assert_eq!(response.headers().get("grpc-status").unwrap(), "16");
    }

    // --- Rune header hygiene (Fase 3) ---

    fn grpc_message(response: &http::Response<tonic::body::Body>) -> String {
        let raw = response
            .headers()
            .get("grpc-message")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        // tonic percent-encodes grpc-message; decode so assertions read the
        // original text.
        let bytes = raw.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Ok(byte) = u8::from_str_radix(&raw[i + 1..i + 3], 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn rune_charset_accepts_base64url_and_restrictions() {
        assert!(is_valid_rune_charset(
            "Q0FXzkB9DzGSJwBEjW9RwTGSfdh_i3e2Xz9O4cM1JDU="
        ));
        assert!(is_valid_rune_charset("abcDEF0123-_"));
        assert!(is_valid_rune_charset(
            "id/method=getinfo&rate=10,listfunds/expiry=1760000000/hmac"
        ));
    }

    #[test]
    fn rune_charset_rejects_spaces_and_controls() {
        assert!(!is_valid_rune_charset("has space"));
        assert!(!is_valid_rune_charset("semi;colon"));
        assert!(!is_valid_rune_charset("quote\"char"));
        assert!(!is_valid_rune_charset("new\nline"));
        assert!(!is_valid_rune_charset(""));
    }

    #[tokio::test]
    async fn duplicate_rune_header_is_rejected_without_backend_call() {
        let (inner, calls) = counting_inner();
        let mut service = AuthLayer::new(lazy_client(), 262_144).layer(inner);

        let mut req = http::Request::new(tonic::body::Body::new(http_body_util::Full::new(
            Bytes::new(),
        )));
        req.headers_mut()
            .append(RUNE_HEADER, "rune-one".parse().unwrap());
        req.headers_mut()
            .append(RUNE_HEADER, "rune-two".parse().unwrap());
        *req.uri_mut() = "/cln.NodeServices/Getinfo".parse().unwrap();

        let response = service.call(req).await.unwrap();
        assert_eq!(response.headers().get("grpc-status").unwrap(), "16");
        assert!(grpc_message(&response).contains("Multiple Rune"));
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "duplicate headers must not reach the backend"
        );
    }

    #[tokio::test]
    async fn oversized_rune_header_is_rejected_before_backend_call() {
        let (inner, calls) = counting_inner();
        let mut service = AuthLayer::new(lazy_client(), 262_144).layer(inner);

        let oversized = "a".repeat(MAX_RUNE_LEN + 1);
        let mut req = http::Request::new(tonic::body::Body::new(http_body_util::Full::new(
            Bytes::new(),
        )));
        req.headers_mut()
            .insert(RUNE_HEADER, oversized.parse().unwrap());
        *req.uri_mut() = "/cln.NodeServices/Getinfo".parse().unwrap();

        let response = service.call(req).await.unwrap();
        assert_eq!(response.headers().get("grpc-status").unwrap(), "16");
        assert!(grpc_message(&response).contains("Invalid Rune"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn invalid_charset_rune_is_rejected_before_backend_call() {
        let (inner, calls) = counting_inner();
        let mut service = AuthLayer::new(lazy_client(), 262_144).layer(inner);

        let mut req = http::Request::new(tonic::body::Body::new(http_body_util::Full::new(
            Bytes::new(),
        )));
        req.headers_mut()
            .insert(RUNE_HEADER, "bad;rune".parse().unwrap());
        *req.uri_mut() = "/cln.NodeServices/Getinfo".parse().unwrap();

        let response = service.call(req).await.unwrap();
        assert_eq!(response.headers().get("grpc-status").unwrap(), "16");
        assert!(grpc_message(&response).contains("Invalid Rune"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn well_formed_rune_reaches_rune_check() {
        let (inner, _calls) = counting_inner();
        let mut service = AuthLayer::new(lazy_client(), 262_144).layer(inner);

        let mut req = http::Request::new(tonic::body::Body::new(http_body_util::Full::new(
            Bytes::new(),
        )));
        req.headers_mut().insert(
            RUNE_HEADER,
            "Q0FXzkB9DzGSJwBEjW9RwTGSfdh_i3e2Xz9O4cM1JDU="
                .parse()
                .unwrap(),
        );
        *req.uri_mut() = "/cln.NodeServices/Getinfo".parse().unwrap();

        let response = service.call(req).await.unwrap();
        // The header passed the hygiene gate; the unreachable CLN fails the
        // actual check (a different message than "Invalid Rune header").
        assert_eq!(response.headers().get("grpc-status").unwrap(), "16");
        assert!(grpc_message(&response).contains("Rune validation failed"));
    }

    // --- Regression: the rune value never reaches logs (Fase 1) ---

    #[derive(Clone, Default)]
    struct CaptureWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriter;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[tokio::test]
    async fn rune_value_is_never_written_to_logs() {
        const SECRET_RUNE: &str = "SuperSecretRune_0123456789-_=";

        let capture = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (inner, _calls) = counting_inner();
        let mut service = AuthLayer::new(lazy_client(), 262_144).layer(inner);

        let mut req = http::Request::new(tonic::body::Body::new(http_body_util::Full::new(
            Bytes::new(),
        )));
        req.headers_mut()
            .insert(RUNE_HEADER, SECRET_RUNE.parse().unwrap());
        *req.uri_mut() = "/cln.NodeServices/Getinfo".parse().unwrap();

        let response = service.call(req).await.unwrap();
        assert_eq!(response.headers().get("grpc-status").unwrap(), "16");

        let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(
            !logs.contains(SECRET_RUNE),
            "rune value leaked into logs: {logs}"
        );
        assert!(logs.contains("check_rune call failed"), "logs: {logs}");
    }
}
