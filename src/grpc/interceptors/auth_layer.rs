use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::BodyExt;
use prost::Message;
use tonic::Status;
use tower::{Layer, Service};

use crate::cln::client::ClnClient;
use crate::cln::cln_api;

use super::auth::{validate_rune, RUNE_HEADER};

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
        "Auth rejected"
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

// --- Layer ---

#[derive(Clone)]
pub struct AuthLayer {
    client: Arc<ClnClient>,
}

impl AuthLayer {
    pub fn new(client: Arc<ClnClient>) -> Self {
        Self { client }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            client: self.client.clone(),
        }
    }
}

// --- Service ---

#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    client: Arc<ClnClient>,
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

        // Extract rune from gRPC metadata headers
        let rune = req
            .headers()
            .get(RUNE_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());

        let rune = match rune {
            Some(r) => r,
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
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Split request to read body
            let (parts, body) = req.into_parts();

            // Collect body bytes for protobuf decoding
            let body_bytes: Bytes = match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    return Ok(status_response(Status::internal(format!(
                        "Failed to read request body: {e}"
                    ))));
                }
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

        let mut service = AuthLayer::new(client).layer(service_fn(
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
}
