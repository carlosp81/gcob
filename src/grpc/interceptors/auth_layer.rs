use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::BodyExt;
use prost::Message;
use tower::{Layer, Service};
use tonic::Status;

use crate::cln::client::ClnClient;
use crate::cln::cln_api;

use super::auth::{validate_rune, RUNE_HEADER};

// --- Path → CLN method name mapping ---

fn rune_method_for_path(path: &str) -> Option<&'static str> {
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

fn unauthenticated_response(message: &str) -> http::Response<tonic::body::Body> {
    tracing::warn!(message = %message, "Auth rejected");
    Status::unauthenticated(message).into_http()
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
            let body_bytes: Bytes = body
                .collect()
                .await
                .map_err(|e| {
                    let msg = format!("Failed to read request body: {}", e);
                    Box::new(std::io::Error::new(std::io::ErrorKind::Other, msg))
                        as Box<dyn std::error::Error + Send + Sync>
                })?
                .to_bytes();

            // Extract params from protobuf body
            let params = extract_params_for_path(&path, &body_bytes);

            // Async rune validation via CLN check_rune (now with params)
            validate_rune(&client, &rune, method, params).await.map_err(|e| {
                let msg = e.message().to_string();
                Box::new(std::io::Error::new(std::io::ErrorKind::Other, msg))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;

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

    #[test]
    fn method_mapping_all_rpc_paths() {
        assert_eq!(rune_method_for_path("/cln.NodeServices/Invoice"), Some("invoice"));
        assert_eq!(rune_method_for_path("/cln.NodeServices/Getinfo"), Some("getinfo"));
        assert_eq!(rune_method_for_path("/cln.NodeServices/Xpay"), Some("xpay"));
        assert_eq!(rune_method_for_path("/cln.NodeServices/InvoiceStream"), Some("invoice"));
        assert_eq!(rune_method_for_path("/cln.NodeServices/XpayStreamWatch"), Some("xpay"));
        assert_eq!(rune_method_for_path("/cln.NodeServices/XpayStream"), Some("xpay_stream"));
        assert_eq!(rune_method_for_path("/cln.NodeServices/InvoiceWatch"), Some("invoice_watch"));
        assert_eq!(rune_method_for_path("/cln.NodeServices/WatchChannels"), Some("watch_channels"));
        assert_eq!(rune_method_for_path("/cln.NodeServices/WatchPeers"), Some("watch_peers"));
        assert_eq!(rune_method_for_path("/cln.NodeServices/WatchSystem"), Some("watch_system"));
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
}
