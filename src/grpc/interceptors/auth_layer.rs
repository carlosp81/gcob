use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tower::{Layer, Service};
use tonic::Status;

use crate::cln::client::ClnClient;

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

impl<S, ReqBody> Service<http::Request<ReqBody>> for AuthService<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<tonic::body::Body>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
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
            // Async rune validation via CLN check_rune
            validate_rune(&client, &rune, method).await.map_err(|e| {
                let msg = e.message().to_string();
                Box::new(std::io::Error::new(std::io::ErrorKind::Other, msg))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;

            tracing::info!(path = %path, method = %method, "Rune validated - request allowed through");

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
}
