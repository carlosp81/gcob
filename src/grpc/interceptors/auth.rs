use std::sync::atomic::{AtomicBool, Ordering};

use tonic::{Request, Status};

use crate::cln::client::ClnClient;
use crate::cln::cln_api;

static RUNE_LOGGED: AtomicBool = AtomicBool::new(false);

pub(crate) const RUNE_HEADER: &str = "x-rune";
pub(crate) const CLIENT_ID_HEADER: &str = "x-client-id";

pub(crate) fn extract_rune_from_request<T>(request: &Request<T>) -> Option<String> {
    request
        .metadata()
        .get(RUNE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

pub(crate) fn extract_client_id<T>(request: &Request<T>) -> Option<String> {
    request
        .metadata()
        .get(CLIENT_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

pub(crate) async fn validate_rune(
    client: &ClnClient,
    rune: &str,
    method: &str,
) -> Result<(), Status> {
    let check_request = cln_api::CheckruneRequest {
        rune: rune.to_string(),
        nodeid: None,
        method: Some(method.to_string()),
        params: vec![],
    };

    let mut cln_client = client.inner.clone();
    let response = cln_client
        .check_rune(Request::new(check_request))
        .await
        .map_err(|e| {
            tracing::warn!("CLN check_rune call failed: {}", e);
            Status::unauthenticated("Rune validation failed")
        })?;

    let result = response.into_inner();
    if result.valid {
        if !RUNE_LOGGED.swap(true, Ordering::Relaxed) {
            tracing::info!("Rune authentication ENABLED (checked per-request)");
        }
        Ok(())
    } else {
        tracing::warn!("Invalid rune provided for method '{}'", method);
        Err(Status::unauthenticated("Invalid rune"))
    }
}
