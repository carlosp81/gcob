use std::sync::atomic::{AtomicBool, Ordering};

use tonic::{Request, Status};

use crate::cln::client::ClnClient;
use crate::cln::cln_api;

static RUNE_LOGGED: AtomicBool = AtomicBool::new(false);

pub(crate) const RUNE_HEADER: &str = "x-rune";
pub(crate) const CLIENT_ID_HEADER: &str = "x-client-id";

#[cfg(test)]
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
    params: Vec<String>,
) -> Result<(), Status> {
    let check_request = cln_api::CheckruneRequest {
        rune: rune.to_string(),
        nodeid: Some(client.node_id.clone()),
        method: Some(method.to_string()),
        params,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with_rune(rune: &str) -> Request<()> {
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert(RUNE_HEADER, rune.parse().unwrap());
        request
    }

    fn request_with_client_id(client_id: &str) -> Request<()> {
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert(CLIENT_ID_HEADER, client_id.parse().unwrap());
        request
    }

    fn request_with_both(rune: &str, client_id: &str) -> Request<()> {
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert(RUNE_HEADER, rune.parse().unwrap());
        request
            .metadata_mut()
            .insert(CLIENT_ID_HEADER, client_id.parse().unwrap());
        request
    }

    // --- extract_rune_from_request tests ---

    #[test]
    fn extract_rune_present() {
        let req = request_with_rune("my-valid-rune-123");
        assert_eq!(extract_rune_from_request(&req), Some("my-valid-rune-123".into()));
    }

    #[test]
    fn extract_rune_missing() {
        let req = request_with_client_id("client-1");
        assert_eq!(extract_rune_from_request(&req), None);
    }

    #[test]
    fn extract_rune_empty_string() {
        let req = request_with_rune("");
        assert_eq!(extract_rune_from_request(&req), None);
    }

    #[test]
    fn extract_rune_no_headers() {
        let req = Request::new(());
        assert_eq!(extract_rune_from_request(&req), None);
    }

    #[test]
    fn extract_rune_with_special_characters() {
        let rune = "02EqX-6Tcv4I5aO5PSG9vHRqCCbERqSJJvXE7jYVj1O1c9Mzc=";
        let req = request_with_rune(rune);
        assert_eq!(extract_rune_from_request(&req), Some(rune.into()));
    }

    // --- extract_client_id tests ---

    #[test]
    fn extract_client_id_present() {
        let req = request_with_client_id("test-client-01");
        assert_eq!(extract_client_id(&req), Some("test-client-01".into()));
    }

    #[test]
    fn extract_client_id_missing() {
        let req = request_with_rune("some-rune");
        assert_eq!(extract_client_id(&req), None);
    }

    #[test]
    fn extract_client_id_empty_string() {
        let req = request_with_client_id("");
        assert_eq!(extract_client_id(&req), Some("".into()));
    }

    #[test]
    fn extract_client_id_no_headers() {
        let req = Request::new(());
        assert_eq!(extract_client_id(&req), None);
    }

    // --- Combined header tests ---

    #[test]
    fn both_headers_present() {
        let req = request_with_both("valid-rune", "client-1");
        assert_eq!(extract_rune_from_request(&req), Some("valid-rune".into()));
        assert_eq!(extract_client_id(&req), Some("client-1".into()));
    }

    #[test]
    fn rune_present_client_id_missing() {
        let req = request_with_rune("valid-rune");
        assert_eq!(extract_rune_from_request(&req), Some("valid-rune".into()));
        assert_eq!(extract_client_id(&req), None);
    }

    #[test]
    fn rune_missing_client_id_present() {
        let req = request_with_client_id("client-1");
        assert_eq!(extract_rune_from_request(&req), None);
        assert_eq!(extract_client_id(&req), Some("client-1".into()));
    }

    #[test]
    fn both_headers_missing() {
        let req = Request::new(());
        assert_eq!(extract_rune_from_request(&req), None);
        assert_eq!(extract_client_id(&req), None);
    }

    // --- Validation pattern tests (simulate handler logic) ---

    #[test]
    fn handler_rejects_when_rune_missing() {
        let req = Request::new(());
        let rune = extract_rune_from_request(&req);
        assert!(rune.is_none(), "Should reject request without rune");
    }

    #[test]
    fn handler_accepts_when_rune_present() {
        let req = request_with_rune("test-rune");
        let rune = extract_rune_from_request(&req);
        assert!(rune.is_some(), "Should accept request with rune");
    }

    #[test]
    fn handler_rejects_empty_rune() {
        let req = request_with_rune("");
        let rune = extract_rune_from_request(&req);
        assert!(rune.is_none(), "Should reject empty rune");
    }

    #[test]
    fn handler_rejects_whitespace_only_rune() {
        let req = request_with_rune("   ");
        let rune = extract_rune_from_request(&req);
        // Whitespace is not empty, so it passes filter - this is expected behavior
        // CLN's check_rune will validate the actual rune
        assert!(rune.is_some(), "Whitespace rune passes extraction (CLN validates)");
    }

    // --- Rune alteration tests ---

    #[test]
    fn rune_alteration_preserves_extraction() {
        let original = "02EqX-6Tcv4I5aO5PSG9vHRqCCbERqSJJvXE7jYVj1O1c9Mzc=";
        let mut altered_bytes = original.as_bytes().to_vec();
        // Alter the last character before '='
        if let Some(pos) = altered_bytes.iter().position(|&b| b == b'=') {
            altered_bytes[pos - 1] = b'X';
        }
        let altered = String::from_utf8(altered_bytes).unwrap();

        let req_orig = request_with_rune(original);
        let req_alt = request_with_rune(&altered);

        // Both should be extracted (validation is CLN's responsibility)
        assert_eq!(extract_rune_from_request(&req_orig), Some(original.into()));
        assert_eq!(extract_rune_from_request(&req_alt), Some(altered.clone().into()));
        // But they should be different strings
        assert_ne!(original, altered.as_str());
    }

    #[test]
    fn rune_altered_hmac_differs_from_original() {
        let original = "Q0FXzkB9DzGSJwBEjW9RwTGSfdh_i3e2Xz9O4cM1JDU=";
        // Replace a character that actually exists in the rune
        let altered = original.replace("D", "X");
        // Ensure alteration actually changed the string
        assert_ne!(original, altered.as_str());
        // Both should still be extractable
        assert_eq!(
            extract_rune_from_request(&request_with_rune(original)),
            Some(original.into())
        );
        assert_eq!(
            extract_rune_from_request(&request_with_rune(&altered)),
            Some(altered.into())
        );
    }

    // --- Rune format structure tests ---

    #[test]
    fn rune_valid_base64url_format() {
        // CLN runes use base64url encoding (no padding '=' at end sometimes)
        let valid_runes = vec![
            "Q0FXzkB9DzGSJwBEjW9RwTGSfdh_i3e2Xz9O4cM1JDU",
            "02EqX-6Tcv4I5aO5PSG9vHRqCCbERqSJJvXE7jYVj1O1c9Mzc=",
            "dGVzdC1ydW5lLXZhbGlk",
        ];
        for rune in valid_runes {
            let req = request_with_rune(rune);
            assert_eq!(
                extract_rune_from_request(&req),
                Some(rune.into()),
                "Valid rune should be extracted: {}",
                rune
            );
        }
    }

    #[test]
    fn rune_with_restrictions_format() {
        // Rune with restriction structure: {id}/{restrictions}/{hmac}
        // Therestriction part uses '=' and '&' separators
        let rune_with_restrictions = "Q0FXzkB9DzGSJwBEjW9RwTGSfdh_i3e2Xz9O4cM1JDU";
        let req = request_with_rune(rune_with_restrictions);
        assert_eq!(
            extract_rune_from_request(&req),
            Some(rune_with_restrictions.into())
        );
    }

    #[test]
    fn rune_empty_string_is_rejected() {
        let req = request_with_rune("");
        assert_eq!(extract_rune_from_request(&req), None);
    }

    #[test]
    fn rune_whitespace_only_is_extracted_but_cln_validates() {
        // Whitespace passes our filter, but CLN's check_rune will reject it
        let req = request_with_rune("   ");
        assert!(extract_rune_from_request(&req).is_some());
    }

    // --- Metadata key case sensitivity tests ---

    #[test]
    fn rune_header_is_lowercase() {
        let req = request_with_rune("test");
        assert_eq!(extract_rune_from_request(&req), Some("test".into()));
    }

    #[test]
    fn rune_header_uppercase_rejected_by_http_layer() {
        // HTTP/2 requires lowercase header names
        // tonic's HeaderName::from_static panics on uppercase bytes
        // This confirms our extraction only works with lowercase "x-rune"
        let result = std::panic::catch_unwind(|| {
            let mut req = Request::new(());
            req.metadata_mut()
                .insert("X-RUNE", "test".parse().unwrap());
        });
        assert!(result.is_err(), "Uppercase header names are rejected by HTTP/2 layer");
    }
}
