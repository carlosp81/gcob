use std::path::Path;

use x509_parser::pem::parse_x509_pem;

use super::generate::CertError;

/// Parsed certificate information
#[derive(Debug)]
pub struct CertInfo {
    pub file: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub days_remaining: i64,
    pub is_ca: bool,
    pub serial: String,
    pub sans: Vec<String>,
}

/// Parse a PEM certificate and extract info
pub fn parse_cert(path: &Path) -> Result<CertInfo, CertError> {
    let pem = std::fs::read(path)?;
    let (_, x509_pem) = parse_x509_pem(&pem).map_err(|e| CertError::Parse(e.to_string()))?;
    let cert = x509_pem.parse_x509().map_err(|e| CertError::Parse(e.to_string()))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let serial = cert.raw_serial_as_string();

    let validity = cert.validity();
    let not_before = validity.not_before.to_string();
    let not_after = validity.not_after.to_string();

    let days_remaining = validity
        .time_to_expiration()
        .map(|d| d.whole_seconds() / 86400)
        .unwrap_or(-1);

    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .map(|bc| bc.value.ca)
        .unwrap_or(false);

    let sans = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .map(|name| format!("{}", name))
                .collect()
        })
        .unwrap_or_default();

    Ok(CertInfo {
        file: path.display().to_string(),
        subject,
        issuer,
        not_before,
        not_after,
        days_remaining,
        is_ca,
        serial,
        sans,
    })
}

/// Get days until certificate expires (negative = expired)
pub fn days_until_expiry(path: &Path) -> Result<i64, CertError> {
    let pem = std::fs::read(path)?;
    let (_, x509_pem) = parse_x509_pem(&pem).map_err(|e| CertError::Parse(e.to_string()))?;
    let cert = x509_pem.parse_x509().map_err(|e| CertError::Parse(e.to_string()))?;

    let validity = cert.validity();
    Ok(validity
        .time_to_expiration()
        .map(|d| d.whole_seconds() / 86400)
        .unwrap_or(-1))
}

/// Check if a certificate is valid (not expired)
#[allow(dead_code)]
pub fn is_valid(path: &Path) -> Result<bool, CertError> {
    let days = days_until_expiry(path)?;
    Ok(days > 0)
}

/// Result of chain verification for a single certificate
#[derive(Debug)]
pub struct ChainResult {
    #[allow(dead_code)]
    pub cert_file: String,
    pub subject: String,
    pub issuer: String,
    pub signed_by_ca: bool,
    #[allow(dead_code)]
    pub ca_subject: String,
    pub expired: bool,
    pub days_remaining: i64,
    #[allow(dead_code)]
    pub san_match: Option<bool>,
    pub errors: Vec<String>,
}

/// Verify that a certificate is structurally signed by a CA
/// Checks: issuer DN matches CA subject DN, cert not expired
pub fn verify_signed_by(cert_path: &Path, ca_path: &Path) -> Result<ChainResult, CertError> {
    let cert_pem = std::fs::read(cert_path)?;
    let ca_pem = std::fs::read(ca_path)?;

    let (_, x509_cert_pem) =
        parse_x509_pem(&cert_pem).map_err(|e| CertError::Parse(e.to_string()))?;
    let cert = x509_cert_pem
        .parse_x509()
        .map_err(|e| CertError::Parse(e.to_string()))?;

    let (_, x509_ca_pem) =
        parse_x509_pem(&ca_pem).map_err(|e| CertError::Parse(e.to_string()))?;
    let ca = x509_ca_pem
        .parse_x509()
        .map_err(|e| CertError::Parse(e.to_string()))?;

    let cert_subject = cert.subject().to_string();
    let cert_issuer = cert.issuer().to_string();
    let ca_subject = ca.subject().to_string();

    let signed_by_ca = cert_issuer == ca_subject;

    let validity = cert.validity();
    let days_remaining = validity
        .time_to_expiration()
        .map(|d| d.whole_seconds() / 86400)
        .unwrap_or(-1);
    let expired = days_remaining <= 0;

    let mut errors = Vec::new();
    if !signed_by_ca {
        errors.push(format!(
            "issuer '{}' does not match CA subject '{}'",
            cert_issuer, ca_subject
        ));
    }
    if expired {
        errors.push(format!("certificate expired {} days ago", -days_remaining));
    }

    Ok(ChainResult {
        cert_file: cert_path.display().to_string(),
        subject: cert_subject,
        issuer: cert_issuer,
        signed_by_ca,
        ca_subject,
        expired,
        days_remaining,
        san_match: None,
        errors,
    })
}

/// Check if server certificate SANs match expected hostname
pub fn check_san_match(cert_path: &Path, expected_hostname: &str) -> Result<bool, CertError> {
    let pem = std::fs::read(cert_path)?;
    let (_, x509_pem) = parse_x509_pem(&pem).map_err(|e| CertError::Parse(e.to_string()))?;
    let cert = x509_pem
        .parse_x509()
        .map_err(|e| CertError::Parse(e.to_string()))?;

    if let Some(san_ext) = cert.subject_alternative_name().ok().flatten() {
        for name in &san_ext.value.general_names {
            let name_str = format!("{}", name);
            if name_str.contains(expected_hostname) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Verify full chain: CA → server, CA → client, SAN match
#[allow(dead_code)]
pub fn verify_chain(
    cert_dir: &Path,
    expected_hostname: &str,
) -> Result<Vec<ChainResult>, CertError> {
    let ca_path = cert_dir.join("ca.pem");
    let server_path = cert_dir.join("server.pem");
    let client_path = cert_dir.join("client.pem");

    let mut results = Vec::new();

    // Verify server cert
    if server_path.exists() {
        let mut result = verify_signed_by(&server_path, &ca_path)?;
        result.san_match = Some(check_san_match(&server_path, expected_hostname)?);
        if result.san_match == Some(false) {
            result.errors.push(format!(
                "SAN does not match expected hostname '{}'",
                expected_hostname
            ));
        }
        results.push(result);
    }

    // Verify client cert
    if client_path.exists() {
        let result = verify_signed_by(&client_path, &ca_path)?;
        results.push(result);
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nonexistent_file() {
        let result = parse_cert(Path::new("/nonexistent.pem"));
        assert!(result.is_err());
    }

    #[test]
    fn days_until_expiry_nonexistent() {
        let result = days_until_expiry(Path::new("/nonexistent.pem"));
        assert!(result.is_err());
    }

    #[test]
    fn verify_nonexistent_cert() {
        let result = verify_signed_by(
            Path::new("/nonexistent.pem"),
            Path::new("/nonexistent-ca.pem"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn check_san_nonexistent() {
        let result = check_san_match(Path::new("/nonexistent.pem"), "localhost");
        assert!(result.is_err());
    }
}
