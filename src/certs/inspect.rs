use std::net::IpAddr;
use std::path::Path;

use x509_parser::extensions::GeneralName;
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
    let cert = x509_pem
        .parse_x509()
        .map_err(|e| CertError::Parse(e.to_string()))?;

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
    let cert = x509_pem
        .parse_x509()
        .map_err(|e| CertError::Parse(e.to_string()))?;

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
/// Verify that a certificate is cryptographically signed by a CA.
///
/// Checks: issuer DN matches CA subject DN, CA has basicConstraints CA:TRUE,
/// the certificate signature actually verifies against the CA public key, and
/// the validity window contains the current time.
pub fn verify_signed_by(cert_path: &Path, ca_path: &Path) -> Result<ChainResult, CertError> {
    let cert_pem = std::fs::read(cert_path)?;
    let ca_pem = std::fs::read(ca_path)?;

    let (_, x509_cert_pem) =
        parse_x509_pem(&cert_pem).map_err(|e| CertError::Parse(e.to_string()))?;
    let cert = x509_cert_pem
        .parse_x509()
        .map_err(|e| CertError::Parse(e.to_string()))?;

    let (_, x509_ca_pem) = parse_x509_pem(&ca_pem).map_err(|e| CertError::Parse(e.to_string()))?;
    let ca = x509_ca_pem
        .parse_x509()
        .map_err(|e| CertError::Parse(e.to_string()))?;

    let cert_subject = cert.subject().to_string();
    let cert_issuer = cert.issuer().to_string();
    let ca_subject = ca.subject().to_string();

    let issuer_matches = cert_issuer == ca_subject;
    let ca_is_ca = ca
        .basic_constraints()
        .ok()
        .flatten()
        .map(|bc| bc.value.ca)
        .unwrap_or(false);

    // Cryptographic check: the leaf's signature must verify with the CA key.
    let signature_ok =
        issuer_matches && ca_is_ca && cert.verify_signature(Some(ca.public_key())).is_ok();

    let signed_by_ca = issuer_matches && ca_is_ca && signature_ok;

    let validity = cert.validity();
    let now = x509_parser::time::ASN1Time::now();
    let expired = now > validity.not_after;
    let not_yet_valid = now < validity.not_before;
    let days_remaining = if expired {
        -((now - validity.not_after)
            .map(|d| d.whole_seconds())
            .unwrap_or(0)
            / 86400)
    } else {
        (validity.not_after - now)
            .map(|d| d.whole_seconds())
            .unwrap_or(0)
            / 86400
    };

    let mut errors = Vec::new();
    if !issuer_matches {
        errors.push(format!(
            "issuer '{}' does not match CA subject '{}'",
            cert_issuer, ca_subject
        ));
    }
    if !ca_is_ca {
        errors.push("CA certificate is not a CA (basicConstraints CA:FALSE)".to_string());
    }
    if issuer_matches && ca_is_ca && !signature_ok {
        errors.push("certificate signature does not verify against the CA key".to_string());
    }
    if expired {
        errors.push(format!("certificate expired {} days ago", -days_remaining));
    }
    if not_yet_valid {
        errors.push("certificate is not yet valid".to_string());
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

/// Return the first DNS name and first IP address of the certificate SANs.
///
/// Used to renew a server certificate while preserving its identity instead of
/// trusting environment variables.
pub fn san_identities(path: &Path) -> Result<(Option<String>, Option<String>), CertError> {
    let pem = std::fs::read(path)?;
    let (_, x509_pem) = parse_x509_pem(&pem).map_err(|e| CertError::Parse(e.to_string()))?;
    let cert = x509_pem
        .parse_x509()
        .map_err(|e| CertError::Parse(e.to_string()))?;

    let mut dns_name = None;
    let mut ip_addr = None;

    if let Some(san_ext) = cert
        .subject_alternative_name()
        .map_err(|e| CertError::Parse(e.to_string()))?
    {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(name) if dns_name.is_none() => {
                    dns_name = Some(name.to_string());
                }
                GeneralName::IPAddress(bytes) if ip_addr.is_none() => {
                    let ip = match bytes.len() {
                        4 => Some(
                            std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
                                .to_string(),
                        ),
                        16 => {
                            let mut octets = [0u8; 16];
                            octets.copy_from_slice(bytes);
                            Some(std::net::Ipv6Addr::from(octets).to_string())
                        }
                        _ => None,
                    };
                    if ip.is_some() {
                        ip_addr = ip;
                    }
                }
                _ => {}
            }
        }
    }

    Ok((dns_name, ip_addr))
}

/// Check if a certificate is valid for exactly the expected hostname or IP.
///
/// DNS names are compared case-insensitively and in full (no substring
/// matching); IP addresses are compared byte-for-byte.
pub fn check_san_match(cert_path: &Path, expected_hostname: &str) -> Result<bool, CertError> {
    let pem = std::fs::read(cert_path)?;
    let (_, x509_pem) = parse_x509_pem(&pem).map_err(|e| CertError::Parse(e.to_string()))?;
    let cert = x509_pem
        .parse_x509()
        .map_err(|e| CertError::Parse(e.to_string()))?;

    let expected_ip: Option<IpAddr> = expected_hostname.parse().ok();

    let Some(san_ext) = cert
        .subject_alternative_name()
        .map_err(|e| CertError::Parse(e.to_string()))?
    else {
        return Ok(false);
    };

    for name in &san_ext.value.general_names {
        match name {
            GeneralName::DNSName(dns) if expected_ip.is_none() => {
                if dns.eq_ignore_ascii_case(expected_hostname) {
                    return Ok(true);
                }
            }
            GeneralName::IPAddress(bytes) => {
                if let Some(ip) = expected_ip {
                    let matches = match ip {
                        IpAddr::V4(v4) => *bytes == v4.octets().as_slice(),
                        IpAddr::V6(v6) => *bytes == v6.octets().as_slice(),
                    };
                    if matches {
                        return Ok(true);
                    }
                }
            }
            _ => {}
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
    use crate::certs::generate::{self, load_validated_ca};
    use crate::certs::paths::ClnSourcePaths;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    };
    use std::path::PathBuf;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    /// Create a self-signed CA with the given common name inside `dir`.
    fn test_issuer(dir: &Path, common_name: &str) -> Issuer<'static, KeyPair> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let cert = params.self_signed(&key).expect("self-signed ca");
        std::fs::write(dir.join("ca.pem"), cert.pem()).unwrap();
        std::fs::write(dir.join("ca-key.pem"), key.serialize_pem()).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.join("ca-key.pem"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }

        load_validated_ca(&ClnSourcePaths::new(dir.to_path_buf()))
            .expect("read ca")
            .issuer
    }

    fn issue_client(issuer: &Issuer<'static, KeyPair>, dir: &Path, hostname: &str) -> PathBuf {
        generate::generate_client_cert(issuer, hostname, dir).unwrap();
        dir.join("client.pem")
    }

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

    #[test]
    fn verify_signed_by_accepts_real_chain() {
        let ca_dir = temp_dir();
        let out_dir = temp_dir();
        let issuer = test_issuer(ca_dir.path(), "gcob-test-ca");
        let client = issue_client(&issuer, out_dir.path(), "client.example");

        let result = verify_signed_by(&client, &ca_dir.path().join("ca.pem")).unwrap();
        assert!(result.signed_by_ca, "errors: {:?}", result.errors);
        assert!(!result.expired);
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
    }

    #[test]
    fn verify_signed_by_rejects_forged_signature_with_same_subject() {
        // Two different CAs sharing the same subject DN: only the key that
        // actually signed the leaf must validate it.
        let ca1_dir = temp_dir();
        let ca2_dir = temp_dir();
        let out_dir = temp_dir();
        let issuer1 = test_issuer(ca1_dir.path(), "same-ca-subject");
        let _issuer2 = test_issuer(ca2_dir.path(), "same-ca-subject");

        let client = issue_client(&issuer1, out_dir.path(), "client.example");

        let result = verify_signed_by(&client, &ca2_dir.path().join("ca.pem")).unwrap();
        assert!(!result.signed_by_ca, "forged signature must not validate");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("signature does not verify")),
            "errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn san_identities_extracts_dns_and_ip() {
        let ca_dir = temp_dir();
        let out_dir = temp_dir();
        let issuer = test_issuer(ca_dir.path(), "gcob-test-ca");
        generate::generate_server_cert(&issuer, "node.example", "10.0.0.5", out_dir.path())
            .unwrap();

        let (dns, ip) = san_identities(&out_dir.path().join("server.pem")).unwrap();
        assert_eq!(dns.as_deref(), Some("node.example"));
        assert_eq!(ip.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn check_san_match_is_exact() {
        let ca_dir = temp_dir();
        let out_dir = temp_dir();
        let issuer = test_issuer(ca_dir.path(), "gcob-test-ca");
        generate::generate_server_cert(&issuer, "node.example", "10.0.0.5", out_dir.path())
            .unwrap();
        let server = out_dir.path().join("server.pem");

        assert!(check_san_match(&server, "node.example").unwrap());
        assert!(check_san_match(&server, "NODE.EXAMPLE").unwrap());
        assert!(check_san_match(&server, "10.0.0.5").unwrap());

        // Substring matching must not be accepted.
        assert!(!check_san_match(&server, "node").unwrap());
        assert!(!check_san_match(&server, "evilnode.example").unwrap());
        assert!(!check_san_match(&server, "10.0.0.6").unwrap());
        assert!(!check_san_match(&server, "10.0.0.50").unwrap());
    }
}
