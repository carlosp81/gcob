use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;

use x509_parser::extensions::GeneralName;

use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, PublicKeyData, SanType,
    SigningKey,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::paths::{validate_cln_source, ClnSourcePaths};

/// Validity of emitted client certificates (days).
pub const CLIENT_CERT_VALIDITY_DAYS: i64 = 365;

/// Validity of emitted server certificates (days).
pub const SERVER_CERT_VALIDITY_DAYS: i64 = 365;

/// Bounded validity window: one hour of clock skew in the past, `days` into the future.
fn validity_window(days: i64) -> (time::OffsetDateTime, time::OffsetDateTime) {
    let now = time::OffsetDateTime::now_utc();
    (
        now - time::Duration::hours(1),
        now + time::Duration::days(days),
    )
}

/// Atomically write `data` to `path` with the given mode, replacing any existing entry.
///
/// Writes to a temporary file in the same directory and renames it into place, so a
/// pre-existing symlink at `path` is replaced instead of followed, and readers never
/// observe partial content. Private keys must be written with mode `0o600`.
fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<(), CertError> {
    write_atomic_impl(path, data, mode, None)
}

/// Atomically write `data` to `path` with the given mode and ownership.
///
/// Used for privileged destinations where the final owner/group must be the
/// consuming service (HAProxy, gcob API) instead of the invoking user.
pub fn write_atomic_owned(
    path: &Path,
    data: &[u8],
    mode: u32,
    owner: (u32, u32),
) -> Result<(), CertError> {
    write_atomic_impl(path, data, mode, Some(owner))
}

fn write_atomic_impl(
    path: &Path,
    data: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> Result<(), CertError> {
    let parent = path.parent().ok_or_else(|| {
        CertError::Io(std::io::Error::other(format!(
            "Cannot determine parent directory for {}",
            path.display()
        )))
    })?;
    if !parent.exists() {
        fs::create_dir_all(parent)?;
    }

    let mut tmp = tempfile::Builder::new()
        .prefix(".gcob-tmp-")
        .tempfile_in(parent)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::io::AsRawFd;

        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(mode))?;

        if let Some((uid, gid)) = owner {
            let rc = unsafe { libc::fchown(tmp.as_file().as_raw_fd(), uid, gid) };
            if rc != 0 {
                return Err(CertError::Io(std::io::Error::last_os_error()));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (mode, owner);

    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| CertError::Io(e.error))?;
    Ok(())
}

/// Errors during certificate generation
#[derive(Debug)]
pub enum CertError {
    Io(std::io::Error),
    Rcgen(rcgen::Error),
    Parse(String),
    MissingSource(String),
    InvalidIp(String),
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertError::Io(e) => write!(f, "IO error: {}", e),
            CertError::Rcgen(e) => write!(f, "Certificate error: {}", e),
            CertError::Parse(e) => write!(f, "Parse error: {}", e),
            CertError::MissingSource(e) => write!(f, "Missing source: {}", e),
            CertError::InvalidIp(e) => write!(f, "Invalid IP address: {}", e),
        }
    }
}

impl std::error::Error for CertError {}

impl From<std::io::Error> for CertError {
    fn from(e: std::io::Error) -> Self {
        CertError::Io(e)
    }
}

impl From<rcgen::Error> for CertError {
    fn from(e: rcgen::Error) -> Self {
        CertError::Rcgen(e)
    }
}

/// A CLN CA that passed all preflight validations.
#[derive(Debug)]
pub struct ValidatedCa {
    pub issuer: Issuer<'static, KeyPair>,
    pub ca_pem: String,
    pub fingerprint_sha256: String,
}

/// Load and validate the CLN CA private key and certificate.
///
/// Security invariants:
/// - no symlinked component in the source paths, regular files only;
/// - source directory not writable by group/other;
/// - CA private key mode 0600 or 0400;
/// - `ca.pem` has `basicConstraints CA:TRUE`;
/// - the private key actually matches the certificate public key;
/// - key material is zeroized after parsing, and a SHA-256 fingerprint of the
///   CA certificate is returned for pinning.
pub fn load_validated_ca(source: &ClnSourcePaths) -> Result<ValidatedCa, CertError> {
    validate_cln_source(source)?;

    if !source.ca_file.exists() {
        return Err(CertError::MissingSource(format!(
            "CA certificate not found: {}",
            source.ca_file.display()
        )));
    }
    if !source.ca_key_file.exists() {
        return Err(CertError::MissingSource(format!(
            "CA key not found: {}",
            source.ca_key_file.display()
        )));
    }

    let ca_key_pem = Zeroizing::new(fs::read_to_string(&source.ca_key_file)?);
    let ca_pem = fs::read_to_string(&source.ca_file)?;

    let ca_key = KeyPair::from_pem(&ca_key_pem).map_err(CertError::Rcgen)?;

    let (_, pem) = x509_parser::pem::parse_x509_pem(ca_pem.as_bytes())
        .map_err(|e| CertError::Parse(format!("CA parse error: {}", e)))?;
    let ca_cert = pem
        .parse_x509()
        .map_err(|e| CertError::Parse(format!("CA parse error: {}", e)))?;

    let is_ca = ca_cert
        .basic_constraints()
        .ok()
        .flatten()
        .map(|bc| bc.value.ca)
        .unwrap_or(false);
    if !is_ca {
        return Err(CertError::Parse(
            "CA certificate is not a CA (basicConstraints CA:FALSE)".to_string(),
        ));
    }

    // The private key must belong to the certificate's public key.
    let cert_public_key = ca_cert.public_key().subject_public_key.as_ref();
    if ca_key.public_key_raw() != cert_public_key {
        return Err(CertError::Parse(
            "CA private key does not match ca.pem".to_string(),
        ));
    }

    let fingerprint_sha256 = hex::encode(Sha256::digest(ca_cert.as_raw()));

    let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key).map_err(CertError::Rcgen)?;

    Ok(ValidatedCa {
        issuer,
        ca_pem,
        fingerprint_sha256,
    })
}

/// Generate a client certificate signed by the CA
pub fn generate_client_cert<S: SigningKey>(
    issuer: &Issuer<'_, S>,
    hostname: &str,
    output_dir: &Path,
) -> Result<(), CertError> {
    let client_key = KeyPair::generate().map_err(CertError::Rcgen)?;

    let mut params =
        CertificateParams::new(vec![hostname.to_string()]).map_err(CertError::Rcgen)?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, hostname);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.is_ca = IsCa::ExplicitNoCa;
    let (not_before, not_after) = validity_window(CLIENT_CERT_VALIDITY_DAYS);
    params.not_before = not_before;
    params.not_after = not_after;

    let cert = params
        .signed_by(&client_key, issuer)
        .map_err(CertError::Rcgen)?;

    write_atomic(&output_dir.join("client.pem"), cert.pem().as_bytes(), 0o644)?;
    write_atomic(
        &output_dir.join("client-key.pem"),
        client_key.serialize_pem().as_bytes(),
        0o600,
    )?;

    Ok(())
}

/// Generate a server certificate signed by the CA with SAN extensions
pub fn generate_server_cert<S: SigningKey>(
    issuer: &Issuer<'_, S>,
    hostname: &str,
    ip: &str,
    output_dir: &Path,
) -> Result<(), CertError> {
    let server_key = KeyPair::generate().map_err(CertError::Rcgen)?;

    let ip_addr: std::net::IpAddr = ip
        .parse()
        .map_err(|_| CertError::InvalidIp(ip.to_string()))?;

    let mut params =
        CertificateParams::new(vec![hostname.to_string()]).map_err(CertError::Rcgen)?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, hostname);
    // Only the explicitly requested IP is added; no implicit "localhost" SAN.
    if !params
        .subject_alt_names
        .iter()
        .any(|san| matches!(san, SanType::IpAddress(addr) if *addr == ip_addr))
    {
        params.subject_alt_names.push(SanType::IpAddress(ip_addr));
    }
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.is_ca = IsCa::ExplicitNoCa;
    let (not_before, not_after) = validity_window(SERVER_CERT_VALIDITY_DAYS);
    params.not_before = not_before;
    params.not_after = not_after;

    let cert = params
        .signed_by(&server_key, issuer)
        .map_err(CertError::Rcgen)?;

    write_atomic(&output_dir.join("server.pem"), cert.pem().as_bytes(), 0o644)?;
    write_atomic(
        &output_dir.join("server-key.pem"),
        server_key.serialize_pem().as_bytes(),
        0o600,
    )?;

    Ok(())
}

/// Concatenate certificate and key for HAProxy
pub fn concat_cert_key(
    cert_path: &Path,
    key_path: &Path,
    output_path: &Path,
) -> Result<(), CertError> {
    let cert = fs::read_to_string(cert_path)?;
    let key = fs::read_to_string(key_path)?;
    // The bundle embeds a private key: restrict to owner read/write.
    write_atomic(output_path, format!("{}{}", cert, key).as_bytes(), 0o600)?;
    Ok(())
}

/// Generate a CSR (Certificate Signing Request) for a client
/// This runs on the CLIENT machine - no CA needed
pub fn generate_csr(hostname: &str, ip: Option<&str>, output_dir: &Path) -> Result<(), CertError> {
    let client_key = KeyPair::generate().map_err(CertError::Rcgen)?;

    // Build SAN list with hostname and optional IP
    let mut san_names = vec![hostname.to_string()];
    if let Some(ip_str) = ip {
        // Validate IP format
        let _ip_addr: std::net::IpAddr = ip_str
            .parse()
            .map_err(|_| CertError::InvalidIp(ip_str.to_string()))?;
        san_names.push(ip_str.to_string());
    }

    let mut params = CertificateParams::new(san_names).map_err(CertError::Rcgen)?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, hostname);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);

    let csr = params
        .serialize_request(&client_key)
        .map_err(CertError::Rcgen)?;

    // Write CSR (public) and client key (private, owner-only).
    let csr_pem = csr.pem().map_err(CertError::Rcgen)?;
    write_atomic(&output_dir.join("client.csr"), csr_pem.as_bytes(), 0o644)?;
    write_atomic(
        &output_dir.join("client-key.pem"),
        client_key.serialize_pem().as_bytes(),
        0o600,
    )?;

    Ok(())
}

/// Sign a CSR with the CA - this runs on the SERVER.
///
/// Security: the CSR is treated as an untrusted source of a public key only. All
/// certificate properties (subject, SANs, EKU, key usages, basic constraints and
/// validity) are rebuilt from `hostname` and never copied from the CSR. This prevents
/// a malicious CSR from obtaining a CA certificate or a certificate for another identity.
pub fn sign_csr<S: SigningKey>(
    csr_path: &Path,
    hostname: &str,
    issuer: &Issuer<'_, S>,
    output_dir: &Path,
) -> Result<(), CertError> {
    let csr_pem = fs::read_to_string(csr_path)?;

    let csr = CertificateSigningRequestParams::from_pem(&csr_pem)
        .map_err(|e| CertError::Parse(format!("CSR parse error: {}", e)))?;

    let mut params =
        CertificateParams::new(vec![hostname.to_string()]).map_err(CertError::Rcgen)?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, hostname);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.is_ca = IsCa::ExplicitNoCa;
    let (not_before, not_after) = validity_window(CLIENT_CERT_VALIDITY_DAYS);
    params.not_before = not_before;
    params.not_after = not_after;

    // Use only the CSR's public key; ignore everything it requested.
    let cert = params
        .signed_by(&csr.public_key, issuer)
        .map_err(|e| CertError::Parse(format!("CSR sign error: {}", e)))?;

    write_atomic(&output_dir.join("client.pem"), cert.pem().as_bytes(), 0o644)?;

    Ok(())
}

/// SHA-256 fingerprint (lowercase hex) of the certificate in `path`.
pub fn cert_fingerprint(path: &Path) -> Result<String, CertError> {
    let pem = fs::read(path)?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem)
        .map_err(|e| CertError::Parse(format!("Certificate parse error: {}", e)))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| CertError::Parse(format!("Certificate parse error: {}", e)))?;
    Ok(hex::encode(Sha256::digest(cert.as_raw())))
}

/// Normalized SAN token used for exact set comparison (`dns:` or `ip:`).
pub fn san_token(value: &str) -> String {
    match value.parse::<std::net::IpAddr>() {
        Ok(_) => format!("ip:{}", value),
        Err(_) => format!("dns:{}", value.to_ascii_lowercase()),
    }
}

/// Set of SAN tokens present in a certificate.
pub fn cert_san_set(path: &Path) -> Result<BTreeSet<String>, CertError> {
    let pem = fs::read(path)?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem)
        .map_err(|e| CertError::Parse(format!("Certificate parse error: {}", e)))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| CertError::Parse(format!("Certificate parse error: {}", e)))?;

    let mut tokens = BTreeSet::new();
    if let Some(san) = cert
        .subject_alternative_name()
        .map_err(|e| CertError::Parse(e.to_string()))?
    {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(dns) => {
                    tokens.insert(format!("dns:{}", dns.to_ascii_lowercase()));
                }
                GeneralName::IPAddress(bytes) => {
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
                    if let Some(ip) = ip {
                        tokens.insert(format!("ip:{}", ip));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(tokens)
}

/// Apply mode and ownership to a staged file before publishing it.
#[cfg(unix)]
pub fn apply_owner_mode(path: &Path, mode: u32, owner: (u32, u32)) -> Result<(), CertError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    std::os::unix::fs::chown(path, Some(owner.0), Some(owner.1))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn apply_owner_mode(_path: &Path, _mode: u32, _owner: (u32, u32)) -> Result<(), CertError> {
    Ok(())
}

/// Post-generation verification of an issued leaf certificate.
///
/// Asserts: chain validates against the CA, certificate is currently valid,
/// EKU matches the intended usage, SANs are exactly the expected set, and the
/// private key belongs to the certificate public key.
pub fn verify_issued_cert(
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
    expected_sans: &BTreeSet<String>,
    expect_server_auth: bool,
) -> Result<(), CertError> {
    let chain = super::inspect::verify_signed_by(cert_path, ca_path)?;
    if !chain.signed_by_ca || chain.expired || !chain.errors.is_empty() {
        return Err(CertError::Parse(format!(
            "Issued certificate {} failed chain validation: {:?}",
            cert_path.display(),
            chain.errors
        )));
    }

    let pem = fs::read(cert_path)?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem)
        .map_err(|e| CertError::Parse(format!("Certificate parse error: {}", e)))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| CertError::Parse(format!("Certificate parse error: {}", e)))?;

    let eku = cert
        .extended_key_usage()
        .map_err(|e| CertError::Parse(e.to_string()))?
        .ok_or_else(|| CertError::Parse("Issued certificate has no EKU".to_string()))?;
    let eku_ok = if expect_server_auth {
        eku.value.server_auth
    } else {
        eku.value.client_auth && !eku.value.server_auth
    };
    if !eku_ok {
        return Err(CertError::Parse(format!(
            "Issued certificate {} has an unexpected EKU",
            cert_path.display()
        )));
    }

    let actual_sans = cert_san_set(cert_path)?;
    if &actual_sans != expected_sans {
        return Err(CertError::Parse(format!(
            "Issued certificate {} SAN mismatch: expected {:?}, got {:?}",
            cert_path.display(),
            expected_sans,
            actual_sans
        )));
    }

    let key_pem = Zeroizing::new(fs::read_to_string(key_path)?);
    let key = KeyPair::from_pem(&key_pem).map_err(CertError::Rcgen)?;
    if key.public_key_raw() != cert.public_key().subject_public_key.as_ref() {
        return Err(CertError::Parse(format!(
            "Private key does not match issued certificate {}",
            cert_path.display()
        )));
    }

    Ok(())
}

/// Post-generation verification of a certificate issued from a CSR.
///
/// Asserts: chain validates against the CA, certificate is currently valid,
/// EKU is clientAuth (and not serverAuth), it is not a CA, SANs are exactly
/// the expected set, and the public key matches the CSR that was signed.
pub fn verify_signed_csr(
    cert_path: &Path,
    csr_path: &Path,
    ca_path: &Path,
    expected_sans: &BTreeSet<String>,
) -> Result<(), CertError> {
    let chain = super::inspect::verify_signed_by(cert_path, ca_path)?;
    if !chain.signed_by_ca || chain.expired || !chain.errors.is_empty() {
        return Err(CertError::Parse(format!(
            "Signed certificate {} failed chain validation: {:?}",
            cert_path.display(),
            chain.errors
        )));
    }

    let pem = fs::read(cert_path)?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem)
        .map_err(|e| CertError::Parse(format!("Certificate parse error: {}", e)))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| CertError::Parse(format!("Certificate parse error: {}", e)))?;

    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .map(|bc| bc.value.ca)
        .unwrap_or(false);
    if is_ca {
        return Err(CertError::Parse(format!(
            "Signed certificate {} must not be a CA",
            cert_path.display()
        )));
    }

    let eku = cert
        .extended_key_usage()
        .map_err(|e| CertError::Parse(e.to_string()))?
        .ok_or_else(|| CertError::Parse("Signed certificate has no EKU".to_string()))?;
    if !(eku.value.client_auth && !eku.value.server_auth) {
        return Err(CertError::Parse(format!(
            "Signed certificate {} must have clientAuth only",
            cert_path.display()
        )));
    }

    let actual_sans = cert_san_set(cert_path)?;
    if &actual_sans != expected_sans {
        return Err(CertError::Parse(format!(
            "Signed certificate {} SAN mismatch: expected {:?}, got {:?}",
            cert_path.display(),
            expected_sans,
            actual_sans
        )));
    }

    let csr_pem = fs::read_to_string(csr_path)?;
    let csr = CertificateSigningRequestParams::from_pem(&csr_pem)
        .map_err(|e| CertError::Parse(format!("CSR parse error: {}", e)))?;
    if csr.public_key.der_bytes() != cert.public_key().subject_public_key.as_ref() {
        return Err(CertError::Parse(format!(
            "Signed certificate {} does not match the CSR public key",
            cert_path.display()
        )));
    }

    Ok(())
}

/// Copy a file, creating parent directories if needed
pub fn copy_file(src: &Path, dst: &Path) -> Result<(), CertError> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(src, dst)?;
    Ok(())
}

/// Set file permissions (Unix only)
#[cfg(unix)]
pub fn set_permissions(path: &Path, mode: u32) -> Result<(), CertError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
pub fn set_permissions(_path: &Path, _mode: u32) -> Result<(), CertError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::extensions::GeneralName;
    use x509_parser::prelude::*;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("create temp dir")
    }

    fn write_test_ca(dir: &Path, is_ca: bool) -> (String, String) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        }

        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::default();
        params.is_ca = if is_ca {
            IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
        } else {
            IsCa::ExplicitNoCa
        };
        params
            .distinguished_name
            .push(DnType::CommonName, "gcob-test-ca");
        let cert = params.self_signed(&key).expect("self-signed ca");
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        fs::write(dir.join("ca.pem"), &cert_pem).unwrap();
        fs::write(dir.join("ca-key.pem"), &key_pem).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.join("ca-key.pem"), fs::Permissions::from_mode(0o600)).unwrap();
        }

        (cert_pem, key_pem)
    }

    fn test_issuer(dir: &Path) -> Issuer<'static, KeyPair> {
        write_test_ca(dir, true);
        load_validated_ca(&ClnSourcePaths::new(dir.to_path_buf()))
            .expect("read ca")
            .issuer
    }

    fn with_cert<R>(path: &Path, f: impl FnOnce(&X509Certificate<'_>) -> R) -> R {
        let data = fs::read(path).expect("read cert");
        let (_, pem) = x509_parser::pem::parse_x509_pem(&data).expect("parse pem");
        let cert = pem.parse_x509().expect("parse x509");
        f(&cert)
    }

    fn san_names(cert: &X509Certificate<'_>) -> Vec<String> {
        cert.subject_alternative_name()
            .expect("san extension")
            .map(|san| {
                san.value
                    .general_names
                    .iter()
                    .map(|name| match name {
                        GeneralName::DNSName(dns) => format!("dns:{}", dns),
                        GeneralName::IPAddress(bytes) => format!(
                            "ip:{}",
                            bytes
                                .iter()
                                .map(|b| b.to_string())
                                .collect::<Vec<_>>()
                                .join(".")
                        ),
                        other => format!("other:{:?}", other),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn sign_csr_ignores_malicious_requested_extensions() {
        let ca_dir = temp_dir();
        let out_dir = temp_dir();
        let issuer = test_issuer(ca_dir.path());

        // Malicious CSR: CA:TRUE, serverAuth, keyCertSign and a foreign SAN.
        let evil_key = KeyPair::generate().unwrap();
        let mut evil = CertificateParams::new(vec!["evil.example".to_string()]).unwrap();
        evil.distinguished_name = DistinguishedName::new();
        evil.distinguished_name.push(DnType::CommonName, "evil");
        evil.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        evil.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        evil.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let csr = evil.serialize_request(&evil_key).unwrap();
        let csr_path = ca_dir.path().join("evil.csr");
        fs::write(&csr_path, csr.pem().unwrap()).unwrap();

        sign_csr(&csr_path, "client.example", &issuer, out_dir.path()).unwrap();

        with_cert(&out_dir.path().join("client.pem"), |cert| {
            let bc = cert
                .basic_constraints()
                .expect("basic constraints")
                .expect("basic constraints extension");
            assert!(!bc.value.ca, "signed certificate must not be a CA");

            let common_names: Vec<String> = cert
                .subject()
                .iter_common_name()
                .filter_map(|attr| attr.as_str().ok().map(str::to_string))
                .collect();
            assert_eq!(common_names, vec!["client.example".to_string()]);

            let eku = cert
                .extended_key_usage()
                .expect("eku parse")
                .expect("eku extension");
            assert!(eku.value.client_auth, "clientAuth must be present");
            assert!(!eku.value.server_auth, "serverAuth must not be granted");
            assert!(!eku.value.any, "ANY EKU must not be granted");

            let sans = san_names(cert);
            assert!(
                sans.contains(&"dns:client.example".to_string()),
                "expected requested hostname SAN, got {:?}",
                sans
            );
            assert!(
                !sans.iter().any(|s| s.contains("evil")),
                "CSR SANs must not be copied: {:?}",
                sans
            );
        });
    }

    #[test]
    fn generated_client_cert_has_bounded_validity_and_private_key_mode() {
        let ca_dir = temp_dir();
        let out_dir = temp_dir();
        let issuer = test_issuer(ca_dir.path());

        generate_client_cert(&issuer, "client.example", out_dir.path()).unwrap();

        let now = ::time::OffsetDateTime::now_utc();
        with_cert(&out_dir.path().join("client.pem"), |cert| {
            let not_before = cert.validity().not_before.to_datetime();
            let not_after = cert.validity().not_after.to_datetime();
            assert!(
                not_before >= now - ::time::Duration::days(1),
                "not_before is not 1975"
            );
            assert!(not_before < now + ::time::Duration::hours(1));
            assert!(not_after > now + ::time::Duration::days(300));
            assert!(
                not_after < now + ::time::Duration::days(366),
                "validity must be bounded"
            );
        });

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(out_dir.path().join("client-key.pem"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "private key must be owner-only");
        }
    }

    #[test]
    fn server_cert_has_only_requested_identity() {
        let ca_dir = temp_dir();
        let out_dir = temp_dir();
        let issuer = test_issuer(ca_dir.path());

        generate_server_cert(&issuer, "node.example", "10.0.0.5", out_dir.path()).unwrap();

        with_cert(&out_dir.path().join("server.pem"), |cert| {
            let sans = san_names(cert);
            assert!(
                sans.contains(&"dns:node.example".to_string()),
                "got {:?}",
                sans
            );
            assert!(sans.contains(&"ip:10.0.0.5".to_string()), "got {:?}", sans);
            assert!(
                !sans.iter().any(|s| s.contains("localhost")),
                "implicit localhost SAN must not exist: {:?}",
                sans
            );

            let bc = cert.basic_constraints().unwrap().unwrap();
            assert!(!bc.value.ca);

            let eku = cert.extended_key_usage().unwrap().unwrap();
            assert!(eku.value.server_auth);
            assert!(!eku.value.client_auth);
        });
    }

    #[test]
    fn write_atomic_replaces_content_and_mode() {
        let dir = temp_dir();
        let path = dir.path().join("out.pem");
        write_atomic(&path, b"first", 0o600).unwrap();
        write_atomic(&path, b"second", 0o644).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644);
        }
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_does_not_follow_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir();
        let victim = dir.path().join("victim.txt");
        fs::write(&victim, b"original").unwrap();

        let link = dir.path().join("client.pem");
        symlink(&victim, &link).unwrap();

        write_atomic(&link, b"pwned", 0o600).unwrap();

        assert_eq!(fs::read(&victim).unwrap(), b"original");
        assert!(!fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&link).unwrap(), b"pwned");
    }

    #[test]
    fn load_validated_ca_accepts_real_ca() {
        let dir = temp_dir();
        write_test_ca(dir.path(), true);
        let validated = load_validated_ca(&ClnSourcePaths::new(dir.path().to_path_buf())).unwrap();
        assert_eq!(validated.fingerprint_sha256.len(), 64);
        assert!(validated.ca_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn load_validated_ca_rejects_non_ca_certificate() {
        let dir = temp_dir();
        write_test_ca(dir.path(), false);
        let err = load_validated_ca(&ClnSourcePaths::new(dir.path().to_path_buf())).unwrap_err();
        assert!(format!("{}", err).contains("not a CA"), "{err}");
    }

    #[test]
    fn load_validated_ca_rejects_mismatched_key() {
        let dir = temp_dir();
        write_test_ca(dir.path(), true);
        // Replace the key with an unrelated one.
        let other = KeyPair::generate().unwrap();
        fs::write(dir.path().join("ca-key.pem"), other.serialize_pem()).unwrap();

        let err = load_validated_ca(&ClnSourcePaths::new(dir.path().to_path_buf())).unwrap_err();
        assert!(format!("{}", err).contains("does not match"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn load_validated_ca_rejects_world_readable_key() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir();
        write_test_ca(dir.path(), true);
        fs::set_permissions(
            dir.path().join("ca-key.pem"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let err = load_validated_ca(&ClnSourcePaths::new(dir.path().to_path_buf())).unwrap_err();
        assert!(format!("{}", err).contains("expected 0600"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn load_validated_ca_rejects_symlinked_key() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir();
        let (_, key_pem) = write_test_ca(dir.path(), true);
        let real = dir.path().join("real-key.pem");
        fs::write(&real, key_pem).unwrap();
        fs::remove_file(dir.path().join("ca-key.pem")).unwrap();
        symlink(&real, dir.path().join("ca-key.pem")).unwrap();

        let err = load_validated_ca(&ClnSourcePaths::new(dir.path().to_path_buf())).unwrap_err();
        assert!(format!("{}", err).contains("symlink"), "{err}");
    }

    fn client_sans(hostname: &str) -> BTreeSet<String> {
        [san_token(hostname)].into_iter().collect()
    }

    #[test]
    fn verify_signed_csr_accepts_valid_certificate() {
        let ca_dir = temp_dir();
        let csr_dir = temp_dir();
        let out_dir = temp_dir();
        let issuer = test_issuer(ca_dir.path());

        generate_csr("client.example", None, csr_dir.path()).unwrap();
        let csr_path = csr_dir.path().join("client.csr");
        sign_csr(&csr_path, "client.example", &issuer, out_dir.path()).unwrap();

        verify_signed_csr(
            &out_dir.path().join("client.pem"),
            &csr_path,
            &ca_dir.path().join("ca.pem"),
            &client_sans("client.example"),
        )
        .unwrap();
    }

    #[test]
    fn verify_signed_csr_rejects_wrong_san() {
        let ca_dir = temp_dir();
        let csr_dir = temp_dir();
        let out_dir = temp_dir();
        let issuer = test_issuer(ca_dir.path());

        generate_csr("client.example", None, csr_dir.path()).unwrap();
        let csr_path = csr_dir.path().join("client.csr");
        sign_csr(&csr_path, "client.example", &issuer, out_dir.path()).unwrap();

        let err = verify_signed_csr(
            &out_dir.path().join("client.pem"),
            &csr_path,
            &ca_dir.path().join("ca.pem"),
            &client_sans("other.example"),
        )
        .unwrap_err();
        assert!(format!("{}", err).contains("SAN mismatch"), "{err}");
    }

    #[test]
    fn verify_signed_csr_rejects_server_auth_eku() {
        let ca_dir = temp_dir();
        let csr_dir = temp_dir();
        let out_dir = temp_dir();
        let issuer = test_issuer(ca_dir.path());

        generate_csr("node.example", None, csr_dir.path()).unwrap();
        let csr_path = csr_dir.path().join("client.csr");
        generate_server_cert(&issuer, "node.example", "10.0.0.5", out_dir.path()).unwrap();

        let err = verify_signed_csr(
            &out_dir.path().join("server.pem"),
            &csr_path,
            &ca_dir.path().join("ca.pem"),
            &client_sans("node.example"),
        )
        .unwrap_err();
        assert!(format!("{}", err).contains("clientAuth only"), "{err}");
    }

    #[test]
    fn verify_signed_csr_rejects_csr_key_mismatch() {
        let ca_dir = temp_dir();
        let csr_dir_a = temp_dir();
        let csr_dir_b = temp_dir();
        let out_dir = temp_dir();
        let issuer = test_issuer(ca_dir.path());

        generate_csr("client.example", None, csr_dir_a.path()).unwrap();
        let signed_csr = csr_dir_a.path().join("client.csr");
        sign_csr(&signed_csr, "client.example", &issuer, out_dir.path()).unwrap();

        generate_csr("client.example", None, csr_dir_b.path()).unwrap();
        let other_csr = csr_dir_b.path().join("client.csr");

        let err = verify_signed_csr(
            &out_dir.path().join("client.pem"),
            &other_csr,
            &ca_dir.path().join("ca.pem"),
            &client_sans("client.example"),
        )
        .unwrap_err();
        assert!(
            format!("{}", err).contains("does not match the CSR public key"),
            "{err}"
        );
    }
}
