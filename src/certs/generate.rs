use std::fs;
use std::path::Path;

use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, Issuer, KeyPair, SanType, SigningKey,
};

use super::paths::ClnSourcePaths;

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

/// Read CA certificate and key from CLN source directory
/// Returns the Issuer (for signing new certificates)
pub fn read_cln_ca(source: &ClnSourcePaths) -> Result<Issuer<'static, KeyPair>, CertError> {
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

    let ca_pem = fs::read_to_string(&source.ca_file)?;
    let ca_key_pem = fs::read_to_string(&source.ca_key_file)?;

    let ca_key = KeyPair::from_pem(&ca_key_pem).map_err(CertError::Rcgen)?;
    let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key).map_err(CertError::Rcgen)?;

    Ok(issuer)
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
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);

    let cert = params
        .signed_by(&client_key, issuer)
        .map_err(CertError::Rcgen)?;

    // Write client certificate
    fs::write(output_dir.join("client.pem"), cert.pem())?;

    // Write client key
    fs::write(
        output_dir.join("client-key.pem"),
        client_key.serialize_pem(),
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

    let san_names = vec![hostname.to_string(), "localhost".to_string()];

    let mut params = CertificateParams::new(san_names).map_err(CertError::Rcgen)?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, hostname);
    params.subject_alt_names.push(SanType::IpAddress(ip_addr));

    let cert = params
        .signed_by(&server_key, issuer)
        .map_err(CertError::Rcgen)?;

    // Write server certificate
    fs::write(output_dir.join("server.pem"), cert.pem())?;

    // Write server key
    fs::write(
        output_dir.join("server-key.pem"),
        server_key.serialize_pem(),
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
    fs::write(output_path, format!("{}{}", cert, key))?;
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

    let mut params =
        CertificateParams::new(san_names).map_err(CertError::Rcgen)?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, hostname);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);

    let csr = params
        .serialize_request(&client_key)
        .map_err(CertError::Rcgen)?;

    // Write CSR
    let csr_pem = csr.pem().map_err(CertError::Rcgen)?;
    fs::write(output_dir.join("client.csr"), csr_pem)?;

    // Write client key
    fs::write(
        output_dir.join("client-key.pem"),
        client_key.serialize_pem(),
    )?;

    Ok(())
}

/// Sign a CSR with the CA - this runs on the SERVER
pub fn sign_csr<S: SigningKey>(
    csr_path: &Path,
    issuer: &Issuer<'_, S>,
    output_dir: &Path,
) -> Result<(), CertError> {
    let csr_pem = fs::read_to_string(csr_path)?;

    let csr = CertificateSigningRequestParams::from_pem(&csr_pem)
        .map_err(|e| CertError::Parse(format!("CSR parse error: {}", e)))?;

    let cert = csr
        .signed_by(issuer)
        .map_err(|e| CertError::Parse(format!("CSR sign error: {}", e)))?;

    // Write signed certificate
    fs::write(output_dir.join("client.pem"), cert.pem())?;

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
