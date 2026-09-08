use std::fs;
use std::path::Path;
use std::process::Command;

/// Errors during certificate generation
#[derive(Debug)]
pub enum CertError {
    Io(std::io::Error),
    Openssl(String),
    MissingSource(String),
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertError::Io(e) => write!(f, "IO error: {}", e),
            CertError::Openssl(e) => write!(f, "OpenSSL error: {}", e),
            CertError::MissingSource(e) => write!(f, "Missing source: {}", e),
        }
    }
}

impl std::error::Error for CertError {}

impl From<std::io::Error> for CertError {
    fn from(e: std::io::Error) -> Self {
        CertError::Io(e)
    }
}

/// Run an openssl command and return error on failure
fn openssl_run(args: &[&str]) -> Result<(), CertError> {
    let output = Command::new("openssl")
        .args(args)
        .output()
        .map_err(CertError::Io)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CertError::Openssl(stderr.to_string()));
    }
    Ok(())
}

/// Generate a client certificate signed by the CA
pub fn generate_client_cert(
    ca_cert_path: &Path,
    ca_key_path: &Path,
    hostname: &str,
    output_dir: &Path,
) -> Result<(), CertError> {
    // Generate client key
    openssl_run(&[
        "genrsa",
        "-out",
        output_dir.join("client-key.pem").to_str().unwrap(),
        "2048",
    ])?;

    // Generate CSR
    openssl_run(&[
        "req",
        "-new",
        "-key",
        output_dir.join("client-key.pem").to_str().unwrap(),
        "-out",
        "/tmp/gcob_client.csr",
        "-subj",
        &format!("/CN={}", hostname),
    ])?;

    // Sign with CA (clientAuth)
    // Create temp ext file
    fs::write("/tmp/gcob_client_ext.cnf", "extendedKeyUsage=clientAuth\n")?;
    openssl_run(&[
        "x509",
        "-req",
        "-in",
        "/tmp/gcob_client.csr",
        "-CA",
        ca_cert_path.to_str().unwrap(),
        "-CAkey",
        ca_key_path.to_str().unwrap(),
        "-CAcreateserial",
        "-out",
        output_dir.join("client.pem").to_str().unwrap(),
        "-days",
        "3650",
        "-extfile",
        "/tmp/gcob_client_ext.cnf",
    ])?;

    // Clean up
    let _ = fs::remove_file("/tmp/gcob_client.csr");
    let _ = fs::remove_file("/tmp/gcob_client_ext.cnf");

    Ok(())
}

/// Generate a server certificate signed by the CA with SAN extensions
pub fn generate_server_cert(
    ca_cert_path: &Path,
    ca_key_path: &Path,
    hostname: &str,
    ip: &str,
    output_dir: &Path,
) -> Result<(), CertError> {
    // Create SAN config
    let san_config = format!(
        "[req]\ndistinguished_name = req_dn\nreq_extensions = v3_ca\n\n[req_dn]\n\n[v3_ca]\nsubjectAltName = DNS:{},DNS:localhost,IP:{}\n",
        hostname, ip
    );
    fs::write("/tmp/gcob_san.cnf", &san_config)?;

    // Generate server key
    openssl_run(&[
        "genrsa",
        "-out",
        output_dir.join("server-key.pem").to_str().unwrap(),
        "4096",
    ])?;

    // Generate CSR with SAN
    openssl_run(&[
        "req",
        "-new",
        "-key",
        output_dir.join("server-key.pem").to_str().unwrap(),
        "-out",
        "/tmp/gcob_server.csr",
        "-subj",
        &format!("/CN={}", hostname),
        "-config",
        "/tmp/gcob_san.cnf",
    ])?;

    // Sign with CA and extensions
    openssl_run(&[
        "x509",
        "-req",
        "-in",
        "/tmp/gcob_server.csr",
        "-CA",
        ca_cert_path.to_str().unwrap(),
        "-CAkey",
        ca_key_path.to_str().unwrap(),
        "-CAcreateserial",
        "-out",
        output_dir.join("server.pem").to_str().unwrap(),
        "-days",
        "3650",
        "-extfile",
        "/tmp/gcob_san.cnf",
        "-extensions",
        "v3_ca",
    ])?;

    // Clean up
    let _ = fs::remove_file("/tmp/gcob_server.csr");
    let _ = fs::remove_file("/tmp/gcob_san.cnf");

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
