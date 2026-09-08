use std::fs;
use std::path::Path;

use crate::certs::generate::{self, CertError};
use crate::certs::paths::{ClientPaths, ClnSourcePaths, ServerPaths};

const CLN_HOSTNAME_DEFAULT: &str = "localhost";
const CLN_IP_DEFAULT: &str = "127.0.0.1";

/// Handle `gcob init --client`
pub fn handle_init_client() -> Result<(), CertError> {
    let hostname =
        std::env::var("CLN_HOSTNAME").unwrap_or_else(|_| CLN_HOSTNAME_DEFAULT.to_string());
    let cln_source = ClnSourcePaths::default_home();
    let client_paths = ClientPaths::default_path();

    println!("=== Initializing gcob client certificates ===");
    println!("  Hostname: {}", hostname);
    println!("  CLN source: {}", cln_source.dir.display());
    println!("  Output: {}", client_paths.cert_dir.display());
    println!();

    // Verify CLN source
    println!("[1/4] Verifying CLN source certificates...");
    if !cln_source.ca_file.exists() {
        return Err(CertError::MissingSource(format!(
            "CA certificate not found: {}",
            cln_source.ca_file.display()
        )));
    }
    if !cln_source.ca_key_file.exists() {
        return Err(CertError::MissingSource(format!(
            "CA key not found: {}",
            cln_source.ca_key_file.display()
        )));
    }
    println!("  [✓] CA certificates found");

    // Create output directory
    println!("[2/4] Creating certificate directory...");
    fs::create_dir_all(&client_paths.cert_dir)?;
    println!("  [✓] {}", client_paths.cert_dir.display());

    // Generate client certificate
    println!("[3/4] Generating client certificate...");
    generate::generate_client_cert(
        &cln_source.ca_file,
        &cln_source.ca_key_file,
        &hostname,
        &client_paths.cert_dir,
    )?;
    println!("  [✓] client.pem generated with clientAuth");

    // Set permissions
    println!("[4/4] Setting permissions...");
    #[cfg(unix)]
    {
        generate::set_permissions(&client_paths.cert_dir, 0o700)?;
        generate::set_permissions(&client_paths.client_file, 0o400)?;
        generate::set_permissions(&client_paths.client_key_file, 0o400)?;
    }
    println!("  [✓] Permissions set");

    println!();
    println!("=== Client certificates generated ===");
    println!("Files:");
    println!("  {} (read-only)", client_paths.client_file.display());
    println!("  {} (read-only)", client_paths.client_key_file.display());
    println!();
    println!("To use with gcob client:");
    println!("  gcob --host <server> --port 50063 info");

    Ok(())
}

/// Handle `gcob init --server`
pub fn handle_init_server() -> Result<(), CertError> {
    let hostname =
        std::env::var("CLN_HOSTNAME").unwrap_or_else(|_| CLN_HOSTNAME_DEFAULT.to_string());
    let ip = std::env::var("CLN_IP").unwrap_or_else(|_| CLN_IP_DEFAULT.to_string());
    let cln_source = ClnSourcePaths::default_home();
    let server_paths = ServerPaths::default_path();

    println!("=== Initializing gcob server certificates ===");
    println!("  Hostname: {}", hostname);
    println!("  IP: {}", ip);
    println!("  CLN source: {}", cln_source.dir.display());
    println!(
        "  HAProxy certs: {}",
        server_paths.haproxy_cert_dir.display()
    );
    println!("  HAProxy CA: {}", server_paths.haproxy_ca_dir.display());
    println!();

    // Verify CLN source
    println!("[1/6] Verifying CLN source certificates...");
    if !cln_source.ca_file.exists() {
        return Err(CertError::MissingSource(format!(
            "CA certificate not found: {}",
            cln_source.ca_file.display()
        )));
    }
    if !cln_source.ca_key_file.exists() {
        return Err(CertError::MissingSource(format!(
            "CA key not found: {}",
            cln_source.ca_key_file.display()
        )));
    }
    println!("  [✓] CA certificates found");

    // Create HAProxy directories
    println!("[2/6] Creating directories...");
    fs::create_dir_all(&server_paths.haproxy_cert_dir)?;
    fs::create_dir_all(&server_paths.haproxy_ca_dir)?;
    println!("  [✓] {}", server_paths.haproxy_cert_dir.display());
    println!("  [✓] {}", server_paths.haproxy_ca_dir.display());

    // Copy CA to HAProxy ca-certs
    println!("[3/6] Copying CA to HAProxy ca-certs...");
    generate::copy_file(&cln_source.ca_file, &server_paths.ca_file)?;
    generate::copy_file(&cln_source.ca_key_file, &server_paths.ca_key_file)?;
    println!("  [✓] ca.pem copied");
    println!("  [✓] ca-key.pem copied");

    // Generate server certificate
    println!("[4/6] Generating server certificate...");
    let temp_dir = Path::new("/tmp/gcob_certs");
    fs::create_dir_all(temp_dir)?;
    generate::generate_server_cert(
        &cln_source.ca_file,
        &cln_source.ca_key_file,
        &hostname,
        &ip,
        temp_dir,
    )?;
    println!("  [✓] server.pem generated with SAN");

    // Generate client certificate for HAProxy
    println!("[5/6] Generating client certificate for HAProxy...");
    generate::generate_client_cert(
        &cln_source.ca_file,
        &cln_source.ca_key_file,
        &hostname,
        temp_dir,
    )?;
    println!("  [✓] client.pem generated with clientAuth");

    // Concatenate and copy to HAProxy
    println!("[6/6] Creating HAProxy bundles...");
    generate::concat_cert_key(
        &temp_dir.join("server.pem"),
        &temp_dir.join("server-key.pem"),
        &server_paths.server_concat_file,
    )?;
    generate::concat_cert_key(
        &temp_dir.join("client.pem"),
        &temp_dir.join("client-key.pem"),
        &server_paths.client_concat_file,
    )?;
    println!("  [✓] cert_server_concat.pem created");
    println!("  [✓] cert_client_concat.pem created");

    // Clean up temp files
    let _ = fs::remove_dir_all(temp_dir);

    // Set permissions
    #[cfg(unix)]
    {
        generate::set_permissions(&server_paths.haproxy_cert_dir, 0o700)?;
        generate::set_permissions(&server_paths.haproxy_ca_dir, 0o700)?;
        generate::set_permissions(&server_paths.ca_file, 0o444)?;
        generate::set_permissions(&server_paths.ca_key_file, 0o400)?;
        generate::set_permissions(&server_paths.server_concat_file, 0o600)?;
        generate::set_permissions(&server_paths.client_concat_file, 0o600)?;
    }

    println!();
    println!("=== Server certificates generated ===");
    println!("HAProxy CA:");
    println!("  {}", server_paths.ca_file.display());
    println!("  {}", server_paths.ca_key_file.display());
    println!();
    println!("HAProxy bundles (cert + key):");
    println!("  {}", server_paths.server_concat_file.display());
    println!("  {}", server_paths.client_concat_file.display());
    println!();
    println!("HAProxy configuration:");
    println!("  bind *:443 ssl crt /etc/haproxy/certs/cert_server_concat.pem ca-file /etc/haproxy/certs/ca-certs/ca.pem verify optional");

    Ok(())
}

/// Handle `gcob serve`
pub async fn handle_serve() -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Starting gcob server");
    crate::grpc::server::run().await
}

/// Handle `gcob certs`
pub fn handle_certs() -> Result<(), CertError> {
    println!("=== Certificate status ===");
    // TODO: Implement certificate expiry check
    println!("  Checking certificate expiration...");
    println!("  [TODO] Not yet implemented");
    Ok(())
}
