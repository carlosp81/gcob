use std::fs;
use std::path::Path;

use crate::certs::generate::{self, CertError};
use crate::certs::paths::{check_gcob_access, ensure_cert_dir, setup_gcob_sudoers, ClientPaths, ClnSourcePaths, ServerPaths};
use crate::certs::detect;

const CLN_HOSTNAME_DEFAULT: &str = "localhost";
const CLN_IP_DEFAULT: &str = "127.0.0.1";

/// Handle `gcob init --client`
/// Generates a CSR (Certificate Signing Request) - runs on CLIENT machine
pub fn handle_init_client(
    force: bool,
    no_confirm: bool,
    client_hostname: Option<&str>,
    client_ip: Option<&str>,
) -> Result<(), CertError> {
    // Validate user has permission to manage certificates
    check_gcob_access()?;

    // Resolve client hostname: CLI flag > env var > auto-detect
    let client_hostname = match client_hostname {
        Some(h) => h.to_string(),
        None => match std::env::var("CLIENT_HOSTNAME") {
            Ok(h) => h,
            Err(_) => detect::detect_hostname().map_err(|e| {
                CertError::Io(std::io::Error::other(format!(
                    "Cannot detect hostname: {}. Use --client-hostname flag or CLIENT_HOSTNAME env var",
                    e
                )))
            })?,
        },
    };

    // Resolve client IP: CLI flag > env var > auto-detect
    let client_ip = match client_ip {
        Some(ip) => Some(ip.to_string()),
        None => match std::env::var("CLIENT_IP") {
            Ok(ip) => Some(ip),
            Err(_) => detect::detect_ip().ok(), // Auto-detect is optional
        },
    };

    // Always use the canonical system path
    let client_paths = ClientPaths::default_path();

    // Check if CSR already exists
    let csr_path = client_paths.cert_dir.join("client.csr");
    if csr_path.exists() && !force {
        eprintln!("Error: CSR already exists at {}", csr_path.display());
        eprintln!("  Use --force to regenerate (will overwrite existing CSR)");
        std::process::exit(1);
    }

    // Show configuration and ask for confirmation
    println!("=== Initializing gcob client (CSR generation) ===");
    println!();
    println!("  Hostname: {}", client_hostname);
    if let Some(ref ip) = client_ip {
        println!("  IP:       {}", ip);
    }
    println!("  Output:   {}", client_paths.cert_dir.display());
    if force && csr_path.exists() {
        println!("  Mode:     Overwrite existing CSR");
    }
    println!();

    // Ask for confirmation unless --no-confirm is passed
    if !no_confirm {
        print!("Proceed? [Y/n] ");
        use std::io::Write;
        std::io::stdout().flush().ok();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        let input = input.trim().to_lowercase();

        if input == "n" || input == "no" {
            println!("Aborted.");
            std::process::exit(0);
        }
        println!();
    }

    // If running as root, setup sudoers first
    let uid = unsafe { libc::getuid() };
    if uid == 0 {
        setup_gcob_sudoers()?;
    }

    // Ensure certificate directory exists
    ensure_cert_dir()?;

    // Step 1: Create output directory
    println!("[1/5] Creating certificate directory...");

    // Step 2: Generate CSR
    println!("[2/5] Generating CSR...");
    generate::generate_csr(&client_hostname, client_ip.as_deref(), &client_paths.cert_dir)?;
    println!("[3/5] CSR generated successfully");

    // Step 3: Set permissions (silent)
    #[cfg(unix)]
    {
        let _ = generate::set_permissions(&client_paths.cert_dir, 0o700);
        let _ = generate::set_permissions(&client_paths.client_key_file, 0o400);
        let _ = generate::set_permissions(&client_paths.cert_dir.join("client.csr"), 0o444);
    }

    // Step 4: Chown to gcob user (silent)
    #[cfg(unix)]
    {
        let _ = chown_recursive(&client_paths.cert_dir, "gcob");
    }

    println!();
    println!("=== CSR generated successfully ===");
    println!();
    println!("Files:");
    println!("  {}/client.csr      (send to server)", client_paths.cert_dir.display());
    println!("  {}/client-key.pem  (keep secret)", client_paths.cert_dir.display());
    println!();
    println!("Next steps:");
    println!("  1. Send client.csr to the server:");
    println!("     scp {}/client.csr user@server:/tmp/", client_paths.cert_dir.display());
    println!();
    println!("  2. On the server, sign the CSR:");
    println!("     gcob sign --csr /tmp/client.csr --hostname {}", client_hostname);
    println!();
    println!("  3. Server will return: ca.pem + client.pem");
    println!("     Place them in: {}/", client_paths.cert_dir.display());

    Ok(())
}

/// Change ownership of a directory recursively using chown command
#[cfg(unix)]
fn chown_recursive(path: &Path, user: &str) -> Result<(), CertError> {
    use std::process::Command;

    let output = Command::new("chown")
        .args(["-R", &format!("{}:{}", user, user)])
        .arg(path)
        .output()
        .map_err(|e| CertError::Io(std::io::Error::other(format!("Failed to run chown: {}", e))))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CertError::Io(std::io::Error::other(
            format!("chown failed: {}", stderr.trim()),
        )));
    }

    Ok(())
}

/// Handle `gcob init --server`
/// Generates all server certificates signed by CLN's CA
pub fn handle_init_server() -> Result<(), CertError> {
    // Validate user has permission to manage certificates
    check_gcob_access()?;

    let hostname =
        std::env::var("CLN_HOSTNAME").unwrap_or_else(|_| CLN_HOSTNAME_DEFAULT.to_string());
    let ip = std::env::var("CLN_IP").unwrap_or_else(|_| CLN_IP_DEFAULT.to_string());
    let cln_source = ClnSourcePaths::default_home();
    let server_paths = ServerPaths::default_path();
    let client_paths = ClientPaths::default_path();

    println!("=== Initializing gcob server certificates ===");
    println!("  Hostname:     {}", hostname);
    println!("  IP:           {}", ip);
    println!("  CLN source:   {}", cln_source.dir.display());
    println!("  HAProxy dir:  {}", server_paths.haproxy_cert_dir.display());
    println!("  Bakog API:    {}", client_paths.cert_dir.display());
    println!();

    // Step 1: Read CA from CLN source
    println!("[1/7] Reading CA from CLN source...");
    let issuer = generate::read_cln_ca(&cln_source)?;
    println!("  [✓] CA loaded");

    // Step 2: Create directories
    println!("[2/7] Creating directories...");
    fs::create_dir_all(&server_paths.haproxy_cert_dir)?;
    fs::create_dir_all(&server_paths.haproxy_ca_dir)?;
    fs::create_dir_all(&client_paths.cert_dir)?;
    println!("  [✓] {}", server_paths.haproxy_cert_dir.display());
    println!("  [✓] {}", client_paths.cert_dir.display());

    // Step 3: Copy CA to HAProxy ca-certs
    println!("[3/7] Copying CA to HAProxy ca-certs...");
    generate::copy_file(&cln_source.ca_file, &server_paths.ca_file)?;
    generate::copy_file(&cln_source.ca_key_file, &server_paths.ca_key_file)?;
    println!("  [✓] ca.pem copied");

    // Step 4: Generate HAProxy server cert (mTLS 2 server side)
    let temp_dir = Path::new("/tmp/gcob_certs");
    fs::create_dir_all(temp_dir)?;
    println!("[4/7] Generating HAProxy server certificate...");
    generate::generate_server_cert(&issuer, &hostname, &ip, temp_dir)?;
    println!("  [✓] server-haproxy.pem generated");

    // Step 5: Generate HAProxy client cert for CLN (mTLS 3 client side)
    println!("[5/7] Generating HAProxy client certificate (→ CLN)...");
    generate::generate_client_cert(&issuer, &hostname, temp_dir)?;
    println!("  [✓] client-proxy.pem generated");

    // Create HAProxy bundles
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
    println!("  [✓] HAProxy bundles created");

    // Step 6: Generate Bakog API server cert (mTLS 1 server side)
    println!("[6/7] Generating Bakog API server certificate...");
    generate::generate_api_server_cert(&issuer, &hostname, &ip, &client_paths.cert_dir)?;
    println!("  [✓] server-api.pem generated");

    // Step 7: Generate Bakog API client cert for HAProxy (mTLS 2 client side)
    println!("[7/7] Generating Bakog API client certificate (→ HAProxy)...");
    generate::generate_client_cert(&issuer, &hostname, &client_paths.cert_dir)?;
    // Rename to avoid confusion with external client
    let api_client = client_paths.cert_dir.join("client.pem");
    let api_client_renamed = client_paths.cert_dir.join("client-api.pem");
    if api_client.exists() {
        fs::rename(&api_client, &api_client_renamed)?;
    }
    let api_client_key = client_paths.cert_dir.join("client-key.pem");
    let api_client_key_renamed = client_paths.cert_dir.join("client-api-key.pem");
    if api_client_key.exists() {
        fs::rename(&api_client_key, &api_client_key_renamed)?;
    }
    println!("  [✓] client-api.pem generated");

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
        generate::set_permissions(&client_paths.cert_dir, 0o700)?;
        let _ = generate::set_permissions(&client_paths.cert_dir.join("server-api.pem"), 0o444);
        let _ = generate::set_permissions(&client_paths.cert_dir.join("server-api-key.pem"), 0o400);
        let _ = generate::set_permissions(&client_paths.cert_dir.join("client-api.pem"), 0o444);
        let _ = generate::set_permissions(&client_paths.cert_dir.join("client-api-key.pem"), 0o400);
    }

    println!();
    println!("=== Server certificates generated ===");
    println!();
    println!("HAProxy (mTLS 2 + 3):");
    println!("  {}", server_paths.server_concat_file.display());
    println!("  {}", server_paths.client_concat_file.display());
    println!();
    println!("Bakog API (mTLS 1 + 2):");
    println!("  {}/server-api.pem", client_paths.cert_dir.display());
    println!("  {}/client-api.pem", client_paths.cert_dir.display());
    println!();
    println!("To sign external client CSR:");
    println!("  gcob sign --csr /tmp/client.csr --hostname <CLIENT_IP>");

    Ok(())
}

/// Handle `gcob serve`
pub async fn handle_serve() -> Result<(), Box<dyn std::error::Error>> {
    let env = std::env::var("GCOB_ENV").unwrap_or_else(|_| "production".into());
    let is_dev = env == "development";

    if is_dev {
        tracing::warn!("Running in DEVELOPMENT mode");
        let config = crate::certs::mtls_certs::ClnConfig::from_env()?;
        config.validate_all()?;
        match crate::certs::mtls_certs::ClnConfig::validate_user() {
            Ok(()) => {}
            Err(e) => tracing::warn!("User validation skipped: {}", e.message()),
        }
    } else {
        tracing::info!("Running in PRODUCTION mode");
        let config = crate::certs::mtls_certs::ClnConfig::from_env()?;
        config.validate_all()?;
        crate::certs::mtls_certs::ClnConfig::validate_user()?;
    }

    crate::grpc::server::run().await
}

/// Handle `gcob certs`
#[allow(dead_code)]
pub fn handle_certs() -> Result<(), CertError> {
    println!("=== Certificate status ===");
    // TODO: Implement certificate expiry check
    println!("  Checking certificate expiration...");
    println!("  [TODO] Not yet implemented");
    Ok(())
}
