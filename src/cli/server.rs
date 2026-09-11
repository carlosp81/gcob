use std::path::PathBuf;

use crate::certs::detect;
use crate::certs::generate::CertError;
use crate::certs::paths::{check_gcob_access, ClientPaths};

use super::provision::{self, InitServerRequest};

/// Arguments collected by the CLI for `gcob init --server`.
pub struct InitServerArgs {
    pub force: bool,
    pub no_confirm: bool,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub cln_dir: Option<PathBuf>,
    pub haproxy_user: String,
    pub api_user: String,
    pub haproxy_cert_dir: PathBuf,
    pub api_certs_dir: Option<PathBuf>,
    pub rotate_ca: bool,
    pub allow_loopback: bool,
    pub dry_run: bool,
}

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

    let plan = gcob::client_init::plan(client_hostname, client_ip, None)?;
    let csr_path = plan.cert_dir.join("client.csr");

    // Show configuration and ask for confirmation
    println!("=== Initializing gcob client (CSR generation) ===");
    println!();
    println!("  Hostname: {}", plan.hostname);
    if let Some(ref ip) = plan.ip {
        println!("  IP:       {}", ip);
    }
    println!("  Output:   {}", plan.cert_dir.display());
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

    println!("[1/3] Ensuring certificate directory...");
    println!("[2/3] Generating CSR...");
    gcob::client_init::run(&plan, force, true)?;
    println!("[3/3] CSR generated successfully");

    println!();
    println!("=== CSR generated successfully ===");
    println!();
    println!("Files:");
    println!(
        "  {}/client.csr      (send to server)",
        plan.cert_dir.display()
    );
    println!(
        "  {}/client-key.pem  (keep secret)",
        plan.cert_dir.display()
    );
    println!();
    println!("Next steps:");
    println!("  1. Send client.csr to the server:");
    println!(
        "     scp {}/client.csr user@server:/tmp/",
        plan.cert_dir.display()
    );
    println!();
    println!("  2. On the server, sign the CSR:");
    println!(
        "     gcob sign --csr /tmp/client.csr --hostname {}",
        plan.hostname
    );
    println!();
    println!("  3. Server will return: ca.pem + client.pem");
    println!("     Place them in: {}/", plan.cert_dir.display());

    Ok(())
}

/// Handle `gcob init --server`
///
/// Preflight-validates CA, identity, destinations and existing material, then
/// stages, verifies and atomically publishes the HAProxy and API certificates.
pub fn handle_init_server(args: InitServerArgs) -> Result<(), CertError> {
    // Validate user has permission to manage certificates
    check_gcob_access()?;

    let cln_dir = args.cln_dir.clone().ok_or_else(|| {
        CertError::MissingSource(
            "--cln-dir <PATH> is required for 'gcob init --server' \
             (directory containing ca.pem and ca-key.pem)"
                .to_string(),
        )
    })?;

    // Resolve identity: CLI flag > auto-detect > default. Environment variables
    // are intentionally ignored for the server identity (IS-4).
    let identity =
        detect::resolve_server_identity(args.hostname.as_deref(), args.ip.as_deref(), "localhost")?;
    let hostname = identity.hostname;
    let ip = match identity.ip {
        Some(ip) => ip,
        None if args.allow_loopback => "127.0.0.1".to_string(),
        None => {
            return Err(CertError::Io(std::io::Error::other(
                "Cannot detect the server IP; pass --server-ip <IP>",
            )));
        }
    };
    detect::validate_hostname(&hostname, args.allow_loopback)?;
    detect::validate_unicast_ip(&ip, args.allow_loopback)?;

    let api_certs_dir = match &args.api_certs_dir {
        Some(dir) => dir.clone(),
        None => ClientPaths::default_path()?.cert_dir,
    };

    let request = InitServerRequest {
        cln_dir,
        hostname,
        ip,
        haproxy_cert_dir: args.haproxy_cert_dir.clone(),
        api_certs_dir,
        haproxy_user: args.haproxy_user.clone(),
        api_user: args.api_user.clone(),
        force: args.force,
        rotate_ca: args.rotate_ca,
        dry_run: args.dry_run,
        haproxy_owner: None,
        api_owner: None,
    };

    let no_confirm = args.no_confirm;
    let mut confirm = |text: &str| -> bool {
        if no_confirm {
            return true;
        }
        println!("{text}");
        print!("Proceed? [y/N] ");
        use std::io::Write;
        std::io::stdout().flush().ok();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
    };

    let summary = provision::provision_server(&request, &mut confirm)?;

    println!();
    if args.dry_run {
        println!("=== Dry run complete: no files were written ===");
    } else {
        println!("=== Server certificates provisioned ===");
    }
    println!();
    println!("CA fingerprint (SHA-256): {}", summary.ca_fingerprint);
    for file in &summary.files {
        match &file.fingerprint {
            Some(fingerprint) => println!(
                "  {} (mode {:04o}) sha256:{}",
                file.path.display(),
                file.mode,
                fingerprint
            ),
            None => println!("  {} (mode {:04o})", file.path.display(), file.mode),
        }
    }
    println!();
    println!(
        "Point CLN_CERT_DIR at {} before starting 'gcob serve'.",
        request.api_certs_dir.display()
    );
    println!("To sign external client CSRs:");
    println!("  gcob sign --csr <file.csr> --hostname <CLIENT_HOST>");

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
