use std::path::PathBuf;

use crate::certs::detect;
use crate::certs::generate::CertError;
use crate::certs::paths::{check_gcob_access, ClientPaths};

use super::provision::{self, InitServerRequest};

/// Arguments collected by the CLI for `gcob init`.
pub struct InitServerArgs {
    pub force: bool,
    pub no_confirm: bool,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub cln_dir: PathBuf,
    pub haproxy_user: String,
    pub api_user: String,
    pub haproxy_cert_dir: PathBuf,
    pub api_certs_dir: Option<PathBuf>,
    pub rotate_ca: bool,
    pub allow_loopback: bool,
    pub dry_run: bool,
}

/// Handle `gcob init`
///
/// Preflight-validates CA, identity, destinations and existing material, then
/// stages, verifies and atomically publishes the HAProxy and API certificates.
pub fn handle_init_server(args: InitServerArgs) -> Result<(), CertError> {
    // Validate user has permission to manage certificates
    check_gcob_access()?;

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
                "Cannot detect the server IP; pass --ip <IP>",
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
        cln_dir: args.cln_dir,
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
