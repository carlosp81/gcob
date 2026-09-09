use std::path::{Path, PathBuf};

use crate::certs::inspect;
use crate::certs::paths::check_gcob_access;

/// Handle `gcob certs` (no subcommand) — show usage help
pub fn handle_no_subcommand() {
    println!("Manage mTLS certificates for Bakog API and HAProxy.\n");
    println!("Usage:");
    println!("  gcob certs list              List client certificate status");
    println!("  gcob certs show --cert FILE  Show detailed certificate info");
    println!("  gcob certs verify            Verify chain of trust and SANs");
    println!("  gcob certs renew             Renew certificates");
}

/// Handle `gcob certs list [--server]`
pub fn handle_list(server: bool) {
    if let Err(e) = check_gcob_access() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    println!("Discovering certificates...\n");

    if server && !crate::certs::paths::is_server_env() {
        eprintln!("Error: Server certificates not available.");
        eprintln!(
            "The Core Lightning node must be running on this machine to list server certificates."
        );
        std::process::exit(1);
    }

    // Client Certificates — always shown
    let client_dir = Path::new("/etc/gcob/certs");
    print_cert_status(
        "Client Certificates:",
        client_dir,
        &["ca.pem", "client.pem", "client-key.pem"],
    );

    // Server sections — only when --server AND is_server_env()
    if server {
        let haproxy_dir = Path::new("/etc/haproxy/certs");
        print_cert_status(
            "HAProxy Certificates:",
            haproxy_dir,
            &[
                "ca-certs/ca.pem",
                "ca-certs/ca-key.pem",
                "cert_server_concat.pem",
                "cert_client_concat.pem",
            ],
        );

        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        let cln_dir = PathBuf::from(format!("{}/.lightning/bitcoin", home));
        print_cert_status(
            "CLN Certificates:",
            &cln_dir,
            &["ca.pem", "ca-key.pem", "server-key.pem"],
        );
    }
}

/// Internal helper: print status of certificate files in a directory
fn print_cert_status(label: &str, dir: &Path, files: &[&str]) {
    if !dir.exists() {
        println!("  {}", label);
        println!("    (directory not found)\n");
        return;
    }
    println!("  {}", label);
    for name in files {
        let path = dir.join(name);
        if !path.exists() {
            println!("    {:<32} \u{2717} Not found", name);
            continue;
        }
        // Private keys: just check existence and permissions
        if name.ends_with("-key.pem") {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                match std::fs::metadata(&path) {
                    Ok(meta) => {
                        let mode = meta.permissions().mode() & 0o777;
                        let perm_str = if mode == 0o400 {
                            "\u{2713} Read-only (0400)"
                        } else {
                            // Build warning with actual octal
                            let mut parts = Vec::new();
                            if mode & 0o004 != 0 {
                                parts.push("group-read");
                            }
                            if mode & 0o002 != 0 {
                                parts.push("group-write");
                            }
                            if mode & 0o040 != 0 {
                                parts.push("other-read");
                            }
                            if mode & 0o020 != 0 {
                                parts.push("other-write");
                            }
                            if mode & 0o001 != 0 {
                                parts.push("other-exec");
                            }
                            if parts.is_empty() {
                                "\u{2713} Restricted"
                            } else {
                                "\u{2717} Insecure"
                            }
                        };
                        println!("    {:<32} {}", name, perm_str);
                    }
                    Err(e) => {
                        println!("    {:<32} \u{2717} {}", name, e);
                    }
                }
            }
            #[cfg(not(unix))]
            {
                println!("    {:<32} \u{2713} Present", name);
            }
            continue;
        }
        // Certificates: parse and show validity
        match inspect::parse_cert(&path) {
            Ok(info) => {
                let status = if info.days_remaining > 0 {
                    format!("\u{2713} Valid ({} days)", info.days_remaining)
                } else {
                    format!("\u{2717} Expired ({} days ago)", -info.days_remaining)
                };
                println!("    {:<32} {}", name, status);
            }
            Err(e) => {
                println!("    {:<32} \u{2717} Parse error: {}", name, e);
            }
        }
    }
    println!();
}

/// Handle `gcob certs show --cert <FILE>`
pub fn handle_show(cert_path: &Path) {
    if let Err(e) = check_gcob_access() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    println!("=== Certificate Details ===\n");

    match inspect::parse_cert(cert_path) {
        Ok(info) => {
            println!("  File:       {}", info.file);
            println!("  Subject:    {}", info.subject);
            println!("  Issuer:     {}", info.issuer);
            println!("  Serial:     {}", info.serial);
            println!("  Not Before: {}", info.not_before);
            println!("  Not After:  {}", info.not_after);

            let status = if info.days_remaining > 0 {
                format!("✓ Valid ({} days remaining)", info.days_remaining)
            } else {
                format!("✗ Expired ({} days ago)", -info.days_remaining)
            };
            println!("  Status:     {}", status);
            println!("  Is CA:      {}", info.is_ca);

            if info.sans.is_empty() {
                println!("  SANs:       None");
            } else {
                println!("  SANs:");
                for san in &info.sans {
                    println!("    - {}", san);
                }
            }
        }
        Err(e) => {
            eprintln!("Error parsing certificate: {}", e);
            std::process::exit(1);
        }
    }
}

/// Handle `gcob certs verify`
pub fn handle_verify(cert_dir: &Path, expected_hostname: Option<&str>) {
    if let Err(e) = check_gcob_access() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    let hostname = expected_hostname.unwrap_or("localhost");

    println!("=== Certificate Verification ===\n");

    // Check CA exists
    let ca_path = cert_dir.join("ca.pem");
    if !ca_path.exists() {
        eprintln!("Error: CA certificate not found at {}", ca_path.display());
        std::process::exit(1);
    }

    match inspect::parse_cert(&ca_path) {
        Ok(info) => {
            println!("  [1/3] ca.pem");
            println!("        Subject: {}", info.subject);
            println!("        Is CA:   {}", info.is_ca);
            if info.is_ca {
                println!("        Status:  ✓ Self-signed CA");
            } else {
                println!("        Status:  ✗ Not a CA certificate");
            }
        }
        Err(e) => {
            eprintln!("  [1/3] ca.pem: ✗ Parse error: {}", e);
            std::process::exit(1);
        }
    }

    // Verify server cert
    let server_path = cert_dir.join("server.pem");
    if server_path.exists() {
        match inspect::verify_signed_by(&server_path, &ca_path) {
            Ok(result) => {
                println!("\n  [2/3] server.pem");
                println!("        Subject: {}", result.subject);
                println!("        Issuer:  {}", result.issuer);

                if result.signed_by_ca {
                    println!("        Chain:   ✓ Signed by CA");
                } else {
                    println!("        Chain:   ✗ NOT signed by CA");
                    for err in &result.errors {
                        println!("               Error: {}", err);
                    }
                }

                if result.expired {
                    println!("        Expiry:  ✗ Expired ({} days ago)", -result.days_remaining);
                } else {
                    println!("        Expiry:  ✓ Valid ({} days remaining)", result.days_remaining);
                }

                // SAN check
                match inspect::check_san_match(&server_path, hostname) {
                    Ok(true) => println!("        SAN:     ✓ Matches '{}'", hostname),
                    Ok(false) => println!("        SAN:     ✗ Does NOT match '{}'", hostname),
                    Err(e) => println!("        SAN:     ✗ Error: {}", e),
                }
            }
            Err(e) => {
                println!("\n  [2/3] server.pem: ✗ Error: {}", e);
            }
        }
    } else {
        println!("\n  [2/3] server.pem: ✗ Not found");
    }

    // Verify client cert
    let client_path = cert_dir.join("client.pem");
    if client_path.exists() {
        match inspect::verify_signed_by(&client_path, &ca_path) {
            Ok(result) => {
                println!("\n  [3/3] client.pem");
                println!("        Subject: {}", result.subject);
                println!("        Issuer:  {}", result.issuer);

                if result.signed_by_ca {
                    println!("        Chain:   ✓ Signed by CA");
                } else {
                    println!("        Chain:   ✗ NOT signed by CA");
                }

                if result.expired {
                    println!("        Expiry:  ✗ Expired ({} days ago)", -result.days_remaining);
                } else {
                    println!("        Expiry:  ✓ Valid ({} days remaining)", result.days_remaining);
                }
            }
            Err(e) => {
                println!("\n  [3/3] client.pem: ✗ Error: {}", e);
            }
        }
    } else {
        println!("\n  [3/3] client.pem: ✗ Not found");
    }

    println!("\nChain of trust verification complete.");
}

/// Handle `gcob certs renew [--force]`
pub fn handle_renew(cert_dir: &Path, force: bool) {
    if let Err(e) = check_gcob_access() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    println!("=== Renewing Certificates ===\n");

    // Check if renewal is needed
    if !force {
        let server_path = cert_dir.join("server.pem");
        if server_path.exists() {
            match inspect::days_until_expiry(&server_path) {
                Ok(days) if days > 30 => {
                    println!("Server certificate is still valid for {} days.", days);
                    println!("Use `--force` to renew anyway.\n");
                    return;
                }
                _ => {}
            }
        }
    }

    // Read CA from CLN source
    let cln_source = crate::certs::paths::ClnSourcePaths::default_home();
    println!("[1/4] Reading CA from CLN source...");
    let issuer = match crate::certs::generate::read_cln_ca(&cln_source) {
        Ok(issuer) => {
            println!("  [✓] CA loaded");
            issuer
        }
        Err(e) => {
            eprintln!("  [✗] Error: {}", e);
            std::process::exit(1);
        }
    };

    // Create output directory
    println!("[2/4] Creating certificate directory...");
    if let Err(e) = std::fs::create_dir_all(cert_dir) {
        eprintln!("  [✗] Error creating directory: {}", e);
        std::process::exit(1);
    }
    println!("  [✓] {}", cert_dir.display());

    // Generate server certificate
    let hostname = std::env::var("CLN_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let ip = std::env::var("CLN_IP").unwrap_or_else(|_| "127.0.0.1".to_string());

    println!("[3/4] Generating server certificate...");
    if let Err(e) = crate::certs::generate::generate_server_cert(&issuer, &hostname, &ip, cert_dir) {
        eprintln!("  [✗] Error: {}", e);
        std::process::exit(1);
    }
    println!("  [✓] server.pem generated with SAN");

    // Generate client certificate
    println!("[4/4] Generating client certificate...");
    if let Err(e) = crate::certs::generate::generate_client_cert(&issuer, &hostname, cert_dir) {
        eprintln!("  [✗] Error: {}", e);
        std::process::exit(1);
    }
    println!("  [✓] client.pem generated");

    // Set permissions
    #[cfg(unix)]
    {
        use crate::certs::generate::set_permissions;
        let _ = set_permissions(cert_dir, 0o700);
        let _ = set_permissions(&cert_dir.join("server-key.pem"), 0o400);
        let _ = set_permissions(&cert_dir.join("client-key.pem"), 0o400);
    }

    println!("\nDone! All certificates renewed.");
}

/// Handle `gcob sign --csr <FILE> --hostname <HOST>`
pub fn handle_sign(csr_path: &Path, hostname: &str, output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Validate user has permission to manage certificates
    check_gcob_access().map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;

    println!("=== Signing Client Certificate ===\n");
    println!("  CSR:      {}", csr_path.display());
    println!("  Hostname: {}", hostname);
    println!("  Output:   {}/client.pem", output_dir.display());
    println!();

    // Verify CSR exists
    if !csr_path.exists() {
        eprintln!("Error: CSR file not found: {}", csr_path.display());
        std::process::exit(1);
    }

    // Read CA from CLN source
    let cln_source = crate::certs::paths::ClnSourcePaths::default_home();
    println!("[1/3] Reading CA from CLN source...");
    let issuer = crate::certs::generate::read_cln_ca(&cln_source)?;
    println!("  [✓] CA loaded");

    // Create output directory
    println!("[2/3] Creating output directory...");
    std::fs::create_dir_all(output_dir)?;
    println!("  [✓] {}", output_dir.display());

    // Sign CSR
    println!("[3/3] Signing CSR...");
    crate::certs::generate::sign_csr(csr_path, &issuer, output_dir)?;
    println!("  [✓] client.pem signed by CA");

    // Set permissions
    #[cfg(unix)]
    {
        use crate::certs::generate::set_permissions;
        let _ = set_permissions(&output_dir.join("client.pem"), 0o444);
    }

    println!();
    println!("=== Certificate signed successfully ===");
    println!();
    println!("Send to client:");
    println!("  {}/ca.pem", cln_source.dir.display());
    println!("  {}/client.pem", output_dir.display());

    Ok(())
}

/// Dispatch certs command
pub fn dispatch(command: super::CertsCommand) {
    match command {
        super::CertsCommand::List { server } => handle_list(server),
        super::CertsCommand::Show { cert } => {
            let cert_path = cert.unwrap_or_else(|| PathBuf::from("/etc/gcob/certs/server.pem"));
            handle_show(&cert_path);
        }
        super::CertsCommand::Verify { hostname } => {
            let cert_dir = PathBuf::from("/etc/gcob/certs");
            handle_verify(&cert_dir, hostname.as_deref());
        }
        super::CertsCommand::Renew { force } => {
            let cert_dir = PathBuf::from("/etc/gcob/certs");
            handle_renew(&cert_dir, force);
        }
    }
}
