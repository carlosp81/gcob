use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use super::atomic::{publish_files, PlannedFile, PublishedFile};
use super::VerifySubcommand;
use crate::certs::detect;
use crate::certs::generate::{self, CertError};
use crate::certs::inspect;
use crate::certs::paths::{
    account_by_name, check_gcob_access, current_account, default_cert_dir, detect_admin_account,
    ensure_secure_dir, is_server_env, lock_dir, ClnSourcePaths, ServerPaths,
};

/// Arguments for `gcob certs renew`.
pub struct RenewArgs {
    pub force: bool,
    pub server_hostname: Option<String>,
    pub server_ip: Option<String>,
    pub cln_dir: PathBuf,
    pub init_ca: bool,
    pub rotate_ca: bool,
    pub api_user: String,
    pub allow_loopback: bool,
    pub dry_run: bool,
}

/// Arguments for `gcob sign`.
pub struct SignArgs {
    pub csr: PathBuf,
    pub hostname: String,
    pub cln_dir: PathBuf,
    pub output: PathBuf,
    pub force: bool,
    pub dry_run: bool,
    pub expected_ca_fingerprint: Option<String>,
}

/// Handle `gcob certs` (no subcommand) — show usage help
pub fn handle_no_subcommand() {
    println!("Manage mTLS certificates for gcob.\n");

    println!("USAGE:");
    println!("    gcob certs list                  List certificate status");
    println!("    gcob certs show --cert <FILE>    Show detailed certificate info");
    println!("    gcob certs verify                Verify chain of trust and SANs");
    println!("    gcob certs renew                 Renew expired certificates\n");

    println!("EXAMPLES:");
    println!("    gcob certs list                  # Show all certificates");
    println!("    gcob certs verify                # Verify with localhost");
    println!("    gcob certs verify --hostname my-server  # Verify with custom hostname");
    println!("    gcob certs show --cert /home/<admin>/.certs/client.pem\n");

    println!("SAN CHECK:");
    println!("    Verify that certificate SANs match the expected hostname.");
    println!("    Supported SAN types: DNS, IP Address");
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
    let client_dir = resolve_cert_dir();
    print_cert_status(
        "Client Certificates:",
        &client_dir,
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

/// Verify API certificates section (server only)
fn verify_api_section(cert_dir: &Path, _hostname: &str) -> Vec<bool> {
    println!("── API Certificates ({}) ──\n", cert_dir.display());
    let mut results = Vec::new();

    // ca.pem
    let ca_path = cert_dir.join("ca.pem");
    if !ca_path.exists() {
        println!("  ca.pem: ✗ Not found");
        results.push(false);
    } else {
        match inspect::parse_cert(&ca_path) {
            Ok(info) => {
                println!("  ca.pem");
                println!("        Subject: {}", info.subject);
                println!("        Is CA:   {}", info.is_ca);
                if info.is_ca {
                    println!("        Status:  ✓ Self-signed CA");
                } else {
                    println!("        Status:  ✗ Not a CA certificate");
                }
                results.push(info.is_ca);
            }
            Err(e) => {
                println!("  ca.pem: ✗ Parse error: {}", e);
                results.push(false);
            }
        }
    }

    results
}

/// Verify HAProxy certificates section (server only)
fn verify_haproxy_section(haproxy_dir: &Path, client_cert_dir: &Path, hostname: &str) -> Vec<bool> {
    println!("\n── HAProxy Certificates ({}) ──\n", haproxy_dir.display());
    let mut results = Vec::new();

    let ca_dir = haproxy_dir.join("ca-certs");

    // 1. ca-certs/ca.pem
    let ca_path = ca_dir.join("ca.pem");
    if !ca_path.exists() {
        println!("  [1/3] ca-certs/ca.pem: ✗ Not found");
        results.push(false);
    } else {
        match inspect::parse_cert(&ca_path) {
            Ok(info) => {
                println!("  [1/3] ca-certs/ca.pem");
                println!("        Subject: {}", info.subject);
                println!("        Is CA:   {}", info.is_ca);
                if info.is_ca {
                    println!("        Status:  ✓ Self-signed CA");
                } else {
                    println!("        Status:  ✗ Not a CA certificate");
                }

                // Compare with client cert dir CA
                let client_ca = client_cert_dir.join("ca.pem");
                if client_ca.exists() {
                    match (fs::read(&ca_path), fs::read(&client_ca)) {
                        (Ok(a), Ok(b)) => {
                            if a == b {
                                println!("        Compare: ✓ Matches {}", client_ca.display());
                            } else {
                                println!(
                                    "        Compare: ✗ Does NOT match {}",
                                    client_ca.display()
                                );
                            }
                        }
                        _ => {
                            println!("        Compare: ✗ Error reading files");
                        }
                    }
                }
                results.push(info.is_ca);
            }
            Err(e) => {
                println!("  [1/3] ca-certs/ca.pem: ✗ Parse error: {}", e);
                results.push(false);
            }
        }
    }

    // 2. cert_server_concat.pem
    let server_concat_path = haproxy_dir.join("cert_server_concat.pem");
    if !server_concat_path.exists() {
        println!("\n  [2/3] cert_server_concat.pem: ✗ Not found");
        results.push(false);
    } else {
        match inspect::verify_signed_by(&server_concat_path, &ca_path) {
            Ok(result) => {
                println!("\n  [2/3] cert_server_concat.pem");
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
                    println!(
                        "        Expiry:  ✗ Expired ({} days ago)",
                        -result.days_remaining
                    );
                } else {
                    println!(
                        "        Expiry:  ✓ Valid ({} days remaining)",
                        result.days_remaining
                    );
                }

                // Show SANs
                if let Ok(info) = inspect::parse_cert(&server_concat_path) {
                    if !info.sans.is_empty() {
                        println!("        SANs:");
                        for san in &info.sans {
                            println!("          - {}", san);
                        }
                    }
                }

                // SAN check
                match inspect::check_san_match(&server_concat_path, hostname) {
                    Ok(true) => println!("        SAN Check: ✓ Matches '{}'", hostname),
                    Ok(false) => println!("        SAN Check: ✗ Does NOT match '{}'", hostname),
                    Err(e) => println!("        SAN Check: ✗ Error: {}", e),
                }
                results.push(result.signed_by_ca && !result.expired);
            }
            Err(e) => {
                println!("\n  [2/3] cert_server_concat.pem: ✗ Error: {}", e);
                results.push(false);
            }
        }
    }

    // 4. cert_client_concat.pem
    let client_concat_path = haproxy_dir.join("cert_client_concat.pem");
    if !client_concat_path.exists() {
        println!("\n  [3/3] cert_client_concat.pem: ✗ Not found");
        results.push(false);
    } else {
        match inspect::verify_signed_by(&client_concat_path, &ca_path) {
            Ok(result) => {
                println!("\n  [3/3] cert_client_concat.pem");
                println!("        Subject: {}", result.subject);
                println!("        Issuer:  {}", result.issuer);

                if result.signed_by_ca {
                    println!("        Chain:   ✓ Signed by CA");
                } else {
                    println!("        Chain:   ✗ NOT signed by CA");
                }

                if result.expired {
                    println!(
                        "        Expiry:  ✗ Expired ({} days ago)",
                        -result.days_remaining
                    );
                } else {
                    println!(
                        "        Expiry:  ✓ Valid ({} days remaining)",
                        result.days_remaining
                    );
                }

                // Show SANs
                if let Ok(info) = inspect::parse_cert(&client_concat_path) {
                    if !info.sans.is_empty() {
                        println!("        SANs:");
                        for san in &info.sans {
                            println!("          - {}", san);
                        }
                    }
                }
                results.push(result.signed_by_ca && !result.expired);
            }
            Err(e) => {
                println!("\n  [3/3] cert_client_concat.pem: ✗ Error: {}", e);
                results.push(false);
            }
        }
    }

    results
}

/// Verify CLN certificates section (server only)
fn verify_cln_section(cln_dir: &Path, client_cert_dir: &Path) -> Vec<bool> {
    println!("\n── CLN Certificates ({}) ──\n", cln_dir.display());
    let mut results = Vec::new();

    // Check if directory exists
    if !cln_dir.exists() {
        println!("  ⚠ Skipped: Directory not found ({})", cln_dir.display());
        println!("  Core Lightning node may not be installed on this server.");
        return results;
    }

    // 1. ca.pem
    let ca_path = cln_dir.join("ca.pem");
    if !ca_path.exists() {
        println!("  [1/3] ca.pem: ✗ Not found");
        results.push(false);
    } else {
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

                // Compare with client cert dir CA
                let client_ca = client_cert_dir.join("ca.pem");
                if client_ca.exists() {
                    match (fs::read(&ca_path), fs::read(&client_ca)) {
                        (Ok(a), Ok(b)) => {
                            if a == b {
                                println!("        Compare: ✓ Matches {}", client_ca.display());
                            } else {
                                println!(
                                    "        Compare: ✗ Does NOT match {}",
                                    client_ca.display()
                                );
                            }
                        }
                        _ => {
                            println!("        Compare: ✗ Error reading files");
                        }
                    }
                }
                results.push(info.is_ca);
            }
            Err(e) => {
                println!("  [1/3] ca.pem: ✗ Parse error: {}", e);
                results.push(false);
            }
        }
    }

    // 2. ca-key.pem
    let ca_key_path = cln_dir.join("ca-key.pem");
    if !ca_key_path.exists() {
        println!("\n  [2/3] ca-key.pem: ✗ Not found");
        results.push(false);
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            match fs::metadata(&ca_key_path) {
                Ok(meta) => {
                    let mode = meta.permissions().mode() & 0o777;
                    println!("\n  [2/3] ca-key.pem");
                    if mode == 0o400 {
                        println!("        Permissions: ✓ 0400 (read-only)");
                        results.push(true);
                    } else {
                        println!("        Permissions: ✗ {:04o} (expected 0400)", mode);
                        results.push(false);
                    }
                }
                Err(e) => {
                    println!("\n  [2/3] ca-key.pem: ✗ {}", e);
                    results.push(false);
                }
            }
        }
        #[cfg(not(unix))]
        {
            println!("\n  [2/3] ca-key.pem: ✓ Exists");
            results.push(true);
        }
    }

    // 3. server-key.pem
    let server_key_path = cln_dir.join("server-key.pem");
    if !server_key_path.exists() {
        println!("\n  [3/3] server-key.pem: ✗ Not found");
        results.push(false);
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            match fs::metadata(&server_key_path) {
                Ok(meta) => {
                    let mode = meta.permissions().mode() & 0o777;
                    println!("\n  [3/3] server-key.pem");
                    if mode == 0o400 {
                        println!("        Permissions: ✓ 0400 (read-only)");
                        results.push(true);
                    } else {
                        println!("        Permissions: ✗ {:04o} (expected 0400)", mode);
                        results.push(false);
                    }
                }
                Err(e) => {
                    println!("\n  [3/3] server-key.pem: ✗ {}", e);
                    results.push(false);
                }
            }
        }
        #[cfg(not(unix))]
        {
            println!("\n  [3/3] server-key.pem: ✓ Exists");
            results.push(true);
        }
    }

    results
}

/// Verify CA certificate section
fn verify_ca_section(cert_dir: &Path) -> Vec<bool> {
    let mut results = Vec::new();

    let ca_path = cert_dir.join("ca.pem");
    if !ca_path.exists() {
        println!("  [1/1] ca.pem: ✗ Not found");
        results.push(false);
    } else {
        match inspect::parse_cert(&ca_path) {
            Ok(info) => {
                println!("  [1/1] ca.pem");
                println!("        Subject: {}", info.subject);
                println!("        Is CA:   {}", info.is_ca);
                if info.is_ca {
                    println!("        Status:  ✓ Self-signed CA");
                } else {
                    println!("        Status:  ✗ Not a CA certificate");
                }
                results.push(info.is_ca);
            }
            Err(e) => {
                println!("  [1/1] ca.pem: ✗ Parse error: {}", e);
                results.push(false);
            }
        }
    }

    results
}

/// Handle `gcob certs verify`
pub fn handle_verify(
    cert_dir: &Path,
    expected_hostname: Option<&str>,
    cln_dir: Option<&Path>,
    target: Option<VerifySubcommand>,
) {
    if let Err(e) = check_gcob_access() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    let hostname = expected_hostname.unwrap_or("localhost");
    let target = target.unwrap_or(VerifySubcommand::All);
    let is_server = is_server_env();
    // The CLN source is only used when explicitly provided; `$HOME` heuristics
    // are no longer trusted for verification (SG-7).
    let cln_source = cln_dir.map(ClnSourcePaths::new);

    if is_server {
        println!("=== Certificate Verification (Server Mode) ===\n");
    } else {
        println!("=== Certificate Verification (Client Mode) ===\n");
    }

    let mut all_results = Vec::new();

    match target {
        VerifySubcommand::Ca => {
            all_results.extend(verify_ca_section(cert_dir));
        }
        VerifySubcommand::Server => {
            if is_server {
                let server_paths = ServerPaths::default_path();
                all_results.extend(verify_haproxy_section(
                    &server_paths.haproxy_cert_dir,
                    cert_dir,
                    hostname,
                ));
                match &cln_source {
                    Some(source) => all_results.extend(verify_cln_section(&source.dir, cert_dir)),
                    None => println!(
                        "  (CLN certificates skipped: pass --cln-dir <PATH> to verify them)\n"
                    ),
                }
            } else {
                println!("⚠ Warning: 'verify server' is not applicable in client mode.");
                println!("  Server certificates are only available on server machines.");
                println!("  Use 'gcob certs verify' to verify client certificates.\n");
            }
        }
        VerifySubcommand::Client => {
            all_results.extend(verify_client_section(cert_dir, hostname));
        }
        VerifySubcommand::All => {
            // Client certificates (always)
            all_results.extend(verify_client_section(cert_dir, hostname));

            // Server sections (only on server)
            if is_server {
                let server_paths = ServerPaths::default_path();
                all_results.extend(verify_api_section(cert_dir, hostname));
                all_results.extend(verify_haproxy_section(
                    &server_paths.haproxy_cert_dir,
                    cert_dir,
                    hostname,
                ));
                match &cln_source {
                    Some(source) => all_results.extend(verify_cln_section(&source.dir, cert_dir)),
                    None => println!(
                        "  (CLN certificates skipped: pass --cln-dir <PATH> to verify them)\n"
                    ),
                }
            }
        }
    }

    let passed = all_results.iter().filter(|&&x| x).count();
    let total = all_results.len();
    println!("\nVerification complete: {}/{} passed", passed, total);
}

/// Verify client certificates section
fn verify_client_section(cert_dir: &Path, hostname: &str) -> Vec<bool> {
    let mut results = Vec::new();

    // 1. ca.pem
    let ca_path = cert_dir.join("ca.pem");
    if !ca_path.exists() {
        println!("  [1/3] ca.pem: ✗ Not found");
        results.push(false);
    } else {
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
                results.push(info.is_ca);
            }
            Err(e) => {
                println!("  [1/3] ca.pem: ✗ Parse error: {}", e);
                results.push(false);
            }
        }
    }

    // 2. client.pem
    let client_path = cert_dir.join("client.pem");
    if !client_path.exists() {
        println!("\n  [2/3] client.pem: ✗ Not found");
        results.push(false);
    } else {
        match inspect::verify_signed_by(&client_path, &ca_path) {
            Ok(result) => {
                println!("\n  [2/3] client.pem");
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
                    println!(
                        "        Expiry:  ✗ Expired ({} days ago)",
                        -result.days_remaining
                    );
                } else {
                    println!(
                        "        Expiry:  ✓ Valid ({} days remaining)",
                        result.days_remaining
                    );
                }

                // Show SANs
                if let Ok(info) = inspect::parse_cert(&client_path) {
                    if !info.sans.is_empty() {
                        println!("        SANs:");
                        for san in &info.sans {
                            println!("          - {}", san);
                        }
                    }
                }

                // SAN check
                match inspect::check_san_match(&client_path, hostname) {
                    Ok(true) => println!("        SAN Check: ✓ Matches '{}'", hostname),
                    Ok(false) => println!("        SAN Check: ✗ Does NOT match '{}'", hostname),
                    Err(e) => println!("        SAN Check: ✗ Error: {}", e),
                }
                results.push(result.signed_by_ca && !result.expired);
            }
            Err(e) => {
                println!("\n  [2/3] client.pem: ✗ Error: {}", e);
                results.push(false);
            }
        }
    }

    // 3. client-key.pem
    let client_key_path = cert_dir.join("client-key.pem");
    if !client_key_path.exists() {
        println!("\n  [3/3] client-key.pem: ✗ Not found");
        results.push(false);
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            match fs::metadata(&client_key_path) {
                Ok(meta) => {
                    let mode = meta.permissions().mode() & 0o777;
                    println!("\n  [3/3] client-key.pem");
                    if mode == 0o400 {
                        println!("        Permissions: ✓ 0400 (read-only)");
                        results.push(true);
                    } else {
                        println!("        Permissions: ✗ {:04o} (expected 0400)", mode);
                        results.push(false);
                    }
                }
                Err(e) => {
                    println!("\n  [3/3] client-key.pem: ✗ {}", e);
                    results.push(false);
                }
            }
        }
        #[cfg(not(unix))]
        {
            println!("\n  [3/3] client-key.pem: ✓ Exists");
            results.push(true);
        }
    }

    results
}

/// Fully resolved request for a certificate renewal run.
pub struct RenewRequest {
    pub cln_dir: PathBuf,
    pub cert_dir: PathBuf,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub init_ca: bool,
    pub rotate_ca: bool,
    pub api_user: String,
    pub allow_loopback: bool,
    pub dry_run: bool,
    /// Test/CI override for the owner of the API material (default api user).
    pub owner_override: Option<(u32, u32)>,
}

/// Result of a renewal run.
#[derive(Debug)]
pub struct RenewSummary {
    pub ca_fingerprint: String,
    pub identity: (String, String),
    pub files: Vec<PublishedFile>,
    pub dry_run: bool,
}

#[cfg(unix)]
fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

/// Renew the API certificate material with a validated CA and atomic publication.
///
/// Security invariants:
/// 1. The CA is loaded with `load_validated_ca` (no `$HOME` heuristic).
/// 2. The new leaves are verified against the CA that will be installed.
/// 3. Changing an installed CA requires `--rotate-ca`; installing a missing one
///    requires `--init-ca`.
/// 4. Nothing is published until staging and postconditions succeed; existing
///    files are backed up and rolled back on failure.
pub fn renew_certificates(req: &RenewRequest) -> Result<RenewSummary, CertError> {
    let api = account_by_name(&req.api_user)?;
    let owner = req.owner_override.unwrap_or((api.uid, api.gid));

    let source = ClnSourcePaths::new(req.cln_dir.clone());
    let validated = generate::load_validated_ca(&source)?;

    // Identity: explicit flags first, otherwise reuse the existing server SANs.
    let existing = req.cert_dir.join("server.pem");
    let (existing_dns, existing_ip) = if existing.exists() {
        inspect::san_identities(&existing).unwrap_or((None, None))
    } else {
        (None, None)
    };

    let hostname = req.hostname.clone().or(existing_dns).ok_or_else(|| {
        CertError::MissingSource(
            "cannot determine the server hostname; pass --server-hostname <HOST>".to_string(),
        )
    })?;
    let ip = req.ip.clone().or(existing_ip).ok_or_else(|| {
        CertError::MissingSource(
            "cannot determine the server IP; pass --server-ip <IP>".to_string(),
        )
    })?;
    detect::validate_hostname(&hostname, req.allow_loopback)?;
    crate::certs::detect::validate_unicast_ip(&ip, req.allow_loopback)?;

    // Destination directory: created securely, no symlinks, service ownership.
    let euid = current_uid();
    let mut allowed_owners = vec![0, euid, owner.0];
    if let Ok(admin) = detect_admin_account() {
        allowed_owners.push(admin.uid);
    }
    ensure_secure_dir(&req.cert_dir, 0o700, owner, &allowed_owners)?;

    // CA pinning: never change the installed trust anchor silently.
    let installed_ca = req.cert_dir.join("ca.pem");
    let install_ca = if installed_ca.exists() {
        let installed_fingerprint = generate::cert_fingerprint(&installed_ca)?;
        if installed_fingerprint != validated.fingerprint_sha256 {
            if !req.rotate_ca {
                return Err(CertError::Parse(format!(
                    "Installed CA {} has a different fingerprint ({}); pass --rotate-ca to replace it",
                    installed_ca.display(),
                    installed_fingerprint
                )));
            }
            true
        } else {
            false
        }
    } else {
        if !req.init_ca {
            return Err(CertError::MissingSource(format!(
                "{} does not exist; pass --init-ca to install the validated CLN CA",
                installed_ca.display()
            )));
        }
        true
    };

    let _lock = lock_dir(&req.cert_dir)?;

    // Stage in the destination filesystem.
    let stage = tempfile::Builder::new()
        .prefix(".gcob-stage-")
        .tempdir_in(&req.cert_dir)?;

    generate::generate_server_cert(&validated.issuer, &hostname, &ip, stage.path())?;
    generate::generate_client_cert(&validated.issuer, &hostname, stage.path())?;
    let staged_ca = stage.path().join("ca.pem");
    generate::write_atomic_owned(&staged_ca, validated.ca_pem.as_bytes(), 0o644, owner)?;

    // Postconditions against the CA that will be installed.
    let server_sans: BTreeSet<String> = [generate::san_token(&hostname), generate::san_token(&ip)]
        .into_iter()
        .collect();
    let client_sans: BTreeSet<String> = [generate::san_token(&hostname)].into_iter().collect();

    generate::verify_issued_cert(
        &stage.path().join("server.pem"),
        &stage.path().join("server-key.pem"),
        &staged_ca,
        &server_sans,
        true,
    )?;
    generate::verify_issued_cert(
        &stage.path().join("client.pem"),
        &stage.path().join("client-key.pem"),
        &staged_ca,
        &client_sans,
        false,
    )?;

    let server_fingerprint = generate::cert_fingerprint(&stage.path().join("server.pem"))?;
    let client_fingerprint = generate::cert_fingerprint(&stage.path().join("client.pem"))?;

    let mut plan = vec![
        PlannedFile {
            staged: stage.path().join("server.pem"),
            target: req.cert_dir.join("server.pem"),
            mode: 0o644,
            owner,
            fingerprint: Some(server_fingerprint),
        },
        PlannedFile {
            staged: stage.path().join("server-key.pem"),
            target: req.cert_dir.join("server-key.pem"),
            mode: 0o600,
            owner,
            fingerprint: None,
        },
        PlannedFile {
            staged: stage.path().join("client.pem"),
            target: req.cert_dir.join("client.pem"),
            mode: 0o644,
            owner,
            fingerprint: Some(client_fingerprint),
        },
        PlannedFile {
            staged: stage.path().join("client-key.pem"),
            target: req.cert_dir.join("client-key.pem"),
            mode: 0o600,
            owner,
            fingerprint: None,
        },
    ];

    if install_ca {
        plan.push(PlannedFile {
            staged: staged_ca,
            target: installed_ca.clone(),
            mode: 0o644,
            owner,
            fingerprint: Some(validated.fingerprint_sha256.clone()),
        });
    }

    for file in &plan {
        generate::apply_owner_mode(&file.staged, file.mode, file.owner)?;
    }

    if !req.dry_run {
        publish_files(&plan)?;
    }

    Ok(RenewSummary {
        ca_fingerprint: validated.fingerprint_sha256,
        identity: (hostname, ip),
        files: plan
            .iter()
            .map(|file| PublishedFile {
                path: file.target.clone(),
                mode: file.mode,
                fingerprint: file.fingerprint.clone(),
            })
            .collect(),
        dry_run: req.dry_run,
    })
}

/// Handle `gcob certs renew [--force]`
pub fn handle_renew(cert_dir: &Path, args: RenewArgs) {
    if let Err(e) = check_gcob_access() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    println!("=== Renewing Certificates ===\n");

    // Check if renewal is needed
    if !args.force {
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

    let request = RenewRequest {
        cln_dir: args.cln_dir.clone(),
        cert_dir: cert_dir.to_path_buf(),
        hostname: args.server_hostname.clone(),
        ip: args.server_ip.clone(),
        init_ca: args.init_ca,
        rotate_ca: args.rotate_ca,
        api_user: args.api_user.clone(),
        allow_loopback: args.allow_loopback,
        dry_run: args.dry_run,
        owner_override: None,
    };

    match renew_certificates(&request) {
        Ok(summary) => {
            println!();
            if summary.dry_run {
                println!("=== Dry run complete: no files were written ===");
            } else {
                println!("=== Certificates renewed ===");
            }
            println!();
            println!(
                "  Identity:       {} ({})",
                summary.identity.0, summary.identity.1
            );
            println!("  CA fingerprint: {}", summary.ca_fingerprint);
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
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Maximum accepted CSR size (defense against oversized input DoS).
const MAX_CSR_BYTES: u64 = 1 << 20;

/// Fully resolved request for a CSR signing run.
pub struct SignRequest {
    pub csr: PathBuf,
    pub hostname: String,
    pub cln_dir: PathBuf,
    pub output: PathBuf,
    pub force: bool,
    pub dry_run: bool,
    pub expected_ca_fingerprint: Option<String>,
    /// Test/CI override for the owner of the output material.
    pub owner_override: Option<(u32, u32)>,
}

/// Result of a signing run.
#[derive(Debug)]
pub struct SignSummary {
    pub ca_fingerprint: String,
    pub cert_fingerprint: String,
    pub path: PathBuf,
    pub dry_run: bool,
}

/// Sign a CSR with a validated CA and publish the certificate atomically.
///
/// Security invariants:
/// 1. CA loaded and validated (symlinks, permissions, `CA:TRUE`, key match).
/// 2. Optional `--expected-ca-fingerprint` pinning.
/// 3. Hostname validated (no wildcards/control chars) before signing.
/// 4. CSR must be a regular, non-symlinked file within the size limit.
/// 5. The issued certificate is verified against the CA and the CSR public key;
///    nothing is published until then.
pub fn sign_csr_file(req: &SignRequest) -> Result<SignSummary, CertError> {
    detect::validate_hostname(&req.hostname, false)?;

    // CSR must be a regular, non-symlinked, bounded file.
    let csr_metadata = fs::symlink_metadata(&req.csr)?;
    if csr_metadata.file_type().is_symlink() {
        return Err(CertError::Parse(format!(
            "Refusing to follow symlinked CSR: {}",
            req.csr.display()
        )));
    }
    if !csr_metadata.is_file() {
        return Err(CertError::Parse(format!(
            "CSR is not a regular file: {}",
            req.csr.display()
        )));
    }
    if csr_metadata.len() > MAX_CSR_BYTES {
        return Err(CertError::Parse(format!(
            "CSR {} exceeds the {} byte limit",
            req.csr.display(),
            MAX_CSR_BYTES
        )));
    }

    // Validated CA + optional fingerprint pinning.
    let source = ClnSourcePaths::new(req.cln_dir.clone());
    let validated = generate::load_validated_ca(&source)?;
    if let Some(expected) = &req.expected_ca_fingerprint {
        if !validated
            .fingerprint_sha256
            .eq_ignore_ascii_case(expected.trim())
        {
            return Err(CertError::Parse(format!(
                "CA fingerprint mismatch: found {}, expected {}",
                validated.fingerprint_sha256, expected
            )));
        }
    }

    // Output directory: secure, owned by the current account.
    let me = current_account()?;
    let owner = req.owner_override.unwrap_or((me.uid, me.gid));
    let mut allowed_owners = vec![0, owner.0];
    if let Ok(admin) = detect_admin_account() {
        allowed_owners.push(admin.uid);
    }
    ensure_secure_dir(&req.output, 0o700, owner, &allowed_owners)?;

    let target = req.output.join("client.pem");
    if target.exists() && !req.force {
        return Err(CertError::Io(std::io::Error::other(format!(
            "{} already exists; pass --force to overwrite it",
            target.display()
        ))));
    }

    let _lock = lock_dir(&req.output)?;

    // Stage in the output filesystem.
    let stage = tempfile::Builder::new()
        .prefix(".gcob-stage-")
        .tempdir_in(&req.output)?;

    generate::sign_csr(&req.csr, &req.hostname, &validated.issuer, stage.path())?;

    let staged_ca = stage.path().join("ca.pem");
    generate::write_atomic_owned(&staged_ca, validated.ca_pem.as_bytes(), 0o644, owner)?;

    // Postcondition: chain to the CA, clientAuth only, exact SAN, CSR key match.
    let expected_sans: BTreeSet<String> =
        [generate::san_token(&req.hostname)].into_iter().collect();
    generate::verify_signed_csr(
        &stage.path().join("client.pem"),
        &req.csr,
        &staged_ca,
        &expected_sans,
    )?;

    let cert_fingerprint = generate::cert_fingerprint(&stage.path().join("client.pem"))?;
    let plan = vec![PlannedFile {
        staged: stage.path().join("client.pem"),
        target: target.clone(),
        mode: 0o644,
        owner,
        fingerprint: Some(cert_fingerprint.clone()),
    }];

    for file in &plan {
        generate::apply_owner_mode(&file.staged, file.mode, file.owner)?;
    }

    if !req.dry_run {
        publish_files(&plan)?;
    }

    Ok(SignSummary {
        ca_fingerprint: validated.fingerprint_sha256,
        cert_fingerprint,
        path: target,
        dry_run: req.dry_run,
    })
}

/// Handle `gcob sign --csr <FILE> --hostname <HOST> --cln-dir <PATH> --output <DIR>`
pub fn handle_sign(args: SignArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Validate user has permission to manage certificates
    check_gcob_access()?;

    println!("=== Signing Client Certificate ===\n");

    let request = SignRequest {
        csr: args.csr.clone(),
        hostname: args.hostname.clone(),
        cln_dir: args.cln_dir.clone(),
        output: args.output.clone(),
        force: args.force,
        dry_run: args.dry_run,
        expected_ca_fingerprint: args.expected_ca_fingerprint.clone(),
        owner_override: None,
    };

    let summary = sign_csr_file(&request)?;

    println!();
    if summary.dry_run {
        println!("=== Dry run complete: no files were written ===");
    } else {
        println!("=== Certificate signed successfully ===");
    }
    println!();
    println!("  Subject:        {}", args.hostname);
    println!("  CA fingerprint: {}", summary.ca_fingerprint);
    println!(
        "  Cert:           {} sha256:{}",
        summary.path.display(),
        summary.cert_fingerprint
    );
    println!();
    println!("Send to client:");
    println!("  {}/ca.pem", request.cln_dir.display());
    println!("  {}", summary.path.display());

    Ok(())
}

/// Resolve the local certificate directory or exit with a clear message.
fn resolve_cert_dir() -> PathBuf {
    match default_cert_dir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Dispatch certs command
pub fn dispatch(command: super::CertsCommand) {
    match command {
        super::CertsCommand::List { server } => handle_list(server),
        super::CertsCommand::Show { cert } => {
            let cert_path = match cert {
                Some(path) => path,
                None => resolve_cert_dir().join("server.pem"),
            };
            handle_show(&cert_path);
        }
        super::CertsCommand::Verify {
            hostname,
            cln_dir,
            target,
        } => {
            let cert_dir = resolve_cert_dir();
            handle_verify(&cert_dir, hostname.as_deref(), cln_dir.as_deref(), target);
        }
        super::CertsCommand::Renew {
            force,
            server_hostname,
            server_ip,
            cln_dir,
            init_ca,
            rotate_ca,
            api_user,
            allow_loopback,
            dry_run,
        } => {
            let cert_dir = resolve_cert_dir();
            handle_renew(
                &cert_dir,
                RenewArgs {
                    force,
                    server_hostname,
                    server_ip,
                    cln_dir,
                    init_ca,
                    rotate_ca,
                    api_user,
                    allow_loopback,
                    dry_run,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::paths::current_account;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    /// Create a CA and write `ca.pem` + `ca-key.pem` (0600) into `dir`.
    fn write_ca(dir: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        }

        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "gcob-ca");
        let cert = params.self_signed(&key).unwrap();

        fs::write(dir.join("ca.pem"), cert.pem()).unwrap();
        fs::write(dir.join("ca-key.pem"), key.serialize_pem()).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.join("ca-key.pem"), fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn request(ca_dir: &Path, cert_dir: &Path, init_ca: bool) -> RenewRequest {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(cert_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }

        let me = current_account().unwrap();
        RenewRequest {
            cln_dir: ca_dir.to_path_buf(),
            cert_dir: cert_dir.to_path_buf(),
            hostname: Some("node.example".to_string()),
            ip: Some("10.0.0.5".to_string()),
            init_ca,
            rotate_ca: false,
            api_user: me.name,
            allow_loopback: false,
            dry_run: false,
            owner_override: Some((me.uid, me.gid)),
        }
    }

    fn server_sans() -> BTreeSet<String> {
        [
            generate::san_token("node.example"),
            generate::san_token("10.0.0.5"),
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn renew_init_ca_publishes_and_verifies() {
        let ca_dir = temp_dir();
        let cert_dir = temp_dir();
        write_ca(ca_dir.path());

        let summary = renew_certificates(&request(ca_dir.path(), cert_dir.path(), true)).unwrap();
        assert_eq!(
            summary.identity,
            ("node.example".to_string(), "10.0.0.5".to_string())
        );
        assert_eq!(summary.files.len(), 5);

        for name in [
            "ca.pem",
            "server.pem",
            "server-key.pem",
            "client.pem",
            "client-key.pem",
        ] {
            assert!(cert_dir.path().join(name).exists(), "missing {name}");
        }

        generate::verify_issued_cert(
            &cert_dir.path().join("server.pem"),
            &cert_dir.path().join("server-key.pem"),
            &cert_dir.path().join("ca.pem"),
            &server_sans(),
            true,
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(cert_dir.path().join("server-key.pem"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn renew_requires_init_ca_when_missing() {
        let ca_dir = temp_dir();
        let cert_dir = temp_dir();
        write_ca(ca_dir.path());

        let err = renew_certificates(&request(ca_dir.path(), cert_dir.path(), false)).unwrap_err();
        assert!(format!("{}", err).contains("--init-ca"), "{err}");
    }

    #[test]
    fn renew_rejects_ca_change_without_rotate() {
        let ca1 = temp_dir();
        let ca2 = temp_dir();
        let cert_dir = temp_dir();
        write_ca(ca1.path());
        write_ca(ca2.path());

        renew_certificates(&request(ca1.path(), cert_dir.path(), true)).unwrap();

        let err = renew_certificates(&request(ca2.path(), cert_dir.path(), false)).unwrap_err();
        assert!(format!("{}", err).contains("--rotate-ca"), "{err}");

        let mut rotate = request(ca2.path(), cert_dir.path(), false);
        rotate.rotate_ca = true;
        renew_certificates(&rotate).unwrap();

        let installed = generate::cert_fingerprint(&cert_dir.path().join("ca.pem")).unwrap();
        let source = generate::cert_fingerprint(&ca2.path().join("ca.pem")).unwrap();
        assert_eq!(installed, source);
    }

    #[test]
    fn renew_reuses_existing_identity() {
        let ca_dir = temp_dir();
        let cert_dir = temp_dir();
        write_ca(ca_dir.path());

        renew_certificates(&request(ca_dir.path(), cert_dir.path(), true)).unwrap();

        let mut reuse = request(ca_dir.path(), cert_dir.path(), false);
        reuse.hostname = None;
        reuse.ip = None;
        let summary = renew_certificates(&reuse).unwrap();
        assert_eq!(
            summary.identity,
            ("node.example".to_string(), "10.0.0.5".to_string())
        );
    }

    #[test]
    fn renew_rejects_invalid_identity() {
        let ca_dir = temp_dir();
        let cert_dir = temp_dir();
        write_ca(ca_dir.path());

        let mut bad = request(ca_dir.path(), cert_dir.path(), true);
        bad.hostname = Some("*.example.com".to_string());
        let err = renew_certificates(&bad).unwrap_err();
        assert!(format!("{}", err).contains("Wildcard"), "{err}");

        let mut bad_ip = request(ca_dir.path(), cert_dir.path(), true);
        bad_ip.ip = Some("0.0.0.0".to_string());
        let err = renew_certificates(&bad_ip).unwrap_err();
        assert!(format!("{}", err).contains("unicast"), "{err}");
    }

    #[test]
    fn renew_dry_run_writes_nothing() {
        let ca_dir = temp_dir();
        let cert_dir = temp_dir();
        write_ca(ca_dir.path());

        let mut dry = request(ca_dir.path(), cert_dir.path(), true);
        dry.dry_run = true;
        let summary = renew_certificates(&dry).unwrap();
        assert!(summary.dry_run);
        assert!(!cert_dir.path().join("server.pem").exists());
        assert!(!cert_dir.path().join("ca.pem").exists());
    }

    #[test]
    fn renew_rejects_group_writable_dir() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let ca_dir = temp_dir();
            let cert_dir = temp_dir();
            write_ca(ca_dir.path());
            let req = request(ca_dir.path(), cert_dir.path(), true);
            fs::set_permissions(cert_dir.path(), fs::Permissions::from_mode(0o777)).unwrap();

            let err = renew_certificates(&req).unwrap_err();
            assert!(format!("{}", err).contains("group/other writable"), "{err}");
        }
    }

    fn sign_request(ca_dir: &Path, csr: &Path, output: &Path) -> SignRequest {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(output, fs::Permissions::from_mode(0o700)).unwrap();
        }

        let me = current_account().unwrap();
        SignRequest {
            csr: csr.to_path_buf(),
            hostname: "client.example".to_string(),
            cln_dir: ca_dir.to_path_buf(),
            output: output.to_path_buf(),
            force: false,
            dry_run: false,
            expected_ca_fingerprint: None,
            owner_override: Some((me.uid, me.gid)),
        }
    }

    fn test_csr(dir: &Path) -> PathBuf {
        generate::generate_csr("client.example", None, dir).unwrap();
        dir.join("client.csr")
    }

    #[test]
    fn sign_issues_and_verifies() {
        let ca_dir = temp_dir();
        let csr_dir = temp_dir();
        let out_dir = temp_dir();
        write_ca(ca_dir.path());
        let csr = test_csr(csr_dir.path());

        let summary = sign_csr_file(&sign_request(ca_dir.path(), &csr, out_dir.path())).unwrap();
        assert!(summary.path.exists());

        let sans: BTreeSet<String> = [generate::san_token("client.example")]
            .into_iter()
            .collect();
        generate::verify_signed_csr(
            &out_dir.path().join("client.pem"),
            &csr,
            &ca_dir.path().join("ca.pem"),
            &sans,
        )
        .unwrap();
    }

    #[test]
    fn sign_rejects_wrong_ca_fingerprint() {
        let ca_dir = temp_dir();
        let csr_dir = temp_dir();
        let out_dir = temp_dir();
        write_ca(ca_dir.path());
        let csr = test_csr(csr_dir.path());

        let mut req = sign_request(ca_dir.path(), &csr, out_dir.path());
        req.expected_ca_fingerprint = Some("00".repeat(32));
        let err = sign_csr_file(&req).unwrap_err();
        assert!(format!("{}", err).contains("fingerprint mismatch"), "{err}");
    }

    #[test]
    fn sign_rejects_wildcard_hostname() {
        let ca_dir = temp_dir();
        let csr_dir = temp_dir();
        let out_dir = temp_dir();
        write_ca(ca_dir.path());
        let csr = test_csr(csr_dir.path());

        let mut req = sign_request(ca_dir.path(), &csr, out_dir.path());
        req.hostname = "*.example.com".to_string();
        let err = sign_csr_file(&req).unwrap_err();
        assert!(format!("{}", err).contains("Wildcard"), "{err}");
    }

    #[test]
    fn sign_requires_force_when_output_exists() {
        let ca_dir = temp_dir();
        let csr_dir = temp_dir();
        let out_dir = temp_dir();
        write_ca(ca_dir.path());
        let csr = test_csr(csr_dir.path());

        sign_csr_file(&sign_request(ca_dir.path(), &csr, out_dir.path())).unwrap();

        let err = sign_csr_file(&sign_request(ca_dir.path(), &csr, out_dir.path())).unwrap_err();
        assert!(format!("{}", err).contains("--force"), "{err}");

        let mut forced = sign_request(ca_dir.path(), &csr, out_dir.path());
        forced.force = true;
        sign_csr_file(&forced).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sign_rejects_symlinked_output_dir() {
        let ca_dir = temp_dir();
        let csr_dir = temp_dir();
        write_ca(ca_dir.path());
        let csr = test_csr(csr_dir.path());

        let real = temp_dir();
        let link_base = temp_dir();
        let link = link_base.path().join("out");
        std::os::unix::fs::symlink(real.path(), &link).unwrap();

        let req = sign_request(ca_dir.path(), &csr, &link);
        let err = sign_csr_file(&req).unwrap_err();
        assert!(format!("{}", err).contains("symlink"), "{err}");
    }

    #[test]
    fn sign_dry_run_writes_nothing() {
        let ca_dir = temp_dir();
        let csr_dir = temp_dir();
        let out_dir = temp_dir();
        write_ca(ca_dir.path());
        let csr = test_csr(csr_dir.path());

        let mut req = sign_request(ca_dir.path(), &csr, out_dir.path());
        req.dry_run = true;
        let summary = sign_csr_file(&req).unwrap();
        assert!(summary.dry_run);
        assert!(!out_dir.path().join("client.pem").exists());
    }

    #[test]
    fn sign_rejects_oversized_csr() {
        let ca_dir = temp_dir();
        let csr_dir = temp_dir();
        let out_dir = temp_dir();
        write_ca(ca_dir.path());

        let big = csr_dir.path().join("big.csr");
        fs::write(&big, vec![b'A'; (MAX_CSR_BYTES + 1) as usize]).unwrap();

        let req = sign_request(ca_dir.path(), &big, out_dir.path());
        let err = sign_csr_file(&req).unwrap_err();
        assert!(format!("{}", err).contains("byte limit"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn sign_rejects_csr_symlink() {
        let ca_dir = temp_dir();
        let csr_dir = temp_dir();
        let out_dir = temp_dir();
        write_ca(ca_dir.path());
        let csr = test_csr(csr_dir.path());

        let link = csr_dir.path().join("linked.csr");
        std::os::unix::fs::symlink(&csr, &link).unwrap();

        let req = sign_request(ca_dir.path(), &link, out_dir.path());
        let err = sign_csr_file(&req).unwrap_err();
        assert!(format!("{}", err).contains("symlinked CSR"), "{err}");
    }
}
