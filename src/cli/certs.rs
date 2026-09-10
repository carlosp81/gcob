use std::fs;
use std::path::{Path, PathBuf};

use crate::certs::inspect;
use crate::certs::paths::{check_gcob_access, default_cert_dir, is_server_env, ClnSourcePaths, ServerPaths};
use super::VerifySubcommand;

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
    let client_dir = default_cert_dir();
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
fn verify_api_section(cert_dir: &Path, hostname: &str) -> Vec<bool> {
    println!("── API Certificates ({}) ──\n", cert_dir.display());
    let mut results = Vec::new();

    // 1. ca.pem
    let ca_path = cert_dir.join("ca.pem");
    if !ca_path.exists() {
        println!("  [1/6] ca.pem: ✗ Not found");
        results.push(false);
    } else {
        match inspect::parse_cert(&ca_path) {
            Ok(info) => {
                println!("  [1/6] ca.pem");
                println!("        Subject: {}", info.subject);
                println!("        Is CA:   {}", info.is_ca);
                if info.is_ca {
                    println!("        Status:  ✓ Self-signed CA");
                } else {
                    println!("        Status:  ✗ Not a CA certificate");
                }
                results.push(true);
            }
            Err(e) => {
                println!("  [1/6] ca.pem: ✗ Parse error: {}", e);
                results.push(false);
            }
        }
    }

    // 2. ca-key.pem
    let ca_key_path = cert_dir.join("ca-key.pem");
    if !ca_key_path.exists() {
        println!("\n  [2/6] ca-key.pem: ✗ Not found");
        results.push(false);
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            match fs::metadata(&ca_key_path) {
                Ok(meta) => {
                    let mode = meta.permissions().mode() & 0o777;
                    println!("\n  [2/6] ca-key.pem");
                    if mode == 0o400 {
                        println!("        Permissions: ✓ 0400 (read-only)");
                        results.push(true);
                    } else {
                        println!("        Permissions: ✗ {:04o} (expected 0400)", mode);
                        results.push(false);
                    }
                }
                Err(e) => {
                    println!("\n  [2/6] ca-key.pem: ✗ {}", e);
                    results.push(false);
                }
            }
        }
        #[cfg(not(unix))]
        {
            println!("\n  [2/6] ca-key.pem: ✓ Exists");
            results.push(true);
        }
    }

    // 3. server-api.pem
    let server_api_path = cert_dir.join("server-api.pem");
    if !server_api_path.exists() {
        println!("\n  [3/6] server-api.pem: ✗ Not found");
        results.push(false);
    } else {
        match inspect::verify_signed_by(&server_api_path, &ca_path) {
            Ok(result) => {
                println!("\n  [3/6] server-api.pem");
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

                // Show SANs
                match inspect::parse_cert(&server_api_path) {
                    Ok(info) => {
                        if !info.sans.is_empty() {
                            println!("        SANs:");
                            for san in &info.sans {
                                println!("          - {}", san);
                            }
                        }
                    }
                    Err(_) => {}
                }

                // SAN check
                match inspect::check_san_match(&server_api_path, hostname) {
                    Ok(true) => println!("        SAN Check: ✓ Matches '{}'", hostname),
                    Ok(false) => println!("        SAN Check: ✗ Does NOT match '{}'", hostname),
                    Err(e) => println!("        SAN Check: ✗ Error: {}", e),
                }
                results.push(true);
            }
            Err(e) => {
                println!("\n  [3/6] server-api.pem: ✗ Error: {}", e);
                results.push(false);
            }
        }
    }

    // 4. server-api-key.pem
    let server_api_key_path = cert_dir.join("server-api-key.pem");
    if !server_api_key_path.exists() {
        println!("\n  [4/6] server-api-key.pem: ✗ Not found");
        results.push(false);
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            match fs::metadata(&server_api_key_path) {
                Ok(meta) => {
                    let mode = meta.permissions().mode() & 0o777;
                    println!("\n  [4/6] server-api-key.pem");
                    if mode == 0o400 {
                        println!("        Permissions: ✓ 0400 (read-only)");
                        results.push(true);
                    } else {
                        println!("        Permissions: ✗ {:04o} (expected 0400)", mode);
                        results.push(false);
                    }
                }
                Err(e) => {
                    println!("\n  [4/6] server-api-key.pem: ✗ {}", e);
                    results.push(false);
                }
            }
        }
        #[cfg(not(unix))]
        {
            println!("\n  [4/6] server-api-key.pem: ✓ Exists");
            results.push(true);
        }
    }

    // 5. client-api.pem
    let client_api_path = cert_dir.join("client-api.pem");
    if !client_api_path.exists() {
        println!("\n  [5/6] client-api.pem: ✗ Not found");
        results.push(false);
    } else {
        match inspect::verify_signed_by(&client_api_path, &ca_path) {
            Ok(result) => {
                println!("\n  [5/6] client-api.pem");
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

                // Show SANs
                match inspect::parse_cert(&client_api_path) {
                    Ok(info) => {
                        if !info.sans.is_empty() {
                            println!("        SANs:");
                            for san in &info.sans {
                                println!("          - {}", san);
                            }
                        }
                    }
                    Err(_) => {}
                }
                results.push(true);
            }
            Err(e) => {
                println!("\n  [5/6] client-api.pem: ✗ Error: {}", e);
                results.push(false);
            }
        }
    }

    // 6. client-api-key.pem
    let client_api_key_path = cert_dir.join("client-api-key.pem");
    if !client_api_key_path.exists() {
        println!("\n  [6/6] client-api-key.pem: ✗ Not found");
        results.push(false);
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            match fs::metadata(&client_api_key_path) {
                Ok(meta) => {
                    let mode = meta.permissions().mode() & 0o777;
                    println!("\n  [6/6] client-api-key.pem");
                    if mode == 0o400 {
                        println!("        Permissions: ✓ 0400 (read-only)");
                        results.push(true);
                    } else {
                        println!("        Permissions: ✗ {:04o} (expected 0400)", mode);
                        results.push(false);
                    }
                }
                Err(e) => {
                    println!("\n  [6/6] client-api-key.pem: ✗ {}", e);
                    results.push(false);
                }
            }
        }
        #[cfg(not(unix))]
        {
            println!("\n  [6/6] client-api-key.pem: ✓ Exists");
            results.push(true);
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
        println!("  [1/4] ca-certs/ca.pem: ✗ Not found");
        results.push(false);
    } else {
        match inspect::parse_cert(&ca_path) {
            Ok(info) => {
                println!("  [1/4] ca-certs/ca.pem");
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
                                println!("        Compare: ✗ Does NOT match {}", client_ca.display());
                            }
                        }
                        _ => {
                            println!("        Compare: ✗ Error reading files");
                        }
                    }
                }
                results.push(true);
            }
            Err(e) => {
                println!("  [1/4] ca-certs/ca.pem: ✗ Parse error: {}", e);
                results.push(false);
            }
        }
    }

    // 2. ca-certs/ca-key.pem
    let ca_key_path = ca_dir.join("ca-key.pem");
    if !ca_key_path.exists() {
        println!("\n  [2/4] ca-certs/ca-key.pem: ✗ Not found");
        results.push(false);
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            match fs::metadata(&ca_key_path) {
                Ok(meta) => {
                    let mode = meta.permissions().mode() & 0o777;
                    println!("\n  [2/4] ca-certs/ca-key.pem");
                    if mode == 0o400 {
                        println!("        Permissions: ✓ 0400 (read-only)");
                        results.push(true);
                    } else {
                        println!("        Permissions: ✗ {:04o} (expected 0400)", mode);
                        results.push(false);
                    }
                }
                Err(e) => {
                    println!("\n  [2/4] ca-certs/ca-key.pem: ✗ {}", e);
                    results.push(false);
                }
            }
        }
        #[cfg(not(unix))]
        {
            println!("\n  [2/4] ca-certs/ca-key.pem: ✓ Exists");
            results.push(true);
        }
    }

    // 3. cert_server_concat.pem
    let server_concat_path = haproxy_dir.join("cert_server_concat.pem");
    if !server_concat_path.exists() {
        println!("\n  [3/4] cert_server_concat.pem: ✗ Not found");
        results.push(false);
    } else {
        match inspect::verify_signed_by(&server_concat_path, &ca_path) {
            Ok(result) => {
                println!("\n  [3/4] cert_server_concat.pem");
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

                // Show SANs
                match inspect::parse_cert(&server_concat_path) {
                    Ok(info) => {
                        if !info.sans.is_empty() {
                            println!("        SANs:");
                            for san in &info.sans {
                                println!("          - {}", san);
                            }
                        }
                    }
                    Err(_) => {}
                }

                // SAN check
                match inspect::check_san_match(&server_concat_path, hostname) {
                    Ok(true) => println!("        SAN Check: ✓ Matches '{}'", hostname),
                    Ok(false) => println!("        SAN Check: ✗ Does NOT match '{}'", hostname),
                    Err(e) => println!("        SAN Check: ✗ Error: {}", e),
                }
                results.push(true);
            }
            Err(e) => {
                println!("\n  [3/4] cert_server_concat.pem: ✗ Error: {}", e);
                results.push(false);
            }
        }
    }

    // 4. cert_client_concat.pem
    let client_concat_path = haproxy_dir.join("cert_client_concat.pem");
    if !client_concat_path.exists() {
        println!("\n  [4/4] cert_client_concat.pem: ✗ Not found");
        results.push(false);
    } else {
        match inspect::verify_signed_by(&client_concat_path, &ca_path) {
            Ok(result) => {
                println!("\n  [4/4] cert_client_concat.pem");
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

                // Show SANs
                match inspect::parse_cert(&client_concat_path) {
                    Ok(info) => {
                        if !info.sans.is_empty() {
                            println!("        SANs:");
                            for san in &info.sans {
                                println!("          - {}", san);
                            }
                        }
                    }
                    Err(_) => {}
                }
                results.push(true);
            }
            Err(e) => {
                println!("\n  [4/4] cert_client_concat.pem: ✗ Error: {}", e);
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
                                println!("        Compare: ✗ Does NOT match {}", client_ca.display());
                            }
                        }
                        _ => {
                            println!("        Compare: ✗ Error reading files");
                        }
                    }
                }
                results.push(true);
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
                results.push(true);
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
pub fn handle_verify(cert_dir: &Path, expected_hostname: Option<&str>, target: Option<VerifySubcommand>) {
    if let Err(e) = check_gcob_access() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    let hostname = expected_hostname.unwrap_or("localhost");
    let target = target.unwrap_or(VerifySubcommand::All);
    let is_server = is_server_env();

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
                let cln_source = ClnSourcePaths::default_home();
                all_results.extend(verify_haproxy_section(&server_paths.haproxy_cert_dir, cert_dir, hostname));
                all_results.extend(verify_cln_section(&cln_source.dir, cert_dir));
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
                let cln_source = ClnSourcePaths::default_home();
                all_results.extend(verify_api_section(cert_dir, hostname));
                all_results.extend(verify_haproxy_section(&server_paths.haproxy_cert_dir, cert_dir, hostname));
                all_results.extend(verify_cln_section(&cln_source.dir, cert_dir));
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
                results.push(true);
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
                    println!("        Expiry:  ✗ Expired ({} days ago)", -result.days_remaining);
                } else {
                    println!("        Expiry:  ✓ Valid ({} days remaining)", result.days_remaining);
                }

                // Show SANs
                match inspect::parse_cert(&client_path) {
                    Ok(info) => {
                        if !info.sans.is_empty() {
                            println!("        SANs:");
                            for san in &info.sans {
                                println!("          - {}", san);
                            }
                        }
                    }
                    Err(_) => {}
                }

                // SAN check
                match inspect::check_san_match(&client_path, hostname) {
                    Ok(true) => println!("        SAN Check: ✓ Matches '{}'", hostname),
                    Ok(false) => println!("        SAN Check: ✗ Does NOT match '{}'", hostname),
                    Err(e) => println!("        SAN Check: ✗ Error: {}", e),
                }
                results.push(true);
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
            let cert_path = cert.unwrap_or_else(|| default_cert_dir().join("server.pem"));
            handle_show(&cert_path);
        }
        super::CertsCommand::Verify { hostname, target } => {
            let cert_dir = default_cert_dir();
            handle_verify(&cert_dir, hostname.as_deref(), target);
        }
        super::CertsCommand::Renew { force } => {
            let cert_dir = default_cert_dir();
            handle_renew(&cert_dir, force);
        }
    }
}
