use std::io::Write;
use std::path::Path;

use anyhow::Result;

/// Generate a client CSR without requiring a server connection.
///
/// The private key never leaves the machine; only `client.csr` should be sent
/// to the server for signing.
pub fn run(
    hostname: Option<&str>,
    ip: Option<&str>,
    output: Option<&Path>,
    force: bool,
    no_confirm: bool,
) -> Result<()> {
    let plan = gcob::client_init::plan(hostname, ip, output)?;
    let csr_path = plan.cert_dir.join("client.csr");

    println!("=== gcob-client CSR generation ===");
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

    if !no_confirm {
        print!("Proceed? [Y/n] ");
        std::io::stdout().flush().ok();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        let input = input.trim().to_lowercase();

        if input == "n" || input == "no" {
            println!("Aborted.");
            return Ok(());
        }
        println!();
    }

    println!("[1/2] Generating CSR...");
    gcob::client_init::run(&plan, force, false)?;
    println!("[2/2] CSR generated successfully");
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
        "     gcob sign --csr /tmp/client.csr --hostname {} --cln-dir <CLN_DIR> --output <DIR>",
        plan.hostname
    );
    println!();
    println!("  3. Server will return: ca.pem + client.pem");
    println!("     Place them in: {}/", plan.cert_dir.display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_generates_csr_in_output_dir() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        run(
            Some("client.example"),
            Some("10.0.0.5"),
            Some(dir.path()),
            false,
            true,
        )
        .unwrap();

        assert!(dir.path().join("client.csr").exists());
        assert!(dir.path().join("client-key.pem").exists());
    }
}
