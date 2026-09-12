use std::path::Path;

use anyhow::Result;

/// Generate a client CSR without requiring a server connection.
///
/// Thin adapter over [`gcob::client_init::run_cli`], which owns the whole flow
/// (plan, confirmation, generation and guidance). The private key never leaves
/// the machine; only `client.csr` should be sent to the server for signing.
pub fn run(
    hostname: Option<&str>,
    ip: Option<&str>,
    output: Option<&Path>,
    force: bool,
    no_confirm: bool,
) -> Result<()> {
    gcob::client_init::run_cli(hostname, ip, output, force, no_confirm)?;
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
