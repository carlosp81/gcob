//! Client-side CSR generation, shared by `gcob init --client` and
//! `gcob-client init`.
//!
//! Split into a pure `plan()` step (identity + output resolution, safe to print
//! and confirm) and a `run()` step (permissions, ownership and generation).

use std::fs;
use std::path::{Path, PathBuf};

use crate::certs::detect;
use crate::certs::generate::{self, CertError};
use crate::certs::paths::{
    chown_recursive, detect_admin_account, ensure_secure_dir, setup_gcob_acls, ClientPaths,
};

/// Resolved parameters for a CSR generation run.
#[derive(Debug)]
pub struct ClientInitPlan {
    pub hostname: String,
    pub ip: Option<String>,
    pub cert_dir: PathBuf,
    /// True when no explicit output was given (admin `~/.certs`).
    pub uses_default_dir: bool,
}

/// Resolve identity and output directory without touching the filesystem.
///
/// Identity priority: CLI flag > `CLIENT_HOSTNAME`/`CLIENT_IP` > auto-detect >
/// default. Output priority: explicit `output` > admin `~/.certs`.
pub fn plan(
    hostname: Option<&str>,
    ip: Option<&str>,
    output: Option<&Path>,
) -> Result<ClientInitPlan, CertError> {
    let identity = detect::resolve_identity(
        hostname,
        ip,
        "CLIENT_HOSTNAME",
        "CLIENT_IP",
        "localhost",
        "127.0.0.1",
        false, // IP optional for client
    )?;

    let (cert_dir, uses_default_dir) = match output {
        Some(dir) => (dir.to_path_buf(), false),
        None => (ClientPaths::default_path()?.cert_dir, true),
    };

    Ok(ClientInitPlan {
        hostname: identity.hostname,
        ip: identity.ip,
        cert_dir,
        uses_default_dir,
    })
}

/// Generate `client.csr` + `client-key.pem` with secure permissions.
///
/// The output directory is created/hardened first; an existing CSR requires
/// `force = true`. Ownership is assigned to the admin account (never an
/// unrelated one).
///
/// `with_gcob_acls` grants the local `gcob` user access to the cert directory;
/// it must be `true` on server hosts (so `serve`/`sign` can read the material)
/// and `false` on pure client hosts, where the `gcob` user does not exist.
pub fn run(plan: &ClientInitPlan, force: bool, with_gcob_acls: bool) -> Result<(), CertError> {
    let csr_path = plan.cert_dir.join("client.csr");
    if csr_path.exists() && !force {
        return Err(CertError::Io(std::io::Error::other(format!(
            "CSR already exists at {} (pass --force to regenerate)",
            csr_path.display()
        ))));
    }

    let account = detect_admin_account()?;

    ensure_secure_dir(
        &plan.cert_dir,
        0o700,
        (account.uid, account.gid),
        &[0, account.uid],
    )?;

    generate::generate_csr(&plan.hostname, plan.ip.as_deref(), &plan.cert_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(
            plan.cert_dir.join("client-key.pem"),
            fs::Permissions::from_mode(0o400),
        )?;
        fs::set_permissions(&csr_path, fs::Permissions::from_mode(0o444))?;
        chown_recursive(&plan.cert_dir, account.uid, account.gid)?;

        if with_gcob_acls {
            setup_gcob_acls()?;
        }
    }
    #[cfg(not(unix))]
    let _ = with_gcob_acls;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::paths::current_account;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    fn test_plan(output: &Path) -> ClientInitPlan {
        plan(Some("client.example"), Some("10.0.0.5"), Some(output)).unwrap()
    }

    #[test]
    fn plan_resolves_flags_and_output_override() {
        let dir = temp_dir();
        let plan = test_plan(dir.path());
        assert_eq!(plan.hostname, "client.example");
        assert_eq!(plan.ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(plan.cert_dir, dir.path());
        assert!(!plan.uses_default_dir);
    }

    #[test]
    fn run_generates_csr_and_key_with_secure_modes() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir();
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

        let plan = test_plan(dir.path());
        run(&plan, false, false).unwrap();

        let csr = dir.path().join("client.csr");
        let key = dir.path().join("client-key.pem");
        assert!(csr.exists());
        assert!(key.exists());

        #[cfg(unix)]
        {
            let csr_mode = fs::metadata(&csr).unwrap().permissions().mode() & 0o777;
            let key_mode = fs::metadata(&key).unwrap().permissions().mode() & 0o777;
            assert_eq!(csr_mode, 0o444);
            assert_eq!(key_mode, 0o400);
        }
    }

    #[test]
    fn run_requires_force_when_csr_exists() {
        let dir = temp_dir();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }

        let plan = test_plan(dir.path());
        run(&plan, false, false).unwrap();

        let err = run(&plan, false, false).unwrap_err();
        assert!(format!("{}", err).contains("--force"), "{err}");

        run(&plan, true, false).unwrap();
    }

    #[test]
    fn run_rejects_group_writable_output() {
        let dir = temp_dir();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
        }

        let plan = test_plan(dir.path());
        assert!(run(&plan, false, false).is_err());
    }

    #[test]
    fn run_ownership_matches_admin_account() {
        let dir = temp_dir();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }

        let plan = test_plan(dir.path());
        run(&plan, false, false).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let account = current_account().unwrap();
            let uid = fs::metadata(dir.path().join("client.csr")).unwrap().uid();
            assert_eq!(uid, account.uid);
        }
    }
}
