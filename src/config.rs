//! Trusted configuration loading.
//!
//! Historically the binaries called `dotenvy::dotenv()`, which searches the current
//! working directory and its parents. Running the CLI from an untrusted directory
//! (a cloned repo, `/tmp`, ...) allowed an attacker-controlled `.env` to inject
//! `GCOD_HOST`, `GCOD_CA`, `USER`, `CLN_CERT_DIR`, etc. This module loads
//! environment files only from explicit, trusted locations and validates
//! ownership and permissions before reading them.

use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};

/// Default environment file for system-wide deployments.
pub const DEFAULT_ENV_FILE: &str = "/etc/gcob/gcob.env";

/// Load configuration from a trusted environment file, if one exists.
///
/// Search order:
/// 1. `GCOB_ENV_FILE` (must be an absolute path)
/// 2. [`DEFAULT_ENV_FILE`]
///
/// Files that are symlinks, non-regular, owned by another user, or writable by
/// group/other are refused. A missing file is not an error.
pub fn load_trusted_env() {
    let path = std::env::var("GCOB_ENV_FILE")
        .ok()
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ENV_FILE));

    if !path.is_absolute() {
        eprintln!(
            "Warning: ignoring GCOB_ENV_FILE (must be an absolute path): {}",
            path.display()
        );
        return;
    }

    if !path.exists() {
        return;
    }

    if let Err(e) = load_env_file(&path) {
        eprintln!(
            "Warning: refusing to load environment file {}: {}",
            path.display(),
            e
        );
    }
}

/// Open and load a single environment file with ownership/permission checks.
///
/// The file is opened with `O_NOFOLLOW` on Unix so a symlink planted at the
/// target path cannot redirect the read. Existing environment variables are
/// never overridden (same semantics as `dotenvy`).
fn load_env_file(path: &Path) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }

    let file = options.open(path)?;
    let metadata = file.metadata()?;

    if !metadata.is_file() {
        return Err(io::Error::other("not a regular file"));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let file_uid = metadata.uid();
        let current_uid = unsafe { libc::geteuid() };
        if file_uid != 0 && file_uid != current_uid {
            return Err(io::Error::other(format!(
                "owner uid {} is neither root nor the current user ({})",
                file_uid, current_uid
            )));
        }

        let mode = metadata.mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(io::Error::other(format!(
                "permissions {:04o} are writable by group/other (expected 0600 or 0640)",
                mode
            )));
        }
    }

    dotenvy::from_read(file).map_err(|e| io::Error::other(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_file(dir: &Path, name: &str, mode: u32, contents: &str) -> PathBuf {
        let path = dir.join(name);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        path
    }

    #[test]
    fn loads_owner_only_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(dir.path(), "env", 0o600, "GCOB_TEST_LOADED=yes\n");
        load_env_file(&path).unwrap();
        assert_eq!(std::env::var("GCOB_TEST_LOADED").unwrap(), "yes");
        std::env::remove_var("GCOB_TEST_LOADED");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_or_other_writable() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(dir.path(), "env", 0o666, "GCOB_TEST_INSECURE=1\n");
        assert!(load_env_file(&path).is_err());
        assert!(std::env::var("GCOB_TEST_INSECURE").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = write_file(dir.path(), "real.env", 0o600, "GCOB_TEST_SYMLINK=1\n");
        let link = dir.path().join("link.env");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(load_env_file(&link).is_err());
        assert!(std::env::var("GCOB_TEST_SYMLINK").is_err());
    }
}
