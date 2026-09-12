use std::env;
use std::path::{Path, PathBuf};

use tonic::Status;

#[derive(Debug, Clone)]
pub struct ClnConfig {
    pub cert_dir: PathBuf,
    pub ca_file: PathBuf,
    pub client_file: PathBuf,
    pub client_key_file: PathBuf,
    pub server_file: PathBuf,
    pub server_key_file: PathBuf,
    pub node_uri: String,
    pub grpc_bind_addr: String,
}

/// Resolve the certificate directory: an explicit absolute `CLN_CERT_DIR`, or
/// the admin account's `~/.certs` when unset/empty.
fn resolve_cert_dir(value: Option<&str>) -> Result<PathBuf, String> {
    match value {
        Some(value) if !value.is_empty() => {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return Err(format!("CLN_CERT_DIR is not absolute: {path:?}"));
            }
            Ok(path)
        }
        _ => crate::certs::paths::default_cert_dir().map_err(|e| {
            format!("CLN_CERT_DIR is not set and ~/.certs could not be resolved: {e}")
        }),
    }
}

impl ClnConfig {
    pub fn from_env() -> Result<Self, Status> {
        let cert_dir = resolve_cert_dir(env::var("CLN_CERT_DIR").ok().as_deref())
            .map_err(Status::failed_precondition)?;

        let ca_name = env::var("CLN_CA_FILE").unwrap_or_else(|_| "ca.pem".into());
        let client_name = env::var("CLN_CLIENT_FILE").unwrap_or_else(|_| "client.pem".into());
        let client_key_name =
            env::var("CLN_CLIENT_KEY_FILE").unwrap_or_else(|_| "client-key.pem".into());

        let ca_file = cert_dir.join(&ca_name);
        let client_file = cert_dir.join(&client_name);
        let client_key_file = cert_dir.join(&client_key_name);

        let server_name = env::var("SERVER_CERT_FILE").unwrap_or_else(|_| "server.pem".into());
        let server_key_name =
            env::var("SERVER_KEY_FILE").unwrap_or_else(|_| "server-key.pem".into());
        let server_file = cert_dir.join(&server_name);
        let server_key_file = cert_dir.join(&server_key_name);

        Ok(Self {
            cert_dir,
            ca_file,
            client_file,
            client_key_file,
            server_file,
            server_key_file,
            node_uri: env::var("CLN_NODE_URI")
                .map_err(|_| Status::failed_precondition("CLN_NODE_URI must be set"))?,
            grpc_bind_addr: env::var("GRPC_BIND_ADDR")
                .map_err(|_| Status::failed_precondition("GRPC_BIND_ADDR must be set"))?,
        })
    }

    pub fn validate_all(&self) -> Result<(), Status> {
        Self::validate_cert_dir(&self.cert_dir)?;
        Self::validate_cert(&self.ca_file, false)?;
        Self::validate_cert(&self.client_file, false)?;
        Self::validate_cert(&self.client_key_file, true)?;
        Self::validate_cert(&self.server_file, false)?;
        Self::validate_cert(&self.server_key_file, true)?;
        Ok(())
    }

    pub fn validate_user() -> Result<(), Status> {
        #[cfg(unix)]
        {
            match crate::certs::paths::is_gcob_user() {
                Ok(true) => {}
                Ok(false) => {
                    tracing::error!("Unauthorized user attempted to start the API");
                    return Err(Status::permission_denied("Unauthorized"));
                }
                Err(e) => {
                    tracing::error!(error = %e, "Cannot verify the API service user");
                    return Err(Status::permission_denied("Unauthorized"));
                }
            }
        }
        Ok(())
    }

    fn validate_cert_dir(path: &Path) -> Result<(), Status> {
        if !path.exists() {
            tracing::error!(path = %path.display(), "Certificate directory does not exist");
            return Err(Status::failed_precondition(
                "Invalid certificate configuration",
            ));
        }
        if !path.is_dir() {
            tracing::error!(path = %path.display(), "Certificate path is not a directory");
            return Err(Status::failed_precondition(
                "Invalid certificate configuration",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(path).map_err(|e| {
                tracing::error!(path = %path.display(), error = %e, "Cannot read certificate directory metadata");
                Status::internal("Internal error")
            })?;
            let mode = metadata.permissions().mode() & 0o777;
            if !crate::certs::paths::effective_perms_are_owner_only(path, mode, 0o077) {
                tracing::error!(
                    path = %path.display(),
                    mode = format_args!("{mode:04o}"),
                    "Certificate directory is accessible by group/other"
                );
                return Err(Status::failed_precondition(
                    "Invalid certificate configuration",
                ));
            }
        }
        Ok(())
    }

    fn validate_cert(path: &Path, is_private_key: bool) -> Result<(), Status> {
        if !path.exists() {
            tracing::error!(path = %path.display(), "Certificate file not found");
            return Err(Status::failed_precondition(
                "Invalid certificate configuration",
            ));
        }
        if !path.is_file() {
            tracing::error!(path = %path.display(), "Certificate path is not a file");
            return Err(Status::failed_precondition(
                "Invalid certificate configuration",
            ));
        }
        if is_private_key {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let metadata = std::fs::metadata(path).map_err(|e| {
                    tracing::error!(path = %path.display(), error = %e, "Cannot read private key metadata");
                    Status::internal("Internal error")
                })?;
                let mode = metadata.permissions().mode() & 0o777;
                if !crate::certs::paths::effective_perms_are_owner_only(path, mode, 0o077) {
                    tracing::error!(
                        path = %path.display(),
                        mode = format_args!("{mode:04o}"),
                        "Private key is readable by group/other"
                    );
                    return Err(Status::failed_precondition(
                        "Invalid certificate configuration",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_cert_dir_prefers_absolute_override() {
        assert_eq!(
            resolve_cert_dir(Some("/srv/certs")).unwrap(),
            PathBuf::from("/srv/certs")
        );
    }

    #[test]
    fn resolve_cert_dir_rejects_relative_override() {
        let err = resolve_cert_dir(Some("certs")).unwrap_err();
        assert!(err.contains("not absolute"), "{err}");
    }

    #[test]
    fn resolve_cert_dir_defaults_to_admin_certs() {
        match resolve_cert_dir(None) {
            Ok(path) => assert!(path.ends_with(".certs"), "{path:?}"),
            Err(e) => assert!(e.contains("CLN_CERT_DIR"), "{e}"),
        }
    }

    #[test]
    fn resolve_cert_dir_empty_falls_back_to_default() {
        match resolve_cert_dir(Some("")) {
            Ok(path) => assert!(path.ends_with(".certs"), "{path:?}"),
            Err(e) => assert!(e.contains("CLN_CERT_DIR"), "{e}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn validate_cert_dir_accepts_acl_named_user_grant() {
        use crate::certs::paths::test_support::{
            set_access_acl, TAG_GROUP_OBJ, TAG_MASK, TAG_OTHER, TAG_USER, TAG_USER_OBJ,
        };
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("certs");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let account = crate::certs::paths::current_account().unwrap();
        let acl = [
            (TAG_USER_OBJ, 7, u32::MAX),
            (TAG_USER, 5, account.uid), // named user: r-x
            (TAG_GROUP_OBJ, 0, u32::MAX),
            (TAG_MASK, 5, u32::MAX), // stat now reports 0750
            (TAG_OTHER, 0, u32::MAX),
        ];
        if !set_access_acl(&dir, &acl) {
            return; // filesystem without POSIX ACL support
        }
        assert!(ClnConfig::validate_cert_dir(&dir).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn validate_cert_dir_rejects_broad_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("certs");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ClnConfig::validate_cert_dir(&dir).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn validate_private_key_accepts_acl_named_user_grant() {
        use crate::certs::paths::test_support::{
            set_access_acl, TAG_GROUP_OBJ, TAG_MASK, TAG_OTHER, TAG_USER, TAG_USER_OBJ,
        };
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().unwrap();
        let key = base.path().join("client-key.pem");
        std::fs::write(&key, b"key").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o400)).unwrap();

        let account = crate::certs::paths::current_account().unwrap();
        let acl = [
            (TAG_USER_OBJ, 6, u32::MAX),
            (TAG_USER, 4, account.uid), // named user: r--
            (TAG_GROUP_OBJ, 0, u32::MAX),
            (TAG_MASK, 4, u32::MAX), // stat now reports 0440
            (TAG_OTHER, 0, u32::MAX),
        ];
        if !set_access_acl(&key, &acl) {
            return;
        }
        assert!(ClnConfig::validate_cert(&key, true).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn validate_private_key_rejects_broad_read() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().unwrap();
        let key = base.path().join("client-key.pem");
        std::fs::write(&key, b"key").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o440)).unwrap();
        assert!(ClnConfig::validate_cert(&key, true).is_err());
    }

    #[test]
    fn validate_cert_dir_error_does_not_leak_paths() {
        let base = tempfile::tempdir().unwrap();
        let missing = base.path().join("missing");
        let status = ClnConfig::validate_cert_dir(&missing).unwrap_err();
        assert_eq!(status.message(), "Invalid certificate configuration");
        assert!(!status.message().contains("missing"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_cert_dir_permission_error_does_not_leak_paths() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("certs");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let status = ClnConfig::validate_cert_dir(&dir).unwrap_err();
        assert_eq!(status.message(), "Invalid certificate configuration");
        assert!(!status.message().contains("certs"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_private_key_error_does_not_leak_paths() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().unwrap();
        let key = base.path().join("client-key.pem");
        std::fs::write(&key, b"key").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o444)).unwrap();
        let status = ClnConfig::validate_cert(&key, true).unwrap_err();
        assert_eq!(status.message(), "Invalid certificate configuration");
        assert!(!status.message().contains("client-key"));
    }
}
