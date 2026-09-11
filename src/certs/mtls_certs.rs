use std::env;
use std::path::{Path, PathBuf};

use tonic::Status;

#[derive(Debug, Clone)]
pub struct ClnConfig {
    #[allow(dead_code)]
    pub cert_dir: PathBuf,
    pub ca_file: PathBuf,
    pub client_file: PathBuf,
    pub client_key_file: PathBuf,
    pub server_file: PathBuf,
    pub server_key_file: PathBuf,
    pub node_uri: String,
    pub grpc_bind_addr: String,
}

impl ClnConfig {
    pub fn from_env() -> Result<Self, Status> {
        let cert_dir = env::var("CLN_CERT_DIR")
            .map(PathBuf::from)
            .map_err(|_| Status::failed_precondition("CLN_CERT_DIR must be set"))?;

        if !cert_dir.is_absolute() {
            return Err(Status::failed_precondition(format!(
                "CLN_CERT_DIR is not absolute: {:?}",
                cert_dir
            )));
        }

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
                    return Err(Status::permission_denied(
                        "Only user 'gcob' can start the API",
                    ));
                }
                Err(e) => {
                    return Err(Status::permission_denied(format!(
                        "Cannot verify service user: {}",
                        e
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_cert_dir(path: &Path) -> Result<(), Status> {
        if !path.exists() {
            return Err(Status::failed_precondition(format!(
                "Certificate directory does not exist: {}",
                path.display()
            )));
        }
        if !path.is_dir() {
            return Err(Status::failed_precondition(format!(
                "Certificate path is not a directory: {}",
                path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(path).map_err(|e| {
                Status::internal(format!(
                    "Error reading metadata of {}: {}",
                    path.display(),
                    e
                ))
            })?;
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(Status::failed_precondition(format!(
                    "Directory {} has permissions {:o} — should be 0700. Run: chmod 0700 {}",
                    path.display(),
                    mode & 0o777,
                    path.display()
                )));
            }
        }
        Ok(())
    }

    fn validate_cert(path: &Path, is_private_key: bool) -> Result<(), Status> {
        if !path.exists() {
            return Err(Status::failed_precondition(format!(
                "Certificate not found: {}",
                path.display()
            )));
        }
        if !path.is_file() {
            return Err(Status::failed_precondition(format!(
                "Path is not a file: {}",
                path.display()
            )));
        }
        if is_private_key {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let metadata = std::fs::metadata(path).map_err(|e| {
                    Status::internal(format!(
                        "Error reading metadata of {}: {}",
                        path.display(),
                        e
                    ))
                })?;
                let mode = metadata.permissions().mode();
                if mode & 0o077 != 0 {
                    return Err(Status::failed_precondition(format!(
                        "Private key {} has permissions {:o} — should be 0400. Run: chmod 0400 {}",
                        path.display(),
                        mode & 0o777,
                        path.display()
                    )));
                }
            }
        }
        Ok(())
    }
}
