use std::env;
use std::path::{Path, PathBuf};

use tonic::Status;
use tracing::warn;

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
        dotenvy::dotenv().ok();

        let cert_dir = env::var("CLN_CERT_DIR")
            .map(PathBuf::from)
            .expect("CLN_CERT_DIR must be set");

        if !cert_dir.is_absolute() {
            warn!(
                "CLN_CERT_DIR is not absolute: {:#?}. Using as-is.",
                cert_dir
            );
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

        if let Err(warning) = Self::validate_cert_dir(&cert_dir) {
            warn!("{}", warning);
        }
        if let Err(warning) = Self::validate_cert(&ca_file, false) {
            warn!("{}", warning);
        }
        if let Err(warning) = Self::validate_cert(&client_file, false) {
            warn!("{}", warning);
        }
        if let Err(warning) = Self::validate_cert(&client_key_file, true) {
            warn!("{}", warning);
        }
        if let Err(warning) = Self::validate_cert(&server_file, false) {
            warn!("{}", warning);
        }
        if let Err(warning) = Self::validate_cert(&server_key_file, true) {
            warn!("{}", warning);
        }

        Ok(Self {
            cert_dir,
            ca_file,
            client_file,
            client_key_file,
            server_file,
            server_key_file,
            node_uri: env::var("CLN_NODE_URI").expect("CLN_NODE_URI must be set"),
            grpc_bind_addr: env::var("GRPC_BIND_ADDR").expect("GRPC_BIND_ADDR must be set"),
        })
    }

    fn validate_cert_dir(path: &Path) -> Result<(), String> {
        if !path.exists() {
            return Err(format!(
                "Certificate directory does not exist: {}",
                path.display()
            ));
        }
        if !path.is_dir() {
            return Err(format!(
                "Certificate path is not a directory: {}",
                path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(path)
                .map_err(|e| format!("Error reading metadata of {}: {}", path.display(), e))?;
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(format!(
                    "Directory {} has permissions {} — should be 0700. Run: chmod 0700 {}",
                    path.display(),
                    mode & 0o777,
                    path.display()
                ));
            }
        }
        Ok(())
    }

    fn validate_cert(path: &Path, is_private_key: bool) -> Result<(), String> {
        if !path.exists() {
            return Err(format!("Certificate not found: {}", path.display()));
        }
        if !path.is_file() {
            return Err(format!("Path is not a file: {}", path.display()));
        }
        if is_private_key {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let metadata = std::fs::metadata(path)
                    .map_err(|e| format!("Error reading metadata of {}: {}", path.display(), e))?;
                let mode = metadata.permissions().mode();
                if mode & 0o077 != 0 {
                    return Err(format!(
                        "Private key {} has permissions {} — should be 0400. Run: chmod 0400 {}",
                        path.display(),
                        mode & 0o777,
                        path.display()
                    ));
                }
            }
        }
        Ok(())
    }
}
