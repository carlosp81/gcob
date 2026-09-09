use std::path::PathBuf;

/// CLN source directory where the node stores its certificates
const CLN_SOURCE_DIR_DEFAULT: &str = ".lightning/bitcoin";

/// Client certificate paths (for gcob gRPC client)
pub struct ClientPaths {
    pub cert_dir: PathBuf,
    #[allow(dead_code)]
    pub ca_file: PathBuf,
    #[allow(dead_code)]
    pub client_file: PathBuf,
    pub client_key_file: PathBuf,
}

impl ClientPaths {
    pub fn new(cert_dir: &str) -> Self {
        let dir = PathBuf::from(cert_dir);
        Self {
            ca_file: dir.join("ca.pem"),
            client_file: dir.join("client.pem"),
            client_key_file: dir.join("client-key.pem"),
            cert_dir: dir,
        }
    }

    pub fn default_path() -> Self {
        if is_root() {
            Self::new("/etc/gcob/certs")
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            Self::new(&format!("{}/.gcob/certs", home))
        }
    }

    /// Validate that the certificate directory can be created and written to
    pub fn validate_writable(&self) -> Result<(), String> {
        // Check if cert_dir already exists and is writable
        if self.cert_dir.exists() {
            let test_file = self.cert_dir.join(".gcob_write_test");
            return match std::fs::write(&test_file, "") {
                Ok(_) => {
                    let _ = std::fs::remove_file(&test_file);
                    Ok(())
                }
                Err(e) => Err(format!(
                    "Directory exists but is not writable: {}\n  Reason: {}",
                    self.cert_dir.display(),
                    e
                )),
            };
        }

        // Find the first existing parent directory
        let mut check_path = self.cert_dir.as_path();
        let mut existing_parent = None;

        while let Some(parent) = check_path.parent() {
            if parent.exists() {
                existing_parent = Some(parent);
                break;
            }
            check_path = parent;
        }

        let parent = existing_parent.ok_or_else(|| {
            format!(
                "No writable parent directory found for: {}",
                self.cert_dir.display()
            )
        })?;

        // Check if parent is writable
        let test_file = parent.join(".gcob_write_test");
        match std::fs::write(&test_file, "") {
            Ok(_) => {
                let _ = std::fs::remove_file(&test_file);
                Ok(())
            }
            Err(e) => {
                let home = std::env::var("HOME").unwrap_or_default();
                let mut msg = format!(
                    "Cannot create directory: {}\n  Parent: {}\n  Reason: {}",
                    self.cert_dir.display(),
                    parent.display(),
                    e
                );

                // Add helpful suggestion based on the error
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    let home_dir = std::path::PathBuf::from(&home);
                    let home_exists = home_dir.exists();

                    if !home_exists || home.is_empty() || home == "/root" {
                        msg.push_str(
                            "\n\nSolution: Use --output-dir to specify a writable location:\n  gcob init --client --output-dir /var/lib/gcob/certs"
                        );
                    } else {
                        msg.push_str(&format!(
                            "\n\nSolution: Check permissions on {} or use --output-dir:\n  gcob init --client --output-dir /var/lib/gcob/certs",
                            home
                        ));
                    }
                }

                Err(msg)
            }
        }
    }
}

fn is_root() -> bool {
    #[cfg(unix)]
    { unsafe { libc::getuid() == 0 } }
    #[cfg(not(unix))]
    { false }
}

/// Check if this environment is a server (GRPC_BIND_ADDR configured in .env)
pub fn is_server_env() -> bool {
    dotenvy::dotenv().ok();
    std::env::var("GRPC_BIND_ADDR")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

/// Server certificate paths (for HAProxy mTLS)
pub struct ServerPaths {
    pub haproxy_cert_dir: PathBuf,
    pub haproxy_ca_dir: PathBuf,
    pub server_concat_file: PathBuf,
    pub client_concat_file: PathBuf,
    pub ca_file: PathBuf,
    pub ca_key_file: PathBuf,
}

impl ServerPaths {
    pub fn new(haproxy_cert_dir: &str) -> Self {
        let dir = PathBuf::from(haproxy_cert_dir);
        let ca_dir = dir.join("ca-certs");
        Self {
            server_concat_file: dir.join("cert_server_concat.pem"),
            client_concat_file: dir.join("cert_client_concat.pem"),
            ca_file: ca_dir.join("ca.pem"),
            ca_key_file: ca_dir.join("ca-key.pem"),
            haproxy_cert_dir: dir,
            haproxy_ca_dir: ca_dir,
        }
    }

    pub fn default_path() -> Self {
        Self::new("/etc/haproxy/certs")
    }
}

/// CLN source certificate paths
pub struct ClnSourcePaths {
    pub dir: PathBuf,
    pub ca_file: PathBuf,
    pub ca_key_file: PathBuf,
    #[allow(dead_code)]
    pub server_key_file: PathBuf,
}

impl ClnSourcePaths {
    pub fn new(dir: &str) -> Self {
        let path = PathBuf::from(dir);
        Self {
            ca_file: path.join("ca.pem"),
            ca_key_file: path.join("ca-key.pem"),
            server_key_file: path.join("server-key.pem"),
            dir: path,
        }
    }

    pub fn default_home() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        Self::new(&format!("{}/{}", home, CLN_SOURCE_DIR_DEFAULT))
    }
}
