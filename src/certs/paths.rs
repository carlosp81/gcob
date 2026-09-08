use std::path::PathBuf;

/// CLN source directory where the node stores its certificates
const CLN_SOURCE_DIR_DEFAULT: &str = ".lightning/bitcoin";

/// Client certificate paths (for gcob gRPC client)
pub struct ClientPaths {
    pub cert_dir: PathBuf,
    pub ca_file: PathBuf,
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
        Self::new("/etc/gcob/certs")
    }
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
