use std::fs;
use std::path::{Path, PathBuf};

use super::generate::CertError;

/// Detect the admin user (UID >= 1000, not gcob) from /etc/passwd
#[cfg(unix)]
pub fn detect_admin_user() -> String {
    unsafe {
        libc::setpwent();
        loop {
            let pwd = libc::getpwent();
            if pwd.is_null() {
                break;
            }
            let entry = &*pwd;
            let uid = entry.pw_uid;
            let name = std::ffi::CStr::from_ptr(entry.pw_name)
                .to_string_lossy()
                .to_string();
            let home = std::ffi::CStr::from_ptr(entry.pw_dir)
                .to_string_lossy()
                .to_string();

            // Skip system users, gcob, and users without a real home
            if uid >= 1000 && name != "gcob" && home.starts_with("/home/") {
                libc::endpwent();
                return name;
            }
        }
        libc::endpwent();
    }
    "deb_cpim".to_string()
}

#[cfg(not(unix))]
fn detect_admin_user() -> String {
    "deb_cpim".to_string()
}

/// Resolve certificate directory: /home/<admin>/.certs
/// Detects the admin user automatically (UID >= 1000, not gcob)
pub fn default_cert_dir() -> PathBuf {
    let admin = detect_admin_user();
    PathBuf::from(format!("/home/{}/.certs", admin))
}

/// CLN source directory where the node stores its certificates
const CLN_SOURCE_DIR_DEFAULT: &str = ".lightning/bitcoin";

/// Client certificate paths (for gcob gRPC client)
pub struct ClientPaths {
    pub cert_dir: PathBuf,
    pub ca_file: PathBuf,
    pub ca_key_file: PathBuf,
    pub client_file: PathBuf,
    pub client_key_file: PathBuf,
    pub server_api_file: PathBuf,
    pub server_api_key_file: PathBuf,
    pub client_api_file: PathBuf,
    pub client_api_key_file: PathBuf,
}

impl ClientPaths {
    pub fn new(cert_dir: &str) -> Self {
        let dir = PathBuf::from(cert_dir);
        Self {
            ca_file: dir.join("ca.pem"),
            ca_key_file: dir.join("ca-key.pem"),
            client_file: dir.join("client.pem"),
            client_key_file: dir.join("client-key.pem"),
            server_api_file: dir.join("server-api.pem"),
            server_api_key_file: dir.join("server-api-key.pem"),
            client_api_file: dir.join("client-api.pem"),
            client_api_key_file: dir.join("client-api-key.pem"),
            cert_dir: dir,
        }
    }

    pub fn default_path() -> Self {
        Self::new(default_cert_dir().to_str().unwrap_or("~/.certs"))
    }
}

/// Check if this environment is a server (GRPC_BIND_ADDR configured in .env + server certs exist)
pub fn is_server_env() -> bool {
    dotenvy::dotenv().ok();
    let has_grpc = std::env::var("GRPC_BIND_ADDR")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    
    // Verificar también que existan certificados de servidor
    let has_server_certs = Path::new("/etc/haproxy/certs").exists();
    
    has_grpc && has_server_certs
}

/// Get username from UID using getpwuid
#[cfg(unix)]
fn get_username_by_uid(uid: u32) -> String {
    unsafe {
        let pwd = libc::getpwuid(uid);
        if pwd.is_null() {
            "unknown".to_string()
        } else {
            std::ffi::CStr::from_ptr((*pwd).pw_name)
                .to_string_lossy()
                .to_string()
        }
    }
}

#[cfg(not(unix))]
fn get_username_by_uid(_uid: u32) -> String {
    "unknown".to_string()
}

/// Check if current user has permission to manage gcob certificates.
/// In production: only 'gcob' user and root can access.
pub fn check_gcob_access() -> Result<(), CertError> {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };

        // Get the gcob user's UID from the system
        let gcob_uid = unsafe {
            let pwd = libc::getpwnam(b"gcob\0".as_ptr() as *const libc::c_char);
            if pwd.is_null() {
                return Err(CertError::Io(std::io::Error::other(
                    "Error: User 'gcob' does not exist on this system.\n\n\
                     To create the gcob user, run as root:\n\n\
                       1. Create the user (no home, no shell):\n\
                          sudo useradd -r -s /usr/sbin/nologin gcob\n\n\
                       2. Set a password (for sudo -u gcob):\n\
                          sudo passwd gcob\n\n\
                     Then run:\n\
                       sudo -u gcob gcob init --client",
                )));
            }
            (*pwd).pw_uid
        };

        if uid == gcob_uid {
            return Ok(()); // Running as gcob user
        }

        // Allow root (uid=0) for initial setup
        if uid == 0 {
            return Ok(());
        }

        // Get current username for the error message
        let current_user = get_username_by_uid(uid);

        return Err(CertError::Io(std::io::Error::other(format!(
            "Permission denied: only user 'gcob' can manage certificates. Current: '{}' (uid={})\n  Run: sudo -u gcob gcob <command>",
            current_user, uid
        ))));
    }

    #[cfg(not(unix))]
    Ok(())
}

/// Minimal sudoers content for gcob certificate management
const GCOB_SUDOERS_CONTENT: &str = r#"# Minimal sudoers for gcob certificate management
# Created by gcob init --client

# Allow gcob to create and manage /etc/gcob/certs/
gcob ALL=(root) NOPASSWD: /usr/bin/mkdir -p /etc/gcob
gcob ALL=(root) NOPASSWD: /usr/bin/mkdir -p /etc/gcob/certs
gcob ALL=(root) NOPASSWD: /usr/bin/chown -R gcob /etc/gcob
gcob ALL=(root) NOPASSWD: /usr/bin/chmod 700 /etc/gcob
gcob ALL=(root) NOPASSWD: /usr/bin/chmod 700 /etc/gcob/certs
gcob ALL=(root) NOPASSWD: /usr/bin/cat /etc/gcob/certs/client.csr
gcob ALL=(root) NOPASSWD: /usr/bin/cat /etc/gcob/certs/ca.pem
"#;

/// Write /etc/sudoers.d/gcob with minimal permissions for certificate management.
/// Must be executed as root (uid=0).
pub fn setup_gcob_sudoers() -> Result<(), CertError> {
    let uid = unsafe { libc::getuid() };
    if uid != 0 {
        return Err(CertError::Io(std::io::Error::other(
            "setup_gcob_sudoers must be run as root",
        )));
    }

    let sudoers_path = "/etc/sudoers.d/gcob";

    // Skip if already configured
    if Path::new(sudoers_path).exists() {
        return Ok(());
    }

    // Write sudoers file
    fs::write(sudoers_path, GCOB_SUDOERS_CONTENT)?;

    // Set permissions (must be 0440 for sudoers)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(sudoers_path, fs::Permissions::from_mode(0o440))?;
    }

    Ok(())
}

/// Change ownership of a path recursively using chown command
#[cfg(unix)]
pub fn chown_recursive(path: &Path, user: &str) -> Result<(), CertError> {
    use std::process::Command;

    let output = Command::new("chown")
        .args(["-R", &format!("{}:{}", user, user)])
        .arg(path)
        .output()
        .map_err(|e| CertError::Io(std::io::Error::other(format!("Failed to run chown: {}", e))))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CertError::Io(std::io::Error::other(
            format!("chown failed: {}", stderr.trim()),
        )));
    }

    Ok(())
}

/// Setup ACLs so gcob can access admin's cert directory.
/// Sets: home → gcob can traverse (x), .certs → gcob can read/write
#[cfg(unix)]
pub fn setup_gcob_acls() -> Result<(), CertError> {
    use std::process::Command;

    let admin = detect_admin_user();
    let home_dir = format!("/home/{}", admin);
    let cert_dir = default_cert_dir();

    // ACL on home: gcob can traverse (x)
    Command::new("setfacl")
        .args(["-m", "u:gcob:x", &home_dir])
        .output()
        .map_err(|e| CertError::Io(std::io::Error::other(format!("setfacl failed: {}", e))))?;

    // ACL on .certs: gcob can read/write
    Command::new("setfacl")
        .args(["-m", "u:gcob:rwx", cert_dir.to_str().unwrap()])
        .output()
        .map_err(|e| CertError::Io(std::io::Error::other(format!("setfacl failed: {}", e))))?;

    Ok(())
}

/// Ensure ~/.certs exists with correct permissions (0700) and ownership (admin).
/// Sets ACLs so gcob can access the directory.
pub fn ensure_cert_dir() -> Result<(), CertError> {
    let cert_dir = default_cert_dir();

    // Already exists - apply ACLs and return
    if cert_dir.exists() {
        #[cfg(unix)]
        setup_gcob_acls()?;
        return Ok(());
    }

    fs::create_dir_all(&cert_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&cert_dir, fs::Permissions::from_mode(0o700))?;
        // Ownership to admin
        let admin = detect_admin_user();
        chown_recursive(&cert_dir, &admin)?;
        // ACLs for gcob access
        setup_gcob_acls()?;
    }

    Ok(())
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
