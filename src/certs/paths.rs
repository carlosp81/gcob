use std::ffi::CStr;
use std::fs;
use std::path::{Path, PathBuf};

use super::generate::CertError;

/// Account that owns the local certificate material.
#[derive(Debug, Clone)]
pub struct AdminAccount {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}

#[cfg(unix)]
fn account_from_name(name: &str) -> Option<AdminAccount> {
    let cname = std::ffi::CString::new(name).ok()?;
    unsafe {
        let pwd = libc::getpwnam(cname.as_ptr());
        if pwd.is_null() {
            return None;
        }
        let entry = &*pwd;
        Some(AdminAccount {
            name: CStr::from_ptr(entry.pw_name).to_string_lossy().to_string(),
            uid: entry.pw_uid,
            gid: entry.pw_gid,
            home: PathBuf::from(CStr::from_ptr(entry.pw_dir).to_string_lossy().to_string()),
        })
    }
}

#[cfg(not(unix))]
fn account_from_name(_name: &str) -> Option<AdminAccount> {
    None
}

#[cfg(unix)]
fn account_from_uid(uid: u32) -> Option<AdminAccount> {
    unsafe {
        let pwd = libc::getpwuid(uid);
        if pwd.is_null() {
            return None;
        }
        let entry = &*pwd;
        Some(AdminAccount {
            name: CStr::from_ptr(entry.pw_name).to_string_lossy().to_string(),
            uid: entry.pw_uid,
            gid: entry.pw_gid,
            home: PathBuf::from(CStr::from_ptr(entry.pw_dir).to_string_lossy().to_string()),
        })
    }
}

#[cfg(not(unix))]
fn account_from_uid(_uid: u32) -> Option<AdminAccount> {
    None
}

/// Resolve an account by name, failing if it does not exist.
pub fn account_by_name(name: &str) -> Result<AdminAccount, CertError> {
    account_from_name(name).ok_or_else(|| {
        CertError::Io(std::io::Error::other(format!(
            "User '{}' does not exist on this system",
            name
        )))
    })
}

/// The account of the current effective user.
#[cfg(unix)]
pub fn current_account() -> Result<AdminAccount, CertError> {
    let uid = unsafe { libc::geteuid() };
    account_from_uid(uid).ok_or_else(|| {
        CertError::Io(std::io::Error::other(format!(
            "Cannot resolve current uid {}",
            uid
        )))
    })
}

#[cfg(not(unix))]
pub fn current_account() -> Result<AdminAccount, CertError> {
    Ok(AdminAccount {
        name: "current".to_string(),
        uid: 0,
        gid: 0,
        home: std::env::var("HOME").map(PathBuf::from).unwrap_or_default(),
    })
}

/// Resolve the account that owns `~/.certs`.
///
/// Priority: `GCOB_ADMIN_USER` > `SUDO_USER` (non-root) > current real user
/// (uid >= 1000). The old heuristic ("first uid >= 1000 in /etc/passwd") was
/// removed: on multi-user systems it could hand CA/client private keys to an
/// unrelated account. If nothing trustworthy can be resolved this fails closed.
pub fn detect_admin_account() -> Result<AdminAccount, CertError> {
    if let Ok(name) = std::env::var("GCOB_ADMIN_USER") {
        if !name.is_empty() {
            return account_from_name(&name).ok_or_else(|| {
                CertError::Io(std::io::Error::other(format!(
                    "GCOB_ADMIN_USER='{}' does not exist on this system",
                    name
                )))
            });
        }
    }

    if let Ok(name) = std::env::var("SUDO_USER") {
        if !name.is_empty() && name != "root" {
            if let Some(account) = account_from_name(&name) {
                return Ok(account);
            }
        }
    }

    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        if uid >= 1000 {
            if let Some(account) = account_from_uid(uid) {
                return Ok(account);
            }
        }
    }

    Err(CertError::Io(std::io::Error::other(
        "Cannot determine the admin account that owns ~/.certs; set GCOB_ADMIN_USER",
    )))
}

/// Resolve the certificate directory: `<admin home>/.certs`.
pub fn default_cert_dir() -> Result<PathBuf, CertError> {
    Ok(detect_admin_account()?.home.join(".certs"))
}

/// Client certificate paths (for gcob gRPC client)
pub struct ClientPaths {
    pub cert_dir: PathBuf,
    pub ca_file: PathBuf,
    pub client_key_file: PathBuf,
}

impl ClientPaths {
    pub fn new(cert_dir: impl Into<PathBuf>) -> Self {
        let dir = cert_dir.into();
        Self {
            ca_file: dir.join("ca.pem"),
            client_key_file: dir.join("client-key.pem"),
            cert_dir: dir,
        }
    }

    pub fn default_path() -> Result<Self, CertError> {
        Ok(Self::new(default_cert_dir()?))
    }
}

/// Check if this environment is a server (GRPC_BIND_ADDR configured + a secure
/// HAProxy certificate directory exists).
pub fn is_server_env() -> bool {
    let has_grpc = std::env::var("GRPC_BIND_ADDR")
        .map(|v| !v.is_empty())
        .unwrap_or(false);

    let has_server_certs = match fs::symlink_metadata("/etc/haproxy/certs") {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                meta.mode() & 0o022 == 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        _ => false,
    };

    has_grpc && has_server_certs
}

/// Check whether the process effective UID is the `gcob` service user.
///
/// This is used instead of the spoofable `$USER` environment variable to decide
/// whether the API server may start in production.
#[cfg(unix)]
pub fn is_gcob_user() -> Result<bool, CertError> {
    let uid = unsafe { libc::geteuid() };
    let gcob = account_from_name("gcob").ok_or_else(|| {
        CertError::Io(std::io::Error::other(
            "User 'gcob' does not exist on this system",
        ))
    })?;
    Ok(uid == gcob.uid)
}

#[cfg(not(unix))]
pub fn is_gcob_user() -> Result<bool, CertError> {
    Ok(true)
}

/// Check if current user has permission to manage gcob certificates.
/// In production: only 'gcob' user and root can access.
#[cfg(unix)]
pub fn check_gcob_access() -> Result<(), CertError> {
    let uid = unsafe { libc::getuid() };

    let gcob = account_from_name("gcob").ok_or_else(|| {
        CertError::Io(std::io::Error::other(
            "Error: User 'gcob' does not exist on this system.\n\n\
             To create the gcob user, run as root:\n\n\
               1. Create the user (no home, no shell):\n\
                  sudo useradd -r -s /usr/sbin/nologin gcob\n\n\
               2. Set a password (for sudo -u gcob):\n\
                  sudo passwd gcob\n\n\
             Then run:\n\
                sudo -u gcob gcob init --client",
        ))
    })?;

    if uid == gcob.uid {
        return Ok(()); // Running as gcob user
    }

    // Allow root (uid=0) for initial setup
    if uid == 0 {
        return Ok(());
    }

    let current_user = account_from_uid(uid)
        .map(|account| account.name)
        .unwrap_or_else(|| "unknown".to_string());

    Err(CertError::Io(std::io::Error::other(format!(
        "Permission denied: only user 'gcob' can manage certificates. Current: '{}' (uid={})\n  Run: sudo -u gcob gcob <command>",
        current_user, uid
    ))))
}

#[cfg(not(unix))]
pub fn check_gcob_access() -> Result<(), CertError> {
    Ok(())
}

/// Change ownership of a path recursively using native `chown` syscalls.
///
/// No external binary is invoked, so a manipulated `PATH` cannot execute
/// arbitrary code with the privileges of this process.
#[cfg(unix)]
pub fn chown_recursive(path: &Path, uid: u32, gid: u32) -> Result<(), CertError> {
    use std::os::unix::fs::{chown, lchown};

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        lchown(path, Some(uid), Some(gid))?;
        return Ok(());
    }

    chown(path, Some(uid), Some(gid))?;

    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            chown_recursive(&entry?.path(), uid, gid)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn chown_recursive(_path: &Path, _uid: u32, _gid: u32) -> Result<(), CertError> {
    Ok(())
}

/// Locate `setfacl` by absolute path (never through `PATH`).
#[cfg(unix)]
fn find_setfacl() -> Option<PathBuf> {
    ["/usr/bin/setfacl", "/bin/setfacl"]
        .iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.is_file())
}

/// Setup ACLs so gcob can access the admin's cert directory.
/// Sets: admin home → gcob can traverse (x), .certs → gcob can read/write.
#[cfg(unix)]
pub fn setup_gcob_acls() -> Result<(), CertError> {
    use std::process::Command;

    let account = detect_admin_account()?;
    let cert_dir = account.home.join(".certs");

    let setfacl = find_setfacl().ok_or_else(|| {
        CertError::Io(std::io::Error::other(
            "setfacl not found (install the 'acl' package or run as the admin user)",
        ))
    })?;

    let run = |perm: &str, target: &Path| -> Result<(), CertError> {
        let output = Command::new(&setfacl)
            .arg("-m")
            .arg(perm)
            .arg(target)
            .output()
            .map_err(|e| CertError::Io(std::io::Error::other(format!("setfacl failed: {}", e))))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CertError::Io(std::io::Error::other(format!(
                "setfacl on '{}' failed: {}",
                target.display(),
                stderr.trim()
            ))));
        }
        Ok(())
    };

    run("u:gcob:x", &account.home)?;
    run("u:gcob:rwx", &cert_dir)?;
    Ok(())
}

#[cfg(not(unix))]
pub fn setup_gcob_acls() -> Result<(), CertError> {
    Ok(())
}

/// Ensure ~/.certs exists with correct permissions (0700) and ownership (admin).
/// Sets ACLs so gcob can access the directory.
pub fn ensure_cert_dir() -> Result<(), CertError> {
    let account = detect_admin_account()?;
    let cert_dir = account.home.join(".certs");

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
        chown_recursive(&cert_dir, account.uid, account.gid)?;
        setup_gcob_acls()?;
    }

    Ok(())
}

/// Reject any symlink component in an absolute path.
///
/// Stops at the first non-existent component (nothing else to check) and
/// rejects relative paths, `..` and prefix components.
pub fn reject_symlink_components(path: &Path) -> Result<(), CertError> {
    use std::path::Component;

    if !path.is_absolute() {
        return Err(CertError::Io(std::io::Error::other(format!(
            "Path must be absolute: {}",
            path.display()
        ))));
    }

    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push("/"),
            Component::CurDir => {}
            Component::Normal(part) => {
                current.push(part);
                match fs::symlink_metadata(&current) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        return Err(CertError::Io(std::io::Error::other(format!(
                            "Refusing to use symlinked path component: {}",
                            current.display()
                        ))));
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                    Err(e) => return Err(CertError::Io(e)),
                }
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(CertError::Io(std::io::Error::other(format!(
                    "Path contains unsupported component: {}",
                    path.display()
                ))));
            }
        }
    }
    Ok(())
}

/// Create (if needed) and validate a directory for privileged certificate output.
///
/// - rejects symlinks in any existing path component;
/// - creates missing components with mode 0700;
/// - rejects a final directory that is writable by group/other or owned by an
///   account outside `allowed_owners`;
/// - applies `mode` and ownership `owner` to the final directory.
pub fn ensure_secure_dir(
    path: &Path,
    mode: u32,
    owner: (u32, u32),
    allowed_owners: &[u32],
) -> Result<(), CertError> {
    use std::path::Component;

    if !path.is_absolute() {
        return Err(CertError::Io(std::io::Error::other(format!(
            "Path must be absolute: {}",
            path.display()
        ))));
    }

    let mut current = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(part) => {
                current.push(part);
                match fs::symlink_metadata(&current) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() {
                            return Err(CertError::Io(std::io::Error::other(format!(
                                "Refusing to use symlinked path component: {}",
                                current.display()
                            ))));
                        }
                        if !meta.is_dir() {
                            return Err(CertError::Io(std::io::Error::other(format!(
                                "Path component is not a directory: {}",
                                current.display()
                            ))));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::DirBuilderExt;
                            fs::DirBuilder::new().mode(0o700).create(&current)?;
                        }
                        #[cfg(not(unix))]
                        fs::create_dir(&current)?;
                    }
                    Err(e) => return Err(CertError::Io(e)),
                }
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(CertError::Io(std::io::Error::other(format!(
                    "Path contains unsupported component: {}",
                    path.display()
                ))));
            }
        }
    }

    let metadata = fs::symlink_metadata(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{chown, MetadataExt, PermissionsExt};

        let current_mode = metadata.mode() & 0o777;
        if current_mode & 0o022 != 0 {
            return Err(CertError::Io(std::io::Error::other(format!(
                "Directory {} has permissions {:04o} (group/other writable); refusing to use it",
                path.display(),
                current_mode
            ))));
        }
        if !allowed_owners.is_empty() && !allowed_owners.contains(&metadata.uid()) {
            return Err(CertError::Io(std::io::Error::other(format!(
                "Directory {} is owned by uid {} which is not allowed",
                path.display(),
                metadata.uid()
            ))));
        }

        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        chown(path, Some(owner.0), Some(owner.1))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (mode, owner, allowed_owners);
    }

    Ok(())
}

/// Acquire an exclusive lock on a directory to prevent concurrent provisioning.
///
/// The returned file must be kept alive for the duration of the operation;
/// dropping it releases the lock.
#[cfg(unix)]
pub fn lock_dir(dir: &Path) -> Result<Option<fs::File>, CertError> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let lock_path = dir.join(".gcob.lock");
    let file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)?;

    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(CertError::Io(std::io::Error::other(
            "Another gcob init is already running (lock held)",
        )));
    }
    Ok(Some(file))
}

#[cfg(not(unix))]
pub fn lock_dir(_dir: &Path) -> Result<Option<fs::File>, CertError> {
    Ok(None)
}

/// Validate the CLN certificate source directory and its CA files.
///
/// Rejects symlinked paths/files, non-regular files, a directory writable by
/// group/other, and a CA private key with permissions looser than 0600/0400.
pub fn validate_cln_source(source: &ClnSourcePaths) -> Result<(), CertError> {
    reject_symlink_components(&source.dir)?;
    reject_symlink_components(&source.ca_file)?;
    reject_symlink_components(&source.ca_key_file)?;

    let dir_meta = fs::symlink_metadata(&source.dir)?;
    if !dir_meta.is_dir() {
        return Err(CertError::MissingSource(format!(
            "CLN source is not a directory: {}",
            source.dir.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let dir_mode = dir_meta.mode() & 0o777;
        if dir_mode & 0o022 != 0 {
            return Err(CertError::Io(std::io::Error::other(format!(
                "CLN source directory {} has permissions {:04o} (group/other writable)",
                source.dir.display(),
                dir_mode
            ))));
        }
    }

    for (path, is_key) in [(&source.ca_file, false), (&source.ca_key_file, true)] {
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_file() {
            return Err(CertError::MissingSource(format!(
                "Not a regular file: {}",
                path.display()
            )));
        }
        #[cfg(unix)]
        if is_key {
            use std::os::unix::fs::MetadataExt;
            let mode = meta.mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(CertError::Io(std::io::Error::other(format!(
                    "CA private key {} has permissions {:04o}; expected 0600 or 0400",
                    path.display(),
                    mode
                ))));
            }
        }
        #[cfg(not(unix))]
        let _ = is_key;
    }

    Ok(())
}

/// Validate that `path` is safe to use as a certificate output directory.
///
/// Refuses symlinks, non-directories, directories writable by group/other, and
/// directories owned by an unrelated account. Used before overwriting existing
/// certificate material.
pub fn validate_cert_dir_target(path: &Path) -> Result<(), CertError> {
    if !path.exists() {
        return Ok(());
    }

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(CertError::Io(std::io::Error::other(format!(
            "Refusing to write certificates into symlink: {}",
            path.display()
        ))));
    }
    if !metadata.is_dir() {
        return Err(CertError::Io(std::io::Error::other(format!(
            "Certificate path is not a directory: {}",
            path.display()
        ))));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let mode = metadata.mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(CertError::Io(std::io::Error::other(format!(
                "Certificate directory {} has permissions {:04o} (group/other writable); refusing to overwrite",
                path.display(),
                mode
            ))));
        }

        let owner = metadata.uid();
        let euid = unsafe { libc::geteuid() };
        let admin_uid = detect_admin_account().ok().map(|account| account.uid);
        if owner != 0 && owner != euid && Some(owner) != admin_uid {
            return Err(CertError::Io(std::io::Error::other(format!(
                "Certificate directory {} is owned by uid {} (not root, current user, or admin); refusing to overwrite",
                path.display(),
                owner
            ))));
        }
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
}

impl ServerPaths {
    pub fn new(haproxy_cert_dir: impl Into<PathBuf>) -> Self {
        let dir = haproxy_cert_dir.into();
        let ca_dir = dir.join("ca-certs");
        Self {
            server_concat_file: dir.join("cert_server_concat.pem"),
            client_concat_file: dir.join("cert_client_concat.pem"),
            ca_file: ca_dir.join("ca.pem"),
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
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let path = dir.into();
        Self {
            ca_file: path.join("ca.pem"),
            ca_key_file: path.join("ca-key.pem"),
            server_key_file: path.join("server-key.pem"),
            dir: path,
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn account_lookup_resolves_root() {
        let root = account_from_name("root").expect("root account");
        assert_eq!(root.uid, 0);
        assert_eq!(root.name, "root");
        assert!(root.home.is_absolute());
    }

    #[test]
    fn account_lookup_rejects_unknown_user() {
        assert!(account_from_name("gcob-definitely-missing-user").is_none());
    }

    #[test]
    fn account_lookup_by_uid_matches_by_name() {
        let by_uid = account_from_uid(0).expect("uid 0");
        assert_eq!(by_uid.name, "root");
    }

    #[test]
    fn explicit_admin_override_is_honored() {
        std::env::set_var("GCOB_ADMIN_USER", "root");
        let account = detect_admin_account().unwrap();
        assert_eq!(account.uid, 0);
        std::env::remove_var("GCOB_ADMIN_USER");
    }

    #[test]
    fn cert_dir_target_rejects_group_writable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(validate_cert_dir_target(dir.path()).is_err());
    }

    #[test]
    fn cert_dir_target_accepts_owner_only_dir() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_cert_dir_target(dir.path()).is_ok());
    }

    #[test]
    fn cert_dir_target_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(validate_cert_dir_target(&link).is_err());
    }

    #[test]
    fn ensure_secure_dir_creates_and_hardens() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().unwrap();
        let target = base.path().join("a/b/certs");
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };

        ensure_secure_dir(&target, 0o700, (uid, gid), &[uid]).unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn ensure_secure_dir_rejects_symlink_component() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let uid = unsafe { libc::geteuid() };
        let err = ensure_secure_dir(&link.join("certs"), 0o700, (uid, uid), &[uid]).unwrap_err();
        assert!(format!("{}", err).contains("symlink"), "{err}");
    }

    #[test]
    fn ensure_secure_dir_rejects_group_writable() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().unwrap();
        let target = base.path().join("certs");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o777)).unwrap();

        let uid = unsafe { libc::geteuid() };
        assert!(ensure_secure_dir(&target, 0o700, (uid, uid), &[uid]).is_err());
    }

    #[test]
    fn lock_dir_is_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let first = lock_dir(dir.path()).unwrap();
        assert!(first.is_some());
        assert!(lock_dir(dir.path()).is_err());
        drop(first);
        assert!(lock_dir(dir.path()).is_ok());
    }
}
