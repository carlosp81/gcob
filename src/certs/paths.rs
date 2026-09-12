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

/// Copy an account entry out of the caller-provided buffer.
#[cfg(unix)]
fn copy_passwd(entry: &libc::passwd) -> Option<AdminAccount> {
    if entry.pw_name.is_null() || entry.pw_dir.is_null() {
        return None;
    }
    Some(AdminAccount {
        name: unsafe { CStr::from_ptr(entry.pw_name) }
            .to_string_lossy()
            .into_owned(),
        uid: entry.pw_uid,
        gid: entry.pw_gid,
        home: PathBuf::from(
            unsafe { CStr::from_ptr(entry.pw_dir) }
                .to_string_lossy()
                .into_owned(),
        ),
    })
}

/// Buffer size for the reentrant passwd lookups. 16 KiB is well above the
/// typical `sysconf(_SC_GETPW_R_SIZE_MAX)` value (1024 on glibc).
#[cfg(unix)]
const PASSWD_BUFFER_SIZE: usize = 16 * 1024;

#[cfg(unix)]
fn account_from_name(name: &str) -> Option<AdminAccount> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; PASSWD_BUFFER_SIZE];
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr() as *mut libc::c_char,
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    copy_passwd(&entry)
}

#[cfg(not(unix))]
fn account_from_name(_name: &str) -> Option<AdminAccount> {
    None
}

#[cfg(unix)]
fn account_from_uid(uid: u32) -> Option<AdminAccount> {
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; PASSWD_BUFFER_SIZE];
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr() as *mut libc::c_char,
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    copy_passwd(&entry)
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

    has_grpc && haproxy_certs_dir_is_secure(Path::new("/etc/haproxy/certs"))
}

/// A HAProxy certificate directory is secure when it is a real directory (not a
/// symlink) and no broad principal (base group, named groups or other) can
/// write to it. Named-user ACL grants (e.g. HAProxy's service user) are
/// accepted.
fn haproxy_certs_dir_is_secure(dir: &Path) -> bool {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                effective_perms_are_owner_only(dir, meta.mode() & 0o777, 0o022)
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        _ => false,
    }
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
                sudo -u gcob gcob init --cln-dir <CLN_DIR>",
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

/// POSIX ACL access tags (`system.posix_acl_access` entries) that can grant
/// broad permissions.
#[cfg(unix)]
const ACL_TAG_GROUP_OBJ: u16 = 0x04;
#[cfg(unix)]
const ACL_TAG_GROUP: u16 = 0x08;
#[cfg(unix)]
const ACL_TAG_OTHER: u16 = 0x20;

/// Parse a `system.posix_acl_access` blob and report whether it grants any of
/// `perms` to a broad principal (base group, named group or other).
///
/// Named-user entries are accepted: they are explicit grants by the file owner
/// (for example the `gcob` service account). Returns `None` when the blob is
/// not a valid v2 ACL.
#[cfg(unix)]
fn acl_has_broad_perms_from_bytes(buf: &[u8], perms: u16) -> Option<bool> {
    if buf.len() < 4 || !(buf.len() - 4).is_multiple_of(8) {
        return None;
    }
    let version = u32::from_le_bytes(buf[0..4].try_into().ok()?);
    if version != 2 {
        return None;
    }

    let mut broad = false;
    for entry in buf[4..].chunks_exact(8) {
        let tag = u16::from_le_bytes(entry[0..2].try_into().ok()?);
        let perm = u16::from_le_bytes(entry[2..4].try_into().ok()?);
        if perm & perms != 0 && matches!(tag, ACL_TAG_GROUP_OBJ | ACL_TAG_GROUP | ACL_TAG_OTHER) {
            broad = true;
        }
    }
    Some(broad)
}

/// Read the access ACL of `path` and report whether it grants any of `perms`
/// to a broad principal.
///
/// Returns `None` when the filesystem has no access ACL or does not support
/// xattrs, so callers can fall back to the plain mode-bit check.
#[cfg(unix)]
fn acl_has_broad_perms(path: &Path, perms: u16) -> Option<bool> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;
    let name = b"system.posix_acl_access\0";

    let size = unsafe {
        libc::getxattr(
            cpath.as_ptr(),
            name.as_ptr().cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size <= 0 {
        return None;
    }

    let mut buf = vec![0u8; size as usize];
    let read = unsafe {
        libc::getxattr(
            cpath.as_ptr(),
            name.as_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if read < 0 {
        return None;
    }
    buf.truncate(read as usize);
    acl_has_broad_perms_from_bytes(&buf, perms)
}

/// Whether the effective permissions of `path` are owner/named-user only.
///
/// True when `mode` has none of `perms` set, or when the group/other bits come
/// solely from a POSIX ACL mask that enables named users. Broad ACL grants
/// (base group, named groups or other) are always rejected, and so is missing
/// ACL information when the mode bits are not clean.
#[cfg(unix)]
pub fn effective_perms_are_owner_only(path: &Path, mode: u32, perms: u32) -> bool {
    if mode & perms == 0 {
        return true;
    }
    matches!(acl_has_broad_perms(path, perms as u16), Some(false))
}

/// Create (if needed) and validate a directory for privileged certificate output.
///
/// - rejects symlinks in any existing path component;
/// - creates missing components with mode 0700;
/// - rejects a final directory that is writable by group/other or owned by an
///   account outside `allowed_owners`. A directory whose write bits come from
///   a POSIX ACL mask enabling named users (e.g. `gcob`) is accepted;
/// - applies `mode` and ownership `owner` to the final directory. When an
///   access ACL is present the mode is left untouched, because `chmod` resets
///   the ACL mask and would revoke the named-user access.
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
        let acl_write = acl_has_broad_perms(path, 0o2);
        // A group/other write bit may be the POSIX ACL mask enabling a named
        // user (e.g. gcob), not real group access. Only the stat fallback and
        // ACLs that grant broad write are rejected.
        if current_mode & 0o022 != 0 && acl_write != Some(false) {
            return Err(CertError::Io(std::io::Error::other(format!(
                "Directory {} has permissions {:04o} (group/other writable); refusing to use it \
                 (run 'chmod 0700 {}' or grant access with a named-user ACL)",
                path.display(),
                current_mode,
                path.display()
            ))));
        }
        if !allowed_owners.is_empty() && !allowed_owners.contains(&metadata.uid()) {
            return Err(CertError::Io(std::io::Error::other(format!(
                "Directory {} is owned by uid {} which is not allowed",
                path.display(),
                metadata.uid()
            ))));
        }

        // `chmod` resets the ACL mask, which would silently revoke named-user
        // access (e.g. the gcob service user). Only normalize the mode when no
        // access ACL is present.
        if acl_write.is_none() {
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        }
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

/// Read a certificate file without following symlinks and validate the opened
/// descriptor before reading.
///
/// `O_NOFOLLOW` makes the open itself fail on a symlinked final component and
/// the subsequent metadata/ACL checks run on the same descriptor that is read,
/// closing the check-then-read (TOCTOU) window of a plain `fs::read`. When
/// `is_private_key` is true the descriptor must be owner-only (0600/0400 or a
/// named-user ACL grant).
pub fn read_secure_file(path: &Path, is_private_key: bool) -> Result<Vec<u8>, CertError> {
    use std::io::Read;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }

    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(e) => {
            #[cfg(unix)]
            if e.raw_os_error() == Some(libc::ELOOP) {
                return Err(CertError::Io(std::io::Error::other(format!(
                    "Refusing to read symlinked certificate file: {}",
                    path.display()
                ))));
            }
            return Err(CertError::Io(e));
        }
    };

    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(CertError::Io(std::io::Error::other(format!(
            "Certificate path is not a regular file: {}",
            path.display()
        ))));
    }

    #[cfg(unix)]
    if is_private_key {
        use std::os::unix::fs::MetadataExt;

        let mode = metadata.mode() & 0o777;
        if !effective_perms_are_owner_only_fd(&file, mode, 0o077) {
            return Err(CertError::Io(std::io::Error::other(format!(
                "Private key {} is readable by group/other; expected 0600 or 0400",
                path.display()
            ))));
        }
    }
    #[cfg(not(unix))]
    let _ = is_private_key;

    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Like [`effective_perms_are_owner_only`] but inspects the descriptor, so a
/// path swap cannot redirect the ACL lookup.
#[cfg(unix)]
fn effective_perms_are_owner_only_fd(file: &fs::File, mode: u32, perms: u32) -> bool {
    if mode & perms == 0 {
        return true;
    }
    matches!(acl_has_broad_perms_fd(file, perms as u16), Some(false))
}

#[cfg(unix)]
fn acl_has_broad_perms_fd(file: &fs::File, perms: u16) -> Option<bool> {
    use std::os::unix::io::AsRawFd;

    let fd = file.as_raw_fd();
    let name = b"system.posix_acl_access\0";

    let size = unsafe { libc::fgetxattr(fd, name.as_ptr().cast(), std::ptr::null_mut(), 0) };
    if size <= 0 {
        return None;
    }

    let mut buf = vec![0u8; size as usize];
    let read =
        unsafe { libc::fgetxattr(fd, name.as_ptr().cast(), buf.as_mut_ptr().cast(), buf.len()) };
    if read < 0 {
        return None;
    }
    buf.truncate(read as usize);
    acl_has_broad_perms_from_bytes(&buf, perms)
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
}

impl ClnSourcePaths {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let path = dir.into();
        Self {
            ca_file: path.join("ca.pem"),
            ca_key_file: path.join("ca-key.pem"),
            dir: path,
        }
    }
}

/// Test helpers for attaching POSIX ACLs without shelling out to `setfacl`.
#[cfg(all(test, unix))]
pub(crate) mod test_support {
    use std::path::Path;

    pub(crate) const TAG_USER_OBJ: u16 = 0x01;
    pub(crate) const TAG_USER: u16 = 0x02;
    pub(crate) const TAG_GROUP_OBJ: u16 = 0x04;
    pub(crate) const TAG_MASK: u16 = 0x10;
    pub(crate) const TAG_OTHER: u16 = 0x20;

    pub(crate) fn acl_blob(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + entries.len() * 8);
        buf.extend_from_slice(&2u32.to_le_bytes());
        for (tag, perm, id) in entries {
            buf.extend_from_slice(&tag.to_le_bytes());
            buf.extend_from_slice(&perm.to_le_bytes());
            buf.extend_from_slice(&id.to_le_bytes());
        }
        buf
    }

    /// Attach an access ACL to `path`; returns false when the filesystem does
    /// not support POSIX ACLs, so the test can be skipped.
    pub(crate) fn set_access_acl(path: &Path, entries: &[(u16, u16, u32)]) -> bool {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let buf = acl_blob(entries);
        let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();
        let name = b"system.posix_acl_access\0";
        let rc = unsafe {
            libc::setxattr(
                cpath.as_ptr(),
                name.as_ptr().cast(),
                buf.as_ptr().cast(),
                buf.len(),
                0,
            )
        };
        rc == 0
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::test_support::{acl_blob, set_access_acl};
    use super::*;

    const TAG_USER_OBJ: u16 = 0x01;
    const TAG_USER: u16 = 0x02;
    const TAG_MASK: u16 = 0x10;

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

    #[test]
    fn account_lookups_are_thread_safe() {
        let handles: Vec<_> = (0..8)
            .map(|_| std::thread::spawn(|| account_from_name("root").map(|account| account.uid)))
            .collect();
        for handle in handles {
            assert_eq!(handle.join().unwrap(), Some(0));
        }
    }

    #[test]
    fn acl_parser_accepts_named_user_write_only() {
        let account = current_account().unwrap();
        let blob = acl_blob(&[
            (TAG_USER_OBJ, 7, u32::MAX),
            (TAG_USER, 7, account.uid), // named user (ACL_USER)
            (ACL_TAG_GROUP_OBJ, 0, u32::MAX),
            (TAG_MASK, 7, u32::MAX), // ACL mask enables the named user
            (ACL_TAG_OTHER, 0, u32::MAX),
        ]);
        assert_eq!(acl_has_broad_perms_from_bytes(&blob, 0o2), Some(false));
        assert_eq!(acl_has_broad_perms_from_bytes(&blob, 0o7), Some(false));
    }

    #[test]
    fn acl_parser_detects_broad_write() {
        let group_write = acl_blob(&[
            (TAG_USER_OBJ, 7, u32::MAX),
            (ACL_TAG_GROUP_OBJ, 2, u32::MAX),
            (ACL_TAG_OTHER, 0, u32::MAX),
        ]);
        assert_eq!(
            acl_has_broad_perms_from_bytes(&group_write, 0o2),
            Some(true)
        );

        let other_write = acl_blob(&[
            (TAG_USER_OBJ, 7, u32::MAX),
            (ACL_TAG_GROUP_OBJ, 0, u32::MAX),
            (ACL_TAG_OTHER, 6, u32::MAX),
        ]);
        assert_eq!(
            acl_has_broad_perms_from_bytes(&other_write, 0o2),
            Some(true)
        );

        let named_group = acl_blob(&[
            (TAG_USER_OBJ, 7, u32::MAX),
            (ACL_TAG_GROUP_OBJ, 0, u32::MAX),
            (ACL_TAG_GROUP, 2, 42),
            (TAG_MASK, 7, u32::MAX),
            (ACL_TAG_OTHER, 0, u32::MAX),
        ]);
        assert_eq!(
            acl_has_broad_perms_from_bytes(&named_group, 0o2),
            Some(true)
        );
    }

    #[test]
    fn acl_parser_detects_broad_read_and_execute() {
        let group_read = acl_blob(&[
            (TAG_USER_OBJ, 7, u32::MAX),
            (ACL_TAG_GROUP_OBJ, 4, u32::MAX),
            (ACL_TAG_OTHER, 0, u32::MAX),
        ]);
        assert_eq!(
            acl_has_broad_perms_from_bytes(&group_read, 0o2),
            Some(false)
        );
        assert_eq!(acl_has_broad_perms_from_bytes(&group_read, 0o7), Some(true));

        let other_execute = acl_blob(&[
            (TAG_USER_OBJ, 7, u32::MAX),
            (ACL_TAG_GROUP_OBJ, 0, u32::MAX),
            (ACL_TAG_OTHER, 1, u32::MAX),
        ]);
        assert_eq!(
            acl_has_broad_perms_from_bytes(&other_execute, 0o4),
            Some(false)
        );
        assert_eq!(
            acl_has_broad_perms_from_bytes(&other_execute, 0o1),
            Some(true)
        );
    }

    #[test]
    fn acl_parser_rejects_invalid_blobs() {
        assert_eq!(acl_has_broad_perms_from_bytes(&[], 0o2), None);
        assert_eq!(
            acl_has_broad_perms_from_bytes(&[2, 0, 0, 0], 0o2),
            Some(false)
        );
        assert_eq!(acl_has_broad_perms_from_bytes(&[1, 0, 0, 0], 0o2), None);
        assert_eq!(
            acl_has_broad_perms_from_bytes(&[2, 0, 0, 0, 1, 0], 0o2),
            None
        );
    }

    #[test]
    fn ensure_secure_dir_accepts_acl_masked_dir_and_preserves_acl() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().unwrap();
        let target = base.path().join("certs");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();

        let account = current_account().unwrap();
        let acl = [
            (TAG_USER_OBJ, 7, u32::MAX),
            (TAG_USER, 7, account.uid), // named user
            (ACL_TAG_GROUP_OBJ, 0, u32::MAX),
            (TAG_MASK, 7, u32::MAX), // mask makes stat report 0770
            (ACL_TAG_OTHER, 0, u32::MAX),
        ];
        if !set_access_acl(&target, &acl) {
            return; // filesystem without POSIX ACL support
        }
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o770
        );

        ensure_secure_dir(&target, 0o700, (account.uid, account.gid), &[account.uid]).unwrap();

        // The ACL mask survived: chmod was skipped, so named-user access was
        // not revoked.
        assert_eq!(acl_has_broad_perms(&target, 0o2), Some(false));
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o770
        );
    }

    #[test]
    fn ensure_secure_dir_rejects_acl_with_broad_write() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().unwrap();
        let target = base.path().join("certs");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o770)).unwrap();

        let account = current_account().unwrap();
        let acl = [
            (TAG_USER_OBJ, 7, u32::MAX),
            (TAG_USER, 7, account.uid),
            (ACL_TAG_GROUP_OBJ, 2, u32::MAX), // real group write
            (TAG_MASK, 7, u32::MAX),
            (ACL_TAG_OTHER, 0, u32::MAX),
        ];
        if !set_access_acl(&target, &acl) {
            return;
        }

        assert!(
            ensure_secure_dir(&target, 0o700, (account.uid, account.gid), &[account.uid]).is_err()
        );
    }

    #[test]
    fn effective_perms_owner_only_accepts_named_user_acl() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().unwrap();
        let target = base.path().join("certs");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();

        let account = current_account().unwrap();
        let acl = [
            (TAG_USER_OBJ, 7, u32::MAX),
            (TAG_USER, 5, account.uid), // named user: r-x
            (ACL_TAG_GROUP_OBJ, 0, u32::MAX),
            (TAG_MASK, 5, u32::MAX), // mask r-x => stat 0750
            (ACL_TAG_OTHER, 0, u32::MAX),
        ];
        if !set_access_acl(&target, &acl) {
            return; // filesystem without POSIX ACL support
        }
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750);

        assert!(effective_perms_are_owner_only(&target, mode, 0o077));
        assert!(effective_perms_are_owner_only(&target, mode, 0o022));
    }

    #[test]
    fn effective_perms_owner_only_rejects_broad_read() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().unwrap();
        let target = base.path().join("client-key.pem");
        std::fs::write(&target, b"x").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o400)).unwrap();

        let account = current_account().unwrap();
        let acl = [
            (TAG_USER_OBJ, 6, u32::MAX),
            (TAG_USER, 4, account.uid),
            (ACL_TAG_GROUP_OBJ, 0, u32::MAX),
            (TAG_MASK, 4, u32::MAX),
            (ACL_TAG_OTHER, 4, u32::MAX), // broad read
        ];
        if !set_access_acl(&target, &acl) {
            return;
        }
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert!(!effective_perms_are_owner_only(&target, mode, 0o077));
    }

    #[test]
    fn effective_perms_owner_only_rejects_clean_mode_without_acl() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert!(!effective_perms_are_owner_only(dir.path(), mode, 0o077));
    }

    #[test]
    fn haproxy_certs_dir_is_secure_accepts_named_user_acl() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().unwrap();
        let target = base.path().join("haproxy");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();

        let account = current_account().unwrap();
        let acl = [
            (TAG_USER_OBJ, 7, u32::MAX),
            (TAG_USER, 5, account.uid),
            (ACL_TAG_GROUP_OBJ, 0, u32::MAX),
            (TAG_MASK, 5, u32::MAX),
            (ACL_TAG_OTHER, 0, u32::MAX),
        ];
        if !set_access_acl(&target, &acl) {
            return;
        }
        assert!(haproxy_certs_dir_is_secure(&target));
    }

    #[test]
    fn haproxy_certs_dir_is_secure_rejects_group_write() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().unwrap();
        let target = base.path().join("haproxy");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o770)).unwrap();

        let account = current_account().unwrap();
        let acl = [
            (TAG_USER_OBJ, 7, u32::MAX),
            (TAG_USER, 7, account.uid),
            (ACL_TAG_GROUP_OBJ, 2, u32::MAX), // real group write
            (TAG_MASK, 7, u32::MAX),
            (ACL_TAG_OTHER, 0, u32::MAX),
        ];
        if !set_access_acl(&target, &acl) {
            return;
        }
        assert!(!haproxy_certs_dir_is_secure(&target));
    }

    // --- read_secure_file (TOCTOU-safe certificate reads) ---

    #[test]
    fn read_secure_file_reads_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, b"certificate").unwrap();
        assert_eq!(read_secure_file(&path, false).unwrap(), b"certificate");
    }

    #[test]
    fn read_secure_file_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.pem");
        std::fs::write(&real, b"secret").unwrap();
        let link = dir.path().join("client-key.pem");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = read_secure_file(&link, true).unwrap_err();
        assert!(format!("{err}").contains("symlink"), "{err}");
    }

    #[test]
    fn read_secure_file_rejects_directory() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_secure_file(dir.path(), false).unwrap_err();
        assert!(format!("{err}").contains("regular file"), "{err}");
    }

    #[test]
    fn read_secure_file_rejects_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_secure_file(&dir.path().join("missing.pem"), false).is_err());
    }

    #[test]
    fn read_secure_file_private_key_requires_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client-key.pem");
        std::fs::write(&path, b"key").unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_secure_file(&path, true).is_err());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_secure_file(&path, true).is_ok());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(read_secure_file(&path, true).is_ok());
    }

    #[test]
    fn read_secure_file_private_key_accepts_named_user_acl() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client-key.pem");
        std::fs::write(&path, b"key").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();

        let account = current_account().unwrap();
        let acl = [
            (TAG_USER_OBJ, 6, u32::MAX),
            (TAG_USER, 4, account.uid), // named user: r--
            (ACL_TAG_GROUP_OBJ, 0, u32::MAX),
            (TAG_MASK, 4, u32::MAX), // stat now reports 0440
            (ACL_TAG_OTHER, 0, u32::MAX),
        ];
        if !set_access_acl(&path, &acl) {
            return; // filesystem without POSIX ACL support
        }
        assert!(read_secure_file(&path, true).is_ok());
    }

    #[test]
    fn read_secure_file_accepts_public_cert_with_broad_read() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, b"ca").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_secure_file(&path, false).is_ok());
    }
}
