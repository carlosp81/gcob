//! Atomic, fail-closed provisioning for `gcob init --server`.
//!
//! Security invariants:
//! 1. Nothing is published until CA, identity, pinning, destinations, staging
//!    and post-generation verification all succeed.
//! 2. No symlinked path component is ever followed for writes.
//! 3. Files are staged in the destination filesystem and published with
//!    `rename`, keeping mode/owner set before any content is visible.
//! 4. Existing material is backed up and restored on any failure.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use crate::certs::generate::{self, CertError};
use crate::certs::paths::{
    account_by_name, detect_admin_account, ensure_secure_dir, lock_dir, ClnSourcePaths, ServerPaths,
};

use super::atomic::{publish_files, PlannedFile, PublishedFile};

/// Fully resolved request for a server provisioning run.
pub struct InitServerRequest {
    pub cln_dir: PathBuf,
    pub hostname: String,
    pub ip: String,
    pub haproxy_cert_dir: PathBuf,
    pub api_certs_dir: PathBuf,
    pub haproxy_user: String,
    pub api_user: String,
    pub force: bool,
    pub rotate_ca: bool,
    pub dry_run: bool,
    /// Test/CI override for the owner of HAProxy material (default root:haproxy).
    pub haproxy_owner: Option<(u32, u32)>,
    /// Test/CI override for the owner of API material (default api user).
    pub api_owner: Option<(u32, u32)>,
}

/// Result of a provisioning run.
#[derive(Debug)]
pub struct ProvisionSummary {
    pub ca_fingerprint: String,
    pub files: Vec<PublishedFile>,
}

#[cfg(unix)]
fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

/// Provision HAProxy and API certificates from a validated CLN CA.
pub fn provision_server(
    req: &InitServerRequest,
    confirm: &mut dyn FnMut(&str) -> bool,
) -> Result<ProvisionSummary, CertError> {
    let haproxy = account_by_name(&req.haproxy_user)?;
    let api = account_by_name(&req.api_user)?;
    let euid = current_uid();

    let haproxy_owner = req.haproxy_owner.unwrap_or((0, haproxy.gid));
    let api_owner = req.api_owner.unwrap_or((api.uid, api.gid));

    // --- CA source (symlinks, permissions, CA:TRUE, key match, fingerprint) ---
    let source = ClnSourcePaths::new(req.cln_dir.clone());
    let validated = generate::load_validated_ca(&source)?;

    let server_paths = ServerPaths::new(req.haproxy_cert_dir.clone());

    // --- Directories: no symlinks, no group/other writable, service owners ---
    ensure_secure_dir(
        &server_paths.haproxy_cert_dir,
        0o750,
        haproxy_owner,
        &[0, euid, haproxy_owner.0],
    )?;
    ensure_secure_dir(
        &server_paths.haproxy_ca_dir,
        0o750,
        haproxy_owner,
        &[0, euid, haproxy_owner.0],
    )?;

    let mut allowed_api_owners = vec![0, euid, api_owner.0];
    if let Ok(admin) = detect_admin_account() {
        allowed_api_owners.push(admin.uid);
    }
    ensure_secure_dir(&req.api_certs_dir, 0o700, api_owner, &allowed_api_owners)?;

    // --- CA pinning: refuse silent trust-anchor changes ---
    for existing_ca in [
        server_paths.ca_file.clone(),
        req.api_certs_dir.join("ca.pem"),
    ] {
        if existing_ca.exists() {
            let existing_fp = generate::cert_fingerprint(&existing_ca)?;
            if existing_fp != validated.fingerprint_sha256 && !req.rotate_ca {
                return Err(CertError::Parse(format!(
                    "Existing CA {} has a different fingerprint ({}); pass --rotate-ca to replace it",
                    existing_ca.display(),
                    existing_fp
                )));
            }
        }
    }

    // --- Exclusive lock against concurrent provisioning ---
    let _lock = lock_dir(&server_paths.haproxy_cert_dir)?;

    // --- Stage in the same filesystem as each destination ---
    let haproxy_stage = tempfile::Builder::new()
        .prefix(".gcob-stage-")
        .tempdir_in(&server_paths.haproxy_cert_dir)?;
    let api_stage = tempfile::Builder::new()
        .prefix(".gcob-stage-")
        .tempdir_in(&req.api_certs_dir)?;

    generate::generate_server_cert(
        &validated.issuer,
        &req.hostname,
        &req.ip,
        haproxy_stage.path(),
    )?;
    generate::generate_client_cert(&validated.issuer, &req.hostname, haproxy_stage.path())?;
    generate::generate_client_cert(&validated.issuer, &req.hostname, api_stage.path())?;

    let server_concat = haproxy_stage.path().join("server_concat.pem");
    generate::concat_cert_key(
        &haproxy_stage.path().join("server.pem"),
        &haproxy_stage.path().join("server-key.pem"),
        &server_concat,
    )?;
    let client_concat = haproxy_stage.path().join("client_concat.pem");
    generate::concat_cert_key(
        &haproxy_stage.path().join("client.pem"),
        &haproxy_stage.path().join("client-key.pem"),
        &client_concat,
    )?;

    let haproxy_ca_pem = haproxy_stage.path().join("ca.pem");
    generate::write_atomic_owned(
        &haproxy_ca_pem,
        validated.ca_pem.as_bytes(),
        0o644,
        haproxy_owner,
    )?;
    let api_ca_pem = api_stage.path().join("ca.pem");
    generate::write_atomic_owned(&api_ca_pem, validated.ca_pem.as_bytes(), 0o644, api_owner)?;

    let api_server = api_stage.path().join("server.pem");
    let api_server_key = api_stage.path().join("server-key.pem");
    fs::copy(haproxy_stage.path().join("server.pem"), &api_server)?;
    fs::copy(haproxy_stage.path().join("server-key.pem"), &api_server_key)?;

    // --- Post-generation verification before anything is published ---
    let server_sans: BTreeSet<String> = [
        generate::san_token(&req.hostname),
        generate::san_token(&req.ip),
    ]
    .into_iter()
    .collect();
    let client_sans: BTreeSet<String> = [generate::san_token(&req.hostname)].into_iter().collect();

    generate::verify_issued_cert(
        &haproxy_stage.path().join("server.pem"),
        &haproxy_stage.path().join("server-key.pem"),
        &haproxy_ca_pem,
        &server_sans,
        true,
    )?;
    generate::verify_issued_cert(
        &haproxy_stage.path().join("client.pem"),
        &haproxy_stage.path().join("client-key.pem"),
        &haproxy_ca_pem,
        &client_sans,
        false,
    )?;
    generate::verify_issued_cert(
        &api_stage.path().join("client.pem"),
        &api_stage.path().join("client-key.pem"),
        &api_ca_pem,
        &client_sans,
        false,
    )?;

    let plan = vec![
        PlannedFile {
            staged: haproxy_ca_pem,
            target: server_paths.ca_file.clone(),
            mode: 0o644,
            owner: haproxy_owner,
            fingerprint: Some(validated.fingerprint_sha256.clone()),
        },
        PlannedFile {
            staged: server_concat,
            target: server_paths.server_concat_file.clone(),
            mode: 0o640,
            owner: haproxy_owner,
            fingerprint: Some(generate::cert_fingerprint(
                &haproxy_stage.path().join("server.pem"),
            )?),
        },
        PlannedFile {
            staged: client_concat,
            target: server_paths.client_concat_file.clone(),
            mode: 0o640,
            owner: haproxy_owner,
            fingerprint: Some(generate::cert_fingerprint(
                &haproxy_stage.path().join("client.pem"),
            )?),
        },
        PlannedFile {
            staged: api_ca_pem,
            target: req.api_certs_dir.join("ca.pem"),
            mode: 0o644,
            owner: api_owner,
            fingerprint: Some(validated.fingerprint_sha256.clone()),
        },
        PlannedFile {
            staged: api_server,
            target: req.api_certs_dir.join("server.pem"),
            mode: 0o644,
            owner: api_owner,
            fingerprint: Some(generate::cert_fingerprint(
                &haproxy_stage.path().join("server.pem"),
            )?),
        },
        PlannedFile {
            staged: api_server_key,
            target: req.api_certs_dir.join("server-key.pem"),
            mode: 0o600,
            owner: api_owner,
            fingerprint: None,
        },
        PlannedFile {
            staged: api_stage.path().join("client.pem"),
            target: req.api_certs_dir.join("client.pem"),
            mode: 0o644,
            owner: api_owner,
            fingerprint: Some(generate::cert_fingerprint(
                &api_stage.path().join("client.pem"),
            )?),
        },
        PlannedFile {
            staged: api_stage.path().join("client-key.pem"),
            target: req.api_certs_dir.join("client-key.pem"),
            mode: 0o600,
            owner: api_owner,
            fingerprint: None,
        },
    ];

    for file in &plan {
        generate::apply_owner_mode(&file.staged, file.mode, file.owner)?;
    }

    if !req.force {
        if let Some(existing) = plan.iter().find(|file| file.target.exists()) {
            return Err(CertError::Io(std::io::Error::other(format!(
                "Target already exists: {} (pass --force to overwrite)",
                existing.target.display()
            ))));
        }
    }

    let mut summary_text = format!(
        "=== gcob init --server ===\n  Hostname:       {}\n  IP:             {}\n  CA fingerprint: {}\n",
        req.hostname, req.ip, validated.fingerprint_sha256
    );
    for file in &plan {
        summary_text.push_str(&format!(
            "  {} (mode {:04o})\n",
            file.target.display(),
            file.mode
        ));
    }

    if req.dry_run {
        return Ok(build_summary(&validated.fingerprint_sha256, &plan));
    }

    if !confirm(&summary_text) {
        return Err(CertError::Io(std::io::Error::other("Aborted by user")));
    }

    publish_files(&plan)?;

    Ok(build_summary(&validated.fingerprint_sha256, &plan))
}

fn build_summary(ca_fingerprint: &str, plan: &[PlannedFile]) -> ProvisionSummary {
    ProvisionSummary {
        ca_fingerprint: ca_fingerprint.to_string(),
        files: plan
            .iter()
            .map(|file| PublishedFile {
                path: file.target.clone(),
                mode: file.mode,
                fingerprint: file.fingerprint.clone(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::paths::current_account;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    use std::path::Path;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    fn write_ca(dir: &Path) -> (PathBuf, PathBuf) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        }

        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "gcob-ca");
        let cert = params.self_signed(&key).unwrap();

        let ca_path = dir.join("ca.pem");
        let key_path = dir.join("ca-key.pem");
        fs::write(&ca_path, cert.pem()).unwrap();
        fs::write(&key_path, key.serialize_pem()).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        (ca_path, key_path)
    }

    fn request(cln_dir: &Path, haproxy_dir: &Path, api_dir: &Path) -> InitServerRequest {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for dir in [haproxy_dir, api_dir] {
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }

        let me = current_account().unwrap();
        InitServerRequest {
            cln_dir: cln_dir.to_path_buf(),
            hostname: "node.example".to_string(),
            ip: "10.0.0.5".to_string(),
            haproxy_cert_dir: haproxy_dir.to_path_buf(),
            api_certs_dir: api_dir.to_path_buf(),
            haproxy_user: me.name.clone(),
            api_user: me.name.clone(),
            force: false,
            rotate_ca: false,
            dry_run: false,
            haproxy_owner: Some((me.uid, me.gid)),
            api_owner: Some((me.uid, me.gid)),
        }
    }

    fn confirm_yes(_: &str) -> bool {
        true
    }

    #[test]
    fn provision_publishes_complete_consistent_material() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let ca_dir = temp_dir();
            let haproxy_dir = temp_dir();
            let api_dir = temp_dir();
            write_ca(ca_dir.path());

            let req = request(ca_dir.path(), haproxy_dir.path(), api_dir.path());
            let mut confirm = confirm_yes;
            let summary = provision_server(&req, &mut confirm).unwrap();

            assert_eq!(summary.ca_fingerprint.len(), 64);
            assert_eq!(summary.files.len(), 8);

            for name in [
                "ca.pem",
                "server.pem",
                "server-key.pem",
                "client.pem",
                "client-key.pem",
            ] {
                assert!(api_dir.path().join(name).exists(), "missing {name}");
            }
            for name in [
                "ca-certs/ca.pem",
                "cert_server_concat.pem",
                "cert_client_concat.pem",
            ] {
                assert!(haproxy_dir.path().join(name).exists(), "missing {name}");
            }

            // Server and API client keys must be different keypairs.
            let server_key = fs::read_to_string(api_dir.path().join("server-key.pem")).unwrap();
            let client_key = fs::read_to_string(api_dir.path().join("client-key.pem")).unwrap();
            assert_ne!(server_key, client_key);

            // Bundle modes are owner+group read only.
            let mode = fs::metadata(haproxy_dir.path().join("cert_server_concat.pem"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o640);
        }
    }

    #[test]
    fn provision_rejects_ca_change_without_rotate() {
        let ca1 = temp_dir();
        let haproxy_dir = temp_dir();
        let api_dir = temp_dir();
        write_ca(ca1.path());

        // First run installs CA1.
        let req = request(ca1.path(), haproxy_dir.path(), api_dir.path());
        let mut confirm = confirm_yes;
        provision_server(&req, &mut confirm).unwrap();

        // Second run with a different CA must abort without --rotate-ca.
        let ca2 = temp_dir();
        write_ca(ca2.path());
        let mut req2 = request(ca2.path(), haproxy_dir.path(), api_dir.path());
        req2.force = true;
        let err = provision_server(&req2, &mut confirm).unwrap_err();
        assert!(format!("{}", err).contains("--rotate-ca"), "{err}");

        // With --rotate-ca it proceeds.
        req2.rotate_ca = true;
        provision_server(&req2, &mut confirm).unwrap();
    }

    #[test]
    fn provision_requires_force_for_existing_targets() {
        let ca_dir = temp_dir();
        let haproxy_dir = temp_dir();
        let api_dir = temp_dir();
        write_ca(ca_dir.path());

        let req = request(ca_dir.path(), haproxy_dir.path(), api_dir.path());
        let mut confirm = confirm_yes;
        provision_server(&req, &mut confirm).unwrap();

        let err = provision_server(&req, &mut confirm).unwrap_err();
        assert!(format!("{}", err).contains("--force"), "{err}");
    }

    #[test]
    fn provision_dry_run_publishes_nothing() {
        let ca_dir = temp_dir();
        let haproxy_dir = temp_dir();
        let api_dir = temp_dir();
        write_ca(ca_dir.path());

        let mut req = request(ca_dir.path(), haproxy_dir.path(), api_dir.path());
        req.dry_run = true;
        let mut confirm = |_: &str| false; // must not be called in dry-run
        let summary = provision_server(&req, &mut confirm).unwrap();

        assert_eq!(summary.files.len(), 8);
        assert!(!api_dir.path().join("server.pem").exists());
        assert!(!haproxy_dir.path().join("cert_server_concat.pem").exists());
    }

    #[test]
    fn provision_rejects_symlinked_haproxy_dir() {
        let ca_dir = temp_dir();
        let api_dir = temp_dir();
        write_ca(ca_dir.path());

        let real = temp_dir();
        let link_base = temp_dir();
        let link = link_base.path().join("haproxy");
        std::os::unix::fs::symlink(real.path(), &link).unwrap();

        let req = request(ca_dir.path(), &link, api_dir.path());
        let mut confirm = confirm_yes;
        assert!(provision_server(&req, &mut confirm).is_err());
    }
}
