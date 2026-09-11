//! Shared atomic publication of staged files.
//!
//! Used by `init --server`, `certs renew` and `sign`: staging happens in the
//! destination filesystem, modes/owners are applied before publication, existing
//! files are backed up as `<name>.bak.<epoch>` and any failure rolls the whole
//! set back to its previous state.

use std::fs;
use std::path::{Path, PathBuf};

use crate::certs::generate::CertError;

/// A file that was (or would be) published, for reporting.
#[derive(Debug)]
pub struct PublishedFile {
    pub path: PathBuf,
    pub mode: u32,
    pub fingerprint: Option<String>,
}

/// A file to publish: staged source, final target, mode, owner and optional
/// certificate fingerprint for reporting.
pub struct PlannedFile {
    pub staged: PathBuf,
    pub target: PathBuf,
    pub mode: u32,
    pub owner: (u32, u32),
    pub fingerprint: Option<String>,
}

/// Publish staged files with per-file backups and full rollback on failure.
///
/// Returns the list of backup files created (kept on disk for recovery).
pub fn publish_files(plan: &[PlannedFile]) -> Result<Vec<PathBuf>, CertError> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut backups: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut published: Vec<PathBuf> = Vec::new();

    for file in plan {
        if file.target.exists() {
            let backup = backup_path(&file.target, stamp);
            if let Err(e) = fs::rename(&file.target, &backup) {
                rollback(&published, &backups);
                return Err(CertError::Io(e));
            }
            backups.push((file.target.clone(), backup));
        }

        if let Err(e) = fs::rename(&file.staged, &file.target) {
            rollback(&published, &backups);
            return Err(CertError::Io(e));
        }
        published.push(file.target.clone());
    }

    Ok(backups.into_iter().map(|(_, backup)| backup).collect())
}

fn backup_path(target: &Path, stamp: u64) -> PathBuf {
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    target.with_file_name(format!("{}.bak.{}", name, stamp))
}

fn rollback(published: &[PathBuf], backups: &[(PathBuf, PathBuf)]) {
    for target in published.iter().rev() {
        let _ = fs::remove_file(target);
    }
    for (target, backup) in backups.iter().rev() {
        let _ = fs::rename(backup, target);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    #[test]
    fn publish_files_restores_backups_on_failure() {
        let dir = temp_dir();
        let target1 = dir.path().join("first.pem");
        fs::write(&target1, b"old").unwrap();

        let staged1 = dir.path().join("staged1.pem");
        fs::write(&staged1, b"new").unwrap();

        let staged2 = dir.path().join("staged2.pem");
        fs::write(&staged2, b"new2").unwrap();
        let target2 = dir.path().join("missing-dir/second.pem");

        let plan = vec![
            PlannedFile {
                staged: staged1,
                target: target1.clone(),
                mode: 0o600,
                owner: (0, 0),
                fingerprint: None,
            },
            PlannedFile {
                staged: staged2,
                target: target2,
                mode: 0o600,
                owner: (0, 0),
                fingerprint: None,
            },
        ];

        assert!(publish_files(&plan).is_err());
        // First target restored to its previous content.
        assert_eq!(fs::read(&target1).unwrap(), b"old");
    }

    #[test]
    fn publish_files_replaces_and_creates_backups() {
        let dir = temp_dir();
        let target = dir.path().join("cert.pem");
        fs::write(&target, b"old").unwrap();

        let staged = dir.path().join("staged.pem");
        fs::write(&staged, b"new").unwrap();

        let plan = vec![PlannedFile {
            staged,
            target: target.clone(),
            mode: 0o600,
            owner: (0, 0),
            fingerprint: Some("abc".to_string()),
        }];

        let backups = publish_files(&plan).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert_eq!(backups.len(), 1);
        assert!(backups[0].exists());
        assert_eq!(fs::read(&backups[0]).unwrap(), b"old");
    }
}
