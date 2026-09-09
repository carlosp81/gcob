# Changelog

## [0.3.3] - 2026-09-09

### Added
- Auto-detection of hostname and IP for client certificates
- User-based access control (gcob user + root only)
- Sudoers configuration for gcob user (restricted commands)
- System-wide certificate storage at `/etc/gcob/certs/`
- `--no-confirm` flag for scripting and automation
- Minimal output (only 3 visible steps)

### Changed
- Removed `--owner` and `--output-dir` flags (always use system path)
- Enhanced security: restricted `cat` to specific files, removed `ls`

### Fixed
- Sudoers syntax errors with command arguments

## [0.3.2] - 2026-09-05

### Added
- CSR-based client certificates
- Certificate management commands
- Root detection for production security

## [0.3.1] - 2026-09-04

### Added
- Initial release with gRPC API for Core Lightning nodes
