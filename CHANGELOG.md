# Changelog

## [0.4.1] - 2026-09-10

### Fixed
- Add missing `x-rune` header to `info` command (was causing authentication failure)
- Add missing `x-client-id` header to `invoice` and `xpay` commands (required by server rate limiter)

### Added
- `--client-id` / `GCOD_CLIENT_ID` global CLI argument for rate limiting identification
- `--expiry` / `-e` CLI argument for invoice command (invoice expiry in seconds)
- `expiry` field in `InvoiceCreated` proto message
- Expiry display in invoice command output

## [0.3.5] - 2026-09-10

### Changed
- Remove CA key copy to ~/.certs/ (reduce attack surface)
- Eliminate dead code: generate_api_server_cert, *_api_* fields, setup_gcob_sudoers
- Simplify verify_api_section (only verifies ca.pem)
- Fix .env.server.example naming consistency (server-api.pem → server.pem)

## [0.3.4] - 2026-09-09

### Changed
- Restructure gcob certs with role-based listing and user restrictions
- Enhanced gcob init client with auto-detection, user restrictions
- Enhanced gcob certs verify with client/server mode detection

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
