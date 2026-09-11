# Changelog

## [0.4.2] - 2026-09-11

### Fixed
- **SECURITY**: Centralize rune auth via tower AuthLayer middleware (was per-handler, could be forgotten)
- **SECURITY**: Add rune auth to 5 streaming RPCs (xpay_stream, invoice_watch, watch_channels, watch_peers, watch_system)
- **SECURITY**: Pass request params to check_rune for rune restriction enforcement (params=amount_msat<100000 now enforced)
- **SECURITY**: Pass nodeid to check_rune for rune ownership verification (rejects runes from other nodes)
- **SECURITY**: Add in-memory rate limiter fallback when Valkey is unavailable (prevents silent rate limit bypass)

### Added
- `AuthLayer` tower middleware: validates rune for ALL gRPC handlers at HTTP layer
- `InMemoryRateLimiter`: token bucket fallback (3 requests/hour per client_id) when Redis is down
- `extract_params_for_path()`: decode protobuf body and pass params to check_rune
- 77 unit tests (auth, auth_layer, rate_limiter, events, certs, router, security)
- Rune alteration verification tests (6 tests for HMAC validation)

### Changed
- Remove 99 lines of manual auth boilerplate from node_service.rs
- Remove dead code: `extract_rune_from_request` marked as `#[cfg(test)]`
- Specialize AuthLayer Service impl for `tonic::body::Body`

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
