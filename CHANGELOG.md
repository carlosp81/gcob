# Changelog

## [Unreleased]

### Changed
- `EventRouter` dispatch is non-blocking: senders are snapshotted under a
  short read lock, delivery uses `try_send`, and dead or persistently slow
  subscribers are unsubscribed after `GCOB_SLOW_SUBSCRIBER_MAX_DROPS`
  consecutive drops (GCOB-005/006)

## [0.5.3] - 2026-09-12

Admission control hardened: certificate-bound rate limiting, a cheap
pre-auth budget and bounded request bodies.

### Added
- `ClientIdentity` derived from the mTLS leaf certificate (SHA-256
  fingerprint) and `ClientIdentityLayer`, the new outermost layer; requests
  without a client certificate are rejected before any other processing
- `AdmissionLayer`: per-fingerprint budget checked before `check_rune`, so
  invalid runes no longer amplify backend load (GCOB-003)
- `Limits` (`src/grpc/limits.rs`): environment-configurable availability
  limits with validated defaults; zero or invalid values fail startup
- Bounded body reads in `AuthLayer` (`GCOB_MAX_REQUEST_BODY_BYTES`) plus
  `max_decoding_message_size` on the service (GCOB-007)
- HTTP/2 transport limits: `max_concurrent_streams`,
  `concurrency_limit_per_connection`, pending-accept-reset streams and
  TCP/HTTP2 keepalive (GCOB-008, partial)
- Structured rejection and audit logs with fingerprint, claimed client id,
  remote address, path and latency
- CI workflow (fmt, clippy `-D warnings`, tests) and
  `security/availability-baseline.md`

### Changed
- Per-method rate limiting is keyed by certificate fingerprint instead of the
  spoofable `x-client-id` header (GCOB-001); the header is optional audit
  metadata and clients that omit it are no longer rejected
- `AuthLayer::new` receives the body limit; body read errors no longer expose
  upstream details

### Fixed
- Rate-limit and body-size rejections are logged as such instead of the
  misleading "Auth rejected" message

## [0.5.2] - 2026-09-11

Per-method rate limiting, ACL-aware certificate validation and error hardening.

### Added
- `RateLimitLayer` (tower, HTTP layer) with independent per-method budgets:
  `invoice`/`xpay` 3/hour, `getinfo` 60/hour and stream subscriptions 12/hour
  per `x-client-id`; Redis primary with in-memory token-bucket fallback

### Changed
- Rate limiting now covers `xpay`, `getinfo` and the five watch RPCs (it was
  only `invoice`/`invoice_stream`); limited methods require `x-client-id`
- `gcob-client info` and `gcob-client watch` now send `x-client-id`
- Certificate lookup defaults to the admin account's `~/.certs`: `CLN_CERT_DIR`
  may be omitted for `gcob serve`, and `gcob-client` resolves `ca.pem`,
  `client.pem` and `client-key.pem` there when no `--ca/--cert/--key` or
  `CLN_CERT_DIR` is given (the CWD-relative `certs/` fallback is gone)

### Fixed
- Auth middleware returns a proper `Unauthenticated` gRPC status for rejected
  runes (invalid or blacklisted) instead of resetting the HTTP/2 stream, which
  the client surfaced as `h2 protocol error ... INTERNAL_ERROR`
- `gcob-client` help no longer prints the current `GCOD_*` environment values:
  a rune or client id loaded from the trusted env file is not leaked into
  terminals or logs
- Server startup validation and host-role detection now accept POSIX ACL
  named-user grants (e.g. `gcob`) and reject only broad group/other
  permissions, so an ACL-hardened certificate directory no longer breaks
  `gcob serve` (`ClnConfig::validate_all`, `is_server_env`)
- Remote gRPC clients no longer receive upstream CLN error details: `Getinfo`,
  `Invoice`, `Xpay` and `XpayStreamWatch` return a generic `Internal error` and
  log the cause locally
- Certificate configuration errors no longer expose filesystem paths,
  permissions or the service user; details are logged with `tracing::error!`

### Removed
- Dead code: unused `handle_certs` stub, `ClnSourcePaths.server_key_file`,
  the `infra`/`valkey` module, `inspect::is_valid`, `inspect::verify_chain`,
  unread `ChainResult` fields and stale `#[allow(dead_code)]` markers

## [0.5.1] - 2026-09-11

Server-only `gcob init`, shared init flags and an ACL-safe certificate
directory check.

### Added
- Shared `gcob::init_common::CommonInitArgs`: `--force`, `--no-confirm`,
  `--hostname` and `--ip` defined once for `gcob init` and `gcob-client init`
- `gcob::client_init::run_cli`: single client-init UI (summary, confirmation
  and next steps); the `gcob-client` binary delegates to it

### Changed
- `gcob init` is server-only and requires `--cln-dir`; it no longer accepts
  `--client`/`--server` mode flags
- `gcob-client init` is the only client CSR entry point; its flags are renamed
  to the shared `--hostname`/`--ip`
- `gcob init --client` removed (deprecated in 0.5.0)
- Mode-specific `init` help is now rendered natively by clap

### Fixed
- `ensure_secure_dir` no longer rejects certificate directories hardened with a
  POSIX ACL (e.g. named-user access for `gcob`): the ACL mask was read as group
  write, and normalizing the mode would have reset it; the ACL is now detected
  and preserved

## [0.5.0] - 2026-09-11

Client/server role separation.

### Added
- `gcob-client init`: local CSR generation (`--client-hostname`, `--client-ip`,
  `--output`, `--force`, `--no-confirm`) without certificates or a server
  connection
- `GCOB_ROLE=client|server|auto` for the `gcob` administration CLI; `auto` uses
  `GRPC_BIND_ADDR` plus a secure `/etc/haproxy/certs`
- Server-only commands (`serve`, `sign`, `certs renew`) are denied in client
  role with an actionable message
- `gcob-client init --help` shows only the local CSR options

### Changed
- `gcob` is server-only: client flags are hidden from `init --help`
- `gcob init --client` is deprecated (still functional) in favor of
  `gcob-client init`
- `gcob-client` help now identifies itself as `gcob-client`
- Client CSR generation moved to the shared library (`gcob::client_init`)

## [0.4.3] - 2026-09-11

Security hardening across the CLI, `init --server`, `sign` and `certs renew`.

### Fixed
- **SECURITY**: `sign_csr` now rebuilds subject/SAN/EKU/basicConstraints/validity from `--hostname` and uses only the CSR public key (previous behavior could copy CA:TRUE/keyCertSign or foreign SANs from the CSR)
- **SECURITY**: `init --server`, `sign` and `renew` load the CLN CA via `load_validated_ca` (symlink/permission checks, CA:TRUE, key↔cert match, SHA-256 fingerprint, zeroized key material) from an explicit `--cln-dir`
- **SECURITY**: CA fingerprint pinning; changing an installed CA requires `--rotate-ca`, installing a missing one requires `--init-ca`
- **SECURITY**: Certificate issuance validates hostnames (no wildcards/control chars) and IPs (unicast only); `sign --output` and `--cln-dir` are explicit
- **SECURITY**: `certs verify` performs real signature verification and exact SAN matching, and no longer relies on `$HOME`
- **SECURITY**: `.env` is loaded only from trusted absolute paths (`GCOB_ENV_FILE` / `/etc/gcob/gcob.env`); the API server validates the gcob account by real UID instead of `$USER`
- **SECURITY**: The CLI verifies the requested TLS hostname; unsafe CA key copies and the `/tmp/gcob_certs` staging path were removed
- **SECURITY**: Client hardening: safe gRPC metadata handling, UTF-8-safe truncation, control-character sanitization, integer-only amount parsing and connection/keepalive timeouts

### Added
- `gcob init --server` flags: `--cln-dir`, `--haproxy-user`, `--api-user`, `--haproxy-cert-dir`, `--api-certs-dir`, `--rotate-ca`, `--allow-loopback`, `--dry-run`
- `gcob sign` flags: `--cln-dir` and `--output` (required), `--force`, `--dry-run`, `--expected-ca-fingerprint`
- `gcob certs renew` flags: `--cln-dir`, `--init-ca`, `--rotate-ca`, `--api-user`, `--allow-loopback`, `--dry-run`
- Atomic publication with `.bak.<epoch>` backups, rollback and `flock` for init/sign/renew
- Mode-specific help: `gcob init --client|--server --help`
- Independent API client certificate for the API→CLN connection
- 166 unit tests (CLI, PKI, config, init/sign/renew)

### Changed
- `gcob init --server` publishes HAProxy material as `root:haproxy` (0640) and API material owned by `--api-user` (keys 0600)
- Legacy `setup_certs.sh` flow deprecated (replacement: `gcob init --server`)
- `read_cln_ca` and `ClnSourcePaths::default_home` removed

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
