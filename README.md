# Bakog (gcob)

Lightweight gRPC API for Core Lightning nodes with mTLS, rune authentication, and event streaming.

## Overview

Bakog is a high-performance, secure gRPC API designed for Core Lightning (CLN) node management. Built with Rust, it provides:

- **mTLS Security**: Double TLS encryption (client → API → CLN)
- **Rune Authentication**: Per-request authorization via CLN runes
- **Event Streaming**: Real-time payment, invoice, and channel events
- **Splicing Support**: Channel management with splice-in/splice-out operations

## Architecture

```
[Client] ──mTLS──▶ [Bakog API :50003] ──mTLS──▶ [HAProxy :50002] ──mTLS──▶ [CLN Node :50001]
```

## Quick Start

### Prerequisites

- Rust 1.75+
- Core Lightning v26.0.7 with gRPC plugin
- HAProxy with mTLS configuration
- Redis (optional, for rate limiting)

### Build

```bash
cargo build --release
```

### Deployment roles

Two binaries are built:

- **`gcob`** — server administration: `init`, `serve`, `sign`, `certs`.
- **`gcob-client`** — client hosts: `init` (CSR generation), `info`, `invoice`,
  `xpay`, `watch`.

Role resolution for `gcob`:

| `GCOB_ROLE` | Behavior |
|-------------|----------|
| unset / `auto` | `server` when `GRPC_BIND_ADDR` is set and `/etc/haproxy/certs` is a secure directory; otherwise `client` |
| `client` | `serve`, `sign` and `certs renew` are denied with a clear message |
| `server` | server commands allowed (use on hosts where auto-detection is inconclusive) |

`gcob init` is exempt because it is the bootstrap command. It provisions server
certificates and is server-only. Client CSR generation runs locally on the
client host:

```bash
gcob-client init --hostname client.example --ip 10.0.0.5
```

`gcob init` and `gcob-client init` share the common options `--force`,
`--no-confirm`, `--hostname` and `--ip`. Server-only options are exclusive to
`gcob init`.

### Server provisioning (gcob init)

Provisions HAProxy and API certificates from the CLN CA. Requires root (or
write access to `/etc/haproxy/certs`) and explicit flags:

```bash
sudo gcob init \
    --cln-dir /home/lightning/.lightning/bitcoin \
    --hostname node.example --ip 10.0.0.5
```

- `--cln-dir` is mandatory: it must contain `ca.pem` and `ca-key.pem`.
- The CA must be `CA:TRUE`, its private key must match, and its SHA-256
  fingerprint is pinned; changing it requires `--rotate-ca`.
- Existing files are never overwritten without `--force`.
- `--dry-run` validates and stages without writing anything.
- Outputs: HAProxy bundles (`root:haproxy`, 0640) and the API directory
  (`api-user`, keys 0600) including its own `client.pem`/`client-key.pem`.

### Sign client certificates (`gcob sign`)

Signs a CSR with the validated CLN CA. All flags are explicit; the output
directory is mandatory (never defaults to the service directory):

```bash
sudo gcob sign \
    --csr /tmp/client.csr \
    --hostname client.example \
    --cln-dir /home/lightning/.lightning/bitcoin \
    --output /tmp/signed
```

- `--cln-dir` must contain the `CA:TRUE` `ca.pem` and its matching `ca-key.pem`.
- `--expected-ca-fingerprint <HEX>` pins the signing CA (recommended in
  automated flows).
- Wildcards and invalid hostnames are rejected.
- The CSR must be a regular file ≤1 MiB (no symlinks).
- An existing `client.pem` requires `--force`; `--dry-run` stages and verifies
  without publishing.

### Renew API certificates (`gcob certs renew`)

```bash
sudo gcob certs renew \
    --cln-dir /home/lightning/.lightning/bitcoin \
    --api-user gcob
```

- Renewal verifies the new leaves against the **installed** `ca.pem`.
- If `~/.certs/ca.pem` is missing, `--init-ca` is required to install it.
- A CA whose fingerprint differs from the installed one requires `--rotate-ca`.
- Publication is atomic with backups (`.bak.<epoch>`) and rollback; existing
  files are always backed up before replacement.
- `--server-hostname`/`--server-ip` override the identity; otherwise the SANs of
  the current `server.pem` are reused and validated.

### Run

```bash
# As service user (recommended)
sudo -u gcob /usr/local/bin/gcob serve

# Or directly (development)
cargo run -- serve
```

### Sudoers Configuration

Add to `/etc/sudoers.d/gcob` (do **not** grant `grpcurl`: it bypasses the API
rune layer by talking to CLN directly with the service identity):

```
user-admin ALL=(gcob) NOPASSWD: /usr/local/bin/gcob
```

### Test with grpcurl

```bash
grpcurl \
    -proto proto/api/v1/cln/services.proto \
    -import-path proto/api/v1 \
    --servername debian-knots \
    -cacert /etc/zapt81/certs/ca.pem \
    -cert /etc/zapt81/certs/client.pem \
    -key /etc/zapt81/certs/client-key.pem \
    -H "x-rune: YOUR_RUNE" \
    -d '{}' \
    YOUR_SERVER_IP:50003 \
    cln.NodeServices/Getinfo | jq
```

## API Methods

| Method | Description | Auth |
|--------|-------------|------|
| `Getinfo` | Node information | Rune |
| `Invoice` | Create invoice | Rune + Rate Limit |
| `Xpay` | Pay BOLT11/BOLT12 | Rune |
| `XpayStream` | Pay with streaming events | Rune |
| `InvoiceWatch` | Watch invoice payments | Rune |
| `WatchChannels` | Channel state events | Rune |
| `WatchPeers` | Peer connect/disconnect | Rune |
| `WatchSystem` | System warnings | Rune |

## Event Streaming

Bakog supports real-time event streaming via gRPC server-side streaming:

```protobuf
rpc XpayStream(cln.XpayRequest) returns (stream cln.PaymentEvent);

message PaymentEvent {
    oneof event {
        PaymentInitiated initiated = 1;
        PaymentPartStarted part_started = 2;
        PaymentPartCompleted part_completed = 3;
        PaymentPartFailed part_failed = 4;
        PaymentSucceeded succeeded = 5;
        PaymentFailed failed = 6;
    }
    string payment_hash = 10;
    uint64 timestamp = 11;
}
```

## Security

### mTLS Configuration

- **Client certificates**: Signed by CLN Root CA
- **Server certificates**: With SANs (DNS:debian-knots, IP:YOUR_SERVER_IP) — `debian-knots` is the server hostname
- **Certificate validation**: Mutual TLS on all connections

### Rune Authentication

Every request must include a valid CLN rune:

```bash
# Header
x-rune: EqX...A0

# Or via JWT (future)
Authorization: Bearer <jwt_token>
```

### Security Filtering

Event streaming automatically filters sensitive data:
- `preimage` excluded from invoice events
- `node_id` truncated to first 8 bytes
- `erroronion` and `raw_message` never exposed

## Project Structure

```
gcob/
├── src/
│   ├── main.rs                 # Entry point
│   ├── grpc/
│   │   ├── server.rs           # Server bootstrap
│   │   ├── node_service.rs     # gRPC service implementation
│   │   └── interceptors/       # Auth, rate limiting
│   ├── domain/
│   │   ├── invoice/            # Invoice + Xpay
│   │   ├── channel/            # Channel management
│   │   ├── peer/               # Peer management
│   │   └── info/               # Node information
│   ├── events/
│   │   ├── router.rs           # Event dispatch
│   │   ├── security.rs         # Data sanitization
│   │   ├── enricher.rs         # Recommendations
│   │   └── subscribers/        # CLN stream subscriptions
│   ├── cln/
│   │   ├── client.rs           # CLN gRPC client
│   │   └── cln_api/            # Generated protobuf code
│   ├── certs/
│   │   └── mtls_certs.rs       # TLS configuration
│   └── infra/
│       └── valkey.rs           # Redis connection
├── proto/
│   └── api/v1/cln/
│       ├── services.proto      # API service definition
│       ├── events.proto        # Event types
│       └── node.proto          # CLN types
├── Cargo.toml
└── build.rs
```

## Configuration

### Environment Variables

```env
# CLN Connection
CLN_NODE_URI=https://YOUR_SERVER_IP:50002
CLN_HOSTNAME=your-node

# Server
GRPC_BIND_ADDR=0.0.0.0:50003

# TLS (CLN_CERT_DIR defaults to the admin account's ~/.certs)
# CLN_CERT_DIR=/home/<admin>/.certs
CLN_CA_FILE=ca.pem
CLN_CLIENT_FILE=client.pem
CLN_CLIENT_KEY_FILE=client-key.pem
SERVER_CERT_FILE=server.pem
SERVER_KEY_FILE=server-key.pem

# Client (gcob-client): --ca/--cert/--key override CLN_CERT_DIR; when none of
# them is set, the admin account's ~/.certs directory is used.

# Redis (optional)
REDIS_URL=redis://127.0.0.1:6379
```

## Development

### Commands

```bash
# Build
cargo build

# Run
cargo run

# Test
cargo test

# Lint
cargo clippy --all-targets -- -D warnings

# Format
cargo fmt
```

### Proto Generation

Protobuf files are compiled automatically on build:

```bash
cargo build  # Runs build.rs
```

## Roadmap

- [x] mTLS authentication
- [x] Rune validation
- [x] Basic RPCs (Invoice, Getinfo, Xpay)
- [x] Event streaming (Phase 2)
- [ ] Splicing support (Phase 3)
- [ ] Channel dashboard (Phase 3)

## License

MIT OR Apache-2.0
