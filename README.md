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

### Run

```bash
# As service user (recommended)
sudo -u gcob /usr/local/bin/gcob

# Or directly (development)
cargo run
```

### Sudoers Configuration

Add to `/etc/sudoers.d/gcob`:

```
user-admin ALL=(gcob) NOPASSWD: /usr/local/bin/gcob, /usr/bin/grpcurl
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

# Server
GRPC_BIND_ADDR=0.0.0.0:50003

# TLS
CERT_DIR=/etc/zapt81/certs
CA_FILE=ca.pem
CLIENT_FILE=client.pem
CLIENT_KEY_FILE=client-key.pem
SERVER_FILE=debian-knots.pem
SERVER_KEY_FILE=server-key.pem

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
