pub mod certs;
pub mod server;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "gcob",
    version,
    about = "Lightweight gRPC API for Core Lightning nodes"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize certificates and configuration
    Init {
        /// Generate CSR for external client (no CA needed)
        #[arg(long, conflicts_with = "server")]
        client: bool,

        /// Generate server certificates for HAProxy mTLS
        #[arg(long, conflicts_with = "client")]
        server: bool,

        /// Output directory for client certs
        /// Default: ~/.gcob/certs (requires writable home)
        /// For system accounts: use --output-dir /var/lib/gcob/certs
        #[arg(long)]
        output_dir: Option<PathBuf>,

        /// Chown certs to this user after creation
        /// Requires root. Example: --owner gcob
        #[arg(long)]
        owner: Option<String>,

        /// Overwrite existing CSR/key files
        #[arg(long)]
        force: bool,

        /// External client hostname (overrides CLIENT_HOSTNAME env var)
        #[arg(long)]
        client_hostname: Option<String>,

        /// External client IP for SAN (overrides CLIENT_IP env var)
        #[arg(long)]
        client_ip: Option<String>,
    },

    /// Start the gRPC API server
    Serve,

    /// Sign a client CSR with the CA
    Sign {
        /// Path to client CSR file
        #[arg(long)]
        csr: PathBuf,

        /// Hostname for the client certificate
        #[arg(long)]
        hostname: String,

        /// Output directory for signed certificate (default: ~/.gcob/certs)
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Manage mTLS certificates
    Certs {
        /// Certificate directory (default: ~/.gcob/certs)
        #[arg(long)]
        dir: Option<PathBuf>,

        #[command(subcommand)]
        command: Option<CertsCommand>,
    },
}

#[derive(Subcommand)]
pub enum CertsCommand {
    /// Show detailed certificate information
    Show {
        /// Path to certificate file
        #[arg(long)]
        cert: Option<PathBuf>,
    },

    /// Verify chain of trust and SANs
    Verify {
        /// Expected hostname for SAN validation
        #[arg(long)]
        hostname: Option<String>,
    },

    /// Renew all certificates
    Renew {
        /// Force renewal even if not expired
        #[arg(long)]
        force: bool,
    },
}
