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

        /// Overwrite existing CSR/key files
        #[arg(long)]
        force: bool,

        /// Hostname for client certificate (auto-detected if not specified)
        #[arg(long)]
        client_hostname: Option<String>,

        /// IP address for client certificate SAN (auto-detected if not specified)
        #[arg(long)]
        client_ip: Option<String>,

        /// Hostname for server certificate (auto-detected if not specified)
        #[arg(long, conflicts_with = "client")]
        server_hostname: Option<String>,

        /// IP address for server certificate SAN (auto-detected if not specified)
        #[arg(long, conflicts_with = "client")]
        server_ip: Option<String>,

        /// Skip confirmation prompt (for scripting)
        #[arg(long)]
        no_confirm: bool,
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
    /// List certificate status with expiry information
    List {
        /// Show server certificates (HAProxy + CLN)
        #[arg(long, hide = true)]
        server: bool,
    },

    /// Show detailed certificate information (subject, issuer, SANs, expiry)
    Show {
        /// Path to certificate file
        #[arg(long)]
        cert: Option<PathBuf>,
    },

    /// Verify chain of trust and SANs against expected hostname
    Verify {
        /// Expected hostname for SAN validation (default: localhost)
        #[arg(long)]
        hostname: Option<String>,

        /// What to verify
        #[command(subcommand)]
        target: Option<VerifySubcommand>,
    },

    /// Renew expired or expiring certificates
    Renew {
        /// Force renewal even if not expired
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum VerifySubcommand {
    /// Verify only the CA certificate
    Ca,

    /// Verify only the server certificate
    Server,

    /// Verify only the client certificate
    Client,

    /// Verify all certificates (default)
    All,
}
