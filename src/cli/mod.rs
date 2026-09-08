pub mod server;

use clap::{Parser, Subcommand};

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
        /// Generate client certificates for gcob gRPC client
        #[arg(long, conflicts_with = "server")]
        client: bool,

        /// Generate server certificates for HAProxy mTLS
        #[arg(long, conflicts_with = "client")]
        server: bool,
    },

    /// Start the gRPC API server
    Serve,

    /// Generate or renew mTLS certificates
    Certs,
}
