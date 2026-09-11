use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "gcob",
    version,
    about = "CLI client for gcob gRPC API — Core Lightning management"
)]
pub struct Cli {
    /// gRPC server host (env: GCOD_HOST)
    #[arg(long, env = "GCOD_HOST", default_value = "localhost", global = true)]
    pub host: String,

    /// gRPC server port (env: GCOD_PORT)
    #[arg(long, env = "GCOD_PORT", default_value_t = 50063, global = true)]
    pub port: u16,

    /// Client certificate path (env: GCOD_CERT)
    #[arg(long, env = "GCOD_CERT", global = true)]
    pub cert: Option<String>,

    /// Client key path (env: GCOD_KEY)
    #[arg(long, env = "GCOD_KEY", global = true)]
    pub key: Option<String>,

    /// CA certificate path (env: GCOD_CA)
    #[arg(long, env = "GCOD_CA", global = true)]
    pub ca: Option<String>,

    /// Rune for authentication (env: GCOD_RUNE)
    #[arg(long, env = "GCOD_RUNE", global = true)]
    pub rune: Option<String>,

    /// Client identifier for rate limiting (env: GCOD_CLIENT_ID)
    #[arg(long, env = "GCOD_CLIENT_ID", global = true)]
    pub client_id: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Get node information
    Info,

    /// Create an invoice and watch for payment
    Invoice {
        /// Invoice label
        #[arg(short, long)]
        label: String,

        /// Amount in millisatoshis (e.g. 35000msat)
        #[arg(short, long)]
        amount: String,

        /// Invoice description
        #[arg(short, long)]
        description: Option<String>,

        /// Invoice expiry in seconds (default: 3600)
        #[arg(short = 'e', long)]
        expiry: Option<u64>,
    },

    /// Pay a BOLT11 invoice and watch for completion
    Xpay {
        /// BOLT11 invoice string
        #[arg(short, long)]
        invoice: String,

        /// Maximum fee in msat
        #[arg(short, long)]
        maxfee: Option<String>,
    },

    /// Watch events of a specific type
    Watch {
        /// Event type to watch
        #[command(subcommand)]
        target: WatchTarget,
    },
}

#[derive(Subcommand)]
pub enum WatchTarget {
    /// Watch payment events
    Payment,
    /// Watch invoice events
    Invoice,
    /// Watch channel events
    Channel,
    /// Watch peer events
    Peer,
    /// Watch system events
    System,
}

impl WatchTarget {
    pub fn name(&self) -> &'static str {
        match self {
            WatchTarget::Payment => "payment",
            WatchTarget::Invoice => "invoice",
            WatchTarget::Channel => "channel",
            WatchTarget::Peer => "peer",
            WatchTarget::System => "system",
        }
    }
}
