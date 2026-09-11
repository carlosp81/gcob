use clap::{CommandFactory, Parser, Subcommand};
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

/// Global connection/auth arguments that do not apply to `init`.
const CONNECTION_ARGS: &[&str] = &["host", "port", "cert", "key", "ca", "rune", "client_id"];

#[derive(Parser)]
#[command(
    name = "gcob-client",
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
    /// Generate a client CSR for the server to sign (no connection required)
    Init {
        /// Hostname for the client certificate (auto-detected if not specified)
        #[arg(long)]
        client_hostname: Option<String>,

        /// IP address for the client certificate SAN (auto-detected if not specified)
        #[arg(long)]
        client_ip: Option<String>,

        /// Output directory for client.csr and client-key.pem (default: ~/.certs)
        #[arg(long)]
        output: Option<PathBuf>,

        /// Overwrite an existing client.csr
        #[arg(long)]
        force: bool,

        /// Skip confirmation prompt (for scripting)
        #[arg(long)]
        no_confirm: bool,
    },

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

/// Render `gcob-client init --help` without the irrelevant connection globals.
pub fn render_init_help() -> Option<String> {
    let mut command = Cli::command();
    command.build();

    let init = command.find_subcommand_mut("init")?;
    let mut init = std::mem::replace(init, clap::Command::new("init"));

    for id in CONNECTION_ARGS.iter().copied() {
        if init.get_arguments().any(|arg| arg.get_id() == id) {
            init = init.mut_arg(id, |arg| arg.hide(true));
        }
    }

    Some(
        init.override_usage("gcob-client init [OPTIONS]")
            .render_help()
            .to_string(),
    )
}

/// Print `init --help` early so the connection globals are not shown.
pub fn maybe_print_init_help() -> bool {
    let args: Vec<OsString> = std::env::args_os().collect();
    if args.get(1).map(OsString::as_os_str) != Some(OsStr::new("init")) {
        return false;
    }
    let has_help = args[2..]
        .iter()
        .any(|arg| arg == OsStr::new("--help") || arg == OsStr::new("-h"));
    if !has_help {
        return false;
    }

    match render_init_help() {
        Some(help) => {
            println!("{help}");
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    #[test]
    fn client_binary_help_uses_gcob_client_name() {
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("gcob-client"), "{help}");
    }

    #[test]
    fn init_subcommand_parses_without_connection_flags() {
        let cli = parse(&[
            "gcob-client",
            "init",
            "--client-hostname",
            "client.example",
            "--client-ip",
            "10.0.0.5",
            "--output",
            "/tmp/x",
            "--force",
            "--no-confirm",
        ])
        .unwrap();

        match cli.command {
            Commands::Init {
                client_hostname,
                client_ip,
                output,
                force,
                no_confirm,
            } => {
                assert_eq!(client_hostname.as_deref(), Some("client.example"));
                assert_eq!(client_ip.as_deref(), Some("10.0.0.5"));
                assert_eq!(output.as_deref(), Some(std::path::Path::new("/tmp/x")));
                assert!(force && no_confirm);
            }
            _ => panic!("expected init subcommand"),
        }
    }

    #[test]
    fn init_subcommand_has_defaults() {
        let cli = parse(&["gcob-client", "init"]).unwrap();
        match cli.command {
            Commands::Init {
                client_hostname,
                output,
                force,
                no_confirm,
                ..
            } => {
                assert!(client_hostname.is_none());
                assert!(output.is_none());
                assert!(!force && !no_confirm);
            }
            _ => panic!("expected init subcommand"),
        }
    }

    #[test]
    fn init_help_hides_connection_globals() {
        let help = render_init_help().expect("init help");
        assert!(help.contains("gcob-client init [OPTIONS]"), "{help}");
        assert!(help.contains("--output"), "{help}");
        assert!(!help.contains("--rune"), "{help}");
        assert!(!help.contains("--host"), "{help}");
        assert!(!help.contains("--ca "), "{help}");
    }
}
