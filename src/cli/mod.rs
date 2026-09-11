pub mod atomic;
pub mod certs;
pub mod provision;
pub mod server;

use clap::{CommandFactory, Parser, Subcommand};
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

/// Mode-specific help requested through `gcob init --client|--server --help`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitHelpMode {
    Client,
    Server,
}

/// Arguments that only apply to `gcob init --server`.
const SERVER_ONLY_ARGS: &[&str] = &[
    "server_hostname",
    "server_ip",
    "cln_dir",
    "haproxy_user",
    "api_user",
    "haproxy_cert_dir",
    "api_certs_dir",
    "rotate_ca",
    "allow_loopback",
    "dry_run",
];

/// Arguments that only apply to `gcob init --client`.
const CLIENT_ONLY_ARGS: &[&str] = &["client_hostname", "client_ip"];

const INIT_CLIENT_NOTES: &str = "\
DEPRECATED: use 'gcob-client init' on the client host instead. This path will be
removed in a future release.

Notes:
  - Generates client.csr and client-key.pem; keep the private key secret.
  - Send client.csr to the server and run 'gcob sign' there to obtain client.pem.
  - Output directory is ~/.certs, owned by the admin account (gcob gets ACLs).";

const INIT_SERVER_NOTES: &str = "\
Notes:
  - --cln-dir must contain ca.pem (CA:TRUE) and its matching ca-key.pem.
  - The CA SHA-256 fingerprint is pinned; changing it requires --rotate-ca.
  - Files are staged and published atomically with backups; use --dry-run to preview.
  - HAProxy material is owned by root:<haproxy-user>; API material by --api-user.";

/// Detect `gcob init --client --help` / `gcob init --server --help`.
///
/// Returns `None` when this is not a mode-specific init help request, so clap
/// can render the regular help (including `gcob init --help`).
pub fn init_help_mode(args: &[OsString]) -> Option<InitHelpMode> {
    if args.get(1).map(OsString::as_os_str) != Some(OsStr::new("init")) {
        return None;
    }

    let rest = &args[2..];
    let has_help = rest
        .iter()
        .any(|arg| arg == OsStr::new("--help") || arg == OsStr::new("-h"));
    if !has_help {
        return None;
    }

    let client = rest.iter().any(|arg| arg == OsStr::new("--client"));
    let server = rest.iter().any(|arg| arg == OsStr::new("--server"));

    match (client, server) {
        (true, false) => Some(InitHelpMode::Client),
        (false, true) => Some(InitHelpMode::Server),
        _ => None,
    }
}

fn hide_args(command: clap::Command, ids: &[&str]) -> clap::Command {
    ids.iter()
        .fold(command, |cmd, id| cmd.mut_arg(id, |arg| arg.hide(true)))
}

/// Render the `init` help with only the arguments relevant to `mode`.
pub fn render_init_help(mode: InitHelpMode) -> String {
    let mut command = Cli::command();
    let Some(init) = command.find_subcommand_mut("init") else {
        return command.render_help().to_string();
    };

    let placeholder = clap::Command::new("init");
    let mut init = std::mem::replace(init, placeholder);

    match mode {
        InitHelpMode::Client => {
            init = init
                .about("Deprecated: generate the client CSR with 'gcob-client init'")
                .override_usage("gcob init --client [OPTIONS]")
                .after_help(INIT_CLIENT_NOTES);
            init = hide_args(init, &["server"]);
            init = hide_args(init, SERVER_ONLY_ARGS);
            // The deprecated client path is hidden from `init --help` but must
            // remain documented when explicitly requested.
            init = init.mut_arg("client", |arg| {
                arg.hide(false).help_heading("Mode (--client)")
            });
            for id in CLIENT_ONLY_ARGS.iter().copied() {
                init = init.mut_arg(id, |arg| arg.hide(false));
            }
        }
        InitHelpMode::Server => {
            init = init
                .about("Initialize server certificates for HAProxy mTLS + API")
                .override_usage("gcob init --server --cln-dir <CLN_DIR> [OPTIONS]")
                .after_help(INIT_SERVER_NOTES);
            init = hide_args(init, &["client"]);
            init = hide_args(init, CLIENT_ONLY_ARGS);
            init = init.mut_arg("server", |arg| arg.help_heading("Mode (--server)"));
        }
    }

    init.render_help().to_string()
}

/// Print mode-specific help before clap parsing when applicable.
///
/// Returns `true` when help was printed and the caller should exit successfully.
pub fn maybe_print_init_help() -> bool {
    let args: Vec<OsString> = std::env::args_os().collect();
    match init_help_mode(&args) {
        Some(mode) => {
            println!("{}", render_init_help(mode));
            true
        }
        None => false,
    }
}

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
    #[command(after_help = "Note: client CSR generation moved to 'gcob-client init'.")]
    Init {
        /// Deprecated: generate the client CSR with 'gcob-client init'
        #[arg(
            long,
            hide = true,
            conflicts_with = "server",
            help_heading = "Mode (choose one)"
        )]
        client: bool,

        /// Generate server certificates for HAProxy mTLS
        #[arg(
            long,
            conflicts_with = "client",
            requires = "cln_dir",
            help_heading = "Mode (choose one)"
        )]
        server: bool,

        /// Overwrite existing CSR/key files (client) or certificate targets (server)
        #[arg(long, help_heading = "Common options")]
        force: bool,

        /// Skip confirmation prompt (for scripting)
        #[arg(long, help_heading = "Common options")]
        no_confirm: bool,

        /// Hostname for client certificate (auto-detected if not specified)
        #[arg(
            long,
            hide = true,
            conflicts_with = "server",
            requires = "client",
            help_heading = "Client options (--client)"
        )]
        client_hostname: Option<String>,

        /// IP address for client certificate SAN (auto-detected if not specified)
        #[arg(
            long,
            hide = true,
            conflicts_with = "server",
            requires = "client",
            help_heading = "Client options (--client)"
        )]
        client_ip: Option<String>,

        /// Hostname for server certificate (auto-detected if not specified)
        #[arg(
            long,
            conflicts_with = "client",
            requires = "server",
            help_heading = "Server options (--server)"
        )]
        server_hostname: Option<String>,

        /// IP address for server certificate SAN (auto-detected if not specified)
        #[arg(
            long,
            conflicts_with = "client",
            requires = "server",
            help_heading = "Server options (--server)"
        )]
        server_ip: Option<String>,

        /// Directory containing CLN's ca.pem and ca-key.pem (required with --server)
        #[arg(
            long,
            conflicts_with = "client",
            requires = "server",
            help_heading = "Server options (--server)"
        )]
        cln_dir: Option<PathBuf>,

        /// Owner user for HAProxy certificate material
        #[arg(
            long,
            default_value = "haproxy",
            conflicts_with = "client",
            requires = "server",
            help_heading = "Server options (--server)"
        )]
        haproxy_user: String,

        /// Owner user for the gcob API certificate directory
        #[arg(
            long,
            default_value = "gcob",
            conflicts_with = "client",
            requires = "server",
            help_heading = "Server options (--server)"
        )]
        api_user: String,

        /// HAProxy certificate directory
        #[arg(
            long,
            default_value = "/etc/haproxy/certs",
            conflicts_with = "client",
            requires = "server",
            help_heading = "Server options (--server)"
        )]
        haproxy_cert_dir: PathBuf,

        /// Override the API certificate directory (default: admin ~/.certs)
        #[arg(
            long,
            conflicts_with = "client",
            requires = "server",
            help_heading = "Server options (--server)"
        )]
        api_certs_dir: Option<PathBuf>,

        /// Allow rotating the CA if the existing fingerprint differs
        #[arg(
            long,
            conflicts_with = "client",
            requires = "server",
            help_heading = "Server options (--server)"
        )]
        rotate_ca: bool,

        /// Allow a loopback IP as a server SAN
        #[arg(
            long,
            conflicts_with = "client",
            requires = "server",
            help_heading = "Server options (--server)"
        )]
        allow_loopback: bool,

        /// Validate and stage everything but do not publish any file
        #[arg(
            long,
            conflicts_with = "client",
            requires = "server",
            help_heading = "Server options (--server)"
        )]
        dry_run: bool,
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

        /// Directory containing CLN's ca.pem and ca-key.pem
        #[arg(long)]
        cln_dir: PathBuf,

        /// Output directory for the signed certificate
        #[arg(long)]
        output: PathBuf,

        /// Overwrite an existing client.pem in the output directory
        #[arg(long)]
        force: bool,

        /// Validate and stage without publishing any file
        #[arg(long)]
        dry_run: bool,

        /// Require this SHA-256 fingerprint (hex) on the signing CA
        #[arg(long)]
        expected_ca_fingerprint: Option<String>,
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

        /// CLN directory with ca.pem/ca-key.pem to verify against (optional)
        #[arg(long)]
        cln_dir: Option<PathBuf>,

        /// What to verify
        #[command(subcommand)]
        target: Option<VerifySubcommand>,
    },

    /// Renew expired or expiring certificates
    Renew {
        /// Force renewal even if not expired
        #[arg(long)]
        force: bool,

        /// Hostname for the renewed server certificate (default: reuse existing SAN)
        #[arg(long)]
        server_hostname: Option<String>,

        /// IP address for the renewed server certificate (default: reuse existing SAN)
        #[arg(long)]
        server_ip: Option<String>,

        /// Directory containing CLN's ca.pem and ca-key.pem
        #[arg(long)]
        cln_dir: PathBuf,

        /// Install cert_dir/ca.pem from the validated CLN CA (required if missing)
        #[arg(long)]
        init_ca: bool,

        /// Allow replacing an existing CA whose fingerprint differs
        #[arg(long)]
        rotate_ca: bool,

        /// Owner user for the API certificate directory
        #[arg(long, default_value = "gcob")]
        api_user: String,

        /// Allow a loopback IP as a server SAN
        #[arg(long)]
        allow_loopback: bool,

        /// Validate and stage without publishing any file
        #[arg(long)]
        dry_run: bool,
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    fn is_init(args: &[&str]) -> bool {
        parse(args).is_ok()
    }

    #[test]
    fn init_client_and_server_conflict() {
        assert!(!is_init(&["gcob", "init", "--client", "--server"]));
    }

    #[test]
    fn init_client_parses_with_defaults() {
        // Server defaults (with `requires = "server"`) must not block client mode.
        assert!(is_init(&["gcob", "init", "--client"]));
        assert!(is_init(&[
            "gcob",
            "init",
            "--client",
            "--force",
            "--no-confirm"
        ]));
    }

    #[test]
    fn init_server_requires_cln_dir() {
        assert!(!is_init(&["gcob", "init", "--server"]));
        assert!(is_init(&[
            "gcob",
            "init",
            "--server",
            "--cln-dir",
            "/srv/cln"
        ]));
    }

    #[test]
    fn init_cln_dir_requires_server() {
        assert!(!is_init(&["gcob", "init", "--cln-dir", "/srv/cln"]));
    }

    #[test]
    fn init_server_flags_require_server() {
        assert!(!is_init(&[
            "gcob",
            "init",
            "--server-hostname",
            "node.example"
        ]));
        assert!(!is_init(&["gcob", "init", "--dry-run"]));
        assert!(is_init(&[
            "gcob",
            "init",
            "--server",
            "--cln-dir",
            "/srv/cln",
            "--server-hostname",
            "node.example",
            "--dry-run"
        ]));
    }

    #[test]
    fn init_client_flags_require_client() {
        assert!(!is_init(&[
            "gcob",
            "init",
            "--client-hostname",
            "client.example"
        ]));
        assert!(is_init(&[
            "gcob",
            "init",
            "--client",
            "--client-hostname",
            "client.example",
            "--client-ip",
            "10.0.0.5"
        ]));
    }

    #[test]
    fn init_client_rejects_server_flags() {
        assert!(!is_init(&[
            "gcob",
            "init",
            "--client",
            "--cln-dir",
            "/srv/cln"
        ]));
        assert!(!is_init(&["gcob", "init", "--client", "--dry-run"]));
    }

    #[test]
    fn init_help_is_server_only() {
        let mut command = Cli::command();
        let init = command
            .find_subcommand_mut("init")
            .expect("init subcommand");
        let help = init.render_help().to_string();
        for heading in [
            "Mode (choose one)",
            "Common options",
            "Server options (--server)",
        ] {
            assert!(help.contains(heading), "missing heading: {heading}");
        }
        // The deprecated client path is hidden from the default help.
        assert!(!help.contains("Client options (--client)"), "{help}");
        assert!(!help.contains("--client-hostname"), "{help}");
        assert!(help.contains("gcob-client init"), "{help}");
    }

    fn os_args(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn init_help_mode_detection() {
        assert_eq!(
            init_help_mode(&os_args(&["gcob", "init", "--client", "--help"])),
            Some(InitHelpMode::Client)
        );
        assert_eq!(
            init_help_mode(&os_args(&["gcob", "init", "--server", "-h"])),
            Some(InitHelpMode::Server)
        );
        // Full help / ambiguous / other subcommand / no help: clap handles it.
        assert_eq!(init_help_mode(&os_args(&["gcob", "init", "--help"])), None);
        assert_eq!(
            init_help_mode(&os_args(&[
                "gcob", "init", "--client", "--server", "--help"
            ])),
            None
        );
        assert_eq!(init_help_mode(&os_args(&["gcob", "sign", "--help"])), None);
        assert_eq!(
            init_help_mode(&os_args(&["gcob", "init", "--client"])),
            None
        );
    }

    #[test]
    fn init_client_help_is_contextual_and_deprecated() {
        let help = render_init_help(InitHelpMode::Client);
        assert!(help.contains("Mode (--client)"), "{help}");
        assert!(help.contains("Client options (--client)"), "{help}");
        assert!(help.contains("Common options"), "{help}");
        assert!(help.contains("gcob init --client [OPTIONS]"), "{help}");
        assert!(help.contains("DEPRECATED"), "{help}");
        assert!(help.contains("gcob-client init"), "{help}");
        assert!(!help.contains("--cln-dir"), "{help}");
        assert!(!help.contains("--haproxy-user"), "{help}");
        assert!(!help.contains("Server options"), "{help}");
    }

    #[test]
    fn init_server_help_is_contextual() {
        let help = render_init_help(InitHelpMode::Server);
        assert!(help.contains("Mode (--server)"), "{help}");
        assert!(help.contains("Server options (--server)"), "{help}");
        assert!(help.contains("--cln-dir"), "{help}");
        assert!(
            help.contains("gcob init --server --cln-dir <CLN_DIR> [OPTIONS]"),
            "{help}"
        );
        assert!(help.contains("requires --rotate-ca"), "{help}");
        assert!(!help.contains("--client-hostname"), "{help}");
        assert!(!help.contains("Client options"), "{help}");
    }
}
