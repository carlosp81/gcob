pub mod atomic;
pub mod certs;
pub mod provision;
pub mod server;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

use gcob::init_common::CommonInitArgs;

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
    /// Initialize server certificates and configuration
    #[command(after_help = "On client hosts, generate the CSR with 'gcob-client init'.")]
    Init {
        /// Common init options (--force, --no-confirm, --hostname, --ip)
        #[command(flatten)]
        common: CommonInitArgs,

        /// Directory containing CLN's ca.pem and ca-key.pem
        #[arg(long, help_heading = "Server options")]
        cln_dir: PathBuf,

        /// Owner user for HAProxy certificate material
        #[arg(long, default_value = "haproxy", help_heading = "Server options")]
        haproxy_user: String,

        /// Owner user for the gcob API certificate directory
        #[arg(long, default_value = "gcob", help_heading = "Server options")]
        api_user: String,

        /// HAProxy certificate directory
        #[arg(
            long,
            default_value = "/etc/haproxy/certs",
            help_heading = "Server options"
        )]
        haproxy_cert_dir: PathBuf,

        /// Override the API certificate directory (default: admin ~/.certs)
        #[arg(long, help_heading = "Server options")]
        api_certs_dir: Option<PathBuf>,

        /// Allow rotating the CA if the existing fingerprint differs
        #[arg(long, help_heading = "Server options")]
        rotate_ca: bool,

        /// Allow a loopback IP as a server SAN
        #[arg(long, help_heading = "Server options")]
        allow_loopback: bool,

        /// Validate and stage everything but do not publish any file
        #[arg(long, help_heading = "Server options")]
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
    fn init_parses_with_common_and_server_flags() {
        assert!(is_init(&["gcob", "init", "--cln-dir", "/srv/cln"]));
        assert!(is_init(&[
            "gcob",
            "init",
            "--cln-dir",
            "/srv/cln",
            "--force",
            "--no-confirm",
            "--hostname",
            "node.example",
            "--ip",
            "10.0.0.5",
            "--haproxy-user",
            "haproxy",
            "--api-user",
            "gcob",
            "--haproxy-cert-dir",
            "/etc/haproxy/certs",
            "--api-certs-dir",
            "/srv/gcob/certs",
            "--rotate-ca",
            "--allow-loopback",
            "--dry-run",
        ]));
    }

    #[test]
    fn init_requires_cln_dir() {
        assert!(!is_init(&["gcob", "init"]));
        assert!(!is_init(&["gcob", "init", "--hostname", "node.example"]));
        assert!(!is_init(&["gcob", "init", "--dry-run"]));
    }

    #[test]
    fn init_rejects_removed_mode_flags() {
        let rejected: &[&[&str]] = &[
            &["gcob", "init", "--client"],
            &["gcob", "init", "--server"],
            &["gcob", "init", "--cln-dir", "/srv/cln", "--client"],
            &["gcob", "init", "--cln-dir", "/srv/cln", "--server"],
            &["gcob", "init", "--client-hostname", "client.example"],
            &["gcob", "init", "--client-ip", "10.0.0.9"],
            &["gcob", "init", "--server-hostname", "node.example"],
            &["gcob", "init", "--server-ip", "10.0.0.5"],
        ];
        for args in rejected {
            assert!(!is_init(args), "should reject: {args:?}");
        }
    }

    #[test]
    fn init_help_lists_common_and_server_flags_only() {
        let mut command = Cli::command();
        let init = command
            .find_subcommand_mut("init")
            .expect("init subcommand");
        let help = init.render_help().to_string();

        for flag in [
            "--force",
            "--no-confirm",
            "--hostname",
            "--ip",
            "--cln-dir",
            "--haproxy-user",
            "--api-user",
            "--haproxy-cert-dir",
            "--api-certs-dir",
            "--rotate-ca",
            "--allow-loopback",
            "--dry-run",
        ] {
            assert!(help.contains(flag), "missing {flag}: {help}");
        }
        assert!(help.contains("Common options"), "{help}");
        assert!(help.contains("Server options"), "{help}");
        assert!(!help.contains("--client"), "{help}");
        assert!(!help.contains("--server"), "{help}");
        assert!(help.contains("gcob-client init"), "{help}");
    }

    #[test]
    fn non_init_commands_still_parse() {
        assert!(parse(&["gcob", "serve"]).is_ok());
        assert!(parse(&["gcob", "certs", "verify"]).is_ok());
    }
}
