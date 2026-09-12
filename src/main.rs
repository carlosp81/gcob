use clap::Parser;

mod cli;

// Re-export library modules so cli/* can use crate::certs, crate::cln, etc.
pub use gcob::{certs, cln, config, domain, events, grpc, infra};

use cli::{Cli, Commands};

#[tokio::main]
async fn main() {
    gcob::config::load_trusted_env();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(true)
        .with_thread_ids(true)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            common,
            cln_dir,
            haproxy_user,
            api_user,
            haproxy_cert_dir,
            api_certs_dir,
            rotate_ca,
            allow_loopback,
            dry_run,
        } => {
            let args = cli::server::InitServerArgs {
                force: common.force,
                no_confirm: common.no_confirm,
                hostname: common.hostname,
                ip: common.ip,
                cln_dir,
                haproxy_user,
                api_user,
                haproxy_cert_dir,
                api_certs_dir,
                rotate_ca,
                allow_loopback,
                dry_run,
            };
            if let Err(e) = cli::server::handle_init_server(args) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Serve => {
            if let Err(e) = gcob::role::require_server("serve") {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
            tracing::info!("Starting gcob");
            if let Err(e) = cli::server::handle_serve().await {
                tracing::error!("Server failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Sign {
            csr,
            hostname,
            cln_dir,
            output,
            force,
            dry_run,
            expected_ca_fingerprint,
        } => {
            if let Err(e) = gcob::role::require_server("sign") {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
            let args = cli::certs::SignArgs {
                csr,
                hostname,
                cln_dir,
                output,
                force,
                dry_run,
                expected_ca_fingerprint,
            };
            if let Err(e) = cli::certs::handle_sign(args) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Certs { dir: _, command } => match command {
            Some(cmd) => cli::certs::dispatch(cmd),
            None => cli::certs::handle_no_subcommand(),
        },
    }
}
