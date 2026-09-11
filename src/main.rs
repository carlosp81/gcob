use clap::Parser;

mod cli;

// Re-export library modules so cli/* can use crate::certs, crate::cln, etc.
pub use gcob::{certs, cln, config, domain, events, grpc, infra};

use cli::{Cli, Commands};

#[tokio::main]
async fn main() {
    gcob::config::load_trusted_env();

    // Mode-specific help: `gcob init --client|--server --help` only shows the
    // arguments relevant to that mode. `gcob init --help` keeps the full help.
    if cli::maybe_print_init_help() {
        return;
    }

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(true)
        .with_thread_ids(true)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            client,
            server,
            force,
            client_hostname,
            client_ip,
            server_hostname,
            server_ip,
            no_confirm,
            cln_dir,
            haproxy_user,
            api_user,
            haproxy_cert_dir,
            api_certs_dir,
            rotate_ca,
            allow_loopback,
            dry_run,
        } => {
            if client {
                if let Err(e) = cli::server::handle_init_client(
                    force,
                    no_confirm,
                    client_hostname.as_deref(),
                    client_ip.as_deref(),
                ) {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            } else if server {
                let args = cli::server::InitServerArgs {
                    force,
                    no_confirm,
                    hostname: server_hostname,
                    ip: server_ip,
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
            } else {
                eprintln!("Run 'gcob init --help' to see available options");
                std::process::exit(1);
            }
        }
        Commands::Serve => {
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
