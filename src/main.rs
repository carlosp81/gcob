use clap::Parser;

mod certs;
mod cli;
mod cln;
mod domain;
mod events;
mod grpc;
mod infra;

use cli::{Cli, Commands};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

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
            output_dir,
            owner,
            force,
            client_hostname,
            client_ip,
        } => {
            if client {
                if let Err(e) = cli::server::handle_init_client(
                    output_dir.as_deref(),
                    owner.as_deref(),
                    force,
                    client_hostname.as_deref(),
                    client_ip.as_deref(),
                ) {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            } else if server {
                if let Err(e) = cli::server::handle_init_server() {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            } else {
                eprintln!("Error: must specify --client or --server");
                eprintln!("Usage: gcob init --client | gcob init --server");
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
            output,
        } => {
            let output_path = output
                .as_deref()
                .unwrap_or_else(|| std::path::Path::new("/etc/gcob/certs"));
            if let Err(e) = cli::certs::handle_sign(&csr, &hostname, output_path) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Certs { dir: _, command } => {
            match command {
                Some(cmd) => cli::certs::dispatch(cmd),
                None => cli::certs::handle_no_subcommand(),
            }
        }
    }
}
