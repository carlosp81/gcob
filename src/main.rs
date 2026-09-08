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
        Commands::Init { client, server } => {
            if client {
                if let Err(e) = cli::server::handle_init_client() {
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
        Commands::Certs => {
            if let Err(e) = cli::server::handle_certs() {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }
}
