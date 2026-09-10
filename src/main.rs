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
            force,
            client_hostname,
            client_ip,
            server_hostname,
            server_ip,
            no_confirm,
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
                if let Err(e) = cli::server::handle_init_server(
                    force,
                    no_confirm,
                    server_hostname.as_deref(),
                    server_ip.as_deref(),
                ) {
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
            output,
        } => {
            let output_path = match output {
                Some(p) => p,
                None => certs::paths::default_cert_dir(),
            };
            if let Err(e) = cli::certs::handle_sign(&csr, &hostname, &output_path) {
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
