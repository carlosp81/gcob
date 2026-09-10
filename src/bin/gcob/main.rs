use anyhow::Result;
use clap::Parser;

mod cli;
mod commands;
mod connection;

use cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .init();

    let cli = Cli::parse();

    let channel = connection::connect(&cli).await?;

    match cli.command {
        Commands::Info => commands::info::run(channel).await,
        Commands::Invoice {
            ref label,
            ref amount,
            ref description,
        } => {
            commands::invoice::run(channel, label, amount, description.as_deref()).await
        }
        Commands::Xpay {
            ref invoice,
            ref maxfee,
        } => commands::xpay::run(channel, invoice, maxfee.as_deref()).await,
        Commands::Watch { target } => commands::watch::run(channel, target).await,
    }
}
