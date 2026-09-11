use anyhow::{Context, Result};
use clap::Parser;

mod cli;
mod commands;
mod connection;

use cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    gcob::config::load_trusted_env();

    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .init();

    let cli = Cli::parse();

    // `--rune` takes precedence over `GCOD_RUNE` via clap's env fallback.
    let rune = cli
        .rune
        .as_deref()
        .filter(|r| !r.is_empty())
        .context("Missing rune: pass --rune or set GCOD_RUNE")?;

    let channel = connection::connect(&cli).await?;

    let client_id = cli.client_id.as_deref().unwrap_or("gcob-client");

    match cli.command {
        Commands::Info => commands::info::run(channel, rune).await,
        Commands::Invoice {
            ref label,
            ref amount,
            ref description,
            ref expiry,
        } => {
            commands::invoice::run(
                channel,
                rune,
                client_id,
                label,
                amount,
                description.as_deref(),
                *expiry,
            )
            .await
        }
        Commands::Xpay {
            ref invoice,
            ref maxfee,
        } => commands::xpay::run(channel, rune, client_id, invoice, maxfee.as_deref()).await,
        Commands::Watch { target } => commands::watch::run(channel, rune, target).await,
    }
}
