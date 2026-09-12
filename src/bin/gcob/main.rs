use anyhow::{Context, Result};
use clap::Parser;

mod cli;
mod commands;
mod connection;

use cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    gcob::config::load_trusted_env();

    // `gcob-client init --help` only shows the local CSR options.
    if cli::maybe_print_init_help() {
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        // CSR generation is local-only: no rune, certificates or connection needed.
        Commands::Init { common, output } => commands::init::run(
            common.hostname.as_deref(),
            common.ip.as_deref(),
            output.as_deref(),
            common.force,
            common.no_confirm,
        ),
        command => {
            // `--rune` takes precedence over `GCOD_RUNE` via clap's env fallback.
            let rune = cli
                .rune
                .as_deref()
                .filter(|r| !r.is_empty())
                .context("Missing rune: pass --rune or set GCOD_RUNE")?;

            let channel = connection::connect(
                &cli.host,
                cli.port,
                cli.ca.as_deref(),
                cli.cert.as_deref(),
                cli.key.as_deref(),
            )
            .await?;

            let client_id = cli.client_id.as_deref().unwrap_or("gcob-client");

            match command {
                Commands::Info => commands::info::run(channel, rune).await,
                Commands::Invoice {
                    label,
                    amount,
                    description,
                    expiry,
                } => {
                    commands::invoice::run(
                        channel,
                        rune,
                        client_id,
                        &label,
                        &amount,
                        description.as_deref(),
                        expiry,
                    )
                    .await
                }
                Commands::Xpay { invoice, maxfee } => {
                    commands::xpay::run(channel, rune, client_id, &invoice, maxfee.as_deref()).await
                }
                Commands::Watch { target } => commands::watch::run(channel, rune, target).await,
                Commands::Init { .. } => unreachable!("handled above"),
            }
        }
    }
}
