use anyhow::{Context, Result};
use tonic::transport::Channel;
use tonic::Request;

use gcob::cln::cln_api;
use gcob::cln::cln_api::node_services_client::NodeServicesClient;

use crate::cli::WatchTarget;

pub async fn run(channel: Channel, target: WatchTarget) -> Result<()> {
    let rune = std::env::var("GCOD_RUNE").context("GCOD_RUNE not set")?;

    let mut client = NodeServicesClient::new(channel);

    let now = chrono::Local::now().format("[%Y-%m-%d %H:%M:%S]");
    println!("{} Watching {} events... (Ctrl+C to stop)", now, target.name());

    match target {
        WatchTarget::Payment => watch_payments(&mut client, &rune).await,
        WatchTarget::Invoice => watch_invoices(&mut client, &rune).await,
        WatchTarget::Channel => watch_channels(&mut client, &rune).await,
        WatchTarget::Peer => watch_peers(&mut client, &rune).await,
        WatchTarget::System => watch_system(&mut client, &rune).await,
    }
}

fn with_rune(rune: &str) -> Request<()> {
    let mut request = Request::new(());
    request
        .metadata_mut()
        .insert("x-rune", rune.parse().unwrap());
    request
}

async fn watch_payments(client: &mut NodeServicesClient<Channel>, rune: &str) -> Result<()> {
    let request = with_rune(rune);
    let mut stream = client
        .xpay_stream(request)
        .await
        .context("Failed to subscribe to XpayStream")?
        .into_inner();

    while let Some(result) = stream.message().await? {
        if let Some(event) = result.event {
            print_payment_event(&event);
        }
    }
    Ok(())
}

async fn watch_invoices(client: &mut NodeServicesClient<Channel>, rune: &str) -> Result<()> {
    let request = with_rune(rune);
    let mut stream = client
        .invoice_watch(request)
        .await
        .context("Failed to subscribe to InvoiceWatch")?
        .into_inner();

    while let Some(result) = stream.message().await? {
        if let Some(event) = result.event {
            print_invoice_event(&event);
        }
    }
    Ok(())
}

async fn watch_channels(client: &mut NodeServicesClient<Channel>, rune: &str) -> Result<()> {
    let request = with_rune(rune);
    let mut stream = client
        .watch_channels(request)
        .await
        .context("Failed to subscribe to WatchChannels")?
        .into_inner();

    while let Some(result) = stream.message().await? {
        if let Some(event) = result.event {
            print_channel_event(&event);
        }
    }
    Ok(())
}

async fn watch_peers(client: &mut NodeServicesClient<Channel>, rune: &str) -> Result<()> {
    let request = with_rune(rune);
    let mut stream = client
        .watch_peers(request)
        .await
        .context("Failed to subscribe to WatchPeers")?
        .into_inner();

    while let Some(result) = stream.message().await? {
        if let Some(event) = result.event {
            print_peer_event(&event);
        }
    }
    Ok(())
}

async fn watch_system(client: &mut NodeServicesClient<Channel>, rune: &str) -> Result<()> {
    let request = with_rune(rune);
    let mut stream = client
        .watch_system(request)
        .await
        .context("Failed to subscribe to WatchSystem")?
        .into_inner();

    while let Some(result) = stream.message().await? {
        if let Some(event) = result.event {
            print_system_event(&event);
        }
    }
    Ok(())
}

fn ts(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|dt| dt.with_timezone(&chrono::Local).format("[%Y-%m-%d %H:%M:%S]").to_string())
        .unwrap_or_else(|| format!("[{}]", seconds))
}

fn print_payment_event(event: &cln_api::event::Event) {
    match event {
        cln_api::event::Event::PaymentSucceeded(p) => {
            println!(
                "{} PaymentSucceeded: {} msat (sent: {} msat) hash={}",
                ts(p.timestamp), p.amount_msat, p.amount_sent_msat, p.payment_hash
            );
        }
        cln_api::event::Event::PaymentFailed(p) => {
            println!(
                "{} PaymentFailed: reason={} hash={}",
                ts(p.timestamp), p.failure_reason, p.payment_hash
            );
        }
        _ => {}
    }
}

fn print_invoice_event(event: &cln_api::event::Event) {
    match event {
        cln_api::event::Event::InvoiceCreated(inv) => {
            println!(
                "{} InvoiceCreated: label={} bolt11={}...",
                ts(inv.timestamp),
                inv.label,
                &inv.bolt11[..inv.bolt11.len().min(40)]
            );
        }
        cln_api::event::Event::InvoicePaid(p) => {
            println!(
                "{} InvoicePaid: label={} amount={}msat",
                ts(p.timestamp), p.label, p.amount_msat
            );
        }
        _ => {}
    }
}

fn print_channel_event(event: &cln_api::event::Event) {
    match event {
        cln_api::event::Event::ChannelOpened(c) => {
            println!(
                "{} ChannelOpened: node={} amount={}msat",
                ts(c.timestamp),
                &c.node_id[..c.node_id.len().min(16)],
                c.amount_msat
            );
        }
        cln_api::event::Event::ChannelOpenFailed(c) => {
            println!("{} ChannelOpenFailed: reason={}", ts(c.timestamp), c.reason);
        }
        cln_api::event::Event::ChannelStateChanged(c) => {
            println!(
                "{} ChannelStateChanged: {} {} -> {}",
                ts(c.timestamp), c.channel_id, c.old_state, c.new_state
            );
        }
        _ => {}
    }
}

fn print_peer_event(event: &cln_api::event::Event) {
    match event {
        cln_api::event::Event::PeerConnected(p) => {
            println!(
                "{} PeerConnected: node={} addr={}",
                ts(p.timestamp),
                &p.node_id[..p.node_id.len().min(16)],
                p.addr
            );
        }
        cln_api::event::Event::PeerDisconnected(p) => {
            println!(
                "{} PeerDisconnected: node={}",
                ts(p.timestamp),
                &p.node_id[..p.node_id.len().min(16)]
            );
        }
        _ => {}
    }
}

fn print_system_event(event: &cln_api::event::Event) {
    match event {
        cln_api::event::Event::SystemWarning(w) => {
            println!("{} SystemWarning: {}", ts(w.timestamp), w.log);
        }
        cln_api::event::Event::SystemBlockAdded(b) => {
            println!("{} BlockAdded: height={}", ts(b.timestamp), b.block_height);
        }
        _ => {}
    }
}
