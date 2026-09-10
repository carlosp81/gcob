use anyhow::{Context, Result};
use tonic::transport::Channel;
use tonic::Request;

use gcob::cln::cln_api;
use gcob::cln::cln_api::node_services_client::NodeServicesClient;
use gcob::cln::cln_api::XpayRequest;

pub async fn run(channel: Channel, invoice: &str, maxfee: Option<&str>) -> Result<()> {
    let rune = std::env::var("GCOD_RUNE").context("GCOD_RUNE not set")?;

    let mut client = NodeServicesClient::new(channel);

    let maxfee_amount = if let Some(fee_str) = maxfee {
        let msat = parse_msat(fee_str)?;
        Some(cln_api::Amount { msat })
    } else {
        None
    };

    let request = XpayRequest {
        invstring: invoice.to_string(),
        amount_msat: None,
        maxfee: maxfee_amount,
        layers: vec![],
        retry_for: None,
        partial_msat: None,
        maxdelay: None,
        payer_note: None,
        label: None,
        localinvreqid: None,
        dev_use_shadow: None,
    };

    let now = chrono::Local::now().format("[%Y-%m-%d %H:%M:%S]");

    println!("{} Paying invoice...", now);

    let mut request = Request::new(request);
    request
        .metadata_mut()
        .insert("x-rune", rune.parse().unwrap());

    let mut stream = client
        .xpay_stream_watch(request)
        .await
        .context("Failed to call XpayStreamWatch")?
        .into_inner();

    while let Some(result) = stream.message().await? {
        let event = result.event.context("Empty event")?;

        match event {
            cln_api::event::Event::PaymentSucceeded(payment) => {
                println!("{} PaymentSucceeded:", now);
                println!("  Amount: {} msat", payment.amount_msat);
                println!("  Amount sent: {} msat", payment.amount_sent_msat);
                println!("  Payment hash: {}", payment.payment_hash);
                println!("  Node: {}", payment.node_id);
                if !payment.recommendation.is_empty() {
                    println!("  Recommendation: {}", payment.recommendation);
                }
                break;
            }
            cln_api::event::Event::PaymentFailed(failure) => {
                println!("{} PaymentFailed:", now);
                println!("  Payment hash: {}", failure.payment_hash);
                println!("  Reason: {}", failure.failure_reason);
                if !failure.recommendation.is_empty() {
                    println!("  Recommendation: {}", failure.recommendation);
                }
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

fn parse_msat(s: &str) -> Result<u64> {
    let s = s.trim().to_lowercase();
    if let Some(v) = s.strip_suffix("msat") {
        v.parse::<u64>().context("Invalid msat amount")
    } else if let Some(v) = s.strip_suffix("sat") {
        v.parse::<u64>()
            .map(|v| v * 1000)
            .context("Invalid sat amount")
    } else {
        s.parse::<u64>().context("Invalid amount (use Nmsat or Nsat)")
    }
}
