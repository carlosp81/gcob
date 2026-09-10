use anyhow::{Context, Result};
use tonic::transport::Channel;
use tonic::Request;

use gcob::cln::cln_api;
use gcob::cln::cln_api::node_services_client::NodeServicesClient;
use gcob::cln::cln_api::InvoiceRequest;

pub async fn run(
    channel: Channel,
    label: &str,
    amount: &str,
    description: Option<&str>,
) -> Result<()> {
    let rune = std::env::var("GCOD_RUNE").context("GCOD_RUNE not set")?;

    let mut client = NodeServicesClient::new(channel);

    // Parse amount: accept "35000msat", "35000", "0.035btc", "35000sat"
    let amount_msat = parse_amount(amount)?;

    let request = InvoiceRequest {
        amount_msat: Some(cln_api::AmountOrAny {
            value: Some(cln_api::amount_or_any::Value::Amount(cln_api::Amount {
                msat: amount_msat,
            })),
        }),
        label: label.to_string(),
        description: description.unwrap_or("").to_string(),
        expiry: None,
        cltv: None,
        fallbacks: vec![],
        preimage: None,
        exposeprivatechannels: vec![],
        deschashonly: None,
    };

    let now = chrono::Local::now().format("[%Y-%m-%d %H:%M:%S]");

    println!("{} Creating invoice...", now);

    let mut request = Request::new(request);
    request
        .metadata_mut()
        .insert("x-rune", rune.parse().unwrap());

    let mut stream = client
        .invoice_stream(request)
        .await
        .context("Failed to call InvoiceStream")?
        .into_inner();

    let mut invoice_created = false;

    while let Some(result) = stream.message().await? {
        let event = result.event.context("Empty event")?;

        match event {
            cln_api::event::Event::InvoiceCreated(inv) => {
                println!("{} Invoice created:", now);
                println!("  Bolt11: {}", inv.bolt11);
                println!("  Label: {}", inv.label);
                if let Some(amt) = inv.amount_msat {
                    println!("  Amount: {} msat", amt);
                }
                println!("  Description: {}", inv.description);
                println!();
                println!("{} Watching for payment...", now);
                invoice_created = true;
            }
            cln_api::event::Event::InvoicePaid(paid) => {
                println!(
                    "{} InvoicePaid: {} msat received",
                    now, paid.amount_msat
                );
                println!("  Label: {}", paid.label);
                println!("  Payment hash: {}", paid.payment_hash);
                break;
            }
            _ => {}
        }
    }

    if !invoice_created {
        anyhow::bail!("Stream ended without receiving InvoiceCreated");
    }

    Ok(())
}

fn parse_amount(s: &str) -> Result<u64> {
    let s = s.trim().to_lowercase();
    if let Some(v) = s.strip_suffix("msat") {
        v.parse::<u64>()
            .context("Invalid msat amount")
    } else if let Some(v) = s.strip_suffix("sat") {
        v.parse::<u64>()
            .map(|v| v * 1000)
            .context("Invalid sat amount")
    } else if let Some(v) = s.strip_suffix("btc") {
        v.parse::<f64>()
            .map(|v| (v * 100_000_000.0 * 1000.0) as u64)
            .context("Invalid btc amount")
    } else {
        s.parse::<u64>().context("Invalid amount (use Nmsat, Nsat, or Nbtc)")
    }
}
