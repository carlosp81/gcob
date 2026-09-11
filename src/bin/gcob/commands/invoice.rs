use anyhow::{bail, Context, Result};
use tonic::transport::Channel;
use tonic::Request;

use gcob::cln::cln_api;
use gcob::cln::cln_api::node_services_client::NodeServicesClient;
use gcob::cln::cln_api::InvoiceRequest;

use super::{insert_header, sanitize};

pub async fn run(
    channel: Channel,
    rune: &str,
    client_id: &str,
    label: &str,
    amount: &str,
    description: Option<&str>,
    expiry: Option<u64>,
) -> Result<()> {
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
        expiry,
        cltv: None,
        fallbacks: vec![],
        preimage: None,
        exposeprivatechannels: vec![],
        deschashonly: None,
    };

    let now = chrono::Local::now().format("[%Y-%m-%d %H:%M:%S]");

    println!("{} Creating invoice...", now);

    let mut request = Request::new(request);
    insert_header(request.metadata_mut(), "x-rune", rune)?;
    insert_header(request.metadata_mut(), "x-client-id", client_id)?;

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
                println!("  Bolt11: {}", sanitize(&inv.bolt11));
                println!("  Label: {}", sanitize(&inv.label));
                if let Some(amt) = inv.amount_msat {
                    println!("  Amount: {} msat", amt);
                }
                println!("  Description: {}", sanitize(&inv.description));
                if let Some(exp) = inv.expiry {
                    println!("  Expiry: {} seconds", exp);
                }
                println!();
                println!("{} Watching for payment...", now);
                invoice_created = true;
            }
            cln_api::event::Event::InvoicePaid(paid) => {
                println!("{} InvoicePaid: {} msat received", now, paid.amount_msat);
                println!("  Label: {}", sanitize(&paid.label));
                println!("  Payment hash: {}", sanitize(&paid.payment_hash));
                break;
            }
            _ => {}
        }
    }

    if !invoice_created {
        bail!("Stream ended without receiving InvoiceCreated");
    }

    Ok(())
}

fn parse_amount(s: &str) -> Result<u64> {
    let s = s.trim().to_lowercase();
    if let Some(v) = s.strip_suffix("msat") {
        v.trim().parse::<u64>().context("Invalid msat amount")
    } else if let Some(v) = s.strip_suffix("sat") {
        let sats: u64 = v.trim().parse().context("Invalid sat amount")?;
        sats.checked_mul(1000).context("Amount too large")
    } else if let Some(v) = s.strip_suffix("btc") {
        parse_btc_to_msat(v.trim())
    } else {
        s.parse::<u64>()
            .context("Invalid amount (use Nmsat, Nsat, or Nbtc)")
    }
}

/// Parse a BTC amount with integer math and up to 11 decimal places
/// (1 msat = 1e-11 BTC). Never uses floating point.
fn parse_btc_to_msat(value: &str) -> Result<u64> {
    if value.is_empty() || value.starts_with('-') || value.starts_with('+') {
        bail!("Invalid btc amount");
    }

    let (whole, frac) = match value.split_once('.') {
        Some((whole, frac)) => (whole, frac),
        None => (value, ""),
    };

    if frac.len() > 11
        || !whole.chars().all(|c| c.is_ascii_digit())
        || !frac.chars().all(|c| c.is_ascii_digit())
    {
        bail!("Invalid btc amount (max 11 decimals)");
    }

    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().context("Invalid btc amount")?
    };
    let whole_msat = whole
        .checked_mul(100_000_000_000)
        .context("Amount too large")?;

    let frac_msat = if frac.is_empty() {
        0
    } else {
        let mut padded = frac.to_string();
        while padded.len() < 11 {
            padded.push('0');
        }
        padded.parse::<u64>().context("Invalid btc amount")?
    };

    whole_msat
        .checked_add(frac_msat)
        .context("Amount too large")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_amount_accepts_units() {
        assert_eq!(parse_amount("35000msat").unwrap(), 35_000);
        assert_eq!(parse_amount("35000").unwrap(), 35_000);
        assert_eq!(parse_amount("35sat").unwrap(), 35_000);
        assert_eq!(parse_amount("0.000000035btc").unwrap(), 3_500);
        assert_eq!(parse_amount("1btc").unwrap(), 100_000_000_000);
    }

    #[test]
    fn parse_amount_rejects_overflow() {
        let too_large_sat = (u64::MAX / 1000 + 1).to_string();
        assert!(parse_amount(&format!("{}sat", too_large_sat)).is_err());
        assert!(parse_amount(&format!("{}sat", u64::MAX)).is_err());
    }

    #[test]
    fn parse_amount_rejects_invalid() {
        assert!(parse_amount("-1btc").is_err());
        assert!(parse_amount("1e3btc").is_err());
        assert!(parse_amount("0.000000000001btc").is_err()); // 12 decimals
        assert!(parse_amount("abc").is_err());
    }
}
