use anyhow::{Context, Result};
use tonic::transport::Channel;
use tonic::Request;

use gcob::cln::cln_api;
use gcob::cln::cln_api::node_services_client::NodeServicesClient;
use gcob::cln::cln_api::XpayRequest;

use super::{insert_header, sanitize};

pub async fn run(
    channel: Channel,
    rune: &str,
    client_id: &str,
    invoice: &str,
    maxfee: Option<&str>,
) -> Result<()> {
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
    insert_header(request.metadata_mut(), "x-rune", rune)?;
    insert_header(request.metadata_mut(), "x-client-id", client_id)?;

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
                println!("  Payment hash: {}", sanitize(&payment.payment_hash));
                println!("  Node: {}", sanitize(&payment.node_id));
                if !payment.recommendation.is_empty() {
                    println!("  Recommendation: {}", sanitize(&payment.recommendation));
                }
                break;
            }
            cln_api::event::Event::PaymentFailed(failure) => {
                println!("{} PaymentFailed:", now);
                println!("  Payment hash: {}", sanitize(&failure.payment_hash));
                println!("  Reason: {}", sanitize(&failure.failure_reason));
                if !failure.recommendation.is_empty() {
                    println!("  Recommendation: {}", sanitize(&failure.recommendation));
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
        v.trim().parse::<u64>().context("Invalid msat amount")
    } else if let Some(v) = s.strip_suffix("sat") {
        let sats: u64 = v.trim().parse().context("Invalid sat amount")?;
        sats.checked_mul(1000).context("Amount too large")
    } else {
        s.parse::<u64>()
            .context("Invalid amount (use Nmsat or Nsat)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_msat_accepts_units() {
        assert_eq!(parse_msat("1000msat").unwrap(), 1000);
        assert_eq!(parse_msat("5sat").unwrap(), 5000);
        assert_eq!(parse_msat("42").unwrap(), 42);
    }

    #[test]
    fn parse_msat_rejects_overflow() {
        let too_large_sat = (u64::MAX / 1000 + 1).to_string();
        assert!(parse_msat(&format!("{}sat", too_large_sat)).is_err());
    }
}
