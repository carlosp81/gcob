use tokio::sync::mpsc;

use crate::cln::cln_api::node_client::NodeClient;
use crate::cln::cln_api::{StreamInvoiceCreationRequest, StreamInvoicePaymentRequest};
use tonic::transport::Channel;

use super::super::types::*;

pub async fn run(client: &mut NodeClient<Channel>, tx: mpsc::Sender<Event>) {
    let mut creation_stream = client
        .subscribe_invoice_creation(StreamInvoiceCreationRequest {})
        .await
        .expect("subscribe_invoice_creation")
        .into_inner();

    let mut payment_stream = client
        .subscribe_invoice_payment(StreamInvoicePaymentRequest {})
        .await
        .expect("subscribe_invoice_payment")
        .into_inner();

    loop {
        tokio::select! {
            result = creation_stream.message() => {
                match result {
                    Ok(Some(n)) => {
                        let event = Event::Invoice(InvoiceEvent::Created {
                            event_id: format!("cln-inv-create-{}", n.label),
                            timestamp: 0,
                            label: n.label.clone(),
                            amount_msat: n.msat.as_ref().map(|a| a.msat),
                            description: String::new(),
                            bolt11: String::new(),
                        });
                        let _ = tx.send(event).await;
                    }
                    Ok(None) => {
                        tracing::info!("invoice creation stream ended");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("invoice creation stream error: {}", e);
                        break;
                    }
                }
            }
            result = payment_stream.message() => {
                match result {
                    Ok(Some(n)) => {
                        let event = Event::Invoice(InvoiceEvent::Paid {
                            event_id: format!("cln-inv-paid-{}", n.label),
                            timestamp: 0,
                            label: n.label.clone(),
                            amount_msat: n.msat.as_ref().map_or(0, |a| a.msat),
                            payment_hash: hex::encode(&n.preimage),
                        });
                        let _ = tx.send(event).await;
                    }
                    Ok(None) => {
                        tracing::info!("invoice payment stream ended");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("invoice payment stream error: {}", e);
                        break;
                    }
                }
            }
        }
    }
}
