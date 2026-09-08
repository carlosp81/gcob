use tokio::sync::mpsc;

use crate::cln::cln_api::node_client::NodeClient;
use crate::cln::cln_api::{
    StreamPayPartEndRequest, StreamPayPartStartRequest, StreamSendPayFailureRequest,
    StreamSendPaySuccessRequest,
};
use tonic::transport::Channel;

use super::super::types::*;

pub async fn run(client: &mut NodeClient<Channel>, tx: mpsc::Sender<Event>) {
    let mut success_stream = client
        .subscribe_send_pay_success(StreamSendPaySuccessRequest {})
        .await
        .expect("subscribe_send_pay_success")
        .into_inner();

    let mut failure_stream = client
        .subscribe_send_pay_failure(StreamSendPayFailureRequest {})
        .await
        .expect("subscribe_send_pay_failure")
        .into_inner();

    let mut part_start_stream = client
        .subscribe_pay_part_start(StreamPayPartStartRequest {})
        .await
        .expect("subscribe_pay_part_start")
        .into_inner();

    let mut part_end_stream = client
        .subscribe_pay_part_end(StreamPayPartEndRequest {})
        .await
        .expect("subscribe_pay_part_end")
        .into_inner();

    loop {
        tokio::select! {
            result = success_stream.message() => {
                match result {
                    Ok(Some(n)) => {
                        let event = Event::Payment(PaymentEvent::Succeeded {
                            event_id: format!("cln-pay-ok-{}", hex::encode(&n.payment_hash[..8])),
                            timestamp: n.created_at as i64,
                            payment_hash: hex::encode(&n.payment_hash),
                            preimage: String::new(),
                            amount_msat: n.amount_msat.as_ref().map_or(0, |a| a.msat),
                            amount_sent_msat: n.amount_sent_msat.as_ref().map_or(0, |a| a.msat),
                            node_id: n.destination.as_ref().map_or(String::new(), hex::encode),
                            created_at: n.created_at as i64,
                        });
                        let _ = tx.send(event).await;
                    }
                    Ok(None) => {
                        tracing::info!("payment success stream ended");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("payment success stream error: {}", e);
                        break;
                    }
                }
            }
            result = failure_stream.message() => {
                match result {
                    Ok(Some(n)) => {
                        let event = Event::Payment(PaymentEvent::Failed {
                            event_id: format!("cln-pay-fail-{}", n.code),
                            timestamp: 0,
                            payment_hash: n.data.as_ref()
                                .and_then(|d| d.payment_hash.as_ref())
                                .map_or(String::new(), hex::encode),
                            failure_reason: n.message.clone(),
                            amount_msat: n.data.as_ref().and_then(|d| d.amount_msat.as_ref()).map_or(0, |a| a.msat),
                            node_id: n.data.as_ref()
                                .and_then(|d| d.destination.as_ref())
                                .map_or(String::new(), hex::encode),
                        });
                        let _ = tx.send(event).await;
                    }
                    Ok(None) => {
                        tracing::info!("payment failure stream ended");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("payment failure stream error: {}", e);
                        break;
                    }
                }
            }
            result = part_start_stream.message() => {
                match result {
                    Ok(Some(n)) => {
                        let event = Event::Payment(PaymentEvent::PartStart {
                            event_id: format!("cln-part-start-{}-{}", hex::encode(&n.payment_hash[..8]), n.partid),
                            timestamp: 0,
                            payment_hash: hex::encode(&n.payment_hash),
                            partid: n.partid,
                            amount_msat: n.attempt_msat.as_ref().map_or(0, |a| a.msat),
                        });
                        let _ = tx.send(event).await;
                    }
                    Ok(None) => {
                        tracing::info!("part start stream ended");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("part start stream error: {}", e);
                        break;
                    }
                }
            }
            result = part_end_stream.message() => {
                match result {
                    Ok(Some(n)) => {
                        let event = Event::Payment(PaymentEvent::PartEnd {
                            event_id: format!("cln-part-end-{}-{}", hex::encode(&n.payment_hash[..8]), n.partid),
                            timestamp: 0,
                            payment_hash: hex::encode(&n.payment_hash),
                            partid: n.partid,
                            amount_msat: 0,
                        });
                        let _ = tx.send(event).await;
                    }
                    Ok(None) => {
                        tracing::info!("part end stream ended");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("part end stream error: {}", e);
                        break;
                    }
                }
            }
        }
    }
}
