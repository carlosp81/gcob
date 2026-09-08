use crate::cln::cln_api;
use crate::events::types;

pub fn to_proto_event(event: &types::Event) -> Option<cln_api::Event> {
    match event {
        types::Event::Payment(e) => match e {
            types::PaymentEvent::Succeeded {
                event_id,
                timestamp,
                payment_hash,
                amount_msat,
                amount_sent_msat,
                node_id,
                ..
            } => {
                let rec = crate::events::enricher::payment_recommendation(e);
                tracing::info!(
                    payment_hash = %payment_hash,
                    amount_msat = %amount_msat,
                    node_id = %node_id,
                    "converted PaymentSucceeded"
                );
                Some(cln_api::Event {
                    event: Some(cln_api::event::Event::PaymentSucceeded(
                        cln_api::PaymentSucceeded {
                            event_id: event_id.clone(),
                            timestamp: *timestamp,
                            payment_hash: payment_hash.clone(),
                            amount_msat: *amount_msat,
                            amount_sent_msat: *amount_sent_msat,
                            node_id: node_id.clone(),
                            recommendation: format!("{}. {}", rec.summary, rec.action),
                        },
                    )),
                })
            }
            types::PaymentEvent::Failed {
                event_id,
                timestamp,
                payment_hash,
                failure_reason,
                amount_msat,
                ..
            } => {
                let rec = crate::events::enricher::payment_recommendation(e);
                tracing::warn!(
                    payment_hash = %payment_hash,
                    failure_reason = %failure_reason,
                    amount_msat = %amount_msat,
                    "converted PaymentFailed"
                );
                Some(cln_api::Event {
                    event: Some(cln_api::event::Event::PaymentFailed(
                        cln_api::PaymentFailed {
                            event_id: event_id.clone(),
                            timestamp: *timestamp,
                            payment_hash: payment_hash.clone(),
                            failure_reason: failure_reason.clone(),
                            amount_msat: *amount_msat,
                            recommendation: format!("{}. {}", rec.summary, rec.action),
                        },
                    )),
                })
            }
            _ => None,
        },
        _ => None,
    }
}
