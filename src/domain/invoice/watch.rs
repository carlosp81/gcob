use crate::cln::cln_api;
use crate::events::types;

pub fn to_proto_event(event: &types::Event) -> Option<cln_api::Event> {
    match event {
        types::Event::Invoice(e) => match e {
            types::InvoiceEvent::Created {
                event_id,
                timestamp,
                label,
                amount_msat,
                description,
                bolt11,
            } => {
                let rec = crate::events::enricher::invoice_recommendation(e);
                tracing::info!(
                    label = %label,
                    amount_msat = ?amount_msat,
                    "converted InvoiceCreated"
                );
                Some(cln_api::Event {
                    event: Some(cln_api::event::Event::InvoiceCreated(
                        cln_api::InvoiceCreated {
                            event_id: event_id.clone(),
                            timestamp: *timestamp,
                            label: label.clone(),
                            amount_msat: *amount_msat,
                            description: description.clone(),
                            bolt11: bolt11.clone(),
                            recommendation: format!("{}. {}", rec.summary, rec.action),
                        },
                    )),
                })
            }
            types::InvoiceEvent::Paid {
                event_id,
                timestamp,
                label,
                amount_msat,
                payment_hash,
            } => {
                let rec = crate::events::enricher::invoice_recommendation(e);
                tracing::info!(
                    label = %label,
                    amount_msat = %amount_msat,
                    payment_hash = %payment_hash,
                    "converted InvoicePaid"
                );
                Some(cln_api::Event {
                    event: Some(cln_api::event::Event::InvoicePaid(cln_api::InvoicePaid {
                        event_id: event_id.clone(),
                        timestamp: *timestamp,
                        label: label.clone(),
                        amount_msat: *amount_msat,
                        payment_hash: payment_hash.clone(),
                        recommendation: format!("{}. {}", rec.summary, rec.action),
                    })),
                })
            }
        },
        _ => None,
    }
}
