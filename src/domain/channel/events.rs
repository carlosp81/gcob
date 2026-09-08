use crate::cln::cln_api;
use crate::events::types;

pub fn to_proto_event(event: &types::Event) -> Option<cln_api::Event> {
    match event {
        types::Event::Channel(e) => match e {
            types::ChannelEvent::Opened {
                event_id,
                timestamp,
                node_id,
                channel_id,
                amount_msat,
                ..
            } => {
                let rec = crate::events::enricher::channel_recommendation(e);
                tracing::info!(
                    channel_id = %channel_id,
                    node_id = %node_id,
                    amount_msat = %amount_msat,
                    "converted ChannelOpened"
                );
                Some(cln_api::Event {
                    event: Some(cln_api::event::Event::ChannelOpened(
                        cln_api::ChannelOpened {
                            event_id: event_id.clone(),
                            timestamp: *timestamp,
                            node_id: node_id.clone(),
                            channel_id: channel_id.clone(),
                            amount_msat: *amount_msat,
                            recommendation: format!("{}. {}", rec.summary, rec.action),
                        },
                    )),
                })
            }
            types::ChannelEvent::OpenFailed {
                event_id,
                timestamp,
                node_id,
                reason,
                ..
            } => {
                let rec = crate::events::enricher::channel_recommendation(e);
                tracing::warn!(
                    node_id = %node_id,
                    reason = %reason,
                    "converted ChannelOpenFailed"
                );
                Some(cln_api::Event {
                    event: Some(cln_api::event::Event::ChannelOpenFailed(
                        cln_api::ChannelOpenFailed {
                            event_id: event_id.clone(),
                            timestamp: *timestamp,
                            node_id: node_id.clone(),
                            reason: reason.clone(),
                            recommendation: format!("{}. {}", rec.summary, rec.action),
                        },
                    )),
                })
            }
            types::ChannelEvent::StateChanged {
                event_id,
                timestamp,
                channel_id,
                old_state,
                new_state,
                ..
            } => {
                let rec = crate::events::enricher::channel_recommendation(e);
                tracing::info!(
                    channel_id = %channel_id,
                    old_state = %old_state,
                    new_state = %new_state,
                    "converted ChannelStateChanged"
                );
                Some(cln_api::Event {
                    event: Some(cln_api::event::Event::ChannelStateChanged(
                        cln_api::ChannelStateChanged {
                            event_id: event_id.clone(),
                            timestamp: *timestamp,
                            channel_id: channel_id.clone(),
                            old_state: old_state.clone(),
                            new_state: new_state.clone(),
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
