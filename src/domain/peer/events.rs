use crate::cln::cln_api;
use crate::events::types;

pub fn to_proto_event(event: &types::Event) -> Option<cln_api::Event> {
    match event {
        types::Event::Peer(e) => match e {
            types::PeerEvent::Connected {
                event_id,
                timestamp,
                node_id,
                addr,
                direction,
                ..
            } => {
                let rec = crate::events::enricher::peer_recommendation(e);
                tracing::info!(
                    node_id = %node_id,
                    addr = %addr,
                    direction = %direction,
                    "converted PeerConnected"
                );
                Some(cln_api::Event {
                    event: Some(cln_api::event::Event::PeerConnected(
                        cln_api::PeerConnected {
                            event_id: event_id.clone(),
                            timestamp: *timestamp,
                            node_id: node_id.clone(),
                            addr: addr.clone(),
                            direction: direction.clone(),
                            recommendation: format!("{}. {}", rec.summary, rec.action),
                        },
                    )),
                })
            }
            types::PeerEvent::Disconnected {
                event_id,
                timestamp,
                node_id,
                ..
            } => {
                let rec = crate::events::enricher::peer_recommendation(e);
                tracing::info!(
                    node_id = %node_id,
                    "converted PeerDisconnected"
                );
                Some(cln_api::Event {
                    event: Some(cln_api::event::Event::PeerDisconnected(
                        cln_api::PeerDisconnected {
                            event_id: event_id.clone(),
                            timestamp: *timestamp,
                            node_id: node_id.clone(),
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
