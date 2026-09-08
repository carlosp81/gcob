use tokio::sync::mpsc;

use crate::cln::cln_api::node_client::NodeClient;
use crate::cln::cln_api::{StreamConnectRequest, StreamDisconnectRequest};
use tonic::transport::Channel;

use super::super::types::*;

pub async fn run(client: &mut NodeClient<Channel>, tx: mpsc::Sender<Event>) {
    let mut connect_stream = client
        .subscribe_connect(StreamConnectRequest {})
        .await
        .expect("subscribe_connect")
        .into_inner();

    let mut disconnect_stream = client
        .subscribe_disconnect(StreamDisconnectRequest {})
        .await
        .expect("subscribe_disconnect")
        .into_inner();

    loop {
        tokio::select! {
            result = connect_stream.message() => {
                match result {
                    Ok(Some(n)) => {
                        let event = Event::Peer(PeerEvent::Connected {
                            event_id: format!("cln-peer-conn-{}", hex::encode(&n.id[..8])),
                            timestamp: 0,
                            node_id: hex::encode(&n.id),
                            addr: String::new(),
                            direction: String::new(),
                        });
                        let _ = tx.send(event).await;
                    }
                    Ok(None) => {
                        tracing::info!("peer connect stream ended");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("peer connect stream error: {}", e);
                        break;
                    }
                }
            }
            result = disconnect_stream.message() => {
                match result {
                    Ok(Some(n)) => {
                        let event = Event::Peer(PeerEvent::Disconnected {
                            event_id: format!("cln-peer-disc-{}", hex::encode(&n.id[..8])),
                            timestamp: 0,
                            node_id: hex::encode(&n.id),
                        });
                        let _ = tx.send(event).await;
                    }
                    Ok(None) => {
                        tracing::info!("peer disconnect stream ended");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("peer disconnect stream error: {}", e);
                        break;
                    }
                }
            }
        }
    }
}
