use tokio::sync::mpsc;

use crate::cln::cln_api::node_client::NodeClient;
use crate::cln::cln_api::StreamWarningRequest;
use tonic::transport::Channel;

use super::super::types::*;

pub async fn run(client: &mut NodeClient<Channel>, tx: mpsc::Sender<Event>) {
    let mut stream = match client.subscribe_warning(StreamWarningRequest {}).await {
        Ok(resp) => resp.into_inner(),
        Err(e) => {
            tracing::warn!("subscribe_warning failed: {}", e);
            return;
        }
    };

    loop {
        match stream.message().await {
            Ok(Some(n)) => {
                let event = Event::System(SystemEvent::Warning {
                    event_id: format!("cln-warn-{}", n.timestamp),
                    timestamp: 0,
                    source: n.source,
                    log: n.log,
                });
                let _ = tx.send(event).await;
            }
            Ok(None) => {
                tracing::info!("system warning stream ended");
                break;
            }
            Err(e) => {
                tracing::warn!("system warning stream error: {}", e);
                break;
            }
        }
    }
}
