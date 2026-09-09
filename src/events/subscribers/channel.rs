use tokio::sync::mpsc;

use crate::cln::cln_api::node_client::NodeClient;
use crate::cln::cln_api::{StreamChannelOpenFailedRequest, StreamChannelOpenedRequest};
use tonic::transport::Channel;

use super::super::types::*;

pub async fn run(client: &mut NodeClient<Channel>, tx: mpsc::Sender<Event>) {
    let mut opened_stream = match client
        .subscribe_channel_opened(StreamChannelOpenedRequest {})
        .await
    {
        Ok(resp) => resp.into_inner(),
        Err(e) => {
            tracing::warn!("subscribe_channel_opened failed: {}", e);
            return;
        }
    };

    let mut failed_stream = match client
        .subscribe_channel_open_failed(StreamChannelOpenFailedRequest {})
        .await
    {
        Ok(resp) => resp.into_inner(),
        Err(e) => {
            tracing::warn!("subscribe_channel_open_failed failed: {}", e);
            return;
        }
    };

    loop {
        tokio::select! {
            result = opened_stream.message() => {
                match result {
                    Ok(Some(n)) => {
                        let event = Event::Channel(ChannelEvent::Opened {
                            event_id: format!("cln-chan-open-{}", hex::encode(&n.id[..8])),
                            timestamp: 0,
                            node_id: hex::encode(&n.id),
                            channel_id: hex::encode(&n.funding_txid),
                            amount_msat: n.funding_msat.as_ref().map_or(0, |a| a.msat),
                        });
                        let _ = tx.send(event).await;
                    }
                    Ok(None) => {
                        tracing::info!("channel opened stream ended");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("channel opened stream error: {}", e);
                        break;
                    }
                }
            }
            result = failed_stream.message() => {
                match result {
                    Ok(Some(n)) => {
                        let event = Event::Channel(ChannelEvent::OpenFailed {
                            event_id: format!("cln-chan-fail-{}", hex::encode(&n.channel_id[..8])),
                            timestamp: 0,
                            node_id: hex::encode(&n.channel_id),
                            reason: String::new(),
                        });
                        let _ = tx.send(event).await;
                    }
                    Ok(None) => {
                        tracing::info!("channel open failed stream ended");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("channel open failed stream error: {}", e);
                        break;
                    }
                }
            }
        }
    }
}
