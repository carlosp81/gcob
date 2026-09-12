pub mod channel;
pub mod invoice;
pub mod payment;
pub mod peer;
pub mod system;

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::cln::cln_api::node_client::NodeClient;
use tonic::transport::Channel;

use super::router::EventRouter;
use super::types::Event;

pub struct ClnEventBridge {
    router: Arc<EventRouter>,
    client: NodeClient<Channel>,
}

impl ClnEventBridge {
    pub fn new(client: NodeClient<Channel>, router: Arc<EventRouter>) -> Self {
        Self { client, router }
    }

    pub async fn start_all(&mut self) {
        let mut handles = Vec::new();

        let (bridge_tx, mut bridge_rx) = mpsc::channel::<Event>(256);

        // Start payment subscriber
        {
            let mut client = self.client.clone();
            let tx = bridge_tx.clone();
            handles.push(tokio::spawn(async move {
                payment::run(&mut client, tx).await;
            }));
        }

        // Start invoice subscriber
        {
            let mut client = self.client.clone();
            let tx = bridge_tx.clone();
            handles.push(tokio::spawn(async move {
                invoice::run(&mut client, tx).await;
            }));
        }

        // Start channel subscriber
        {
            let mut client = self.client.clone();
            let tx = bridge_tx.clone();
            handles.push(tokio::spawn(async move {
                channel::run(&mut client, tx).await;
            }));
        }

        // Start peer subscriber
        {
            let mut client = self.client.clone();
            let tx = bridge_tx.clone();
            handles.push(tokio::spawn(async move {
                peer::run(&mut client, tx).await;
            }));
        }

        // Start system subscriber
        {
            let mut client = self.client.clone();
            let tx = bridge_tx.clone();
            handles.push(tokio::spawn(async move {
                system::run(&mut client, tx).await;
            }));
        }

        // Drop the original sender so bridge_rx completes when all tasks drop their senders
        drop(bridge_tx);

        // Dispatcher loop: route events from bridge to EventRouter
        let router = self.router.clone();
        while let Some(event) = bridge_rx.recv().await {
            let event_type = match &event {
                Event::Payment(_) => "payment",
                Event::Invoice(_) => "invoice",
                Event::Channel(_) => "channel",
                Event::Peer(_) => "peer",
                Event::System(_) => "system",
            };
            router.dispatch(event_type, event).await;
        }

        // All senders dropped — join handles
        for h in handles {
            let _ = h.await;
        }
    }
}
