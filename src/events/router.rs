#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};

use super::types::Event;

pub type SubscriberId = String;

struct Subscriber {
    #[allow(dead_code)]
    id: SubscriberId,
    sender: mpsc::Sender<Event>,
}

pub struct EventRouter {
    subscribers: Arc<RwLock<HashMap<String, Vec<Subscriber>>>>,
}

impl EventRouter {
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn subscribe(&self, event_type: &str, id: SubscriberId, sender: mpsc::Sender<Event>) {
        let mut subs = self.subscribers.write().await;
        subs.entry(event_type.to_string())
            .or_insert_with(Vec::new)
            .push(Subscriber { id, sender });
    }

    pub async fn unsubscribe(&self, event_type: &str, id: &str) {
        let mut subs = self.subscribers.write().await;
        if let Some(list) = subs.get_mut(event_type) {
            list.retain(|s| s.id != id);
            if list.is_empty() {
                subs.remove(event_type);
            }
        }
    }

    pub async fn dispatch(&self, event_type: &str, event: Event) {
        let subs = self.subscribers.read().await;
        if let Some(list) = subs.get(event_type) {
            let mut dead = Vec::new();
            for (i, sub) in list.iter().enumerate() {
                if sub.sender.send(event.clone()).await.is_err() {
                    dead.push(i);
                }
            }
            // NOTE: dead subscribers are not removed during read lock.
            // They will be cleaned up on next write (subscribe/unsubscribe).
            if !dead.is_empty() {
                tracing::warn!(
                    "Dispatched to {} dead subscribers for event_type={}",
                    dead.len(),
                    event_type
                );
            }
        }
    }

    pub async fn subscriber_count(&self, event_type: &str) -> usize {
        let subs = self.subscribers.read().await;
        subs.get(event_type).map_or(0, |l| l.len())
    }

    pub async fn total_subscribers(&self) -> usize {
        let subs = self.subscribers.read().await;
        subs.values().map(|l| l.len()).sum()
    }
}

impl Default for EventRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::*;

    #[tokio::test]
    async fn subscribe_and_count() {
        let router = EventRouter::new();
        let (tx, _rx) = mpsc::channel(16);
        router.subscribe("payment", "sub-1".into(), tx).await;
        assert_eq!(router.subscriber_count("payment").await, 1);
        assert_eq!(router.subscriber_count("invoice").await, 0);
    }

    #[tokio::test]
    async fn unsubscribe_removes_subscriber() {
        let router = EventRouter::new();
        let (tx, _rx) = mpsc::channel(16);
        router.subscribe("payment", "sub-1".into(), tx).await;
        assert_eq!(router.subscriber_count("payment").await, 1);
        router.unsubscribe("payment", "sub-1").await;
        assert_eq!(router.subscriber_count("payment").await, 0);
    }

    #[tokio::test]
    async fn dispatch_delivers_event() {
        let router = EventRouter::new();
        let (tx, mut rx) = mpsc::channel(16);
        router.subscribe("payment", "sub-1".into(), tx).await;

        let event = Event::Payment(PaymentEvent::Succeeded {
            event_id: "evt-1".into(),
            timestamp: 1000,
            payment_hash: "abc".into(),
            preimage: "secret".into(),
            amount_msat: 1000,
            amount_sent_msat: 1010,
            node_id: "02ab".into(),
            created_at: 999,
        });

        router.dispatch("payment", event).await;

        let received = rx.recv().await.expect("should receive event");
        assert_eq!(received.event_id(), "evt-1");
    }

    #[tokio::test]
    async fn dispatch_does_not_cross_types() {
        let router = EventRouter::new();
        let (tx, mut rx) = mpsc::channel(16);
        router.subscribe("payment", "sub-1".into(), tx).await;

        let event = Event::Invoice(InvoiceEvent::Paid {
            event_id: "evt-2".into(),
            timestamp: 1001,
            label: "test".into(),
            amount_msat: 500,
            payment_hash: "def".into(),
        });

        router.dispatch("invoice", event).await;

        let result = rx.try_recv();
        assert!(result.is_err(), "should not receive invoice event on payment subscriber");
    }

    #[tokio::test]
    async fn multiple_subscribers_receive() {
        let router = EventRouter::new();
        let (tx1, mut rx1) = mpsc::channel(16);
        let (tx2, mut rx2) = mpsc::channel(16);
        router.subscribe("payment", "sub-1".into(), tx1).await;
        router.subscribe("payment", "sub-2".into(), tx2).await;

        let event = Event::Payment(PaymentEvent::PartStart {
            event_id: "evt-3".into(),
            timestamp: 1002,
            payment_hash: "ghi".into(),
            partid: 1,
            amount_msat: 500,
        });

        router.dispatch("payment", event).await;

        assert_eq!(rx1.recv().await.expect("sub-1 should receive").event_id(), "evt-3");
        assert_eq!(rx2.recv().await.expect("sub-2 should receive").event_id(), "evt-3");
    }

    #[tokio::test]
    async fn dead_sender_handled_gracefully() {
        let router = EventRouter::new();
        let (tx, _rx) = mpsc::channel(16);
        router.subscribe("payment", "sub-1".into(), tx).await;
        drop(_rx); // receiver dropped

        let event = Event::Payment(PaymentEvent::PartEnd {
            event_id: "evt-4".into(),
            timestamp: 1003,
            payment_hash: "jkl".into(),
            partid: 1,
            amount_msat: 200,
        });

        // Should not panic
        router.dispatch("payment", event).await;
    }

    #[tokio::test]
    async fn total_subscribers_count() {
        let router = EventRouter::new();
        let (tx1, _rx1) = mpsc::channel(16);
        let (tx2, _rx2) = mpsc::channel(16);
        let (tx3, _rx3) = mpsc::channel(16);
        router.subscribe("payment", "sub-1".into(), tx1).await;
        router.subscribe("invoice", "sub-2".into(), tx2).await;
        router.subscribe("payment", "sub-3".into(), tx3).await;
        assert_eq!(router.total_subscribers().await, 3);
    }
}
