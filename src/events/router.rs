use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};

use super::types::Event;

pub type SubscriberId = String;

/// Default consecutive send failures before a slow subscriber is dropped.
pub const DEFAULT_SLOW_SUBSCRIBER_MAX_DROPS: u64 = 64;

/// Subscriber caps and slow-consumer policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterLimits {
    pub max_subscribers_global: usize,
    pub max_subscribers_per_type: usize,
    pub slow_subscriber_max_drops: u64,
}

impl Default for RouterLimits {
    fn default() -> Self {
        Self {
            max_subscribers_global: 512,
            max_subscribers_per_type: 256,
            slow_subscriber_max_drops: DEFAULT_SLOW_SUBSCRIBER_MAX_DROPS,
        }
    }
}

/// Reason a subscription was refused by the router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeError {
    GlobalLimit,
    TypeLimit,
}

struct Subscriber {
    id: SubscriberId,
    sender: mpsc::Sender<Event>,
    /// Consecutive events dropped because the channel was full. Reset to zero
    /// whenever a send succeeds.
    drops: Arc<AtomicU64>,
}

/// Availability counters for the event fan-out.
#[derive(Debug, Default)]
pub struct EventRouterStats {
    /// Dispatches that had at least one subscriber.
    pub events_dispatched: AtomicU64,
    /// Events handed to a subscriber channel.
    pub events_delivered: AtomicU64,
    /// Events discarded because a subscriber channel was full or closed.
    pub events_dropped: AtomicU64,
    /// Subscribers removed for being dead or persistently slow.
    pub subscribers_dropped: AtomicU64,
}

pub struct EventRouter {
    subscribers: Arc<RwLock<HashMap<String, Vec<Subscriber>>>>,
    max_subscribers_global: usize,
    max_subscribers_per_type: usize,
    slow_subscriber_max_drops: u64,
    stats: Arc<EventRouterStats>,
}

impl EventRouter {
    pub fn new() -> Self {
        Self::with_limits(RouterLimits::default())
    }

    /// Router that drops a subscriber after `max_drops` consecutive failed
    /// sends, keeping the default subscriber caps.
    pub fn with_max_drops(slow_subscriber_max_drops: u64) -> Self {
        Self::with_limits(RouterLimits {
            slow_subscriber_max_drops,
            ..RouterLimits::default()
        })
    }

    /// Router with explicit subscriber caps and slow-consumer policy.
    pub fn with_limits(limits: RouterLimits) -> Self {
        Self {
            subscribers: Arc::new(RwLock::new(HashMap::new())),
            max_subscribers_global: limits.max_subscribers_global.max(1),
            max_subscribers_per_type: limits.max_subscribers_per_type.max(1),
            slow_subscriber_max_drops: limits.slow_subscriber_max_drops.max(1),
            stats: Arc::new(EventRouterStats::default()),
        }
    }

    /// Register a subscriber, enforcing the global and per-event-type caps.
    pub async fn subscribe(
        &self,
        event_type: &str,
        id: SubscriberId,
        sender: mpsc::Sender<Event>,
    ) -> Result<(), SubscribeError> {
        let mut subs = self.subscribers.write().await;

        let type_count = subs.get(event_type).map_or(0, |list| list.len());
        if type_count >= self.max_subscribers_per_type {
            return Err(SubscribeError::TypeLimit);
        }
        let total: usize = subs.values().map(|list| list.len()).sum();
        if total >= self.max_subscribers_global {
            return Err(SubscribeError::GlobalLimit);
        }

        subs.entry(event_type.to_string())
            .or_default()
            .push(Subscriber {
                id,
                sender,
                drops: Arc::new(AtomicU64::new(0)),
            });
        Ok(())
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

    /// Deliver an event without ever holding the subscriber lock across a
    /// send and without blocking on a slow subscriber.
    ///
    /// Senders are snapshotted under a short read lock; delivery uses
    /// `try_send`, so a full or closed channel costs nothing and the event is
    /// counted as dropped. A subscriber that keeps failing is unsubscribed
    /// after [`Self::slow_subscriber_max_drops`] consecutive drops.
    pub async fn dispatch(&self, event_type: &str, event: Event) {
        let snapshot: Vec<(SubscriberId, mpsc::Sender<Event>, Arc<AtomicU64>)> = {
            let subs = self.subscribers.read().await;
            subs.get(event_type)
                .map(|list| {
                    list.iter()
                        .map(|s| (s.id.clone(), s.sender.clone(), s.drops.clone()))
                        .collect()
                })
                .unwrap_or_default()
        };

        if snapshot.is_empty() {
            return;
        }

        self.stats.events_dispatched.fetch_add(1, Ordering::Relaxed);
        let mut to_remove: Vec<SubscriberId> = Vec::new();

        for (id, sender, drops) in snapshot {
            match sender.try_send(event.clone()) {
                Ok(()) => {
                    drops.store(0, Ordering::Relaxed);
                    self.stats.events_delivered.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                    let consecutive = drops.fetch_add(1, Ordering::Relaxed) + 1;
                    if consecutive >= self.slow_subscriber_max_drops {
                        to_remove.push(id);
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                    to_remove.push(id);
                }
            }
        }

        if !to_remove.is_empty() {
            let removed = to_remove.len() as u64;
            let mut subs = self.subscribers.write().await;
            if let Some(list) = subs.get_mut(event_type) {
                list.retain(|s| !to_remove.contains(&s.id));
                if list.is_empty() {
                    subs.remove(event_type);
                }
            }
            drop(subs);
            self.stats
                .subscribers_dropped
                .fetch_add(removed, Ordering::Relaxed);
            tracing::warn!(event_type, removed, "Unsubscribed dead or slow subscribers");
        }
    }

    pub fn stats(&self) -> Arc<EventRouterStats> {
        self.stats.clone()
    }

    pub fn slow_subscriber_max_drops(&self) -> u64 {
        self.slow_subscriber_max_drops
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
    use super::super::types::*;
    use super::*;
    use std::time::Duration;

    fn payment_event(id: &str) -> Event {
        Event::Payment(PaymentEvent::Succeeded {
            event_id: id.into(),
            timestamp: 1000,
            payment_hash: "abc".into(),
            preimage: "secret".into(),
            amount_msat: 1000,
            amount_sent_msat: 1010,
            node_id: "02ab".into(),
            created_at: 999,
        })
    }

    #[tokio::test]
    async fn subscribe_and_count() {
        let router = EventRouter::new();
        let (tx, _rx) = mpsc::channel(16);
        router
            .subscribe("payment", "sub-1".into(), tx)
            .await
            .unwrap();
        assert_eq!(router.subscriber_count("payment").await, 1);
        assert_eq!(router.subscriber_count("invoice").await, 0);
    }

    #[tokio::test]
    async fn unsubscribe_removes_subscriber() {
        let router = EventRouter::new();
        let (tx, _rx) = mpsc::channel(16);
        router
            .subscribe("payment", "sub-1".into(), tx)
            .await
            .unwrap();
        assert_eq!(router.subscriber_count("payment").await, 1);
        router.unsubscribe("payment", "sub-1").await;
        assert_eq!(router.subscriber_count("payment").await, 0);
    }

    #[tokio::test]
    async fn dispatch_delivers_event() {
        let router = EventRouter::new();
        let (tx, mut rx) = mpsc::channel(16);
        router
            .subscribe("payment", "sub-1".into(), tx)
            .await
            .unwrap();

        router.dispatch("payment", payment_event("evt-1")).await;

        let received = rx.recv().await.expect("should receive event");
        assert_eq!(received.event_id(), "evt-1");
    }

    #[tokio::test]
    async fn dispatch_does_not_cross_types() {
        let router = EventRouter::new();
        let (tx, mut rx) = mpsc::channel(16);
        router
            .subscribe("payment", "sub-1".into(), tx)
            .await
            .unwrap();

        let event = Event::Invoice(InvoiceEvent::Paid {
            event_id: "evt-2".into(),
            timestamp: 1001,
            label: "test".into(),
            amount_msat: 500,
            payment_hash: "def".into(),
        });

        router.dispatch("invoice", event).await;

        let result = rx.try_recv();
        assert!(
            result.is_err(),
            "should not receive invoice event on payment subscriber"
        );
    }

    #[tokio::test]
    async fn multiple_subscribers_receive() {
        let router = EventRouter::new();
        let (tx1, mut rx1) = mpsc::channel(16);
        let (tx2, mut rx2) = mpsc::channel(16);
        router
            .subscribe("payment", "sub-1".into(), tx1)
            .await
            .unwrap();
        router
            .subscribe("payment", "sub-2".into(), tx2)
            .await
            .unwrap();

        let event = Event::Payment(PaymentEvent::PartStart {
            event_id: "evt-3".into(),
            timestamp: 1002,
            payment_hash: "ghi".into(),
            partid: 1,
            amount_msat: 500,
        });

        router.dispatch("payment", event).await;

        assert_eq!(
            rx1.recv().await.expect("sub-1 should receive").event_id(),
            "evt-3"
        );
        assert_eq!(
            rx2.recv().await.expect("sub-2 should receive").event_id(),
            "evt-3"
        );
    }

    #[tokio::test]
    async fn dead_sender_is_removed_during_dispatch() {
        let router = EventRouter::new();
        let (tx, rx) = mpsc::channel(16);
        router
            .subscribe("payment", "sub-1".into(), tx)
            .await
            .unwrap();
        drop(rx); // receiver dropped

        // Must not panic, and the dead subscriber must be gone afterwards.
        router.dispatch("payment", payment_event("evt-4")).await;
        assert_eq!(router.subscriber_count("payment").await, 0);
        assert_eq!(
            router.stats().subscribers_dropped.load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn total_subscribers_count() {
        let router = EventRouter::new();
        let (tx1, _rx1) = mpsc::channel(16);
        let (tx2, _rx2) = mpsc::channel(16);
        let (tx3, _rx3) = mpsc::channel(16);
        router
            .subscribe("payment", "sub-1".into(), tx1)
            .await
            .unwrap();
        router
            .subscribe("invoice", "sub-2".into(), tx2)
            .await
            .unwrap();
        router
            .subscribe("payment", "sub-3".into(), tx3)
            .await
            .unwrap();
        assert_eq!(router.total_subscribers().await, 3);
    }

    // --- GCOB-005/006 regression tests ---

    #[tokio::test]
    async fn dispatch_does_not_block_on_full_subscriber() {
        let router = EventRouter::new();
        let (slow_tx, _slow_rx) = mpsc::channel(1);
        let (fast_tx, mut fast_rx) = mpsc::channel(16);
        router
            .subscribe("payment", "slow".into(), slow_tx.clone())
            .await
            .unwrap();
        router
            .subscribe("payment", "fast".into(), fast_tx)
            .await
            .unwrap();

        // Fill the slow subscriber's only slot.
        slow_tx.try_send(payment_event("filler")).unwrap();

        tokio::time::timeout(
            Duration::from_millis(100),
            router.dispatch("payment", payment_event("evt-5")),
        )
        .await
        .expect("dispatch must not block on a full subscriber channel");

        // The healthy subscriber still receives the event.
        let received = fast_rx.recv().await.expect("fast subscriber receives");
        assert_eq!(received.event_id(), "evt-5");
        assert_eq!(
            router.stats().events_dropped.load(Ordering::Relaxed),
            1,
            "the full channel must be counted as a drop"
        );
    }

    #[tokio::test]
    async fn slow_subscriber_is_dropped_after_max_consecutive_drops() {
        let router = EventRouter::with_max_drops(3);
        let (slow_tx, _slow_rx) = mpsc::channel(1);
        router
            .subscribe("payment", "slow".into(), slow_tx.clone())
            .await
            .unwrap();
        slow_tx.try_send(payment_event("filler")).unwrap();

        for i in 0..2 {
            tokio::time::timeout(
                Duration::from_millis(100),
                router.dispatch("payment", payment_event(&format!("evt-{i}"))),
            )
            .await
            .expect("dispatch must not block");
            assert_eq!(
                router.subscriber_count("payment").await,
                1,
                "subscriber must survive until the threshold"
            );
        }

        tokio::time::timeout(
            Duration::from_millis(100),
            router.dispatch("payment", payment_event("evt-3")),
        )
        .await
        .expect("dispatch must not block");

        assert_eq!(
            router.subscriber_count("payment").await,
            0,
            "subscriber must be unsubscribed at the threshold"
        );
        assert_eq!(
            router.stats().subscribers_dropped.load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn draining_the_channel_resets_the_drop_counter() {
        let router = EventRouter::with_max_drops(2);
        let (tx, mut rx) = mpsc::channel(1);
        router
            .subscribe("payment", "sub".into(), tx.clone())
            .await
            .unwrap();
        tx.try_send(payment_event("filler")).unwrap();

        // First dispatch fails (channel full after the filler).
        router.dispatch("payment", payment_event("evt-1")).await;
        // Drain the filler so the next send succeeds.
        let _ = rx.recv().await;
        router.dispatch("payment", payment_event("evt-2")).await;
        // Drain the delivered event before filling the single slot again.
        let _ = rx.recv().await;
        // The counter must have been reset by the successful send, so the
        // subscriber survives another full-channel dispatch.
        tx.try_send(payment_event("filler-2")).unwrap();
        router.dispatch("payment", payment_event("evt-3")).await;

        assert_eq!(
            router.subscriber_count("payment").await,
            1,
            "a successful send must reset consecutive drops"
        );
    }

    #[tokio::test]
    async fn stats_track_delivered_and_dropped() {
        let router = EventRouter::new();
        let (full_tx, _full_rx) = mpsc::channel(1);
        let (ok_tx, mut ok_rx) = mpsc::channel(16);
        router
            .subscribe("payment", "full".into(), full_tx.clone())
            .await
            .unwrap();
        router
            .subscribe("payment", "ok".into(), ok_tx)
            .await
            .unwrap();
        full_tx.try_send(payment_event("filler")).unwrap();

        router.dispatch("payment", payment_event("evt-1")).await;

        let stats = router.stats();
        assert_eq!(stats.events_dispatched.load(Ordering::Relaxed), 1);
        assert_eq!(stats.events_delivered.load(Ordering::Relaxed), 1);
        assert_eq!(stats.events_dropped.load(Ordering::Relaxed), 1);
        assert_eq!(ok_rx.recv().await.unwrap().event_id(), "evt-1");
    }

    // --- Subscriber caps ---

    #[tokio::test]
    async fn subscribe_enforces_per_type_limit() {
        let router = EventRouter::with_limits(RouterLimits {
            max_subscribers_global: 10,
            max_subscribers_per_type: 2,
            slow_subscriber_max_drops: 64,
        });
        let (tx1, _rx1) = mpsc::channel(4);
        let (tx2, _rx2) = mpsc::channel(4);
        let (tx3, _rx3) = mpsc::channel(4);

        router.subscribe("payment", "s1".into(), tx1).await.unwrap();
        router.subscribe("payment", "s2".into(), tx2).await.unwrap();
        assert_eq!(
            router
                .subscribe("payment", "s3".into(), tx3)
                .await
                .unwrap_err(),
            SubscribeError::TypeLimit
        );
        assert_eq!(router.subscriber_count("payment").await, 2);
    }

    #[tokio::test]
    async fn subscribe_enforces_global_limit() {
        let router = EventRouter::with_limits(RouterLimits {
            max_subscribers_global: 2,
            max_subscribers_per_type: 10,
            slow_subscriber_max_drops: 64,
        });
        let (tx1, _rx1) = mpsc::channel(4);
        let (tx2, _rx2) = mpsc::channel(4);
        let (tx3, _rx3) = mpsc::channel(4);

        router.subscribe("payment", "s1".into(), tx1).await.unwrap();
        router.subscribe("invoice", "s2".into(), tx2).await.unwrap();
        assert_eq!(
            router
                .subscribe("peer", "s3".into(), tx3)
                .await
                .unwrap_err(),
            SubscribeError::GlobalLimit
        );
        assert_eq!(router.total_subscribers().await, 2);
    }

    #[tokio::test]
    async fn unsubscribe_frees_subscriber_budget() {
        let router = EventRouter::with_limits(RouterLimits {
            max_subscribers_global: 1,
            max_subscribers_per_type: 1,
            slow_subscriber_max_drops: 64,
        });
        let (tx1, _rx1) = mpsc::channel(4);
        let (tx2, _rx2) = mpsc::channel(4);

        router.subscribe("payment", "s1".into(), tx1).await.unwrap();
        assert!(router
            .subscribe("payment", "s2".into(), tx2.clone())
            .await
            .is_err());

        router.unsubscribe("payment", "s1").await;
        router.subscribe("payment", "s2".into(), tx2).await.unwrap();
        assert_eq!(router.total_subscribers().await, 1);
    }
}
