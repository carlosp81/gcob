//! Active-stream budgeting and cancellation-aware event bridging.
//!
//! Rate limits cover stream *creation*; these semaphores bound concurrent
//! streams globally and per client certificate. A [`StreamPermit`] is moved
//! into the streaming task, so the slot is released when the task exits —
//! including when the client disconnects and the response stream is dropped.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tonic::Status;

use crate::cln::cln_api;
use crate::events::types::Event;

/// Concurrency limits for server-streaming RPCs.
pub struct StreamLimits {
    global: Arc<Semaphore>,
    per_client: Mutex<HashMap<String, Arc<Semaphore>>>,
    max_global: usize,
    max_per_client: usize,
}

/// RAII permit holding one global and one per-client stream slot.
#[derive(Debug)]
pub struct StreamPermit {
    _global: OwnedSemaphorePermit,
    _client: OwnedSemaphorePermit,
}

impl StreamLimits {
    pub fn new(max_global: usize, max_per_client: usize) -> Arc<Self> {
        Arc::new(Self {
            global: Arc::new(Semaphore::new(max_global)),
            per_client: Mutex::new(HashMap::new()),
            max_global,
            max_per_client,
        })
    }

    /// Reserve a stream slot for `client_key` (the certificate fingerprint).
    ///
    /// Fails closed with `RESOURCE_EXHAUSTED` when either the global or the
    /// per-client budget is already fully used.
    pub fn acquire(&self, client_key: &str) -> Result<StreamPermit, Status> {
        let client = {
            let mut map = self.per_client.lock().unwrap();
            map.entry(client_key.to_string())
                .or_insert_with(|| Arc::new(Semaphore::new(self.max_per_client)))
                .clone()
        };

        let global = self.global.clone().try_acquire_owned().map_err(|_| {
            Status::resource_exhausted("Too many active streams (global limit reached)")
        })?;
        let client_permit = client
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("Too many active streams for this client"))?;

        Ok(StreamPermit {
            _global: global,
            _client: client_permit,
        })
    }

    /// Streams currently holding a slot across all clients.
    pub fn active_streams(&self) -> usize {
        self.max_global - self.global.available_permits()
    }

    /// Streams currently holding a slot for one client.
    pub fn active_streams_for(&self, client_key: &str) -> usize {
        let map = self.per_client.lock().unwrap();
        map.get(client_key)
            .map_or(0, |s| self.max_per_client - s.available_permits())
    }
}

/// Wait for the next router event or for the client to drop the response.
///
/// Returns `None` when the client disconnected (`proto_tx` closed) or the
/// router channel ended (`internal_rx` closed). `mpsc::Receiver::recv` and
/// `mpsc::Sender::closed` are both cancel-safe, so this can be used in a loop.
pub async fn next_event_or_cancel(
    internal_rx: &mut mpsc::Receiver<Event>,
    proto_tx: &mpsc::Sender<Result<cln_api::Event, Status>>,
) -> Option<Event> {
    tokio::select! {
        _ = proto_tx.closed() => None,
        event = internal_rx.recv() => event,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn per_client_limit_is_enforced() {
        let limits = StreamLimits::new(10, 2);
        let first = limits.acquire("cert-a").unwrap();
        let second = limits.acquire("cert-a").unwrap();

        let err = limits.acquire("cert-a").unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(limits.active_streams_for("cert-a"), 2);

        drop(first);
        assert_eq!(limits.active_streams_for("cert-a"), 1);

        let third = limits.acquire("cert-a").unwrap();
        drop(second);
        drop(third);
        assert_eq!(limits.active_streams_for("cert-a"), 0);
    }

    #[test]
    fn clients_have_independent_budgets() {
        let limits = StreamLimits::new(10, 1);
        let _a = limits.acquire("cert-a").unwrap();
        let _b = limits.acquire("cert-b").unwrap();
        assert_eq!(limits.active_streams_for("cert-a"), 1);
        assert_eq!(limits.active_streams_for("cert-b"), 1);
    }

    #[test]
    fn global_limit_is_shared() {
        let limits = StreamLimits::new(2, 10);
        let a = limits.acquire("cert-a").unwrap();
        let b = limits.acquire("cert-b").unwrap();

        let err = limits.acquire("cert-c").unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(limits.active_streams(), 2);

        drop(a);
        let _c = limits.acquire("cert-c").unwrap();
        drop(b);
        assert_eq!(limits.active_streams(), 1);
    }

    #[tokio::test]
    async fn next_event_or_cancel_returns_pending_event() {
        let (tx, mut rx) = mpsc::channel::<Event>(4);
        let (proto_tx, _proto_rx) = mpsc::channel::<Result<cln_api::Event, Status>>(4);

        tx.send(Event::Invoice(crate::events::types::InvoiceEvent::Paid {
            event_id: "evt-1".into(),
            timestamp: 1,
            label: "l".into(),
            amount_msat: 1,
            payment_hash: "h".into(),
        }))
        .await
        .unwrap();

        let event = next_event_or_cancel(&mut rx, &proto_tx).await;
        assert!(matches!(
            event,
            Some(Event::Invoice(
                crate::events::types::InvoiceEvent::Paid { .. }
            ))
        ));
    }

    #[tokio::test]
    async fn next_event_or_cancel_detects_client_disconnect_without_events() {
        let (_tx, mut rx) = mpsc::channel::<Event>(4);
        let (proto_tx, proto_rx) = mpsc::channel::<Result<cln_api::Event, Status>>(4);
        drop(proto_rx);

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            next_event_or_cancel(&mut rx, &proto_tx),
        )
        .await
        .expect("cancellation must resolve immediately");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn next_event_or_cancel_detects_router_channel_close() {
        let (tx, mut rx) = mpsc::channel::<Event>(4);
        let (proto_tx, _proto_rx) = mpsc::channel::<Result<cln_api::Event, Status>>(4);
        drop(tx);

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            next_event_or_cancel(&mut rx, &proto_tx),
        )
        .await
        .expect("channel close must resolve immediately");
        assert!(result.is_none());
    }

    // --- Lifecycle regression (GCOB-004): disconnect frees subscriber and permit ---

    #[tokio::test]
    async fn client_disconnect_unsubscribes_and_releases_permit() {
        use crate::events::router::EventRouter;

        let router = Arc::new(EventRouter::new());
        let limits = StreamLimits::new(10, 10);
        let permit = limits.acquire("cert-a").unwrap();

        let (internal_tx, mut internal_rx) = mpsc::channel::<Event>(8);
        let (proto_tx, proto_rx) = mpsc::channel::<Result<cln_api::Event, Status>>(8);
        router
            .subscribe("payment", "sub-1".into(), internal_tx)
            .await
            .unwrap();
        assert_eq!(limits.active_streams(), 1);
        assert_eq!(router.subscriber_count("payment").await, 1);

        let handle = tokio::spawn({
            let router = router.clone();
            async move {
                let _permit = permit;
                while next_event_or_cancel(&mut internal_rx, &proto_tx)
                    .await
                    .is_some()
                {}
                router.unsubscribe("payment", "sub-1").await;
            }
        });

        // Client disconnects (response body dropped): task must exit on its own.
        drop(proto_rx);
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("stream task must stop on client disconnect")
            .unwrap();

        assert_eq!(router.subscriber_count("payment").await, 0);
        assert_eq!(limits.active_streams(), 0);
    }

    #[tokio::test]
    async fn repeated_open_and_abandon_returns_to_baseline() {
        use crate::events::router::EventRouter;

        let router = Arc::new(EventRouter::new());
        let limits = StreamLimits::new(4, 4);

        for i in 0..100 {
            let permit = limits.acquire("cert-a").unwrap();
            let (internal_tx, mut internal_rx) = mpsc::channel::<Event>(8);
            let (proto_tx, proto_rx) = mpsc::channel::<Result<cln_api::Event, Status>>(8);
            router
                .subscribe("payment", format!("sub-{i}"), internal_tx)
                .await
                .unwrap();

            let handle = tokio::spawn({
                let router = router.clone();
                async move {
                    let _permit = permit;
                    while next_event_or_cancel(&mut internal_rx, &proto_tx)
                        .await
                        .is_some()
                    {}
                    router.unsubscribe("payment", &format!("sub-{i}")).await;
                }
            });

            drop(proto_rx);
            tokio::time::timeout(Duration::from_secs(1), handle)
                .await
                .expect("stream task must stop on client disconnect")
                .unwrap();
        }

        assert_eq!(router.total_subscribers().await, 0);
        assert_eq!(limits.active_streams(), 0);
        assert_eq!(limits.active_streams_for("cert-a"), 0);
    }
}
