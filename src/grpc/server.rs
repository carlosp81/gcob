use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use redis::Client;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use crate::certs::mtls_certs::ClnConfig;
use crate::certs::paths::read_secure_file;
use crate::cln::client::ClnClient;
use crate::cln::cln_api::node_services_server::NodeServicesServer;
use crate::events::router::{EventRouter, RouterLimits};
use crate::events::subscribers::ClnEventBridge;
use crate::grpc::interceptors::admission_layer::AdmissionLayer;
use crate::grpc::interceptors::auth_layer::AuthLayer;
use crate::grpc::interceptors::identity::ClientIdentityLayer;
use crate::grpc::interceptors::rate_limit_layer::RateLimitLayer;
use crate::grpc::interceptors::rate_limiter::InMemoryRateLimiter;
use crate::grpc::limits::Limits;
use crate::grpc::stream_limits::{StreamLimits, IDLE_CLIENT_CLEANUP_INTERVAL};

/// Interval between availability snapshots emitted as structured logs.
const AVAILABILITY_SNAPSHOT_INTERVAL: Duration = Duration::from_secs(60);

pub struct ApiService {
    pub client: Arc<ClnClient>,
    pub event_router: Arc<EventRouter>,
    pub stream_limits: Arc<StreamLimits>,
}

/// Point-in-time availability gauges emitted periodically by `gcob serve`.
///
/// Read-only snapshot: it takes existing atomic/under-lock values and never
/// holds a lock across an await beyond the router's own read lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AvailabilitySnapshot {
    active_streams: usize,
    tracked_clients: usize,
    idle_clients: usize,
    subscribers: usize,
    events_dispatched: u64,
    events_delivered: u64,
    events_dropped: u64,
    subscribers_dropped: u64,
    fallback_buckets: usize,
}

impl AvailabilitySnapshot {
    async fn collect(
        limits: &StreamLimits,
        router: &EventRouter,
        fallback: &InMemoryRateLimiter,
    ) -> Self {
        let stats = router.stats();
        Self {
            active_streams: limits.active_streams(),
            tracked_clients: limits.tracked_clients(),
            idle_clients: limits.idle_clients(),
            subscribers: router.total_subscribers().await,
            events_dispatched: stats.events_dispatched.load(Ordering::Relaxed),
            events_delivered: stats.events_delivered.load(Ordering::Relaxed),
            events_dropped: stats.events_dropped.load(Ordering::Relaxed),
            subscribers_dropped: stats.subscribers_dropped.load(Ordering::Relaxed),
            fallback_buckets: fallback.tracked_keys().await,
        }
    }

    fn emit(&self) {
        tracing::info!(
            active_streams = self.active_streams,
            tracked_clients = self.tracked_clients,
            idle_clients = self.idle_clients,
            subscribers = self.subscribers,
            events_dispatched = self.events_dispatched,
            events_delivered = self.events_delivered,
            events_dropped = self.events_dropped,
            subscribers_dropped = self.subscribers_dropped,
            fallback_buckets = self.fallback_buckets,
            "availability snapshot"
        );
    }
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits::from_env().map_err(std::io::Error::other)?;
    let cert_config = ClnConfig::from_env()?;
    cert_config.validate_all()?;
    let client = ClnClient::connect(&cert_config).await?;
    let addr = cert_config.grpc_bind_addr.parse()?;

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let redis_cm = match Client::open(redis_url.as_str()) {
        Ok(redis_client) => match redis_client.get_multiplexed_async_connection().await {
            Ok(cm) => {
                tracing::info!("Valkey connected - rate limiting enabled");
                Some(cm)
            }
            Err(e) => {
                tracing::warn!("Valkey not connected: {} - rate limiting disabled", e);
                None
            }
        },
        Err(e) => {
            tracing::warn!("Valkey not connected: {} - rate limiting disabled", e);
            None
        }
    };

    let server_cert = read_secure_file(&cert_config.server_file, false)?;
    let server_key = read_secure_file(&cert_config.server_key_file, true)?;
    let ca_cert = read_secure_file(&cert_config.ca_file, false)?;

    let tls_config = ServerTlsConfig::new()
        .identity(Identity::from_pem(server_cert, server_key))
        .client_ca_root(Certificate::from_pem(ca_cert));

    // --- Event bridge setup ---
    let router = Arc::new(EventRouter::with_limits(RouterLimits {
        max_subscribers_global: limits.max_subscribers_global,
        max_subscribers_per_type: limits.max_subscribers_per_type,
        slow_subscriber_max_drops: limits.slow_subscriber_max_drops,
    }));
    let mut bridge = ClnEventBridge::new(client.inner.clone(), router.clone());
    let bridge_handle = tokio::spawn(async move {
        bridge.start_all().await;
    });
    tracing::info!("Event bridge started");

    // --- In-memory rate limiter fallback ---
    let in_memory_limiter = InMemoryRateLimiter::new();
    let limiter_clone = in_memory_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            limiter_clone.cleanup().await;
        }
    });

    // --- Stream limits + idle-client reclamation ---
    //
    // The per-client map is keyed by certificate fingerprint; without cleanup
    // it would retain one semaphore per fingerprint ever seen. `cleanup_idle`
    // only removes entries with no active stream and no in-flight acquire.
    let stream_limits = StreamLimits::new(
        limits.max_active_streams_global,
        limits.max_active_streams_per_client,
    );
    let cleanup_limits = stream_limits.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(IDLE_CLIENT_CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            let removed = cleanup_limits.cleanup_idle();
            if removed > 0 {
                tracing::debug!(removed, "Removed idle stream-limit client entries");
            }
        }
    });

    // --- Periodic availability snapshot ---
    //
    // Emits gauges that the availability invariants are checked against
    // (streams, tracked clients, subscribers, router stats, fallback buckets)
    // without adding any network endpoint.
    let snapshot_limits = stream_limits.clone();
    let snapshot_router = router.clone();
    let snapshot_fallback = in_memory_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(AVAILABILITY_SNAPSHOT_INTERVAL);
        loop {
            interval.tick().await;
            AvailabilitySnapshot::collect(&snapshot_limits, &snapshot_router, &snapshot_fallback)
                .await
                .emit();
        }
    });

    let api_service = ApiService {
        client: Arc::new(client),
        event_router: router,
        stream_limits,
    };

    tracing::info!("gRPC API server listening on {}", addr);

    let auth_layer = AuthLayer::new(api_service.client.clone(), limits.max_request_body_bytes);
    let admission_layer = AdmissionLayer::new(redis_cm.clone(), in_memory_limiter.clone(), &limits);
    let rate_limit_layer = RateLimitLayer::new(redis_cm, in_memory_limiter);
    let max_decoding_message_size = limits.max_request_body_bytes;

    // tower calls the layer added FIRST first (first added = outermost):
    // identity -> admission -> auth -> rate limit -> service. The pre-auth
    // budget is consumed before any CLN interaction; only authenticated
    // requests consume method quota.
    //
    // Transport limits bound per-connection resources independently of the
    // application budgets; keepalive detects dead peers on idle streams.
    Server::builder()
        .tls_config(tls_config)?
        .max_concurrent_streams(limits.max_concurrent_streams)
        .concurrency_limit_per_connection(limits.concurrency_limit_per_connection)
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .http2_keepalive_interval(Some(Duration::from_secs(30)))
        .http2_keepalive_timeout(Some(Duration::from_secs(10)))
        .http2_max_pending_accept_reset_streams(Some(limits.concurrency_limit_per_connection))
        .layer(ClientIdentityLayer::new())
        .layer(admission_layer)
        .layer(auth_layer)
        .layer(rate_limit_layer)
        .add_service(
            NodeServicesServer::new(api_service)
                .max_decoding_message_size(max_decoding_message_size),
        )
        .serve_with_shutdown(addr, shutdown_signal(bridge_handle))
        .await?;
    Ok(())
}

async fn shutdown_signal(bridge_handle: tokio::task::JoinHandle<()>) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received, starting graceful shutdown");
    bridge_handle.abort();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::types::Event;
    use crate::grpc::interceptors::rate_limiter::PAYMENT_POLICY;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn availability_snapshot_reflects_current_state() {
        let limits = StreamLimits::new(10, 2);
        let router = EventRouter::new();
        let fallback = InMemoryRateLimiter::new();

        let _permit = limits.acquire("cert-a").unwrap();
        let (tx, _rx) = mpsc::channel::<Event>(4);
        router
            .subscribe("payment", "sub-1".into(), tx)
            .await
            .unwrap();
        assert!(fallback.check("key", PAYMENT_POLICY).await);

        let snapshot = AvailabilitySnapshot::collect(&limits, &router, &fallback).await;
        assert_eq!(snapshot.active_streams, 1);
        assert_eq!(snapshot.tracked_clients, 1);
        assert_eq!(snapshot.idle_clients, 0);
        assert_eq!(snapshot.subscribers, 1);
        assert_eq!(snapshot.fallback_buckets, 1);
        assert_eq!(snapshot.events_dispatched, 0);
        assert_eq!(snapshot.subscribers_dropped, 0);
    }

    #[tokio::test]
    async fn availability_snapshot_returns_to_baseline() {
        let limits = StreamLimits::new(10, 2);
        let router = EventRouter::new();
        let fallback = InMemoryRateLimiter::new();

        drop(limits.acquire("cert-a").unwrap());
        limits.cleanup_idle();

        let snapshot = AvailabilitySnapshot::collect(&limits, &router, &fallback).await;
        assert_eq!(snapshot.active_streams, 0);
        assert_eq!(snapshot.tracked_clients, 0);
        assert_eq!(snapshot.idle_clients, 0);
        assert_eq!(snapshot.subscribers, 0);
        assert_eq!(snapshot.fallback_buckets, 0);
    }

    #[tokio::test]
    async fn availability_snapshot_emit_is_safe_without_subscriber() {
        let limits = StreamLimits::new(1, 1);
        let router = EventRouter::new();
        let fallback = InMemoryRateLimiter::new();
        AvailabilitySnapshot::collect(&limits, &router, &fallback)
            .await
            .emit();
    }
}
