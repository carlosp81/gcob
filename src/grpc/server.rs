use std::fs;
use std::sync::Arc;
use std::time::Duration;

use redis::Client;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use crate::certs::mtls_certs::ClnConfig;
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
use crate::grpc::stream_limits::StreamLimits;

pub struct ApiService {
    pub client: Arc<ClnClient>,
    pub event_router: Arc<EventRouter>,
    pub stream_limits: Arc<StreamLimits>,
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

    let server_cert = fs::read(&cert_config.server_file)?;
    let server_key = fs::read(&cert_config.server_key_file)?;
    let ca_cert = fs::read(&cert_config.ca_file)?;

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

    let api_service = ApiService {
        client: Arc::new(client),
        event_router: router,
        stream_limits: StreamLimits::new(
            limits.max_active_streams_global,
            limits.max_active_streams_per_client,
        ),
    };

    tracing::info!("gRPC API server listening on {}", addr);

    let auth_layer = AuthLayer::new(api_service.client.clone(), limits.max_request_body_bytes);
    let admission_layer = AdmissionLayer::new(redis_cm.clone(), in_memory_limiter.clone(), &limits);
    let rate_limit_layer = RateLimitLayer::new(redis_cm, in_memory_limiter);
    let max_decoding_message_size = limits.max_request_body_bytes;

    // Layer order (outermost first): identity -> admission -> auth -> rate
    // limit -> service. The pre-auth budget is consumed before any CLN
    // interaction; only authenticated requests consume method quota.
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
        .layer(rate_limit_layer)
        .layer(auth_layer)
        .layer(admission_layer)
        .layer(ClientIdentityLayer::new())
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
