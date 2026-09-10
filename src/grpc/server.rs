use std::fs;
use std::sync::Arc;

use redis::Client;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use crate::certs::mtls_certs::ClnConfig;
use crate::cln::client::ClnClient;
use crate::cln::cln_api::node_services_server::NodeServicesServer;
use crate::events::router::EventRouter;
use crate::events::subscribers::ClnEventBridge;

pub struct ApiService {
    pub client: Arc<ClnClient>,
    pub redis_cm: Option<redis::aio::MultiplexedConnection>,
    pub event_router: Arc<EventRouter>,
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
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
    let router = Arc::new(EventRouter::new());
    let mut bridge = ClnEventBridge::new(client.inner.clone(), router.clone());
    let bridge_handle = tokio::spawn(async move {
        bridge.start_all().await;
    });
    tracing::info!("Event bridge started");

    let api_service = ApiService {
        client: Arc::new(client),
        redis_cm,
        event_router: router,
    };

    tracing::info!("gRPC API server listening on {}", addr);

    Server::builder()
        .tls_config(tls_config)?
        .add_service(NodeServicesServer::new(api_service))
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
