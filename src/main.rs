mod certs;
mod cln;
mod domain;
mod events;
mod grpc;
mod infra;

#[tokio::main]
async fn main() {
    // Forzar tracing con configuración explícita
    tracing_subscriber::fmt()
        .with_target(true)
        .with_thread_ids(true)
        .init();
    
    tracing::info!("Starting gcob");
    
    if let Err(e) = grpc::server::run().await {
        tracing::error!("Server failed: {}", e);
        std::process::exit(1);
    }
}
