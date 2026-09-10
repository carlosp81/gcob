use std::fs;

use anyhow::{Context, Result};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use crate::cli::Cli;

pub async fn connect(cli: &Cli) -> Result<Channel> {
    // Resolve certificate paths
    let cert_dir = std::env::var("CLN_CERT_DIR").ok().map(std::path::PathBuf::from);

    let ca_path = resolve_path(&cli.ca, &cert_dir, "ca.pem")?;
    let cert_path = resolve_path(&cli.cert, &cert_dir, "client.pem")?;
    let key_path = resolve_path(&cli.key, &cert_dir, "client-key.pem")?;

    // Read certificates
    let ca_pem = fs::read(&ca_path)
        .with_context(|| format!("Failed to read CA certificate: {}", ca_path.display()))?;
    let cert_pem = fs::read(&cert_path)
        .with_context(|| format!("Failed to read client certificate: {}", cert_path.display()))?;
    let key_pem = fs::read(&key_path)
        .with_context(|| format!("Failed to read client key: {}", key_path.display()))?;

    let ca = Certificate::from_pem(&ca_pem);
    let identity = Identity::from_pem(&cert_pem, &key_pem);

    let tls = ClientTlsConfig::new()
        .ca_certificate(ca)
        .identity(identity)
        .domain_name("localhost".to_string());

    let uri = format!("https://{}:{}", cli.host, cli.port);
    let channel = Endpoint::from_shared(uri.clone())
        .with_context(|| format!("Invalid endpoint: {}", uri))?
        .tls_config(tls)
        .with_context(|| "Failed to configure TLS")?
        .connect()
        .await
        .with_context(|| format!("Failed to connect to {}", uri))?;

    Ok(channel)
}

fn resolve_path(
    arg: &Option<String>,
    cert_dir: &Option<std::path::PathBuf>,
    default_name: &str,
) -> Result<std::path::PathBuf> {
    if let Some(p) = arg {
        return Ok(std::path::PathBuf::from(p));
    }
    if let Some(dir) = cert_dir {
        return Ok(dir.join(default_name));
    }
    // Fallback to certs/ relative to current dir
    Ok(std::path::PathBuf::from("certs").join(default_name))
}
