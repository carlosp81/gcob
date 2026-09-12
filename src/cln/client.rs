use anyhow::{Context, Result};

use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
use tonic::Request;

use tonic::transport::Channel;

use crate::cln::cln_api;
use crate::cln::cln_api::node_client::NodeClient;

pub struct ClnClient {
    pub(crate) inner: NodeClient<Channel>,
    pub node_id: String,
}

use crate::certs::mtls_certs::ClnConfig;

impl ClnClient {
    /// Conecta al nodo CLN mediante mTLS a través de HAProxy.
    pub async fn connect(config: &ClnConfig) -> Result<Self> {
        // 1. Leer los certificados del sistema de archivos sin seguir symlinks
        let ca_pem = crate::certs::paths::read_secure_file(&config.ca_file, false)
            .with_context(|| format!("Failed to read CA certificate from {:#?}", config.ca_file))?;
        let client_cert_pem = crate::certs::paths::read_secure_file(&config.client_file, false)
            .with_context(|| {
                format!(
                    "Failed to read client certificate from {:#?}",
                    config.client_file
                )
            })?;
        let client_key_pem = crate::certs::paths::read_secure_file(&config.client_key_file, true)
            .with_context(|| {
            format!(
                "Failed to read client key from {:#?}",
                config.client_key_file
            )
        })?;

        let ca_cert = Certificate::from_pem(&ca_pem);

        let client_identity = Identity::from_pem(&client_cert_pem, &client_key_pem);

        let tls_config = ClientTlsConfig::new()
            .ca_certificate(ca_cert)
            .identity(client_identity)
            .domain_name(std::env::var("CLN_HOSTNAME").expect("CLN_HOSTNAME must be set"));
        let h2 = tls_config.assume_http2(true);

        let channel = Endpoint::from_shared(config.node_uri.clone())?
            .tls_config(h2)?
            .connect_lazy();

        let mut client = NodeClient::new(channel);

        // Fetch and cache node ID via getinfo
        let id_bytes = client
            .getinfo(Request::new(cln_api::GetinfoRequest {}))
            .await
            .context("Failed to fetch node ID via getinfo")?
            .into_inner()
            .id;
        let node_id = hex::encode(&id_bytes);

        tracing::info!("Node ID: {}", node_id);
        tracing::info!("Successfully connected to CLN via mTLS over Unix socket — TLS ENABLED (server cert + client CA verification)");

        Ok(Self {
            inner: client,
            node_id,
        })
    }
}
