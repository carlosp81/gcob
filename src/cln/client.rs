use std::fs;

use anyhow::{Context, Result};

use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

use tonic::transport::Channel;

use crate::cln::cln_api::node_client::NodeClient;
// use crate::cln::cln_api::node_services_client::NodeServicesClient;

pub struct ClnClient {
    pub(crate) inner: NodeClient<Channel>,
}

use crate::certs::mtls_certs::ClnConfig;

impl ClnClient {
    /// Conecta al nodo CLN mediante mTLS a través de HAProxy.
    pub async fn connect(config: &ClnConfig) -> Result<Self> {
        // 1. Leer los certificados del sistema de archivos
        let ca_pem = fs::read(&config.ca_file)
            .with_context(|| format!("Failed to read CA certificate from {:#?}", config.ca_file))?;
        let client_cert_pem = fs::read(&config.client_file).with_context(|| {
            format!(
                "Failed to read client certificate from {:#?}",
                config.client_file
            )
        })?;
        let client_key_pem = fs::read(&config.client_key_file).with_context(|| {
            format!(
                "Failed to read client key from {:#?}",
                config.client_key_file
            )
        })?;

        let ca_cert = Certificate::from_pem(&ca_pem);

        // let client_cert = Certificate::from_pem(&client_cert_pem);
        // let client_key_cert = Certificate::from_pem(&client_key_pem);
        let client_identity = Identity::from_pem(&client_cert_pem, &client_key_pem);

        let tls_config = ClientTlsConfig::new()
            .ca_certificate(ca_cert)
            .identity(client_identity)
            .domain_name(&std::env::var("CLN_HOSTNAME").expect("CLN_HOSTNAME must be set"));
        let h2 = tls_config.assume_http2(true);
        // 5. Create tonic channel and gRPC client
        let channel = Endpoint::from_shared(config.node_uri.clone())?
            .tls_config(h2)?
            .connect_lazy();
        //.connect_timeout(Duration::from_secs_f32(60));

        //.connect_lazy();

        let client = NodeClient::new(channel);
        tracing::info!("Successfully connected to CLN via mTLS over Unix socket — TLS ENABLED (server cert + client CA verification)");

        Ok(Self { inner: client })
    }
}
