pub(crate) mod client;

pub mod cln_api {
    #![allow(clippy::enum_variant_names)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/cln.rs"));
}

/// Test helpers to build a `ClnClient` whose upstream calls fail fast.
#[cfg(test)]
pub(crate) mod api_test_support {
    use tonic::transport::Endpoint;

    use super::client::ClnClient;

    pub(crate) fn unreachable_client() -> ClnClient {
        let channel = Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        ClnClient {
            inner: super::cln_api::node_client::NodeClient::new(channel),
            node_id: "test-node".to_string(),
        }
    }
}
