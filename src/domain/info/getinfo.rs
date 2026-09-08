use tonic::{Request, Response, Status};

use crate::cln::client::ClnClient;
use crate::cln::cln_api;

pub(crate) async fn get_info(
    client: &ClnClient,
    request: Request<cln_api::GetinfoRequest>,
) -> Result<Response<cln_api::GetinfoResponse>, Status> {
    tracing::info!("getinfo requested");
    let req = request.into_inner();

    let mut cln_client = client.inner.clone();
    let client_response = cln_client
        .getinfo(req)
        .await
        .map_err(|e| Status::internal(format!("Upstream CLN error: {}", e)))?;

    let cln_res = client_response.into_inner();

    let res = cln_api::GetinfoResponse {
        id: cln_res.id,
        alias: cln_res.alias,
        color: cln_res.color,
        num_peers: cln_res.num_peers,
        num_pending_channels: cln_res.num_pending_channels,
        num_active_channels: cln_res.num_active_channels,
        num_inactive_channels: cln_res.num_inactive_channels,
        version: cln_res.version,
        lightning_dir: cln_res.lightning_dir,
        our_features: cln_res.our_features,
        blockheight: cln_res.blockheight,
        network: cln_res.network,
        fees_collected_msat: cln_res.fees_collected_msat,
        address: cln_res.address,
        binding: cln_res.binding,
        warning_bitcoind_sync: cln_res.warning_bitcoind_sync,
        warning_lightningd_sync: cln_res.warning_lightningd_sync,
    };

    Ok(Response::new(res))
}
