use tonic::{Request, Response, Status};

use crate::cln::client::ClnClient;
use crate::cln::cln_api;

pub(crate) async fn xpay(
    client: &ClnClient,
    request: Request<cln_api::XpayRequest>,
) -> Result<Response<cln_api::XpayResponse>, Status> {
    tracing::info!("xpay requested");
    let req = request.into_inner();

    let mut cln_client = client.inner.clone();
    let client_response = cln_client
        .xpay(req)
        .await
        .map_err(|e| Status::internal(format!("Upstream CLN error: {}", e)))?;

    let cln_res = client_response.into_inner();

    let res = cln_api::XpayResponse {
        payment_preimage: cln_res.payment_preimage,
        failed_parts: cln_res.failed_parts,
        successful_parts: cln_res.successful_parts,
        amount_msat: cln_res.amount_msat,
        amount_sent_msat: cln_res.amount_sent_msat,
    };

    Ok(Response::new(res))
}
