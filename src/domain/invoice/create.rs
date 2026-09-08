use tonic::{Request, Response, Status};

use crate::cln::client::ClnClient;
use crate::cln::cln_api;

pub(crate) async fn create_invoice(
    client: &ClnClient,
    request: Request<cln_api::InvoiceRequest>,
) -> Result<Response<cln_api::InvoiceResponse>, Status> {
    let req = request.into_inner();

    let cln_request = cln_api::InvoiceRequest {
        amount_msat: req.amount_msat,
        label: req.label,
        description: req.description,
        expiry: req.expiry,
        cltv: req.cltv,
        fallbacks: req.fallbacks,
        preimage: req.preimage,
        exposeprivatechannels: req.exposeprivatechannels,
        deschashonly: req.deschashonly,
    };

    let mut cln_client = client.inner.clone();
    let cln_response = cln_client
        .invoice(Request::new(cln_request))
        .await
        .map_err(|e| Status::internal(format!("Upstream CLN error: {}", e)))?;

    let cln_res = cln_response.into_inner();

    let response = cln_api::InvoiceResponse {
        bolt11: cln_res.bolt11,
        payment_hash: cln_res.payment_hash,
        payment_secret: cln_res.payment_secret,
        created_index: cln_res.created_index,
        expires_at: cln_res.expires_at,
        warning_capacity: cln_res.warning_capacity,
        warning_offline: cln_res.warning_offline,
        warning_deadends: cln_res.warning_deadends,
        warning_private_unused: cln_res.warning_private_unused,
        warning_mpp: cln_res.warning_mpp,
    };

    Ok(Response::new(response))
}
