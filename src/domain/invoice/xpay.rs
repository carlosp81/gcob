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
    let client_response = cln_client.xpay(req).await.map_err(|e| {
        tracing::error!(error = %e, "CLN xpay failed");
        Status::internal("Internal error")
    })?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cln::api_test_support::unreachable_client;

    #[tokio::test]
    async fn upstream_error_is_sanitized() {
        let client = unreachable_client();
        let request = Request::new(cln_api::XpayRequest {
            invstring: "lnbc1...".to_string(),
            ..Default::default()
        });
        let status = xpay(&client, request).await.unwrap_err();
        assert_eq!(status.message(), "Internal error");
    }
}
