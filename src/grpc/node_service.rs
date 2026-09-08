use std::sync::atomic::{AtomicU64, Ordering};

use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::cln::cln_api;
use crate::cln::cln_api::node_services_server::NodeServices;
use crate::domain::info::getinfo::get_info;
use crate::domain::invoice::{create, xpay};
use crate::grpc::interceptors::auth::{
    extract_client_id, extract_rune_from_request, validate_rune, CLIENT_ID_HEADER, RUNE_HEADER,
};
use crate::grpc::interceptors::rate_limiter::check_rate_limit;

use super::server::ApiService;

static SUBSCRIBER_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_subscriber_id() -> String {
    format!("sub-{}", SUBSCRIBER_COUNTER.fetch_add(1, Ordering::Relaxed))
}

#[tonic::async_trait]
impl NodeServices for ApiService {
    async fn invoice(
        &self,
        request: Request<cln_api::InvoiceRequest>,
    ) -> Result<Response<cln_api::InvoiceResponse>, Status> {
        let rune = extract_rune_from_request(&request).ok_or_else(|| {
            Status::unauthenticated(format!(
                "Missing or empty Rune header '{}'. Provide a valid Rune for authentication.",
                RUNE_HEADER
            ))
        })?;

        validate_rune(&self.client, &rune, "invoice").await?;
        tracing::info!("Rune validated - allowing invoice request through");

        let client_id = extract_client_id(&request).ok_or_else(|| {
            Status::invalid_argument(format!("Missing or invalid '{}' header", CLIENT_ID_HEADER))
        })?;

        let allowed = match &self.redis_cm {
            Some(cm) => check_rate_limit(cm, &client_id)
                .await
                .map_err(|_| Status::unavailable("Rate limiter unavailable"))?,
            None => {
                tracing::warn!("Valkey not connected - rate limiting skipped");
                true
            }
        };

        if !allowed {
            return Err(Status::resource_exhausted(
                "Rate limit exceeded: maximum 3 invoices per hour",
            ));
        }

        create::create_invoice(&self.client, request).await
    }

    async fn getinfo(
        &self,
        request: Request<cln_api::GetinfoRequest>,
    ) -> Result<Response<cln_api::GetinfoResponse>, Status> {
        let rune = extract_rune_from_request(&request).ok_or_else(|| {
            Status::unauthenticated(format!(
                "Missing or empty Rune header '{}'. Provide a valid Rune for authentication.",
                RUNE_HEADER
            ))
        })?;

        validate_rune(&self.client, &rune, "getinfo").await?;
        tracing::info!("Rune validated - allowing getinfo request through");

        let c = self.client.as_ref();
        get_info(c, request).await
    }

    async fn xpay(
        &self,
        request: Request<cln_api::XpayRequest>,
    ) -> Result<Response<cln_api::XpayResponse>, Status> {
        let rune = extract_rune_from_request(&request).ok_or_else(|| {
            Status::unauthenticated(format!(
                "Missing or empty Rune header '{}'. Provide a valid Rune for authentication.",
                RUNE_HEADER
            ))
        })?;

        validate_rune(&self.client, &rune, "xpay").await?;
        tracing::info!("Rune validated - allowing xpay request through");

        let c = self.client.as_ref();
        xpay::xpay(c, request).await
    }

    // --- Streaming RPCs ---

    type XpayStreamStream = ReceiverStream<Result<cln_api::Event, Status>>;

    async fn xpay_stream(
        &self,
        _request: Request<()>,
    ) -> Result<Response<Self::XpayStreamStream>, Status> {
        let (internal_tx, mut internal_rx) =
            tokio::sync::mpsc::channel::<crate::events::types::Event>(64);
        let (proto_tx, proto_rx) = tokio::sync::mpsc::channel::<Result<cln_api::Event, Status>>(64);

        let router = self.event_router.clone();
        let subscriber_id = next_subscriber_id();

        router
            .subscribe("payment", subscriber_id.clone(), internal_tx)
            .await;

        let router_clone = router.clone();
        let sub_id = subscriber_id.clone();
        tokio::spawn(async move {
            tracing::info!(subscriber_id = %sub_id, "xpay_stream subscribed");
            while let Some(event) = internal_rx.recv().await {
                tracing::debug!(subscriber_id = %sub_id, "payment event received");
                if let Some(proto_event) =
                    crate::domain::invoice::pay_stream::to_proto_event(&event)
                {
                    if proto_tx.send(Ok(proto_event)).await.is_err() {
                        tracing::warn!(subscriber_id = %sub_id, "xpay_stream client disconnected");
                        break;
                    }
                }
            }
            router_clone.unsubscribe("payment", &sub_id).await;
            tracing::info!(subscriber_id = %sub_id, "xpay_stream unsubscribed");
        });

        Ok(Response::new(ReceiverStream::new(proto_rx)))
    }

    type InvoiceWatchStream = ReceiverStream<Result<cln_api::Event, Status>>;

    async fn invoice_watch(
        &self,
        _request: Request<()>,
    ) -> Result<Response<Self::InvoiceWatchStream>, Status> {
        let (internal_tx, mut internal_rx) =
            tokio::sync::mpsc::channel::<crate::events::types::Event>(64);
        let (proto_tx, proto_rx) = tokio::sync::mpsc::channel::<Result<cln_api::Event, Status>>(64);

        let router = self.event_router.clone();
        let subscriber_id = next_subscriber_id();

        router
            .subscribe("invoice", subscriber_id.clone(), internal_tx)
            .await;

        let router_clone = router.clone();
        let sub_id = subscriber_id.clone();
        tokio::spawn(async move {
            tracing::info!(subscriber_id = %sub_id, "invoice_watch subscribed");
            while let Some(event) = internal_rx.recv().await {
                tracing::debug!(subscriber_id = %sub_id, "invoice event received");
                if let Some(proto_event) = crate::domain::invoice::watch::to_proto_event(&event) {
                    if proto_tx.send(Ok(proto_event)).await.is_err() {
                        tracing::warn!(subscriber_id = %sub_id, "invoice_watch client disconnected");
                        break;
                    }
                }
            }
            router_clone.unsubscribe("invoice", &sub_id).await;
            tracing::info!(subscriber_id = %sub_id, "invoice_watch unsubscribed");
        });

        Ok(Response::new(ReceiverStream::new(proto_rx)))
    }

    type WatchChannelsStream = ReceiverStream<Result<cln_api::Event, Status>>;

    async fn watch_channels(
        &self,
        _request: Request<()>,
    ) -> Result<Response<Self::WatchChannelsStream>, Status> {
        let (internal_tx, mut internal_rx) =
            tokio::sync::mpsc::channel::<crate::events::types::Event>(64);
        let (proto_tx, proto_rx) = tokio::sync::mpsc::channel::<Result<cln_api::Event, Status>>(64);

        let router = self.event_router.clone();
        let subscriber_id = next_subscriber_id();

        router
            .subscribe("channel", subscriber_id.clone(), internal_tx)
            .await;

        let router_clone = router.clone();
        let sub_id = subscriber_id.clone();
        tokio::spawn(async move {
            tracing::info!(subscriber_id = %sub_id, "watch_channels subscribed");
            while let Some(event) = internal_rx.recv().await {
                tracing::debug!(subscriber_id = %sub_id, "channel event received");
                if let Some(proto_event) = crate::domain::channel::events::to_proto_event(&event) {
                    if proto_tx.send(Ok(proto_event)).await.is_err() {
                        tracing::warn!(subscriber_id = %sub_id, "watch_channels client disconnected");
                        break;
                    }
                }
            }
            router_clone.unsubscribe("channel", &sub_id).await;
            tracing::info!(subscriber_id = %sub_id, "watch_channels unsubscribed");
        });

        Ok(Response::new(ReceiverStream::new(proto_rx)))
    }

    type WatchPeersStream = ReceiverStream<Result<cln_api::Event, Status>>;

    async fn watch_peers(
        &self,
        _request: Request<()>,
    ) -> Result<Response<Self::WatchPeersStream>, Status> {
        let (internal_tx, mut internal_rx) =
            tokio::sync::mpsc::channel::<crate::events::types::Event>(64);
        let (proto_tx, proto_rx) = tokio::sync::mpsc::channel::<Result<cln_api::Event, Status>>(64);

        let router = self.event_router.clone();
        let subscriber_id = next_subscriber_id();

        router
            .subscribe("peer", subscriber_id.clone(), internal_tx)
            .await;

        let router_clone = router.clone();
        let sub_id = subscriber_id.clone();
        tokio::spawn(async move {
            tracing::info!(subscriber_id = %sub_id, "watch_peers subscribed");
            while let Some(event) = internal_rx.recv().await {
                tracing::debug!(subscriber_id = %sub_id, "peer event received");
                if let Some(proto_event) = crate::domain::peer::events::to_proto_event(&event) {
                    if proto_tx.send(Ok(proto_event)).await.is_err() {
                        tracing::warn!(subscriber_id = %sub_id, "watch_peers client disconnected");
                        break;
                    }
                }
            }
            router_clone.unsubscribe("peer", &sub_id).await;
            tracing::info!(subscriber_id = %sub_id, "watch_peers unsubscribed");
        });

        Ok(Response::new(ReceiverStream::new(proto_rx)))
    }

    type WatchSystemStream = ReceiverStream<Result<cln_api::Event, Status>>;

    async fn watch_system(
        &self,
        _request: Request<()>,
    ) -> Result<Response<Self::WatchSystemStream>, Status> {
        let (internal_tx, mut internal_rx) =
            tokio::sync::mpsc::channel::<crate::events::types::Event>(64);
        let (proto_tx, proto_rx) = tokio::sync::mpsc::channel::<Result<cln_api::Event, Status>>(64);

        let router = self.event_router.clone();
        let subscriber_id = next_subscriber_id();

        router
            .subscribe("system", subscriber_id.clone(), internal_tx)
            .await;

        let router_clone = router.clone();
        let sub_id = subscriber_id.clone();
        tokio::spawn(async move {
            tracing::info!(subscriber_id = %sub_id, "watch_system subscribed");
            while let Some(event) = internal_rx.recv().await {
                tracing::debug!(subscriber_id = %sub_id, "system event received");
                if let Some(proto_event) =
                    crate::domain::info::system_events::to_proto_event(&event)
                {
                    if proto_tx.send(Ok(proto_event)).await.is_err() {
                        tracing::warn!(subscriber_id = %sub_id, "watch_system client disconnected");
                        break;
                    }
                }
            }
            router_clone.unsubscribe("system", &sub_id).await;
            tracing::info!(subscriber_id = %sub_id, "watch_system unsubscribed");
        });

        Ok(Response::new(ReceiverStream::new(proto_rx)))
    }
}
