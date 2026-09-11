use std::sync::atomic::{AtomicU64, Ordering};

use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::cln::cln_api;
use crate::cln::cln_api::node_services_server::NodeServices;
use crate::domain::info::getinfo::get_info;
use crate::domain::invoice::{create, xpay};
use crate::grpc::interceptors::auth::{extract_client_id, CLIENT_ID_HEADER};
use crate::grpc::interceptors::rate_limiter::check_rate_limit_with_fallback;

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
        // Rate limiting (rune already validated by AuthLayer)
        let client_id = extract_client_id(&request).ok_or_else(|| {
            Status::invalid_argument(format!("Missing or invalid '{}' header", CLIENT_ID_HEADER))
        })?;

        let allowed = check_rate_limit_with_fallback(
            &self.redis_cm,
            &self.in_memory_limiter,
            &client_id,
        )
        .await;

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
        // Rune already validated by AuthLayer
        let c = self.client.as_ref();
        get_info(c, request).await
    }

    async fn xpay(
        &self,
        request: Request<cln_api::XpayRequest>,
    ) -> Result<Response<cln_api::XpayResponse>, Status> {
        // Rune already validated by AuthLayer
        let c = self.client.as_ref();
        xpay::xpay(c, request).await
    }

    // --- Unary + Watch integrado ---

    type InvoiceStreamStream = ReceiverStream<Result<cln_api::Event, Status>>;

    async fn invoice_stream(
        &self,
        request: Request<cln_api::InvoiceRequest>,
    ) -> Result<Response<Self::InvoiceStreamStream>, Status> {
        // Rate limiting (rune already validated by AuthLayer)
        let client_id = extract_client_id(&request).ok_or_else(|| {
            Status::invalid_argument(format!("Missing or invalid '{}' header", CLIENT_ID_HEADER))
        })?;
        let allowed = check_rate_limit_with_fallback(
            &self.redis_cm,
            &self.in_memory_limiter,
            &client_id,
        )
        .await;
        if !allowed {
            return Err(Status::resource_exhausted(
                "Rate limit exceeded: maximum 3 invoices per hour",
            ));
        }

        // 2. Llamar CLN invoice()
        let req_label = request.get_ref().label.clone();
        let req_amount = request
            .get_ref()
            .amount_msat
            .as_ref()
            .and_then(|a| match &a.value {
                Some(crate::cln::cln_api::amount_or_any::Value::Amount(amt)) => Some(amt.msat),
                _ => None,
            });
        let req_description = request.get_ref().description.clone();
        let req_expiry = request.get_ref().expiry;
        let cln_response = create::create_invoice(&self.client, request).await?;
        let cln_res = cln_response.into_inner();

        // 3. Construir InvoiceCreated desde la respuesta CLN
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let internal_event = crate::events::types::Event::Invoice(
            crate::events::types::InvoiceEvent::Created {
                event_id: format!("cln-inv-stream-{}", req_label),
                timestamp: now,
                label: req_label.clone(),
                amount_msat: req_amount,
                description: req_description.clone(),
                bolt11: cln_res.bolt11.clone(),
                expiry: req_expiry,
            },
        );
        let proto_created = crate::domain::invoice::watch::to_proto_event(&internal_event)
            .unwrap_or_else(|| {
                tracing::warn!("Failed to convert InvoiceCreated to proto");
                cln_api::Event {
                    event: Some(cln_api::event::Event::InvoiceCreated(cln_api::InvoiceCreated {
                        event_id: format!("cln-inv-stream-{}", req_label),
                        timestamp: now,
                        label: req_label.clone(),
                        amount_msat: req_amount,
                        description: req_description,
                        bolt11: cln_res.bolt11.clone(),
                        recommendation: String::new(),
                        expiry: req_expiry,
                    })),
                }
            });

        // 4. Suscribir a "invoice" y crear canales
        let (internal_tx, mut internal_rx) =
            tokio::sync::mpsc::channel::<crate::events::types::Event>(64);
        let (proto_tx, proto_rx) =
            tokio::sync::mpsc::channel::<Result<cln_api::Event, Status>>(64);

        let router = self.event_router.clone();
        let subscriber_id = next_subscriber_id();
        router
            .subscribe("invoice", subscriber_id.clone(), internal_tx)
            .await;

        // 5. Spawn task con filtro por label
        let router_clone = router.clone();
        let sub_id = subscriber_id.clone();
        let target_label = req_label.clone();
        tokio::spawn(async move {
            tracing::info!(
                subscriber_id = %sub_id,
                label = %target_label,
                "invoice_stream subscribed, sending InvoiceCreated"
            );

            // Enviar InvoiceCreated de inmediato
            if proto_tx.send(Ok(proto_created)).await.is_err() {
                tracing::warn!(subscriber_id = %sub_id, "invoice_stream client disconnected (created)");
                router_clone.unsubscribe("invoice", &sub_id).await;
                return;
            }

            // Filtrar InvoicePaid por label
            while let Some(event) = internal_rx.recv().await {
                if let crate::events::types::Event::Invoice(
                    crate::events::types::InvoiceEvent::Paid { label, .. },
                ) = &event
                {
                    if label == &target_label {
                        tracing::info!(
                            subscriber_id = %sub_id,
                            label = %label,
                            "invoice_stream: InvoicePaid received, closing stream"
                        );
                        if let Some(proto_event) =
                            crate::domain::invoice::watch::to_proto_event(&event)
                        {
                            let _ = proto_tx.send(Ok(proto_event)).await;
                        }
                        break;
                    }
                }
            }

            router_clone.unsubscribe("invoice", &sub_id).await;
            tracing::info!(subscriber_id = %sub_id, "invoice_stream unsubscribed");
        });

        Ok(Response::new(ReceiverStream::new(proto_rx)))
    }

    type XpayStreamWatchStream = ReceiverStream<Result<cln_api::Event, Status>>;

    async fn xpay_stream_watch(
        &self,
        request: Request<cln_api::XpayRequest>,
    ) -> Result<Response<Self::XpayStreamWatchStream>, Status> {
        // Rune already validated by AuthLayer

        // 2. Llamar CLN xpay()
        let cln_response = xpay::xpay(&self.client, request).await?;
        let cln_res = cln_response.into_inner();

        // 3. Calcular payment_hash = SHA256(preimage)
        use sha2::{Digest, Sha256};
        let preimage_bytes = hex::decode(&cln_res.payment_preimage).map_err(|e| {
            Status::internal(format!("Failed to decode payment_preimage: {}", e))
        })?;
        let payment_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&preimage_bytes);
            hex::encode(hasher.finalize())
        };

        // 4. Suscribir a "payment" y crear canales
        let (internal_tx, mut internal_rx) =
            tokio::sync::mpsc::channel::<crate::events::types::Event>(64);
        let (proto_tx, proto_rx) =
            tokio::sync::mpsc::channel::<Result<cln_api::Event, Status>>(64);

        let router = self.event_router.clone();
        let subscriber_id = next_subscriber_id();
        router
            .subscribe("payment", subscriber_id.clone(), internal_tx)
            .await;

        // 5. Spawn task con filtro por payment_hash
        let router_clone = router.clone();
        let sub_id = subscriber_id.clone();
        let target_hash = payment_hash.clone();
        tokio::spawn(async move {
            tracing::info!(
                subscriber_id = %sub_id,
                payment_hash = %target_hash,
                "xpay_stream_watch subscribed, waiting for payment event"
            );

            // Filtrar PaymentSucceeded o PaymentFailed por payment_hash
            while let Some(event) = internal_rx.recv().await {
                let matches = match &event {
                    crate::events::types::Event::Payment(
                        crate::events::types::PaymentEvent::Succeeded {
                            payment_hash, ..
                        },
                    ) => payment_hash == &target_hash,
                    crate::events::types::Event::Payment(
                        crate::events::types::PaymentEvent::Failed {
                            payment_hash, ..
                        },
                    ) => payment_hash == &target_hash,
                    _ => false,
                };

                if matches {
                    tracing::info!(
                        subscriber_id = %sub_id,
                        payment_hash = %target_hash,
                        "xpay_stream_watch: matching payment event received, closing stream"
                    );
                    if let Some(proto_event) =
                        crate::domain::invoice::pay_stream::to_proto_event(&event)
                    {
                        let _ = proto_tx.send(Ok(proto_event)).await;
                    }
                    break;
                }
            }

            router_clone.unsubscribe("payment", &sub_id).await;
            tracing::info!(subscriber_id = %sub_id, "xpay_stream_watch unsubscribed");
        });

        Ok(Response::new(ReceiverStream::new(proto_rx)))
    }

    // --- Streaming RPCs ---

    type XpayStreamStream = ReceiverStream<Result<cln_api::Event, Status>>;

    async fn xpay_stream(
        &self,
        _request: Request<()>,
    ) -> Result<Response<Self::XpayStreamStream>, Status> {
        // Rune already validated by AuthLayer

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
        // Rune already validated by AuthLayer

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
        // Rune already validated by AuthLayer

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
        // Rune already validated by AuthLayer

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
        // Rune already validated by AuthLayer

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
