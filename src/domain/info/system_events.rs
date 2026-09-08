use crate::cln::cln_api;
use crate::events::types;

pub fn to_proto_event(event: &types::Event) -> Option<cln_api::Event> {
    match event {
        types::Event::System(e) => {
            let rec = crate::events::enricher::system_recommendation(e);
            let (event_id, timestamp, source, log) = match e {
                types::SystemEvent::BlockAdded {
                    event_id,
                    timestamp,
                    block_height,
                } => {
                    tracing::info!(block_height = %block_height, "converted BlockAdded");
                    (
                        event_id.clone(),
                        *timestamp,
                        "blockchain".into(),
                        format!("New block height: {}", block_height),
                    )
                }
                types::SystemEvent::BalanceSnapshot {
                    event_id,
                    timestamp,
                } => {
                    tracing::info!("converted BalanceSnapshot");
                    (
                        event_id.clone(),
                        *timestamp,
                        "wallet".into(),
                        "Balance snapshot recorded.".into(),
                    )
                }
                types::SystemEvent::Shutdown {
                    event_id,
                    timestamp,
                } => {
                    tracing::warn!("converted Shutdown");
                    (
                        event_id.clone(),
                        *timestamp,
                        "node".into(),
                        "Node is shutting down.".into(),
                    )
                }
                types::SystemEvent::Warning {
                    event_id,
                    timestamp,
                    source,
                    log,
                } => {
                    tracing::warn!(source = %source, "converted Warning");
                    (event_id.clone(), *timestamp, source.clone(), log.clone())
                }
                types::SystemEvent::Log {
                    event_id,
                    timestamp,
                    level,
                    message,
                } => {
                    tracing::debug!(level = %level, "converted Log");
                    (
                        event_id.clone(),
                        *timestamp,
                        "cln".into(),
                        format!("[{}] {}", level, message),
                    )
                }
                types::SystemEvent::PluginStarted {
                    event_id,
                    timestamp,
                    name,
                } => {
                    tracing::info!(name = %name, "converted PluginStarted");
                    (
                        event_id.clone(),
                        *timestamp,
                        "plugin".into(),
                        format!("Plugin {} started", name),
                    )
                }
                types::SystemEvent::PluginStopped {
                    event_id,
                    timestamp,
                    name,
                } => {
                    tracing::info!(name = %name, "converted PluginStopped");
                    (
                        event_id.clone(),
                        *timestamp,
                        "plugin".into(),
                        format!("Plugin {} stopped", name),
                    )
                }
                types::SystemEvent::ForwardEvent {
                    event_id,
                    timestamp,
                    in_channel,
                    out_channel,
                    amount_msat,
                    fee_msat,
                } => {
                    tracing::info!(
                        in_channel = %in_channel,
                        out_channel = %out_channel,
                        amount_msat = %amount_msat,
                        fee_msat = %fee_msat,
                        "converted ForwardEvent"
                    );
                    (
                        event_id.clone(),
                        *timestamp,
                        "forward".into(),
                        format!(
                            "Forwarded {} msat from {} to {} (fee: {} msat)",
                            amount_msat, in_channel, out_channel, fee_msat
                        ),
                    )
                }
            };
            Some(cln_api::Event {
                event: Some(cln_api::event::Event::SystemWarning(
                    cln_api::SystemWarning {
                        event_id,
                        timestamp,
                        source,
                        log,
                        recommendation: format!("{}. {}", rec.summary, rec.action),
                    },
                )),
            })
        }
        _ => None,
    }
}
