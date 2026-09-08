#![allow(dead_code)]

use super::types::*;

pub struct Recommendation {
    pub summary: String,
    pub action: String,
}

pub fn payment_recommendation(event: &PaymentEvent) -> Recommendation {
    match event {
        PaymentEvent::Succeeded {
            amount_msat,
            amount_sent_msat,
            ..
        } => {
            let fee = amount_sent_msat.saturating_sub(*amount_msat);
            Recommendation {
                summary: format!("Payment completed. Fee: {} msat", fee),
                action: "No action required.".into(),
            }
        }
        PaymentEvent::Failed { failure_reason, .. } => match failure_reason.as_str() {
            "timeout" => Recommendation {
                summary: "Payment timed out.".into(),
                action: "Check network connectivity and CLN peers.".into(),
            },
            "rejected" => Recommendation {
                summary: "Payment rejected by recipient.".into(),
                action: "Verify invoice details and amount.".into(),
            },
            "incorrect_payment_details" => Recommendation {
                summary: "Incorrect payment details.".into(),
                action: "Verify bolt11 invoice and payment hash.".into(),
            },
            "route_not_found" => Recommendation {
                summary: "No route found to destination.".into(),
                action: "Check peer connectivity and channel capacity.".into(),
            },
            _ => Recommendation {
                summary: format!("Payment failed: {}", failure_reason),
                action: "Check CLN logs for detailed error information.".into(),
            },
        },
        PaymentEvent::PartEnd { amount_msat, .. } => Recommendation {
            summary: format!("Payment part completed: {} msat", amount_msat),
            action: "Multi-part payment in progress.".into(),
        },
        PaymentEvent::PartStart { amount_msat, .. } => Recommendation {
            summary: format!("Payment part starting: {} msat", amount_msat),
            action: "Multi-part payment initiated.".into(),
        },
    }
}

pub fn invoice_recommendation(event: &InvoiceEvent) -> Recommendation {
    match event {
        InvoiceEvent::Created {
            label, amount_msat, ..
        } => {
            let amount_str = match amount_msat {
                Some(a) => format!("{} msat", a),
                None => "any amount".into(),
            };
            Recommendation {
                summary: format!("Invoice created: {} ({})", label, amount_str),
                action: "Share bolt11 with payer.".into(),
            }
        }
        InvoiceEvent::Paid {
            label, amount_msat, ..
        } => Recommendation {
            summary: format!("Invoice '{}' paid: {} msat", label, amount_msat),
            action: "Funds received. Fulfill order if applicable.".into(),
        },
    }
}

pub fn channel_recommendation(event: &ChannelEvent) -> Recommendation {
    match event {
        ChannelEvent::Opened {
            channel_id,
            amount_msat,
            ..
        } => Recommendation {
            summary: format!(
                "Channel {} opened with {} msat capacity",
                channel_id, amount_msat
            ),
            action: "Channel is ready for payments.".into(),
        },
        ChannelEvent::OpenFailed { reason, .. } => Recommendation {
            summary: format!("Channel opening failed: {}", reason),
            action: "Check peer connectivity, funding transaction, and CLN logs.".into(),
        },
        ChannelEvent::StateChanged {
            old_state,
            new_state,
            ..
        } => {
            let action = if new_state == "ONCHAIN" {
                "Channel closed. Funds are on-chain. Wait for confirmation."
            } else if new_state == "NORMAL" {
                "Channel is active and ready for payments."
            } else {
                "Monitor channel state for further changes."
            };
            Recommendation {
                summary: format!("Channel state: {} -> {}", old_state, new_state),
                action: action.into(),
            }
        }
        ChannelEvent::PeerSig { channel_id, .. } => Recommendation {
            summary: format!("Channel {} received peer signature", channel_id),
            action: "Channel update in progress.".into(),
        },
    }
}

pub fn peer_recommendation(event: &PeerEvent) -> Recommendation {
    match event {
        PeerEvent::Connected { node_id, addr, .. } => Recommendation {
            summary: format!("Peer {} connected at {}", node_id, addr),
            action: "Peer is available for payments.".into(),
        },
        PeerEvent::Disconnected { node_id, .. } => Recommendation {
            summary: format!("Peer {} disconnected", node_id),
            action: "Check peer connectivity and network status.".into(),
        },
        PeerEvent::CustomMsg {
            node_id, msgtype, ..
        } => Recommendation {
            summary: format!("Custom message type {} from peer {}", msgtype, node_id),
            action: "Custom protocol message received.".into(),
        },
    }
}

pub fn system_recommendation(event: &SystemEvent) -> Recommendation {
    match event {
        SystemEvent::BlockAdded { block_height, .. } => Recommendation {
            summary: format!("New block: {}", block_height),
            action: "Blockchain synced.".into(),
        },
        SystemEvent::BalanceSnapshot { .. } => Recommendation {
            summary: "Balance snapshot recorded.".into(),
            action: "On-chain balance state captured.".into(),
        },
        SystemEvent::Shutdown { .. } => Recommendation {
            summary: "Node is shutting down.".into(),
            action: "Verify graceful shutdown completes.".into(),
        },
        SystemEvent::Warning { source, log, .. } => Recommendation {
            summary: format!("Warning from {}: {}", source, log),
            action: "Review system health and CLN logs.".into(),
        },
        SystemEvent::Log { level, message, .. } => Recommendation {
            summary: format!("[{}] {}", level, message),
            action: "Log entry recorded.".into(),
        },
        SystemEvent::PluginStarted { name, .. } => Recommendation {
            summary: format!("Plugin '{}' started", name),
            action: "Plugin is active.".into(),
        },
        SystemEvent::PluginStopped { name, .. } => Recommendation {
            summary: format!("Plugin '{}' stopped", name),
            action: "Plugin may need restart if unintentional.".into(),
        },
        SystemEvent::ForwardEvent {
            in_channel,
            out_channel,
            amount_msat,
            fee_msat,
            ..
        } => Recommendation {
            summary: format!(
                "Forwarded {} msat from {} to {} (fee: {} msat)",
                amount_msat, in_channel, out_channel, fee_msat
            ),
            action: "Forward event recorded.".into(),
        },
    }
}

pub fn enrich(event: &Event) -> Recommendation {
    match event {
        Event::Payment(e) => payment_recommendation(e),
        Event::Invoice(e) => invoice_recommendation(e),
        Event::Channel(e) => channel_recommendation(e),
        Event::Peer(e) => peer_recommendation(e),
        Event::System(e) => system_recommendation(e),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_timeout_recommendation() {
        let e = PaymentEvent::Failed {
            event_id: "evt-1".into(),
            timestamp: 1000,
            payment_hash: "abc".into(),
            amount_msat: 1000,
            node_id: "02ab".into(),
            failure_reason: "timeout".into(),
        };
        let r = payment_recommendation(&e);
        assert!(r.summary.contains("timed out"));
        assert!(r.action.contains("network"));
    }

    #[test]
    fn payment_succeeded_fee_calculation() {
        let e = PaymentEvent::Succeeded {
            event_id: "evt-2".into(),
            timestamp: 1001,
            payment_hash: "def".into(),
            preimage: "secret".into(),
            amount_msat: 1000,
            amount_sent_msat: 1010,
            node_id: "02cd".into(),
            created_at: 1000,
        };
        let r = payment_recommendation(&e);
        assert!(r.summary.contains("Fee: 10 msat"));
    }

    #[test]
    fn invoice_created_recommendation() {
        let e = InvoiceEvent::Created {
            event_id: "evt-3".into(),
            timestamp: 1002,
            label: "order-42".into(),
            amount_msat: Some(5000),
            description: "Test".into(),
            bolt11: "lnbc...".into(),
        };
        let r = invoice_recommendation(&e);
        assert!(r.summary.contains("order-42"));
        assert!(r.summary.contains("5000 msat"));
    }

    #[test]
    fn channel_open_failed_recommendation() {
        let e = ChannelEvent::OpenFailed {
            event_id: "evt-4".into(),
            timestamp: 1003,
            node_id: "02ef".into(),
            reason: "insufficient funds".into(),
        };
        let r = channel_recommendation(&e);
        assert!(r.summary.contains("insufficient funds"));
        assert!(r.action.contains("funding"));
    }

    #[test]
    fn peer_disconnected_recommendation() {
        let e = PeerEvent::Disconnected {
            event_id: "evt-5".into(),
            timestamp: 1004,
            node_id: "02gh".into(),
        };
        let r = peer_recommendation(&e);
        assert!(r.summary.contains("disconnected"));
        assert!(r.action.contains("connectivity"));
    }

    #[test]
    fn system_warning_recommendation() {
        let e = SystemEvent::Warning {
            event_id: "evt-6".into(),
            timestamp: 1005,
            source: "bitcoind".into(),
            log: "connection lost".into(),
        };
        let r = system_recommendation(&e);
        assert!(r.summary.contains("bitcoind"));
        assert!(r.action.contains("health"));
    }

    #[test]
    fn enrich_delegates_correctly() {
        let e = Event::Payment(PaymentEvent::Failed {
            event_id: "evt-7".into(),
            timestamp: 1006,
            payment_hash: "xyz".into(),
            amount_msat: 2000,
            node_id: "02ij".into(),
            failure_reason: "rejected".into(),
        });
        let r = enrich(&e);
        assert!(r.summary.contains("rejected"));
    }
}
