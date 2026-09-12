use super::types::*;

const NODE_ID_MAX_LEN: usize = 8;
const LOG_MAX_LEN: usize = 200;

fn truncate_id(id: &str) -> String {
    id.chars().take(NODE_ID_MAX_LEN).collect()
}

fn truncate_log(log: &str) -> String {
    if log.len() > LOG_MAX_LEN {
        format!("{}...", &log[..LOG_MAX_LEN])
    } else {
        log.to_string()
    }
}

pub trait Sanitize {
    fn sanitize(&self) -> Self;
}

impl Sanitize for PaymentEvent {
    fn sanitize(&self) -> Self {
        match self.clone() {
            PaymentEvent::Succeeded {
                event_id,
                timestamp,
                payment_hash,
                preimage: _,
                amount_msat,
                amount_sent_msat,
                node_id,
                created_at,
            } => PaymentEvent::Succeeded {
                event_id,
                timestamp,
                payment_hash,
                preimage: String::new(),
                amount_msat,
                amount_sent_msat,
                node_id: truncate_id(&node_id),
                created_at,
            },
            PaymentEvent::Failed {
                event_id,
                timestamp,
                payment_hash,
                amount_msat,
                node_id,
                failure_reason,
            } => PaymentEvent::Failed {
                event_id,
                timestamp,
                payment_hash,
                amount_msat,
                node_id: truncate_id(&node_id),
                failure_reason,
            },
            other => other,
        }
    }
}

impl Sanitize for InvoiceEvent {
    fn sanitize(&self) -> Self {
        self.clone()
    }
}

impl Sanitize for ChannelEvent {
    fn sanitize(&self) -> Self {
        match self.clone() {
            ChannelEvent::Opened {
                event_id,
                timestamp,
                node_id,
                channel_id,
                amount_msat,
            } => ChannelEvent::Opened {
                event_id,
                timestamp,
                node_id: truncate_id(&node_id),
                channel_id,
                amount_msat,
            },
            ChannelEvent::OpenFailed {
                event_id,
                timestamp,
                node_id,
                reason,
            } => ChannelEvent::OpenFailed {
                event_id,
                timestamp,
                node_id: truncate_id(&node_id),
                reason,
            },
            other => other,
        }
    }
}

impl Sanitize for PeerEvent {
    fn sanitize(&self) -> Self {
        match self.clone() {
            PeerEvent::Connected {
                event_id,
                timestamp,
                node_id,
                addr,
                direction,
            } => PeerEvent::Connected {
                event_id,
                timestamp,
                node_id: truncate_id(&node_id),
                addr,
                direction,
            },
            PeerEvent::Disconnected {
                event_id,
                timestamp,
                node_id,
            } => PeerEvent::Disconnected {
                event_id,
                timestamp,
                node_id: truncate_id(&node_id),
            },
            PeerEvent::CustomMsg {
                event_id,
                timestamp,
                node_id,
                msgtype,
            } => PeerEvent::CustomMsg {
                event_id,
                timestamp,
                node_id: truncate_id(&node_id),
                msgtype,
            },
        }
    }
}

impl Sanitize for SystemEvent {
    fn sanitize(&self) -> Self {
        match self.clone() {
            SystemEvent::Warning {
                event_id,
                timestamp,
                source,
                log,
            } => SystemEvent::Warning {
                event_id,
                timestamp,
                source: truncate_id(&source),
                log: truncate_log(&log),
            },
            other => other,
        }
    }
}

impl Sanitize for Event {
    fn sanitize(&self) -> Self {
        match self {
            Event::Payment(e) => Event::Payment(e.sanitize()),
            Event::Invoice(e) => Event::Invoice(e.sanitize()),
            Event::Channel(e) => Event::Channel(e.sanitize()),
            Event::Peer(e) => Event::Peer(e.sanitize()),
            Event::System(e) => Event::System(e.sanitize()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_succeeded_preimage_removed() {
        let e = PaymentEvent::Succeeded {
            event_id: "evt-1".into(),
            timestamp: 1000,
            payment_hash: "abc123".into(),
            preimage: "secret123".into(),
            amount_msat: 1000,
            amount_sent_msat: 1010,
            node_id: "02abcdef12345678".into(),
            created_at: 999,
        };
        let sanitized = e.sanitize();
        if let PaymentEvent::Succeeded { preimage, .. } = sanitized {
            assert!(preimage.is_empty(), "preimage must be empty after sanitize");
        } else {
            panic!("expected PaymentEvent::Succeeded");
        }
    }

    #[test]
    fn payment_node_id_truncated() {
        let e = PaymentEvent::Failed {
            event_id: "evt-2".into(),
            timestamp: 1001,
            payment_hash: "def456".into(),
            amount_msat: 2000,
            node_id: "02abcdef12345678".into(),
            failure_reason: "timeout".into(),
        };
        let sanitized = e.sanitize();
        if let PaymentEvent::Failed { node_id, .. } = sanitized {
            assert_eq!(node_id, "02abcdef");
        } else {
            panic!("expected PaymentEvent::Failed");
        }
    }

    #[test]
    fn peer_node_id_truncated() {
        let e = PeerEvent::Connected {
            event_id: "evt-3".into(),
            timestamp: 1002,
            node_id: "02abcdef12345678".into(),
            addr: "127.0.0.1:9735".into(),
            direction: "in".into(),
        };
        let sanitized = e.sanitize();
        if let PeerEvent::Connected { node_id, .. } = sanitized {
            assert_eq!(node_id, "02abcdef");
        } else {
            panic!("expected PeerEvent::Connected");
        }
    }

    #[test]
    fn system_warning_truncated() {
        let e = SystemEvent::Warning {
            event_id: "evt-4".into(),
            timestamp: 1003,
            source: "bitcoind-super-long-source-name".into(),
            log: "x".repeat(300),
        };
        let sanitized = e.sanitize();
        if let SystemEvent::Warning { source, log, .. } = sanitized {
            assert_eq!(source, "bitcoind");
            assert!(log.len() <= 204, "log must be truncated + ellipsis");
            assert!(log.ends_with("..."));
        } else {
            panic!("expected SystemEvent::Warning");
        }
    }

    #[test]
    fn event_wrapper_sanitize() {
        let e = Event::Payment(PaymentEvent::Succeeded {
            event_id: "evt-5".into(),
            timestamp: 1004,
            payment_hash: "aaa".into(),
            preimage: "topsecret".into(),
            amount_msat: 500,
            amount_sent_msat: 510,
            node_id: "02aabbccdd112233".into(),
            created_at: 1003,
        });
        let sanitized = e.sanitize();
        assert_eq!(sanitized.event_id(), "evt-5");
    }
}
