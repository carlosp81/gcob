#![allow(dead_code)]

/// Unique identifier for each event instance.
pub type EventId = String;

/// Unix timestamp in seconds when the event was generated.
pub type Timestamp = i64;

// ---------------------------------------------------------------------------
// Payment Events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum PaymentEvent {
    Succeeded {
        event_id: EventId,
        timestamp: Timestamp,
        payment_hash: String,
        /// Only included in Succeeded — never exposed in other variants.
        preimage: String,
        amount_msat: u64,
        amount_sent_msat: u64,
        /// Truncated to first 8 bytes for safety.
        node_id: String,
        created_at: Timestamp,
    },
    Failed {
        event_id: EventId,
        timestamp: Timestamp,
        payment_hash: String,
        amount_msat: u64,
        /// Truncated to first 8 bytes for safety.
        node_id: String,
        failure_reason: String,
    },
    PartEnd {
        event_id: EventId,
        timestamp: Timestamp,
        payment_hash: String,
        partid: u64,
        amount_msat: u64,
    },
    PartStart {
        event_id: EventId,
        timestamp: Timestamp,
        payment_hash: String,
        partid: u64,
        amount_msat: u64,
    },
}

// ---------------------------------------------------------------------------
// Invoice Events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum InvoiceEvent {
    Created {
        event_id: EventId,
        timestamp: Timestamp,
        label: String,
        amount_msat: Option<u64>,
        description: String,
        bolt11: String,
    },
    Paid {
        event_id: EventId,
        timestamp: Timestamp,
        label: String,
        amount_msat: u64,
        payment_hash: String,
    },
}

// ---------------------------------------------------------------------------
// Channel Events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum ChannelEvent {
    Opened {
        event_id: EventId,
        timestamp: Timestamp,
        /// Truncated to first 8 bytes.
        node_id: String,
        channel_id: String,
        amount_msat: u64,
    },
    OpenFailed {
        event_id: EventId,
        timestamp: Timestamp,
        /// Truncated to first 8 bytes.
        node_id: String,
        reason: String,
    },
    StateChanged {
        event_id: EventId,
        timestamp: Timestamp,
        channel_id: String,
        old_state: String,
        new_state: String,
    },
    PeerSig {
        event_id: EventId,
        timestamp: Timestamp,
        channel_id: String,
    },
}

// ---------------------------------------------------------------------------
// Peer Events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum PeerEvent {
    Connected {
        event_id: EventId,
        timestamp: Timestamp,
        /// Truncated to first 8 bytes.
        node_id: String,
        addr: String,
        direction: String,
    },
    Disconnected {
        event_id: EventId,
        timestamp: Timestamp,
        /// Truncated to first 8 bytes.
        node_id: String,
    },
    CustomMsg {
        event_id: EventId,
        timestamp: Timestamp,
        /// Truncated to first 8 bytes.
        node_id: String,
        msgtype: u64,
    },
}

// ---------------------------------------------------------------------------
// System Events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum SystemEvent {
    BlockAdded {
        event_id: EventId,
        timestamp: Timestamp,
        block_height: u64,
    },
    BalanceSnapshot {
        event_id: EventId,
        timestamp: Timestamp,
    },
    Shutdown {
        event_id: EventId,
        timestamp: Timestamp,
    },
    Warning {
        event_id: EventId,
        timestamp: Timestamp,
        /// Truncated source — never expose full log.
        source: String,
        log: String,
    },
    Log {
        event_id: EventId,
        timestamp: Timestamp,
        level: String,
        message: String,
    },
    PluginStarted {
        event_id: EventId,
        timestamp: Timestamp,
        name: String,
    },
    PluginStopped {
        event_id: EventId,
        timestamp: Timestamp,
        name: String,
    },
    ForwardEvent {
        event_id: EventId,
        timestamp: Timestamp,
        in_channel: String,
        out_channel: String,
        amount_msat: u64,
        fee_msat: u64,
    },
}

// ---------------------------------------------------------------------------
// Unified Event Wrapper
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Event {
    Payment(PaymentEvent),
    Invoice(InvoiceEvent),
    Channel(ChannelEvent),
    Peer(PeerEvent),
    System(SystemEvent),
}

impl Event {
    pub fn event_id(&self) -> &str {
        match self {
            Event::Payment(e) => match e {
                PaymentEvent::Succeeded { event_id, .. }
                | PaymentEvent::Failed { event_id, .. }
                | PaymentEvent::PartEnd { event_id, .. }
                | PaymentEvent::PartStart { event_id, .. } => event_id,
            },
            Event::Invoice(e) => match e {
                InvoiceEvent::Created { event_id, .. } | InvoiceEvent::Paid { event_id, .. } => {
                    event_id
                }
            },
            Event::Channel(e) => match e {
                ChannelEvent::Opened { event_id, .. }
                | ChannelEvent::OpenFailed { event_id, .. }
                | ChannelEvent::StateChanged { event_id, .. }
                | ChannelEvent::PeerSig { event_id, .. } => event_id,
            },
            Event::Peer(e) => match e {
                PeerEvent::Connected { event_id, .. }
                | PeerEvent::Disconnected { event_id, .. }
                | PeerEvent::CustomMsg { event_id, .. } => event_id,
            },
            Event::System(e) => match e {
                SystemEvent::BlockAdded { event_id, .. }
                | SystemEvent::BalanceSnapshot { event_id, .. }
                | SystemEvent::Shutdown { event_id, .. }
                | SystemEvent::Warning { event_id, .. }
                | SystemEvent::Log { event_id, .. }
                | SystemEvent::PluginStarted { event_id, .. }
                | SystemEvent::PluginStopped { event_id, .. }
                | SystemEvent::ForwardEvent { event_id, .. } => event_id,
            },
        }
    }

    pub fn timestamp(&self) -> Timestamp {
        match self {
            Event::Payment(e) => match e {
                PaymentEvent::Succeeded { timestamp, .. }
                | PaymentEvent::Failed { timestamp, .. }
                | PaymentEvent::PartEnd { timestamp, .. }
                | PaymentEvent::PartStart { timestamp, .. } => *timestamp,
            },
            Event::Invoice(e) => match e {
                InvoiceEvent::Created { timestamp, .. } | InvoiceEvent::Paid { timestamp, .. } => {
                    *timestamp
                }
            },
            Event::Channel(e) => match e {
                ChannelEvent::Opened { timestamp, .. }
                | ChannelEvent::OpenFailed { timestamp, .. }
                | ChannelEvent::StateChanged { timestamp, .. }
                | ChannelEvent::PeerSig { timestamp, .. } => *timestamp,
            },
            Event::Peer(e) => match e {
                PeerEvent::Connected { timestamp, .. }
                | PeerEvent::Disconnected { timestamp, .. }
                | PeerEvent::CustomMsg { timestamp, .. } => *timestamp,
            },
            Event::System(e) => match e {
                SystemEvent::BlockAdded { timestamp, .. }
                | SystemEvent::BalanceSnapshot { timestamp, .. }
                | SystemEvent::Shutdown { timestamp, .. }
                | SystemEvent::Warning { timestamp, .. }
                | SystemEvent::Log { timestamp, .. }
                | SystemEvent::PluginStarted { timestamp, .. }
                | SystemEvent::PluginStopped { timestamp, .. }
                | SystemEvent::ForwardEvent { timestamp, .. } => *timestamp,
            },
        }
    }
}

impl std::fmt::Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Event::Payment(e) => write!(
                f,
                "Payment({})",
                match e {
                    PaymentEvent::Succeeded { .. } => "Succeeded",
                    PaymentEvent::Failed { .. } => "Failed",
                    PaymentEvent::PartEnd { .. } => "PartEnd",
                    PaymentEvent::PartStart { .. } => "PartStart",
                }
            ),
            Event::Invoice(e) => write!(
                f,
                "Invoice({})",
                match e {
                    InvoiceEvent::Created { .. } => "Created",
                    InvoiceEvent::Paid { .. } => "Paid",
                }
            ),
            Event::Channel(e) => write!(
                f,
                "Channel({})",
                match e {
                    ChannelEvent::Opened { .. } => "Opened",
                    ChannelEvent::OpenFailed { .. } => "OpenFailed",
                    ChannelEvent::StateChanged { .. } => "StateChanged",
                    ChannelEvent::PeerSig { .. } => "PeerSig",
                }
            ),
            Event::Peer(e) => write!(
                f,
                "Peer({})",
                match e {
                    PeerEvent::Connected { .. } => "Connected",
                    PeerEvent::Disconnected { .. } => "Disconnected",
                    PeerEvent::CustomMsg { .. } => "CustomMsg",
                }
            ),
            Event::System(e) => write!(
                f,
                "System({})",
                match e {
                    SystemEvent::BlockAdded { .. } => "BlockAdded",
                    SystemEvent::BalanceSnapshot { .. } => "BalanceSnapshot",
                    SystemEvent::Shutdown { .. } => "Shutdown",
                    SystemEvent::Warning { .. } => "Warning",
                    SystemEvent::Log { .. } => "Log",
                    SystemEvent::PluginStarted { .. } => "PluginStarted",
                    SystemEvent::PluginStopped { .. } => "PluginStopped",
                    SystemEvent::ForwardEvent { .. } => "ForwardEvent",
                }
            ),
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
    fn payment_succeeded_has_preimage() {
        let e = PaymentEvent::Succeeded {
            event_id: "evt-1".into(),
            timestamp: 1000,
            payment_hash: "abc123".into(),
            preimage: "secret123".into(),
            amount_msat: 1000,
            amount_sent_msat: 1010,
            node_id: "02abcdef".into(),
            created_at: 999,
        };
        let event = Event::Payment(e);
        assert_eq!(event.event_id(), "evt-1");
        assert_eq!(event.timestamp(), 1000);
    }

    #[test]
    fn payment_failed_no_preimage() {
        let e = PaymentEvent::Failed {
            event_id: "evt-2".into(),
            timestamp: 1001,
            payment_hash: "def456".into(),
            amount_msat: 2000,
            node_id: "02abcdef".into(),
            failure_reason: "timeout".into(),
        };
        let event = Event::Payment(e);
        assert_eq!(event.event_id(), "evt-2");
    }

    #[test]
    fn event_display_format() {
        let e = InvoiceEvent::Paid {
            event_id: "evt-3".into(),
            timestamp: 1002,
            label: "test-label".into(),
            amount_msat: 500,
            payment_hash: "789abc".into(),
        };
        let event = Event::Invoice(e);
        assert_eq!(format!("{}", event), "Invoice(Paid)");
    }

    #[test]
    fn system_event_accessors() {
        let e = SystemEvent::Warning {
            event_id: "evt-4".into(),
            timestamp: 1003,
            source: "bitcoind".into(),
            log: "connection lost".into(),
        };
        let event = Event::System(e);
        assert_eq!(event.event_id(), "evt-4");
        assert_eq!(event.timestamp(), 1003);
    }
}
