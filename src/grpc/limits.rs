//! Resource limits for the gRPC admission path.
//!
//! Every limit has a conservative default and can be overridden through the
//! environment variables documented in `.env.server.example`. Invalid or
//! zero values fail startup instead of silently disabling a control.

use std::env;

/// Conservative default: enough for BOLT11/BOLT12 payloads, far below the
/// tonic default.
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 256 * 1024;
/// Cheap pre-authentication budget per client certificate.
pub const DEFAULT_PREAUTH_LIMIT: u32 = 120;
pub const DEFAULT_PREAUTH_WINDOW_SECONDS: u64 = 60;
pub const DEFAULT_MAX_ACTIVE_STREAMS_GLOBAL: usize = 256;
pub const DEFAULT_MAX_ACTIVE_STREAMS_PER_CLIENT: usize = 8;
pub const DEFAULT_MAX_SUBSCRIBERS_GLOBAL: usize = 512;
pub const DEFAULT_MAX_SUBSCRIBERS_PER_TYPE: usize = 256;
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 32;
pub const DEFAULT_CONCURRENCY_LIMIT_PER_CONNECTION: usize = 16;
pub const DEFAULT_SLOW_SUBSCRIBER_MAX_DROPS: u64 = 64;

/// Availability controls applied at the transport, admission and streaming
/// layers. All values are strictly positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum size of a request body materialized in memory.
    pub max_request_body_bytes: usize,
    /// Cheap budget checked before any CLN interaction (per fingerprint).
    pub preauth_limit: u32,
    pub preauth_window_seconds: u64,
    /// Concurrent streaming RPCs across all clients.
    pub max_active_streams_global: usize,
    /// Concurrent streaming RPCs per client certificate.
    pub max_active_streams_per_client: usize,
    /// Event router subscribers across all event types.
    pub max_subscribers_global: usize,
    /// Event router subscribers per event type.
    pub max_subscribers_per_type: usize,
    /// HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS` per connection.
    pub max_concurrent_streams: u32,
    /// In-flight requests per connection (tonic concurrency limit).
    pub concurrency_limit_per_connection: usize,
    /// Consecutive `try_send` failures before a slow subscriber is dropped.
    pub slow_subscriber_max_drops: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            preauth_limit: DEFAULT_PREAUTH_LIMIT,
            preauth_window_seconds: DEFAULT_PREAUTH_WINDOW_SECONDS,
            max_active_streams_global: DEFAULT_MAX_ACTIVE_STREAMS_GLOBAL,
            max_active_streams_per_client: DEFAULT_MAX_ACTIVE_STREAMS_PER_CLIENT,
            max_subscribers_global: DEFAULT_MAX_SUBSCRIBERS_GLOBAL,
            max_subscribers_per_type: DEFAULT_MAX_SUBSCRIBERS_PER_TYPE,
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            concurrency_limit_per_connection: DEFAULT_CONCURRENCY_LIMIT_PER_CONNECTION,
            slow_subscriber_max_drops: DEFAULT_SLOW_SUBSCRIBER_MAX_DROPS,
        }
    }
}

impl Limits {
    /// Load limits from the process environment, falling back to defaults.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| env::var(name).ok())
    }

    /// Testable variant: `lookup` returns `None` for unset variables.
    fn from_lookup<F>(lookup: F) -> Result<Self, String>
    where
        F: Fn(&str) -> Option<String>,
    {
        Ok(Self {
            max_request_body_bytes: parse_usize(
                &lookup,
                "GCOB_MAX_REQUEST_BODY_BYTES",
                DEFAULT_MAX_REQUEST_BODY_BYTES,
            )?,
            preauth_limit: parse_u32(&lookup, "GCOB_PREAUTH_LIMIT", DEFAULT_PREAUTH_LIMIT)?,
            preauth_window_seconds: parse_u64(
                &lookup,
                "GCOB_PREAUTH_WINDOW_SECONDS",
                DEFAULT_PREAUTH_WINDOW_SECONDS,
            )?,
            max_active_streams_global: parse_usize(
                &lookup,
                "GCOB_MAX_ACTIVE_STREAMS_GLOBAL",
                DEFAULT_MAX_ACTIVE_STREAMS_GLOBAL,
            )?,
            max_active_streams_per_client: parse_usize(
                &lookup,
                "GCOB_MAX_ACTIVE_STREAMS_PER_CLIENT",
                DEFAULT_MAX_ACTIVE_STREAMS_PER_CLIENT,
            )?,
            max_subscribers_global: parse_usize(
                &lookup,
                "GCOB_MAX_SUBSCRIBERS_GLOBAL",
                DEFAULT_MAX_SUBSCRIBERS_GLOBAL,
            )?,
            max_subscribers_per_type: parse_usize(
                &lookup,
                "GCOB_MAX_SUBSCRIBERS_PER_TYPE",
                DEFAULT_MAX_SUBSCRIBERS_PER_TYPE,
            )?,
            max_concurrent_streams: parse_u32(
                &lookup,
                "GCOB_MAX_CONCURRENT_STREAMS",
                DEFAULT_MAX_CONCURRENT_STREAMS,
            )?,
            concurrency_limit_per_connection: parse_usize(
                &lookup,
                "GCOB_CONCURRENCY_LIMIT_PER_CONNECTION",
                DEFAULT_CONCURRENCY_LIMIT_PER_CONNECTION,
            )?,
            slow_subscriber_max_drops: parse_u64(
                &lookup,
                "GCOB_SLOW_SUBSCRIBER_MAX_DROPS",
                DEFAULT_SLOW_SUBSCRIBER_MAX_DROPS,
            )?,
        })
    }
}

fn parse_usize<F: Fn(&str) -> Option<String>>(
    lookup: &F,
    name: &str,
    default: usize,
) -> Result<usize, String> {
    match lookup(name) {
        None => Ok(default),
        Some(value) => {
            let parsed = value
                .parse::<usize>()
                .map_err(|_| format!("{name} must be a positive integer, got {value:?}"))?;
            if parsed == 0 {
                return Err(format!("{name} must be greater than zero"));
            }
            Ok(parsed)
        }
    }
}

fn parse_u32<F: Fn(&str) -> Option<String>>(
    lookup: &F,
    name: &str,
    default: u32,
) -> Result<u32, String> {
    match lookup(name) {
        None => Ok(default),
        Some(value) => {
            let parsed = value
                .parse::<u32>()
                .map_err(|_| format!("{name} must be a positive integer, got {value:?}"))?;
            if parsed == 0 {
                return Err(format!("{name} must be greater than zero"));
            }
            Ok(parsed)
        }
    }
}

fn parse_u64<F: Fn(&str) -> Option<String>>(
    lookup: &F,
    name: &str,
    default: u64,
) -> Result<u64, String> {
    match lookup(name) {
        None => Ok(default),
        Some(value) => {
            let parsed = value
                .parse::<u64>()
                .map_err(|_| format!("{name} must be a positive integer, got {value:?}"))?;
            if parsed == 0 {
                return Err(format!("{name} must be greater than zero"));
            }
            Ok(parsed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(values: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        }
    }

    #[test]
    fn defaults_when_unset() {
        let limits = Limits::from_lookup(lookup(&[])).unwrap();
        assert_eq!(limits, Limits::default());
        assert_eq!(limits.max_request_body_bytes, 262_144);
        assert_eq!(limits.preauth_limit, 120);
        assert_eq!(limits.preauth_window_seconds, 60);
        assert_eq!(limits.max_active_streams_per_client, 8);
        assert_eq!(limits.max_subscribers_per_type, 256);
    }

    #[test]
    fn overrides_are_applied() {
        let limits = Limits::from_lookup(lookup(&[
            ("GCOB_MAX_REQUEST_BODY_BYTES", "1024"),
            ("GCOB_PREAUTH_LIMIT", "10"),
            ("GCOB_PREAUTH_WINDOW_SECONDS", "5"),
            ("GCOB_MAX_ACTIVE_STREAMS_GLOBAL", "100"),
            ("GCOB_MAX_ACTIVE_STREAMS_PER_CLIENT", "4"),
            ("GCOB_MAX_SUBSCRIBERS_GLOBAL", "200"),
            ("GCOB_MAX_SUBSCRIBERS_PER_TYPE", "50"),
            ("GCOB_MAX_CONCURRENT_STREAMS", "8"),
            ("GCOB_CONCURRENCY_LIMIT_PER_CONNECTION", "2"),
            ("GCOB_SLOW_SUBSCRIBER_MAX_DROPS", "3"),
        ]))
        .unwrap();

        assert_eq!(
            limits,
            Limits {
                max_request_body_bytes: 1024,
                preauth_limit: 10,
                preauth_window_seconds: 5,
                max_active_streams_global: 100,
                max_active_streams_per_client: 4,
                max_subscribers_global: 200,
                max_subscribers_per_type: 50,
                max_concurrent_streams: 8,
                concurrency_limit_per_connection: 2,
                slow_subscriber_max_drops: 3,
            }
        );
    }

    #[test]
    fn zero_is_rejected() {
        let err = Limits::from_lookup(lookup(&[("GCOB_PREAUTH_LIMIT", "0")])).unwrap_err();
        assert!(err.contains("GCOB_PREAUTH_LIMIT"), "{err}");
        assert!(err.contains("greater than zero"), "{err}");
    }

    #[test]
    fn non_numeric_is_rejected() {
        let err =
            Limits::from_lookup(lookup(&[("GCOB_MAX_ACTIVE_STREAMS_GLOBAL", "many")])).unwrap_err();
        assert!(err.contains("GCOB_MAX_ACTIVE_STREAMS_GLOBAL"), "{err}");
    }

    #[test]
    fn empty_value_is_rejected() {
        let err = Limits::from_lookup(lookup(&[("GCOB_MAX_CONCURRENT_STREAMS", "")])).unwrap_err();
        assert!(err.contains("GCOB_MAX_CONCURRENT_STREAMS"), "{err}");
    }

    #[test]
    fn negative_is_rejected() {
        let err =
            Limits::from_lookup(lookup(&[("GCOB_PREAUTH_WINDOW_SECONDS", "-1")])).unwrap_err();
        assert!(err.contains("GCOB_PREAUTH_WINDOW_SECONDS"), "{err}");
    }

    #[test]
    fn unused_process_env_is_ignored() {
        // The map-based lookup must not depend on the real process environment.
        let limits = Limits::from_lookup(lookup(&[("SOME_OTHER_VAR", "42")])).unwrap();
        assert_eq!(limits, Limits::default());
    }

    #[test]
    fn all_known_variable_names_are_distinct() {
        let names = [
            "GCOB_MAX_REQUEST_BODY_BYTES",
            "GCOB_PREAUTH_LIMIT",
            "GCOB_PREAUTH_WINDOW_SECONDS",
            "GCOB_MAX_ACTIVE_STREAMS_GLOBAL",
            "GCOB_MAX_ACTIVE_STREAMS_PER_CLIENT",
            "GCOB_MAX_SUBSCRIBERS_GLOBAL",
            "GCOB_MAX_SUBSCRIBERS_PER_TYPE",
            "GCOB_MAX_CONCURRENT_STREAMS",
            "GCOB_CONCURRENCY_LIMIT_PER_CONNECTION",
            "GCOB_SLOW_SUBSCRIBER_MAX_DROPS",
        ];
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len());
    }
}
