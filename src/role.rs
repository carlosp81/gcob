//! Host role for the `gcob` administration CLI.
//!
//! Server-only commands (`serve`, `sign`, `certs renew`) are denied when the
//! host is resolved to the client role, so a client machine does not expose or
//! execute server operations. `gcob init` is intentionally exempt: it is the
//! bootstrap command that creates the server environment.
//!
//! Resolution order:
//! 1. `GCOB_ROLE=client|server` (explicit override)
//! 2. `GCOB_ROLE=auto` (or unset): [`crate::certs::paths::is_server_env`]

use crate::certs::paths::is_server_env;

/// Resolved role for this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Client => "client",
            Role::Server => "server",
        }
    }
}

/// Pure role resolution, safe to unit test without touching the environment.
///
/// Unknown values fall back to auto-detection; when the host is not recognized
/// as a server environment it is treated as a client (least privilege).
pub fn role_from(explicit: Option<&str>, server_env: bool) -> Role {
    match explicit
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("client") => Role::Client,
        Some("server") => Role::Server,
        _ => {
            if server_env {
                Role::Server
            } else {
                Role::Client
            }
        }
    }
}

/// Role of the current process: `GCOB_ROLE` > auto-detection.
pub fn current_role() -> Role {
    let explicit = std::env::var("GCOB_ROLE").ok();
    role_from(explicit.as_deref(), is_server_env())
}

/// Error message when `command` is not allowed for `role`, or `None` if allowed.
pub fn server_role_error(command: &str, role: Role) -> Option<String> {
    if role == Role::Server {
        return None;
    }
    Some(format!(
        "'{command}' is only available in server role (detected: {}). \
         Set GCOB_ROLE=server to override, or use 'gcob-client' on client hosts.",
        role.as_str()
    ))
}

/// Fail-closed guard for server-only commands.
pub fn require_server(command: &str) -> Result<(), String> {
    match server_role_error(command, current_role()) {
        Some(message) => Err(message),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_role_wins() {
        assert_eq!(role_from(Some("client"), true), Role::Client);
        assert_eq!(role_from(Some("server"), false), Role::Server);
        assert_eq!(role_from(Some(" CLIENT "), true), Role::Client);
        assert_eq!(role_from(Some("Server"), false), Role::Server);
    }

    #[test]
    fn auto_uses_server_env_and_defaults_to_client() {
        assert_eq!(role_from(None, true), Role::Server);
        assert_eq!(role_from(Some("auto"), false), Role::Client);
        assert_eq!(role_from(Some("unknown"), false), Role::Client);
        assert_eq!(role_from(Some(""), false), Role::Client);
    }

    #[test]
    fn server_role_error_blocks_only_clients() {
        assert!(server_role_error("serve", Role::Server).is_none());
        let err = server_role_error("serve", Role::Client).unwrap();
        assert!(err.contains("server role"), "{err}");
        assert!(err.contains("GCOB_ROLE=server"), "{err}");
        assert!(err.contains("gcob-client"), "{err}");
    }
}
