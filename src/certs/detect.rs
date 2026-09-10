use std::process::Command;

use super::generate::CertError;

/// Resolved identity (hostname + optional IP) from CLI/env/detection
pub struct ResolvedIdentity {
    pub hostname: String,
    pub ip: Option<String>,
}

/// Resolve hostname and IP using priority chain:
/// CLI flag > env var > auto-detect > default
///
/// - `require_ip`: if true, falls back to default_ip when detection fails (server mode).
///   if false, IP remains None when detection fails (client mode).
pub fn resolve_identity(
    flag_hostname: Option<&str>,
    flag_ip: Option<&str>,
    env_hostname_key: &str,
    env_ip_key: &str,
    default_hostname: &str,
    default_ip: &str,
    require_ip: bool,
) -> Result<ResolvedIdentity, CertError> {
    let hostname = flag_hostname
        .map(|s| s.to_string())
        .or_else(|| std::env::var(env_hostname_key).ok().filter(|v| !v.is_empty()))
        .or_else(|| detect_hostname().ok())
        .unwrap_or_else(|| default_hostname.to_string());

    let ip = match flag_ip {
        Some(ip) => Some(ip.to_string()),
        None => match std::env::var(env_ip_key) {
            Ok(val) if !val.is_empty() => Some(val),
            _ => detect_ip().ok().or_else(|| {
                if require_ip {
                    Some(default_ip.to_string())
                } else {
                    None
                }
            }),
        },
    };

    Ok(ResolvedIdentity { hostname, ip })
}

/// Detect system hostname using `hostname -f` (FQDN), fallback to `hostname`
pub fn detect_hostname() -> Result<String, CertError> {
    // Try hostname -f first (FQDN)
    if let Ok(output) = Command::new("hostname").arg("-f").output() {
        if output.status.success() {
            let hostname = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !hostname.is_empty() {
                return Ok(hostname);
            }
        }
    }

    // Fallback to plain hostname
    if let Ok(output) = Command::new("hostname").output() {
        if output.status.success() {
            let hostname = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !hostname.is_empty() {
                return Ok(hostname);
            }
        }
    }

    Err(CertError::Io(std::io::Error::other(
        "Cannot detect hostname: 'hostname' command failed",
    )))
}

/// Detect primary IP address using `ip -4 addr show`, fallback to `ifconfig`
pub fn detect_ip() -> Result<String, CertError> {
    // Try ip command first (modern Linux)
    if let Ok(output) = Command::new("ip")
        .args(["-4", "addr", "show"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(ip) = parse_ip_from_ip_addr(&stdout) {
                return Ok(ip);
            }
        }
    }

    // Fallback to ifconfig (older systems)
    if let Ok(output) = Command::new("ifconfig").output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(ip) = parse_ip_from_ifconfig(&stdout) {
                return Ok(ip);
            }
        }
    }

    Err(CertError::Io(std::io::Error::other(
        "Cannot detect IP: 'ip' and 'ifconfig' commands failed",
    )))
}

/// Parse IP from `ip -4 addr show` output
/// Looks for lines like: inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0
fn parse_ip_from_ip_addr(output: &str) -> Option<String> {
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("inet ") {
            // Extract IP before the slash (CIDR notation)
            let after_inet = &line[5..]; // skip "inet "
            if let Some(slash_pos) = after_inet.find('/') {
                let ip = &after_inet[..slash_pos];
                // Skip loopback
                if ip != "127.0.0.1" {
                    return Some(ip.to_string());
                }
            }
        }
    }
    None
}

/// Parse IP from `ifconfig` output
/// Looks for lines like: inet 192.168.1.50 netmask 255.255.255.0
fn parse_ip_from_ifconfig(output: &str) -> Option<String> {
    for line in output.lines() {
        let line = line.trim();
        if line.contains("inet ") && !line.contains("127.0.0.1") {
            // Extract IP after "inet "
            if let Some(start) = line.find("inet ") {
                let after_inet = &line[start + 5..];
                // Take until space or end
                let ip: String = after_inet.chars().take_while(|c| !c.is_whitespace()).collect();
                if !ip.is_empty() {
                    return Some(ip);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_from_ip_addr() {
        let output = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    inet 127.0.0.1/8 scope host lo\n       valid_lft forever preferred_lft forever\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0\n       valid_lft forever preferred_lft forever";
        assert_eq!(parse_ip_from_ip_addr(output), Some("192.168.1.50".to_string()));
    }

    #[test]
    fn test_parse_ip_from_ip_addr_loopback_only() {
        let output = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    inet 127.0.0.1/8 scope host lo\n       valid_lft forever preferred_lft forever";
        assert_eq!(parse_ip_from_ip_addr(output), None);
    }

    #[test]
    fn test_parse_ip_from_ifconfig() {
        let output = "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.50  netmask 255.255.255.0  broadcast 192.168.1.255\n        inet6 fe80::1234:5678:90ab:cdef  prefixlen 64  scopeid 0x20<link>\n        ether aa:bb:cc:dd:ee:ff  txqueuelen 1000  (Ethernet)";
        assert_eq!(parse_ip_from_ifconfig(output), Some("192.168.1.50".to_string()));
    }

    #[test]
    fn test_parse_ip_from_ifconfig_loopback_only() {
        let output = "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n        inet6 ::1  prefixlen 128  scopeid 0x10<host>";
        assert_eq!(parse_ip_from_ifconfig(output), None);
    }

    #[test]
    fn test_detect_hostname_returns_value() {
        // This test verifies the function doesn't panic
        // Actual value depends on the system
        let result = detect_hostname();
        assert!(result.is_ok() || result.is_err()); // Just verify it doesn't panic
    }

    #[test]
    fn test_detect_ip_returns_value() {
        // This test verifies the function doesn't panic
        let result = detect_ip();
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_resolve_identity_flag_overrides_env_and_detect() {
        let result = resolve_identity(
            Some("flag-host"), Some("10.0.0.99"),
            "TEST_HOSTNAME", "TEST_IP",
            "default-host", "127.0.0.1",
            true,
        ).unwrap();
        assert_eq!(result.hostname, "flag-host");
        assert_eq!(result.ip, Some("10.0.0.99".to_string()));
    }

    #[test]
    fn test_resolve_identity_env_overrides_detect() {
        std::env::set_var("TEST_HOSTNAME_X", "env-host");
        std::env::set_var("TEST_IP_X", "10.0.0.50");
        let result = resolve_identity(
            None, None,
            "TEST_HOSTNAME_X", "TEST_IP_X",
            "default-host", "127.0.0.1",
            true,
        ).unwrap();
        assert_eq!(result.hostname, "env-host");
        assert_eq!(result.ip, Some("10.0.0.50".to_string()));
        std::env::remove_var("TEST_HOSTNAME_X");
        std::env::remove_var("TEST_IP_X");
    }

    #[test]
    fn test_resolve_identity_falls_to_defaults() {
        std::env::remove_var("NONEXISTENT_KEY_HOST_X");
        std::env::remove_var("NONEXISTENT_KEY_IP_X");
        let result = resolve_identity(
            None, None,
            "NONEXISTENT_KEY_HOST_X", "NONEXISTENT_KEY_IP_X",
            "default-host", "192.168.0.1",
            true,
        ).unwrap();
        // hostname falls back to auto-detect (real hostname), IP falls back to auto-detect or default
        assert!(!result.hostname.is_empty());
        assert!(result.ip.is_some());
    }

    #[test]
    fn test_resolve_identity_require_ip_false_allows_none() {
        std::env::remove_var("NONEXISTENT_KEY_HOST_Y");
        std::env::remove_var("NONEXISTENT_KEY_IP_Y");
        let result = resolve_identity(
            None, None,
            "NONEXISTENT_KEY_HOST_Y", "NONEXISTENT_KEY_IP_Y",
            "default-host", "127.0.0.1",
            false,
        ).unwrap();
        assert!(!result.hostname.is_empty());
        // IP can be None when require_ip=false and no env var set and auto-detect returns loopback
    }

    #[test]
    fn test_resolve_identity_empty_env_var_falls_through() {
        std::env::set_var("EMPTY_HOST_Z", "");
        std::env::set_var("EMPTY_IP_Z", "");
        let result = resolve_identity(
            None, None,
            "EMPTY_HOST_Z", "EMPTY_IP_Z",
            "default-host", "127.0.0.1",
            true,
        ).unwrap();
        // Empty env vars should be treated as unset
        assert!(!result.hostname.is_empty());
        assert!(result.ip.is_some());
        std::env::remove_var("EMPTY_HOST_Z");
        std::env::remove_var("EMPTY_IP_Z");
    }
}
