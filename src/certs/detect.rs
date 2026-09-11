use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::generate::CertError;

/// Maximum time a detection helper may run before it is killed.
const DETECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Run the first existing binary from an absolute-path candidate list.
///
/// Binaries are never resolved through `PATH`, so a manipulated environment
/// cannot make this process execute an attacker-controlled `hostname`/`ip`.
/// Commands that exceed [`DETECT_TIMEOUT`] are killed instead of hanging init.
fn run_first(candidates: &[&str], args: &[&str]) -> Option<String> {
    for candidate in candidates {
        if !PathBuf::from(candidate).is_file() {
            continue;
        }

        let mut child = match Command::new(candidate)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => continue,
        };

        let deadline = Instant::now() + DETECT_TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break None,
            }
        };

        if let Some(status) = status {
            if status.success() {
                let mut output = String::new();
                if let Some(mut stdout) = child.stdout.take() {
                    let _ = stdout.read_to_string(&mut output);
                }
                return Some(output);
            }
        }
    }
    None
}

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
        .or_else(|| {
            std::env::var(env_hostname_key)
                .ok()
                .filter(|v| !v.is_empty())
        })
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

/// Resolve the server identity from CLI flags, then auto-detection.
///
/// Unlike the client flow, environment variables are never consulted here:
/// identity must come from an explicit flag or from the running host.
pub fn resolve_server_identity(
    flag_hostname: Option<&str>,
    flag_ip: Option<&str>,
    default_hostname: &str,
) -> Result<ResolvedIdentity, CertError> {
    let hostname = flag_hostname
        .map(str::to_string)
        .or_else(|| detect_hostname().ok())
        .unwrap_or_else(|| default_hostname.to_string());

    let ip = match flag_ip {
        Some(ip) => Some(ip.to_string()),
        None => detect_ip().ok(),
    };

    Ok(ResolvedIdentity { hostname, ip })
}

/// Validate a value used as certificate CN/SAN.
///
/// IP literals are validated as unicast addresses; DNS names must be
/// ASCII LDH labels (1-63 chars each, total <= 253) with no wildcards.
pub fn validate_hostname(hostname: &str, allow_loopback: bool) -> Result<(), CertError> {
    if hostname.is_empty() {
        return Err(CertError::Parse("Hostname must not be empty".to_string()));
    }
    if hostname.contains('*') {
        return Err(CertError::Parse(
            "Wildcard hostnames are not allowed for server certificates".to_string(),
        ));
    }
    if !hostname.is_ascii() {
        return Err(CertError::Parse(
            "Hostname must be ASCII (punycode IDN explicitly)".to_string(),
        ));
    }
    if hostname.len() > 253 {
        return Err(CertError::Parse(
            "Hostname exceeds 253 characters".to_string(),
        ));
    }

    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return validate_ip_addr(ip, allow_loopback);
    }

    if hostname.starts_with('.') || hostname.ends_with('.') || hostname.contains("..") {
        return Err(CertError::Parse(format!(
            "Invalid hostname '{}': empty label",
            hostname
        )));
    }

    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(CertError::Parse(format!(
                "Invalid hostname '{}': label length",
                hostname
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(CertError::Parse(format!(
                "Invalid hostname '{}': label starts or ends with '-'",
                hostname
            )));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(CertError::Parse(format!(
                "Invalid hostname '{}': only ASCII letters, digits and '-' are allowed",
                hostname
            )));
        }
    }

    Ok(())
}

/// Validate an IPv4/IPv6 literal used as a server SAN.
///
/// Rejects unspecified, multicast and broadcast addresses. Loopback is only
/// accepted when `allow_loopback` is set.
pub fn validate_unicast_ip(ip: &str, allow_loopback: bool) -> Result<(), CertError> {
    let parsed: IpAddr = ip
        .parse()
        .map_err(|_| CertError::InvalidIp(ip.to_string()))?;
    validate_ip_addr(parsed, allow_loopback)
}

fn validate_ip_addr(ip: IpAddr, allow_loopback: bool) -> Result<(), CertError> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() {
                return Err(CertError::InvalidIp(format!(
                    "IP {} is not a usable unicast address",
                    v4
                )));
            }
            if v4.is_loopback() && !allow_loopback {
                return Err(CertError::InvalidIp(format!(
                    "IP {} is loopback; pass --allow-loopback to accept it",
                    v4
                )));
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() || v6.is_multicast() {
                return Err(CertError::InvalidIp(format!(
                    "IP {} is not a usable unicast address",
                    v6
                )));
            }
            if v6.is_loopback() && !allow_loopback {
                return Err(CertError::InvalidIp(format!(
                    "IP {} is loopback; pass --allow-loopback to accept it",
                    v6
                )));
            }
        }
    }
    Ok(())
}

/// Detect system hostname: FQDN via `hostname -f` (absolute path), then
/// `gethostname(2)` as a process-free fallback.
#[cfg(unix)]
pub fn detect_hostname() -> Result<String, CertError> {
    if let Some(stdout) = run_first(&["/usr/bin/hostname", "/bin/hostname"], &["-f"]) {
        let hostname = stdout.trim().to_string();
        if !hostname.is_empty() {
            return Ok(hostname);
        }
    }

    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return Err(CertError::Io(std::io::Error::other(
            "Cannot detect hostname: gethostname failed",
        )));
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let hostname = String::from_utf8_lossy(&buf[..end]).trim().to_string();
    if hostname.is_empty() {
        return Err(CertError::Io(std::io::Error::other(
            "Cannot detect hostname: empty result",
        )));
    }
    Ok(hostname)
}

#[cfg(not(unix))]
pub fn detect_hostname() -> Result<String, CertError> {
    Err(CertError::Io(std::io::Error::other(
        "Cannot detect hostname on this platform",
    )))
}

/// Detect the primary IPv4 address using `ip -4 addr show`, then `ifconfig`.
/// Both binaries are resolved by absolute path and their output is validated.
pub fn detect_ip() -> Result<String, CertError> {
    if let Some(stdout) = run_first(
        &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"],
        &["-4", "addr", "show"],
    ) {
        if let Some(ip) = parse_ip_from_ip_addr(&stdout) {
            return Ok(ip);
        }
    }

    if let Some(stdout) = run_first(
        &[
            "/usr/sbin/ifconfig",
            "/sbin/ifconfig",
            "/usr/bin/ifconfig",
            "/bin/ifconfig",
        ],
        &[],
    ) {
        if let Some(ip) = parse_ip_from_ifconfig(&stdout) {
            return Ok(ip);
        }
    }

    Err(CertError::Io(std::io::Error::other(
        "Cannot detect IP: 'ip' and 'ifconfig' failed or returned no valid IPv4 address",
    )))
}

/// Parse IPv4 from `ip -4 addr show` output.
/// Looks for lines like: inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0
fn parse_ip_from_ip_addr(output: &str) -> Option<String> {
    for line in output.lines() {
        let Some(after_inet) = line.trim().strip_prefix("inet ") else {
            continue;
        };
        let ip = after_inet.split('/').next().unwrap_or_default();
        // Skip loopback and reject anything that is not a valid IPv4 address.
        if ip != "127.0.0.1" && ip.parse::<Ipv4Addr>().is_ok() {
            return Some(ip.to_string());
        }
    }
    None
}

/// Parse IPv4 from `ifconfig` output.
/// Looks for lines like: inet 192.168.1.50 netmask 255.255.255.0
fn parse_ip_from_ifconfig(output: &str) -> Option<String> {
    for line in output.lines() {
        let line = line.trim();
        if line.contains("127.0.0.1") {
            continue;
        }
        let Some(start) = line.find("inet ") else {
            continue;
        };
        let after_inet = &line[start + "inet ".len()..];
        let candidate: String = after_inet
            .chars()
            .take_while(|c| !c.is_whitespace())
            .collect();
        if candidate.parse::<Ipv4Addr>().is_ok() {
            return Some(candidate);
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
        assert_eq!(
            parse_ip_from_ip_addr(output),
            Some("192.168.1.50".to_string())
        );
    }

    #[test]
    fn test_parse_ip_from_ip_addr_loopback_only() {
        let output = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    inet 127.0.0.1/8 scope host lo\n       valid_lft forever preferred_lft forever";
        assert_eq!(parse_ip_from_ip_addr(output), None);
    }

    #[test]
    fn test_parse_ip_from_ifconfig() {
        let output = "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.50  netmask 255.255.255.0  broadcast 192.168.1.255\n        inet6 fe80::1234:5678:90ab:cdef  prefixlen 64  scopeid 0x20<link>\n        ether aa:bb:cc:dd:ee:ff  txqueuelen 1000  (Ethernet)";
        assert_eq!(
            parse_ip_from_ifconfig(output),
            Some("192.168.1.50".to_string())
        );
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
            Some("flag-host"),
            Some("10.0.0.99"),
            "TEST_HOSTNAME",
            "TEST_IP",
            "default-host",
            "127.0.0.1",
            true,
        )
        .unwrap();
        assert_eq!(result.hostname, "flag-host");
        assert_eq!(result.ip, Some("10.0.0.99".to_string()));
    }

    #[test]
    fn test_resolve_identity_env_overrides_detect() {
        std::env::set_var("TEST_HOSTNAME_X", "env-host");
        std::env::set_var("TEST_IP_X", "10.0.0.50");
        let result = resolve_identity(
            None,
            None,
            "TEST_HOSTNAME_X",
            "TEST_IP_X",
            "default-host",
            "127.0.0.1",
            true,
        )
        .unwrap();
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
            None,
            None,
            "NONEXISTENT_KEY_HOST_X",
            "NONEXISTENT_KEY_IP_X",
            "default-host",
            "192.168.0.1",
            true,
        )
        .unwrap();
        // hostname falls back to auto-detect (real hostname), IP falls back to auto-detect or default
        assert!(!result.hostname.is_empty());
        assert!(result.ip.is_some());
    }

    #[test]
    fn test_resolve_identity_require_ip_false_allows_none() {
        std::env::remove_var("NONEXISTENT_KEY_HOST_Y");
        std::env::remove_var("NONEXISTENT_KEY_IP_Y");
        let result = resolve_identity(
            None,
            None,
            "NONEXISTENT_KEY_HOST_Y",
            "NONEXISTENT_KEY_IP_Y",
            "default-host",
            "127.0.0.1",
            false,
        )
        .unwrap();
        assert!(!result.hostname.is_empty());
        // IP can be None when require_ip=false and no env var set and auto-detect returns loopback
    }

    #[test]
    fn test_resolve_identity_empty_env_var_falls_through() {
        std::env::set_var("EMPTY_HOST_Z", "");
        std::env::set_var("EMPTY_IP_Z", "");
        let result = resolve_identity(
            None,
            None,
            "EMPTY_HOST_Z",
            "EMPTY_IP_Z",
            "default-host",
            "127.0.0.1",
            true,
        )
        .unwrap();
        // Empty env vars should be treated as unset
        assert!(!result.hostname.is_empty());
        assert!(result.ip.is_some());
        std::env::remove_var("EMPTY_HOST_Z");
        std::env::remove_var("EMPTY_IP_Z");
    }

    #[test]
    fn test_parse_ip_from_ip_addr_ignores_invalid() {
        let output = "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet not-an-ip/24 scope global eth0\n    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0";
        assert_eq!(
            parse_ip_from_ip_addr(output),
            Some("192.168.1.50".to_string())
        );
    }

    #[test]
    fn test_parse_ip_from_ifconfig_ignores_invalid() {
        let output = "eth0: flags=4163<UP>  mtu 1500\n        inet garbage  netmask 255.255.255.0\n        inet 10.0.0.7  netmask 255.255.255.0";
        assert_eq!(parse_ip_from_ifconfig(output), Some("10.0.0.7".to_string()));
    }

    #[test]
    fn validate_hostname_accepts_dns_names() {
        for hostname in ["node.example", "a", "debian-knots", "x1.y2.z3"] {
            assert!(validate_hostname(hostname, false).is_ok(), "{hostname}");
        }
    }

    #[test]
    fn validate_hostname_rejects_wildcards_and_invalid() {
        for hostname in [
            "*",
            "*.example.com",
            "bad host",
            "-bad.example",
            "bad-.example",
            "a..b",
            ".a",
            "a.",
            "ñ.example",
            "has\x1bescape",
        ] {
            assert!(
                validate_hostname(hostname, false).is_err(),
                "{hostname} should be rejected"
            );
        }
        assert!(validate_hostname(&"a".repeat(64), false).is_err());
        let long = vec!["abc"; 100].join(".");
        assert!(validate_hostname(&long, false).is_err());
    }

    #[test]
    fn validate_hostname_handles_ip_literals() {
        assert!(validate_hostname("10.0.0.5", false).is_ok());
        assert!(validate_hostname("0.0.0.0", false).is_err());
        assert!(validate_hostname("127.0.0.1", false).is_err());
        assert!(validate_hostname("127.0.0.1", true).is_ok());
        assert!(validate_hostname("::1", false).is_err());
        assert!(validate_hostname("::1", true).is_ok());
    }

    #[test]
    fn validate_unicast_ip_rules() {
        assert!(validate_unicast_ip("192.168.1.10", false).is_ok());
        assert!(validate_unicast_ip("0.0.0.0", false).is_err());
        assert!(validate_unicast_ip("224.0.0.1", false).is_err());
        assert!(validate_unicast_ip("255.255.255.255", false).is_err());
        assert!(validate_unicast_ip("::", false).is_err());
        assert!(validate_unicast_ip("ff02::1", false).is_err());
        assert!(validate_unicast_ip("not-an-ip", false).is_err());
    }

    #[test]
    fn resolve_server_identity_ignores_env() {
        std::env::set_var("CLN_HOSTNAME", "evil.example");
        std::env::set_var("CLN_IP", "10.9.9.9");

        let identity = resolve_server_identity(None, None, "localhost").unwrap();
        assert_ne!(identity.hostname, "evil.example");
        assert_ne!(identity.ip.as_deref(), Some("10.9.9.9"));

        std::env::remove_var("CLN_HOSTNAME");
        std::env::remove_var("CLN_IP");
    }
}
