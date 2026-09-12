use std::fs;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

pub async fn connect(
    host: &str,
    port: u16,
    ca: Option<&str>,
    cert: Option<&str>,
    key: Option<&str>,
) -> Result<Channel> {
    // Resolve certificate paths
    let cert_dir = std::env::var("CLN_CERT_DIR")
        .ok()
        .map(std::path::PathBuf::from);

    let ca_path = resolve_path(ca, &cert_dir, "ca.pem")?;
    let cert_path = resolve_path(cert, &cert_dir, "client.pem")?;
    let key_path = resolve_path(key, &cert_dir, "client-key.pem")?;

    // Read certificates
    let ca_pem = fs::read(&ca_path)
        .with_context(|| format!("Failed to read CA certificate: {}", ca_path.display()))?;
    let cert_pem = fs::read(&cert_path)
        .with_context(|| format!("Failed to read client certificate: {}", cert_path.display()))?;
    let key_pem = fs::read(&key_path)
        .with_context(|| format!("Failed to read client key: {}", key_path.display()))?;

    let ca = Certificate::from_pem(&ca_pem);
    let identity = Identity::from_pem(&cert_pem, &key_pem);

    // Verify the certificate against the host actually requested by the user.
    // Never hardcode a target name: that would defeat name verification.
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca)
        .identity(identity)
        .domain_name(tls_domain_name(host));

    let uri = format!("https://{}:{}", host, port);
    let channel = Endpoint::from_shared(uri.clone())
        .with_context(|| format!("Invalid endpoint: {}", uri))?
        .tls_config(tls)
        .with_context(|| "Failed to configure TLS")?
        // Bounded connection setup, without imposing a total timeout that would
        // kill long-lived streaming subscriptions.
        .connect_timeout(Duration::from_secs(10))
        .tcp_keepalive(Some(Duration::from_secs(60)))
        // Detect dead peers on idle streams.
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10))
        .connect()
        .await
        .with_context(|| format!("Failed to connect to {}", uri))?;

    Ok(channel)
}

fn resolve_path(
    arg: Option<&str>,
    cert_dir: &Option<std::path::PathBuf>,
    default_name: &str,
) -> Result<std::path::PathBuf> {
    if let Some(p) = arg {
        return Ok(std::path::PathBuf::from(p));
    }
    if let Some(dir) = cert_dir {
        return Ok(dir.join(default_name));
    }
    // Default to the admin ~/.certs directory; never a CWD-relative path.
    let default = gcob::certs::paths::ClientPaths::default_path()
        .map_err(|e| anyhow!("Cannot resolve the default ~/.certs directory: {e}"))?;
    Ok(default.cert_dir.join(default_name))
}

/// Target name used for TLS certificate verification.
///
/// DNS names are used as-is; bracketed IPv6 literals are unwrapped so that
/// rustls can parse them as IP addresses.
fn tls_domain_name(host: &str) -> String {
    host.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_domain_name_keeps_dns_host() {
        assert_eq!(tls_domain_name("node.example"), "node.example");
        assert_eq!(tls_domain_name("localhost"), "localhost");
    }

    #[test]
    fn tls_domain_name_unwraps_ipv6() {
        assert_eq!(tls_domain_name("[::1]"), "::1");
        assert_eq!(tls_domain_name("[fe80::1]"), "fe80::1");
    }

    #[test]
    fn explicit_cert_dir_wins_over_default() {
        let dir = Some(std::path::PathBuf::from("/srv/gcob/certs"));
        assert_eq!(
            resolve_path(None, &dir, "ca.pem").unwrap(),
            std::path::PathBuf::from("/srv/gcob/certs/ca.pem")
        );
        assert_eq!(
            resolve_path(Some("/tmp/ca.pem"), &dir, "ca.pem").unwrap(),
            std::path::PathBuf::from("/tmp/ca.pem")
        );
    }

    #[test]
    fn default_fallback_is_the_admin_certs_dir() {
        match resolve_path(None, &None, "client.pem") {
            Ok(path) => {
                assert!(path.is_absolute(), "{path:?}");
                assert!(path.ends_with(".certs/client.pem"), "{path:?}");
            }
            Err(e) => assert!(format!("{e}").contains("~/.certs"), "{e}"),
        }
    }
}
