pub mod info;
pub mod invoice;
pub mod watch;
pub mod xpay;

use anyhow::{anyhow, Result};
use tonic::metadata::{Ascii, MetadataMap, MetadataValue};

/// Insert a gRPC metadata header, returning an error instead of panicking when
/// the value contains invalid header characters (e.g. CR, LF or NUL).
pub fn insert_header(map: &mut MetadataMap, key: &'static str, value: &str) -> Result<()> {
    let parsed: MetadataValue<Ascii> = value
        .parse()
        .map_err(|_| anyhow!("Invalid value for header '{}': must be visible ASCII", key))?;
    map.insert(key, parsed);
    Ok(())
}

/// Truncate a string at (or before) `max` bytes without splitting a UTF-8
/// code point. Untrusted server data must never trigger a slicing panic.
pub fn truncate_utf8(input: &str, max: usize) -> String {
    if input.len() <= max {
        return input.to_string();
    }
    let mut end = max;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &input[..end])
}

/// Remove control characters (including ANSI/OSC escapes) from untrusted text
/// before printing it to the terminal.
pub fn sanitize(input: &str) -> String {
    input.chars().filter(|c| !c.is_control()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_utf8_does_not_split_code_points() {
        // Each 'ñ' is 2 bytes; truncating at 3 bytes must back off to 2.
        let text = "añañ";
        assert_eq!(truncate_utf8(text, 3), "añ...");

        // Every boundary must produce valid UTF-8 without panicking.
        for max in 0..text.len() + 2 {
            let result = truncate_utf8(text, max);
            let body = result.strip_suffix("...").unwrap_or(&result);
            assert!(body.chars().count() <= text.chars().count());
        }
    }

    #[test]
    fn truncate_utf8_keeps_short_strings() {
        assert_eq!(truncate_utf8("hello", 10), "hello");
    }

    #[test]
    fn sanitize_strips_escapes_and_control_chars() {
        let malicious = "invoice\x1b]52;c;cGF3bmVk\x07\nspoof";
        let clean = sanitize(malicious);
        assert!(!clean.contains('\x1b'));
        assert!(!clean.contains('\x07'));
        assert!(!clean.contains('\n'));
        assert!(clean.starts_with("invoice]52;c;cGF3bmVk"));
        assert!(clean.ends_with("spoof"));
    }

    #[test]
    fn insert_header_rejects_control_chars() {
        let mut map = MetadataMap::new();
        assert!(insert_header(&mut map, "x-rune", "valid-rune").is_ok());
        assert!(insert_header(&mut map, "x-rune", "bad\nvalue").is_err());
        assert!(insert_header(&mut map, "x-rune", "bad\rvalue").is_err());
        assert!(insert_header(&mut map, "x-rune", "bad\0value").is_err());
    }
}
