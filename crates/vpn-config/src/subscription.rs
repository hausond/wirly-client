use crate::error::ConfigError;
use crate::profile::Profile;
use crate::uri::{decode_base64, parse_uri};

/// Parse a subscription payload: either base64-encoded or plain text, one URI per line.
pub fn parse_subscription(payload: &str) -> Result<Vec<Profile>, ConfigError> {
    let payload = payload.trim();
    let decoded = decode_base64(payload).unwrap_or_else(|_| payload.to_string());

    let mut profiles = Vec::new();
    for line in decoded.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        profiles.push(parse_uri(line)?);
    }
    Ok(profiles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn parses_base64_subscription() {
        let body = "vless://uuid@1.2.3.4:443?security=tls#one\ntrojan://pw@example.com:443#two";
        let encoded = base64::engine::general_purpose::STANDARD.encode(body);
        let profiles = parse_subscription(&encoded).unwrap();
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].name, "one");
        assert_eq!(profiles[1].name, "two");
    }

    #[test]
    fn parses_plain_subscription() {
        let body = "ss://YWVzLTI1Ni1nY206cGFzcw==@example.com:8388#ss";
        let profiles = parse_subscription(body).unwrap();
        assert_eq!(profiles.len(), 1);
    }
}
