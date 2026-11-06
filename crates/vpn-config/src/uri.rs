use base64::Engine as _;
use url::Url;

use crate::error::ConfigError;
use crate::profile::{
    Hysteria2Config, Profile, ProtocolConfig, Security, ShadowsocksConfig, Transport, TrojanConfig,
    VlessConfig,
};

/// Parse a share link into a [`Profile`].
///
/// Supported: `vless://`, `trojan://`, `ss://` (SIP002 + legacy), `hysteria2://` / `hy2://`.
pub fn parse_uri(input: &str) -> Result<Profile, ConfigError> {
    let input = input.trim();
    let (scheme, rest) = input
        .split_once("://")
        .ok_or_else(|| ConfigError::InvalidUri(input.to_string()))?;

    match scheme.to_ascii_lowercase().as_str() {
        "vless" => parse_vless(rest),
        "trojan" => parse_trojan(rest),
        "ss" => parse_ss(rest),
        "hysteria2" | "hy2" => parse_hysteria2(rest),
        other => Err(ConfigError::UnsupportedScheme(other.to_string())),
    }
}

fn parse_vless(rest: &str) -> Result<Profile, ConfigError> {
    let url = Url::parse(&format!("vless://{rest}"))
        .map_err(|e| ConfigError::InvalidUri(e.to_string()))?;

    let uuid = url.username().to_string();
    if uuid.is_empty() {
        return Err(ConfigError::MissingField("uuid"));
    }
    let host = url
        .host_str()
        .ok_or(ConfigError::MissingField("address"))?
        .to_string();
    let port = url.port().ok_or(ConfigError::MissingField("port"))?;

    let q = Query::new(&url);
    let network = match q.get("type").as_deref() {
        Some("ws") | Some("websocket") => Transport::Ws,
        Some("grpc") | Some("gun") => Transport::Grpc,
        Some("xhttp") | Some("splithttp") => Transport::Xhttp,
        _ => Transport::Tcp,
    };
    let security = match q.get("security").as_deref() {
        Some("tls") => Security::Tls,
        Some("reality") => Security::Reality,
        _ => Security::None,
    };

    let cfg = VlessConfig {
        address: host,
        port,
        uuid,
        flow: q.get("flow").filter(|s| !s.is_empty()),
        network,
        security,
        sni: q.get("sni").filter(|s| !s.is_empty()),
        host: q.get("host").filter(|s| !s.is_empty()),
        path: q.get("path").filter(|s| !s.is_empty()),
        public_key: q.get("pbk").filter(|s| !s.is_empty()),
        short_id: q.get("sid").filter(|s| !s.is_empty()),
        fingerprint: q.get("fp").filter(|s| !s.is_empty()),
    };

    let name = profile_name(&url, &format!("vless-{}", cfg.address));
    Ok(Profile::new(name, ProtocolConfig::Vless(cfg)))
}

fn parse_trojan(rest: &str) -> Result<Profile, ConfigError> {
    let url = Url::parse(&format!("trojan://{rest}"))
        .map_err(|e| ConfigError::InvalidUri(e.to_string()))?;
    let password = percent_decode(url.username());
    if password.is_empty() {
        return Err(ConfigError::MissingField("password"));
    }
    let address = url
        .host_str()
        .ok_or(ConfigError::MissingField("address"))?
        .to_string();
    let port = url.port().ok_or(ConfigError::MissingField("port"))?;
    let q = Query::new(&url);
    let network = match q.get("type").as_deref() {
        Some("ws") | Some("websocket") => Transport::Ws,
        Some("grpc") => Transport::Grpc,
        _ => Transport::Tcp,
    };

    let cfg = TrojanConfig {
        address: address.clone(),
        port,
        password,
        sni: q.get("sni").filter(|s| !s.is_empty()),
        network,
        path: q.get("path").filter(|s| !s.is_empty()),
    };
    let name = profile_name(&url, &format!("trojan-{address}"));
    Ok(Profile::new(name, ProtocolConfig::Trojan(cfg)))
}

fn parse_ss(rest: &str) -> Result<Profile, ConfigError> {
    // SIP002: ss://base64(method:password)@host:port
    // Legacy: ss://base64(method:password@host:port)
    let (body, fragment) = match rest.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (rest, None),
    };

    let (credentials, host_port) = match body.rsplit_once('@') {
        Some((userinfo, host_port)) => {
            let decoded = percent_decode(userinfo);
            let credentials = decode_base64(&decoded).unwrap_or(decoded);
            (credentials, host_port.to_string())
        }
        None => {
            let decoded = decode_base64(body)?;
            let (credentials, host_port) = decoded
                .rsplit_once('@')
                .ok_or(ConfigError::MissingField("method:password@host:port"))?;
            (credentials.to_string(), host_port.to_string())
        }
    };

    let (method, password) = credentials
        .split_once(':')
        .ok_or(ConfigError::MissingField("method:password"))?;

    let url = Url::parse(&format!("ss://x@{host_port}"))
        .map_err(|e| ConfigError::InvalidUri(e.to_string()))?;
    let address = url
        .host_str()
        .ok_or(ConfigError::MissingField("address"))?
        .to_string();
    let port = url.port().ok_or(ConfigError::MissingField("port"))?;

    let cfg = ShadowsocksConfig {
        address: address.clone(),
        port,
        method: method.to_string(),
        password: password.to_string(),
    };
    let name = fragment
        .map(percent_decode)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("ss-{address}"));
    Ok(Profile::new(name, ProtocolConfig::Shadowsocks(cfg)))
}

fn parse_hysteria2(rest: &str) -> Result<Profile, ConfigError> {
    let url = Url::parse(&format!("hysteria2://{rest}"))
        .map_err(|e| ConfigError::InvalidUri(e.to_string()))?;
    let password = percent_decode(url.username());
    if password.is_empty() {
        return Err(ConfigError::MissingField("password"));
    }
    let q = Query::new(&url);
    let cfg = Hysteria2Config {
        address: url
            .host_str()
            .ok_or(ConfigError::MissingField("address"))?
            .to_string(),
        port: url.port().ok_or(ConfigError::MissingField("port"))?,
        password,
        sni: q.get("sni"),
        obfs: q.get("obfs"),
        obfs_password: q.get("obfs-password"),
        insecure: matches!(q.get("insecure").as_deref(), Some("1") | Some("true")),
    };
    let name = profile_name(&url, "hysteria2");
    Ok(Profile::new(name, ProtocolConfig::Hysteria2(cfg)))
}

struct Query(Vec<(String, String)>);

impl Query {
    fn new(url: &Url) -> Self {
        Self(
            url.query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect(),
        )
    }

    fn get(&self, key: &str) -> Option<String> {
        self.0
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.clone())
    }
}

fn profile_name(url: &Url, fallback: &str) -> String {
    url.fragment()
        .map(percent_decode)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

pub(crate) fn decode_base64(input: &str) -> Result<String, ConfigError> {
    let mut cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .collect();
    let pad = (4 - cleaned.len() % 4) % 4;
    cleaned.push_str(&"=".repeat(pad));
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(cleaned)
        .map_err(|e| ConfigError::Base64(e.to_string()))?;
    String::from_utf8(bytes).map_err(|e| ConfigError::Base64(e.to_string()))
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vless_ws_tls() {
        let uri = "vless://98d47ea6-7c92-4693-aff2-4b2a381c71de@91.192.157.137:443?type=ws&path=%2Fws-50ada98a&security=tls&sni=91.192.157.137&host=91.192.157.137&fp=chrome#vpn-Nikita-ws";
        let profile = parse_uri(uri).unwrap();
        assert_eq!(profile.name, "vpn-Nikita-ws");
        match profile.protocol {
            ProtocolConfig::Vless(c) => {
                assert_eq!(c.address, "91.192.157.137");
                assert_eq!(c.port, 443);
                assert_eq!(c.uuid, "98d47ea6-7c92-4693-aff2-4b2a381c71de");
                assert_eq!(c.network, Transport::Ws);
                assert_eq!(c.security, Security::Tls);
                assert_eq!(c.path.as_deref(), Some("/ws-50ada98a"));
                assert_eq!(c.fingerprint.as_deref(), Some("chrome"));
            }
            other => panic!("unexpected protocol: {other:?}"),
        }
    }

    #[test]
    fn parses_vless_reality() {
        let uri = "vless://uuid@1.2.3.4:443?security=reality&sni=www.microsoft.com&pbk=PUB&sid=abcd&flow=xtls-rprx-vision#reality";
        match parse_uri(uri).unwrap().protocol {
            ProtocolConfig::Vless(c) => {
                assert_eq!(c.security, Security::Reality);
                assert_eq!(c.public_key.as_deref(), Some("PUB"));
                assert_eq!(c.short_id.as_deref(), Some("abcd"));
                assert_eq!(c.flow.as_deref(), Some("xtls-rprx-vision"));
            }
            other => panic!("unexpected protocol: {other:?}"),
        }
    }

    #[test]
    fn parses_trojan() {
        let uri = "trojan://secret@example.com:443?sni=example.com&type=ws&path=%2Ft#node";
        match parse_uri(uri).unwrap().protocol {
            ProtocolConfig::Trojan(c) => {
                assert_eq!(c.password, "secret");
                assert_eq!(c.network, Transport::Ws);
                assert_eq!(c.path.as_deref(), Some("/t"));
            }
            other => panic!("unexpected protocol: {other:?}"),
        }
    }

    #[test]
    fn parses_ss_sip002() {
        let userinfo = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:pass");
        let uri = format!("ss://{userinfo}@example.com:8388#ssnode");
        match parse_uri(&uri).unwrap().protocol {
            ProtocolConfig::Shadowsocks(c) => {
                assert_eq!(c.method, "aes-256-gcm");
                assert_eq!(c.password, "pass");
            }
            other => panic!("unexpected protocol: {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(matches!(
            parse_uri("vmess://abc"),
            Err(ConfigError::UnsupportedScheme(_))
        ));
    }

    #[test]
    fn parses_hysteria2_with_obfs() {
        let uri = "hysteria2://secret@example.com:443?sni=example.com&obfs=salamander&obfs-password=pw&insecure=1#hy";
        match parse_uri(uri).unwrap().protocol {
            ProtocolConfig::Hysteria2(c) => {
                assert_eq!(c.password, "secret");
                assert_eq!(c.sni.as_deref(), Some("example.com"));
                assert_eq!(c.obfs.as_deref(), Some("salamander"));
                assert_eq!(c.obfs_password.as_deref(), Some("pw"));
                assert!(c.insecure);
            }
            other => panic!("unexpected protocol: {other:?}"),
        }
    }

    #[test]
    fn parses_legacy_ss() {
        let payload =
            base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:pw@example.com:8388");
        match parse_uri(&format!("ss://{payload}#legacy"))
            .unwrap()
            .protocol
        {
            ProtocolConfig::Shadowsocks(c) => {
                assert_eq!(c.address, "example.com");
                assert_eq!(c.port, 8388);
                assert_eq!(c.method, "aes-256-gcm");
                assert_eq!(c.password, "pw");
            }
            other => panic!("unexpected protocol: {other:?}"),
        }
    }

    #[test]
    fn decodes_percent_encoded_profile_name() {
        let profile = parse_uri("trojan://pw@example.com:443#my%20node").unwrap();
        assert_eq!(profile.name, "my node");
    }

    #[test]
    fn rejects_vless_without_uuid() {
        assert!(matches!(
            parse_uri("vless://example.com:443?security=tls"),
            Err(ConfigError::MissingField("uuid"))
        ));
    }

    #[test]
    fn rejects_vless_without_port() {
        assert!(matches!(
            parse_uri("vless://uuid@example.com"),
            Err(ConfigError::MissingField("port"))
        ));
    }

    #[test]
    fn rejects_invalid_base64() {
        assert!(matches!(
            parse_uri("ss://!!!@example.com:1"),
            Err(ConfigError::MissingField(_))
        ));
    }
}
