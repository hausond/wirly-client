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
    // `Url::parse` rejects empty hosts for these schemes, so the host is always present.
    let host = url.host_str().unwrap_or_default().to_string();
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
    // `Url::parse` rejects empty hosts for these schemes, so the host is always present.
    let address = url.host_str().unwrap_or_default().to_string();
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
    // `Url::parse` rejects empty hosts for these schemes, so the host is always present.
    let address = url.host_str().unwrap_or_default().to_string();
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
        // `Url::parse` rejects empty hosts for these schemes, so the host is always present.
        address: url.host_str().unwrap_or_default().to_string(),
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
