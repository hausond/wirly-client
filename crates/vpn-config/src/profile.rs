use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single user-facing configuration ("node").
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub id: Uuid,
    pub name: String,
    pub protocol: ProtocolConfig,
    /// Name of the routing preset to use; `None` means the app default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_preset: Option<String>,
}

impl Profile {
    pub fn new(name: impl Into<String>, protocol: ProtocolConfig) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            protocol,
            routing_preset: None,
        }
    }
}

/// Wire format is adjacently tagged: `{"type": "vless", "params": { ... }}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "params", rename_all = "snake_case")]
pub enum ProtocolConfig {
    Vless(VlessConfig),
    Trojan(TrojanConfig),
    Shadowsocks(ShadowsocksConfig),
    WireGuard(WireGuardConfig),
    Hysteria2(Hysteria2Config),
    Tuic(TuicConfig),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    #[default]
    Tcp,
    Ws,
    Grpc,
    Xhttp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Security {
    #[default]
    None,
    Tls,
    Reality,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VlessConfig {
    pub address: String,
    pub port: u16,
    pub uuid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(default)]
    pub network: Transport,
    #[serde(default)]
    pub security: Security,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrojanConfig {
    pub address: String,
    pub port: u16,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default)]
    pub network: Transport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowsocksConfig {
    pub address: String,
    pub port: u16,
    pub method: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireGuardConfig {
    pub endpoint: String,
    pub port: u16,
    pub private_key: String,
    pub peer_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
    /// Interface address, e.g. `10.9.0.2/32`.
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hysteria2Config {
    pub address: String,
    pub port: u16,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs_password: Option<String>,
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TuicConfig {
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub congestion: Option<String>,
}
