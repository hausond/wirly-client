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

impl ProtocolConfig {
    /// Returns the VLESS settings if this profile uses VLESS.
    pub fn as_vless(&self) -> Option<&VlessConfig> {
        match self {
            ProtocolConfig::Vless(config) => Some(config),
            _ => None,
        }
    }

    /// Returns the Trojan settings if this profile uses Trojan.
    pub fn as_trojan(&self) -> Option<&TrojanConfig> {
        match self {
            ProtocolConfig::Trojan(config) => Some(config),
            _ => None,
        }
    }

    /// Returns the Shadowsocks settings if this profile uses Shadowsocks.
    pub fn as_shadowsocks(&self) -> Option<&ShadowsocksConfig> {
        match self {
            ProtocolConfig::Shadowsocks(config) => Some(config),
            _ => None,
        }
    }

    /// Returns the WireGuard settings if this profile uses WireGuard.
    pub fn as_wireguard(&self) -> Option<&WireGuardConfig> {
        match self {
            ProtocolConfig::WireGuard(config) => Some(config),
            _ => None,
        }
    }

    /// Returns the Hysteria2 settings if this profile uses Hysteria2.
    pub fn as_hysteria2(&self) -> Option<&Hysteria2Config> {
        match self {
            ProtocolConfig::Hysteria2(config) => Some(config),
            _ => None,
        }
    }

    /// Returns the TUIC settings if this profile uses TUIC.
    pub fn as_tuic(&self) -> Option<&TuicConfig> {
        match self {
            ProtocolConfig::Tuic(config) => Some(config),
            _ => None,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn vless() -> ProtocolConfig {
        ProtocolConfig::Vless(VlessConfig {
            address: "a".into(),
            port: 1,
            uuid: "u".into(),
            flow: None,
            network: Transport::Tcp,
            security: Security::None,
            sni: None,
            host: None,
            path: None,
            public_key: None,
            short_id: None,
            fingerprint: None,
        })
    }

    #[test]
    fn given_vless_when_querying_accessors_then_only_vless_matches() {
        let config = vless();
        assert!(config.as_vless().is_some());
        assert!(config.as_trojan().is_none());
        assert!(config.as_shadowsocks().is_none());
        assert!(config.as_wireguard().is_none());
        assert!(config.as_hysteria2().is_none());
        assert!(config.as_tuic().is_none());
    }

    #[test]
    fn given_other_protocols_when_querying_accessors_then_matching_variant_is_some() {
        let trojan = ProtocolConfig::Trojan(TrojanConfig {
            address: "a".into(),
            port: 1,
            password: "p".into(),
            sni: None,
            network: Transport::Tcp,
            path: None,
        });
        assert!(trojan.as_trojan().is_some());

        let ss = ProtocolConfig::Shadowsocks(ShadowsocksConfig {
            address: "a".into(),
            port: 1,
            method: "m".into(),
            password: "p".into(),
        });
        assert!(ss.as_shadowsocks().is_some());

        let wg = ProtocolConfig::WireGuard(WireGuardConfig {
            endpoint: "e".into(),
            port: 1,
            private_key: "k".into(),
            peer_public_key: "p".into(),
            preshared_key: None,
            address: "10.0.0.2/32".into(),
            dns: None,
            mtu: None,
        });
        assert!(wg.as_wireguard().is_some());

        let hy2 = ProtocolConfig::Hysteria2(Hysteria2Config {
            address: "a".into(),
            port: 1,
            password: "p".into(),
            sni: None,
            obfs: None,
            obfs_password: None,
            insecure: false,
        });
        assert!(hy2.as_hysteria2().is_some());

        let tuic = ProtocolConfig::Tuic(TuicConfig {
            address: "a".into(),
            port: 1,
            uuid: "u".into(),
            password: "p".into(),
            sni: None,
            congestion: None,
        });
        assert!(tuic.as_tuic().is_some());
    }

    #[test]
    fn given_profile_when_serialized_then_roundtrips() {
        let profile = Profile::new("node", vless());
        let json = serde_json::to_string(&profile).unwrap();
        let restored: Profile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile, restored);
    }
}
