use async_trait::async_trait;
use tokio::net::{TcpStream, UdpSocket};
use vpn_config::{Profile, ProtocolConfig};

use crate::stubs::StubOutbound;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("protocol `{0}` is not implemented yet")]
    NotImplemented(&'static str),
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// A protocol engine able to open flows towards arbitrary destinations.
#[async_trait]
pub trait Outbound: Send + Sync {
    fn name(&self) -> &str;

    /// Open a reliable stream to `target` through the tunnel.
    async fn dial_tcp(&self, target: &Target) -> Result<TcpStream, ProtoError>;

    /// Open a datagram channel to `target` through the tunnel.
    async fn dial_udp(&self, target: &Target) -> Result<UdpSocket, ProtoError>;
}

/// Build an outbound from a stored profile.
pub fn create(profile: &Profile) -> Result<Box<dyn Outbound>, ProtoError> {
    let name = format!("{}:{}", profile.name, profile.id);
    Ok(match &profile.protocol {
        ProtocolConfig::WireGuard(_) => Box::new(StubOutbound::new(name, "wireguard")),
        ProtocolConfig::Shadowsocks(_) => Box::new(StubOutbound::new(name, "shadowsocks")),
        ProtocolConfig::Trojan(_) => Box::new(StubOutbound::new(name, "trojan")),
        ProtocolConfig::Vless(_) => Box::new(StubOutbound::new(name, "vless")),
        ProtocolConfig::Hysteria2(_) => Box::new(StubOutbound::new(name, "hysteria2")),
        ProtocolConfig::Tuic(_) => Box::new(StubOutbound::new(name, "tuic")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpn_config::{
        Hysteria2Config, ShadowsocksConfig, TrojanConfig, TuicConfig, VlessConfig, WireGuardConfig,
    };

    fn profile(protocol: ProtocolConfig) -> Profile {
        Profile::new("test", protocol)
    }

    fn vless() -> ProtocolConfig {
        ProtocolConfig::Vless(VlessConfig {
            address: "127.0.0.1".into(),
            port: 443,
            uuid: "u".into(),
            flow: None,
            network: vpn_config::Transport::Ws,
            security: vpn_config::Security::Tls,
            sni: None,
            host: None,
            path: None,
            public_key: None,
            short_id: None,
            fingerprint: None,
        })
    }

    #[test]
    fn given_each_protocol_when_creating_outbound_then_name_is_prefixed() {
        let cases = vec![
            ProtocolConfig::WireGuard(WireGuardConfig {
                endpoint: "e".into(),
                port: 1,
                private_key: "k".into(),
                peer_public_key: "p".into(),
                preshared_key: None,
                address: "10.0.0.2/32".into(),
                dns: None,
                mtu: None,
            }),
            ProtocolConfig::Shadowsocks(ShadowsocksConfig {
                address: "a".into(),
                port: 1,
                method: "m".into(),
                password: "p".into(),
            }),
            ProtocolConfig::Trojan(TrojanConfig {
                address: "a".into(),
                port: 1,
                password: "p".into(),
                sni: None,
                network: vpn_config::Transport::Tcp,
                path: None,
            }),
            vless(),
            ProtocolConfig::Hysteria2(Hysteria2Config {
                address: "a".into(),
                port: 1,
                password: "p".into(),
                sni: None,
                obfs: None,
                obfs_password: None,
                insecure: false,
            }),
            ProtocolConfig::Tuic(TuicConfig {
                address: "a".into(),
                port: 1,
                uuid: "u".into(),
                password: "p".into(),
                sni: None,
                congestion: None,
            }),
        ];

        for protocol in cases {
            let outbound = create(&profile(protocol)).expect("outbound is created");
            assert!(outbound.name().starts_with("test:"));
            assert!(outbound.name().len() > 5);
        }
    }
}
