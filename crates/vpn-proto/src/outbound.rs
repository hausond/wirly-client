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
