use async_trait::async_trait;
use tokio::net::{TcpStream, UdpSocket};

use crate::outbound::{Outbound, ProtoError, Target};

/// Placeholder outbound: keeps the interface wired until the real engine lands.
pub struct StubOutbound {
    name: String,
    protocol: &'static str,
}

impl StubOutbound {
    pub fn new(name: String, protocol: &'static str) -> Self {
        Self { name, protocol }
    }
}

#[async_trait]
impl Outbound for StubOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn dial_tcp(&self, _target: &Target) -> Result<TcpStream, ProtoError> {
        Err(ProtoError::NotImplemented(self.protocol))
    }

    async fn dial_udp(&self, _target: &Target) -> Result<UdpSocket, ProtoError> {
        Err(ProtoError::NotImplemented(self.protocol))
    }
}
