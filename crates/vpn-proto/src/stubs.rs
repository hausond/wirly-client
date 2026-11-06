use async_trait::async_trait;
use tokio::net::{TcpStream, UdpSocket};

use crate::outbound::{Outbound, ProtoError, Target};

/// Placeholder outbound: keeps the interface wired until the real engine lands.
#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::Target;

    #[tokio::test]
    async fn given_stub_when_dialing_tcp_then_not_implemented() {
        let outbound = StubOutbound::new("node".into(), "test");
        assert_eq!(outbound.name(), "node");
        let err = outbound.dial_tcp(&Target::new("example.com", 443)).await;
        assert!(matches!(err, Err(ProtoError::NotImplemented("test"))));
    }

    #[tokio::test]
    async fn given_stub_when_dialing_udp_then_not_implemented() {
        let outbound = StubOutbound::new("node".into(), "test");
        let err = outbound.dial_udp(&Target::new("example.com", 53)).await;
        assert!(matches!(err, Err(ProtoError::NotImplemented("test"))));
    }
}
