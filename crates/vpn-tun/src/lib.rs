//! TUN abstraction.
//!
//! Phase 1 target: `wintun.dll` on Windows, `netlink`/`tun` on Linux.
//! The core only sees [`TunDevice`], so the platform code stays isolated.

use async_trait::async_trait;

#[derive(Debug, thiserror::Error)]
pub enum TunError {
    #[error("tun backend is not implemented yet")]
    NotImplemented,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("requires administrator privileges")]
    NotElevated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    /// Interface name, e.g. `hausond`.
    pub name: String,
    /// Address assigned to the interface, e.g. `10.9.0.1/24` or `198.19.0.1/15`.
    pub address: String,
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "hausond".into(),
            address: "198.19.0.1/15".into(),
            mtu: 1400,
        }
    }
}

/// An L3 tunnel interface exchanging raw IP packets.
#[async_trait]
pub trait TunDevice: Send + Sync {
    fn name(&self) -> &str;

    /// Read one IP packet into `buf`, returning its length.
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError>;

    /// Write one IP packet.
    async fn write_packet(&self, packet: &[u8]) -> Result<usize, TunError>;
}

/// Placeholder used until the wintun backend is wired up.
#[derive(Debug)]
pub struct NullTun;

#[async_trait]
impl TunDevice for NullTun {
    fn name(&self) -> &str {
        "null"
    }

    async fn read_packet(&self, _buf: &mut [u8]) -> Result<usize, TunError> {
        Err(TunError::NotImplemented)
    }

    async fn write_packet(&self, _packet: &[u8]) -> Result<usize, TunError> {
        Err(TunError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_default_config_then_sane_values() {
        let cfg = TunConfig::default();
        assert_eq!(cfg.name, "hausond");
        assert_eq!(cfg.mtu, 1400);
        assert!(cfg.address.contains('/'));
    }

    #[tokio::test]
    async fn given_null_tun_when_reading_then_not_implemented() {
        let tun = NullTun;
        assert_eq!(tun.name(), "null");
        let mut buf = [0u8; 4];
        assert!(matches!(
            tun.read_packet(&mut buf).await,
            Err(TunError::NotImplemented)
        ));
    }

    #[tokio::test]
    async fn given_null_tun_when_writing_then_not_implemented() {
        let tun = NullTun;
        assert!(matches!(
            tun.write_packet(&[1, 2, 3]).await,
            Err(TunError::NotImplemented)
        ));
    }
}
