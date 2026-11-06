//! Profile model and import of share links / subscriptions.

mod error;
mod profile;
mod subscription;
mod uri;

pub use error::ConfigError;
pub use profile::{
    Hysteria2Config, Profile, ProtocolConfig, Security, ShadowsocksConfig, Transport, TrojanConfig,
    TuicConfig, VlessConfig, WireGuardConfig,
};
pub use subscription::parse_subscription;
pub use uri::parse_uri;
