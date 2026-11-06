//! UI <-> service protocol. Windows: named pipe with an ACL that only allows
//! the interactive user. Linux: unix socket. Same serde payloads everywhere.

use serde::{Deserialize, Serialize};
use vpn_config::Profile;
use vpn_core::{SessionState, TrafficStats};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Request {
    Status,
    Stats,
    ListProfiles,
    ListPresets,
    Connect {
        profile: Box<Profile>,
        preset: Option<String>,
    },
    Disconnect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Status(SessionState),
    Stats(TrafficStats),
    Profiles(Vec<Profile>),
    Presets(Vec<String>),
    Error { message: String },
}
