use serde::{Deserialize, Serialize};
use vpn_config::Profile;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SessionState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Failed {
        reason: String,
    },
}

impl SessionState {
    pub fn is_active(&self) -> bool {
        matches!(self, SessionState::Connected)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficStats {
    pub up_bytes: u64,
    pub down_bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("cannot connect while the session is in state `{0:?}`")]
    InvalidTransition(SessionState),
    #[error("no profile selected")]
    NoProfile,
    #[error("protocol error: {0}")]
    Protocol(#[from] vpn_proto::ProtoError),
}

#[derive(Debug, Default)]
pub struct Session {
    state: SessionState,
    profile: Option<Profile>,
    stats: TrafficStats,
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self) -> &SessionState {
        &self.state
    }

    pub fn profile(&self) -> Option<&Profile> {
        self.profile.as_ref()
    }

    pub fn stats(&self) -> TrafficStats {
        self.stats
    }

    /// Select a profile and move to `Connecting`.
    pub fn begin_connect(&mut self, profile: Profile) -> Result<(), SessionError> {
        if matches!(
            self.state,
            SessionState::Connecting | SessionState::Connected | SessionState::Disconnecting
        ) {
            return Err(SessionError::InvalidTransition(self.state.clone()));
        }
        self.profile = Some(profile);
        self.state = SessionState::Connecting;
        Ok(())
    }

    /// The tunnel is up and traffic can flow.
    pub fn mark_connected(&mut self) -> Result<(), SessionError> {
        if self.profile.is_none() {
            return Err(SessionError::NoProfile);
        }
        if self.state != SessionState::Connecting {
            return Err(SessionError::InvalidTransition(self.state.clone()));
        }
        self.state = SessionState::Connected;
        Ok(())
    }

    pub fn fail(&mut self, reason: impl Into<String>) {
        self.state = SessionState::Failed {
            reason: reason.into(),
        };
    }

    pub fn begin_disconnect(&mut self) -> Result<(), SessionError> {
        if self.state != SessionState::Connected {
            return Err(SessionError::InvalidTransition(self.state.clone()));
        }
        self.state = SessionState::Disconnecting;
        Ok(())
    }

    pub fn mark_disconnected(&mut self) {
        self.state = SessionState::Disconnected;
        self.profile = None;
        self.stats = TrafficStats::default();
    }

    pub fn add_traffic(&mut self, up: u64, down: u64) {
        self.stats.up_bytes = self.stats.up_bytes.saturating_add(up);
        self.stats.down_bytes = self.stats.down_bytes.saturating_add(down);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpn_config::{Profile, ProtocolConfig, ShadowsocksConfig};

    fn profile() -> Profile {
        Profile::new(
            "test",
            ProtocolConfig::Shadowsocks(ShadowsocksConfig {
                address: "127.0.0.1".into(),
                port: 8388,
                method: "aes-256-gcm".into(),
                password: "pw".into(),
            }),
        )
    }

    #[test]
    fn happy_path() {
        let mut s = Session::new();
        assert_eq!(*s.state(), SessionState::Disconnected);
        s.begin_connect(profile()).unwrap();
        assert_eq!(*s.state(), SessionState::Connecting);
        s.mark_connected().unwrap();
        assert_eq!(*s.state(), SessionState::Connected);
        s.add_traffic(100, 200);
        assert_eq!(s.stats().up_bytes, 100);
        s.begin_disconnect().unwrap();
        s.mark_disconnected();
        assert_eq!(*s.state(), SessionState::Disconnected);
        assert!(s.profile().is_none());
        assert_eq!(s.stats(), TrafficStats::default());
    }

    #[test]
    fn rejects_double_connect() {
        let mut s = Session::new();
        s.begin_connect(profile()).unwrap();
        assert!(matches!(
            s.begin_connect(profile()),
            Err(SessionError::InvalidTransition(_))
        ));
    }

    #[test]
    fn cannot_connect_without_profile() {
        let mut s = Session::new();
        assert!(matches!(s.mark_connected(), Err(SessionError::NoProfile)));
    }
}
