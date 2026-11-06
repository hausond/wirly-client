use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    #[default]
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DomainMode {
    Exact,
    #[default]
    Suffix,
    Keyword,
}

/// What to do with a connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Direct,
    Block,
    /// Use the outbound with this name.
    Proxy(String),
}

impl Action {
    pub fn is_proxy(&self) -> bool {
        matches!(self, Action::Proxy(_))
    }
}

/// A single routing predicate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Matcher {
    Domain {
        value: String,
        #[serde(default)]
        mode: DomainMode,
    },
    /// CIDR, e.g. `10.0.0.0/8`, `142.250.0.0/15`.
    Ip {
        cidr: String,
    },
    Port {
        value: u16,
    },
    Process {
        name: String,
    },
    Network {
        value: Network,
    },
    /// Matches everything; useful as an explicit catch-all.
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    #[serde(rename = "match")]
    pub matcher: Matcher,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Preset {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub default_action: Action,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl Preset {
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}
