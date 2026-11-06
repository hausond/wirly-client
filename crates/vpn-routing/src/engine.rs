use std::net::IpAddr;

use ipnet::IpNet;

use crate::model::{Action, DomainMode, Matcher, Network, Preset, Rule};

#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    #[error("invalid CIDR `{0}`: {1}")]
    InvalidCidr(String, String),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Input for a routing decision.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionInfo<'a> {
    /// Domain from sniffing (TLS SNI / HTTP Host / QUIC SNI), if known.
    pub domain: Option<&'a str>,
    /// Destination IP, if known.
    pub ip: Option<IpAddr>,
    pub port: u16,
    /// Process executable name, if known (Windows: socket owner lookup).
    pub process: Option<&'a str>,
    pub network: Network,
}

impl<'a> ConnectionInfo<'a> {
    pub fn tcp(ip: IpAddr, port: u16) -> Self {
        Self {
            domain: None,
            ip: Some(ip),
            port,
            process: None,
            network: Network::Tcp,
        }
    }

    pub fn with_domain(mut self, domain: &'a str) -> Self {
        self.domain = Some(domain);
        self
    }

    pub fn with_process(mut self, process: &'a str) -> Self {
        self.process = Some(process);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    /// Index of the matched rule, `None` if the preset default was used.
    pub matched_rule: Option<usize>,
}

impl Decision {
    pub fn reason(&self) -> String {
        match self.matched_rule {
            Some(i) => format!("rule #{i}"),
            None => "preset default".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
enum CompiledMatcher {
    Domain { value: String, mode: DomainMode },
    Ip(IpNet),
    Port(u16),
    Process(String),
    Network(Network),
    Any,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    matcher: CompiledMatcher,
    action: Action,
    note: Option<String>,
}

/// Immutable, pre-compiled rule set. Cheap to query, safe to share across tasks.
#[derive(Debug, Clone)]
pub struct RoutingEngine {
    rules: Vec<CompiledRule>,
    default_action: Action,
}

impl RoutingEngine {
    pub fn new(preset: &Preset) -> Result<Self, RoutingError> {
        let mut rules = Vec::with_capacity(preset.rules.len());
        for rule in &preset.rules {
            rules.push(compile_rule(rule)?);
        }
        Ok(Self {
            rules,
            default_action: preset.default_action.clone(),
        })
    }

    pub fn from_json(json: &str) -> Result<Self, RoutingError> {
        let preset = Preset::from_json(json)?;
        Self::new(&preset)
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn decide(&self, conn: &ConnectionInfo<'_>) -> Decision {
        for (index, rule) in self.rules.iter().enumerate() {
            if matches(&rule.matcher, conn) {
                let _ = &rule.note;
                return Decision {
                    action: rule.action.clone(),
                    matched_rule: Some(index),
                };
            }
        }
        Decision {
            action: self.default_action.clone(),
            matched_rule: None,
        }
    }
}

fn compile_rule(rule: &Rule) -> Result<CompiledRule, RoutingError> {
    let matcher = match &rule.matcher {
        Matcher::Domain { value, mode } => CompiledMatcher::Domain {
            value: value.trim_start_matches('.').to_ascii_lowercase(),
            mode: *mode,
        },
        Matcher::Ip { cidr } => {
            CompiledMatcher::Ip(cidr.parse().map_err(|e: ipnet::AddrParseError| {
                RoutingError::InvalidCidr(cidr.clone(), e.to_string())
            })?)
        }
        Matcher::Port { value } => CompiledMatcher::Port(*value),
        Matcher::Process { name } => CompiledMatcher::Process(name.to_ascii_lowercase()),
        Matcher::Network { value } => CompiledMatcher::Network(*value),
        Matcher::Any => CompiledMatcher::Any,
    };
    Ok(CompiledRule {
        matcher,
        action: rule.action.clone(),
        note: rule.note.clone(),
    })
}

fn matches(matcher: &CompiledMatcher, conn: &ConnectionInfo<'_>) -> bool {
    match matcher {
        CompiledMatcher::Any => true,
        CompiledMatcher::Port(port) => conn.port == *port,
        CompiledMatcher::Network(net) => conn.network == *net,
        CompiledMatcher::Ip(net) => conn.ip.is_some_and(|ip| net.contains(&ip)),
        CompiledMatcher::Process(name) => conn.process.is_some_and(|p| {
            p.eq_ignore_ascii_case(name) || p.to_ascii_lowercase().ends_with(name)
        }),
        CompiledMatcher::Domain { value, mode } => {
            let Some(domain) = conn.domain else {
                return false;
            };
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            match mode {
                DomainMode::Exact => domain == *value,
                DomainMode::Keyword => domain.contains(value),
                DomainMode::Suffix => domain == *value || domain.ends_with(&format!(".{value}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Action;

    const PRESET: &str = r#"{
        "name": "test",
        "default_action": {"proxy": "default"},
        "rules": [
            { "match": { "type": "domain", "value": "youtube.com", "mode": "suffix" }, "action": {"proxy": "yt"} },
            { "match": { "type": "ip", "cidr": "10.0.0.0/8" }, "action": "direct" },
            { "match": { "type": "process", "name": "Wow.exe" }, "action": "direct" },
            { "match": { "type": "network", "value": "udp" }, "action": "block" }
        ]
    }"#;

    fn engine() -> RoutingEngine {
        RoutingEngine::from_json(PRESET).unwrap()
    }

    #[test]
    fn suffix_domain_matches_subdomains() {
        let e = engine();
        let ip = "142.250.1.1".parse().unwrap();
        let d = e.decide(&ConnectionInfo::tcp(ip, 443).with_domain("www.youtube.com"));
        assert_eq!(d.action, Action::Proxy("yt".into()));
        assert_eq!(d.matched_rule, Some(0));
    }

    #[test]
    fn suffix_does_not_match_lookalike() {
        let e = engine();
        let ip = "142.250.1.1".parse().unwrap();
        let d = e.decide(&ConnectionInfo::tcp(ip, 443).with_domain("notyoutube.com"));
        assert_eq!(d.action, Action::Proxy("default".into()));
        assert_eq!(d.matched_rule, None);
    }

    #[test]
    fn cidr_and_process_rules() {
        let e = engine();
        let lan: IpAddr = "10.1.2.3".parse().unwrap();
        assert_eq!(
            e.decide(&ConnectionInfo::tcp(lan, 80)).action,
            Action::Direct
        );
        let wan: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(
            e.decide(&ConnectionInfo::tcp(wan, 443).with_process("Wow.exe"))
                .action,
            Action::Direct
        );
    }

    #[test]
    fn udp_rule_wins_over_default() {
        let e = engine();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let d = e.decide(&ConnectionInfo {
            domain: None,
            ip: Some(ip),
            port: 443,
            process: None,
            network: Network::Udp,
        });
        assert_eq!(d.action, Action::Block);
        assert_eq!(d.matched_rule, Some(3));
    }

    #[test]
    fn invalid_cidr_is_reported() {
        let preset = Preset {
            name: "bad".into(),
            description: String::new(),
            default_action: Action::Direct,
            rules: vec![Rule {
                matcher: Matcher::Ip {
                    cidr: "nope".into(),
                },
                action: Action::Block,
                note: None,
            }],
        };
        assert!(matches!(
            RoutingEngine::new(&preset),
            Err(RoutingError::InvalidCidr(_, _))
        ));
    }

    #[test]
    fn given_matched_rule_then_reason_names_it() {
        let e = engine();
        let ip: IpAddr = "142.250.1.1".parse().unwrap();
        let decision = e.decide(&ConnectionInfo::tcp(ip, 443).with_domain("youtube.com"));
        assert_eq!(decision.reason(), "rule #0");
        let default = e.decide(&ConnectionInfo::tcp(ip, 443).with_domain("other.example"));
        assert_eq!(default.reason(), "preset default");
    }

    #[test]
    fn given_exact_and_keyword_modes_then_only_matching_domains_match() {
        let preset = Preset {
            name: "modes".into(),
            description: String::new(),
            default_action: Action::Block,
            rules: vec![
                Rule {
                    matcher: Matcher::Domain {
                        value: "exact.example".into(),
                        mode: DomainMode::Exact,
                    },
                    action: Action::Direct,
                    note: None,
                },
                Rule {
                    matcher: Matcher::Domain {
                        value: "keyword".into(),
                        mode: DomainMode::Keyword,
                    },
                    action: Action::Proxy("kw".into()),
                    note: None,
                },
            ],
        };
        let e = RoutingEngine::new(&preset).unwrap();
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(
            e.decide(&ConnectionInfo::tcp(ip, 443).with_domain("exact.example"))
                .action,
            Action::Direct
        );
        assert_eq!(
            e.decide(&ConnectionInfo::tcp(ip, 443).with_domain("sub.exact.example"))
                .action,
            Action::Block
        );
        assert_eq!(
            e.decide(&ConnectionInfo::tcp(ip, 443).with_domain("my-keyword-host.net"))
                .action,
            Action::Proxy("kw".into())
        );
    }

    #[test]
    fn given_any_matcher_then_matches_everything() {
        let preset = Preset {
            name: "any".into(),
            description: String::new(),
            default_action: Action::Block,
            rules: vec![Rule {
                matcher: Matcher::Any,
                action: Action::Direct,
                note: Some("catch-all".into()),
            }],
        };
        let e = RoutingEngine::new(&preset).unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(e.decide(&ConnectionInfo::tcp(ip, 1)).action, Action::Direct);
    }

    #[test]
    fn given_process_mismatch_then_default_applies() {
        let e = engine();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(
            e.decide(&ConnectionInfo::tcp(ip, 443).with_process("chrome.exe"))
                .action,
            Action::Proxy("default".into())
        );
    }

    #[test]
    fn action_helpers() {
        assert!(Action::Proxy("x".into()).is_proxy());
        assert!(!Action::Direct.is_proxy());
        assert!(!Action::Block.is_proxy());
    }

    #[test]
    fn preset_json_roundtrip() {
        let preset = Preset::from_json(PRESET).unwrap();
        let json = preset.to_json().unwrap();
        let again = Preset::from_json(&json).unwrap();
        assert_eq!(preset, again);
    }

    #[test]
    fn given_preset_then_rule_count_is_reported() {
        assert_eq!(engine().rule_count(), 4);
    }

    #[test]
    fn given_port_rule_when_connection_uses_port_then_matched() {
        let preset = Preset {
            name: "port".into(),
            description: String::new(),
            default_action: Action::Block,
            rules: vec![Rule {
                matcher: Matcher::Port { value: 443 },
                action: Action::Direct,
                note: None,
            }],
        };
        let e = RoutingEngine::new(&preset).unwrap();
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(
            e.decide(&ConnectionInfo::tcp(ip, 443)).action,
            Action::Direct
        );
        assert_eq!(e.decide(&ConnectionInfo::tcp(ip, 80)).action, Action::Block);
    }
}
