//! Routing rule model, matcher compilation and decision engine.

mod engine;
mod model;

pub use engine::{ConnectionInfo, Decision, RoutingEngine, RoutingError};
pub use model::{Action, DomainMode, Matcher, Network, Preset, Rule};
