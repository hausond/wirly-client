#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("unsupported or malformed URI: {0}")]
    InvalidUri(String),
    #[error("unsupported protocol scheme: {0}")]
    UnsupportedScheme(String),
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid port: {0}")]
    InvalidPort(String),
    #[error("invalid base64 payload: {0}")]
    Base64(String),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
