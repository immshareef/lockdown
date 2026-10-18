use thiserror::Error;

#[derive(Error, Debug)]
pub enum LockdownError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Auth error: {0}")]
    Auth(String),

    #[error("Stealth error: {0}")]
    Stealth(String),

    #[error("Invalid file format")]
    InvalidFormat,

    #[error("Path traversal detected")]
    PathTraversal,

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T, E = LockdownError> = std::result::Result<T, E>;
