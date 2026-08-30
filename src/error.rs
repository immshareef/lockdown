use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum LockdownError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Auth error: {0}")]
    Auth(String),

    #[error("Scanner error: {0}")]
    #[allow(dead_code)]
    Scanner(String),

    #[error("Stealth error: {0}")]
    #[allow(dead_code)]
    Stealth(String),

    #[error("Invalid file format")]
    InvalidFormat,

    #[error("Password verification failed")]
    #[allow(dead_code)]
    PasswordMismatch,

    #[error("File not found: {0}")]
    #[allow(dead_code)]
    FileNotFound(String),

    #[error("Path traversal detected")]
    #[allow(dead_code)]
    PathTraversal,

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, LockdownError>;
