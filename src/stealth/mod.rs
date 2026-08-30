pub mod disguise;
pub mod attributes;

pub use disguise::*;
pub use attributes::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StealthMode {
    Disguise,
    Hide,
    Ghost,
}

impl Default for StealthMode {
    fn default() -> Self {
        Self::Disguise
    }
}

impl std::fmt::Display for StealthMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disguise => write!(f, "Disguise"),
            Self::Hide => write!(f, "Hide"),
            Self::Ghost => write!(f, "Ghost"),
        }
    }
}
