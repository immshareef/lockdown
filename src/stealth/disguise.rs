use rand::Rng;
use std::path::{Path, PathBuf};

use crate::error::Result;

const BENIGN_EXTENSIONS: &[&str] = &[
    ".dat", ".tmp", ".cache", ".bin", ".sys", ".log", ".bak", ".old", ".swp", ".dmp",
];

const ADJECTIVES: &[&str] = &[
    "sys", "cache", "temp", "backup", "core", "data", "index", "store", "blob", "chunk",
];

const NOUNS: &[&str] = &[
    "32", "64", "128", "256", "512", "1024", "a1", "b2", "c3", "x7", "f0", "e9",
];

pub fn generate_disguised_name() -> String {
    let mut rng = rand::thread_rng();
    let adj = ADJECTIVES[rng.gen_range(0..ADJECTIVES.len())];
    let noun = NOUNS[rng.gen_range(0..NOUNS.len())];
    let ext = BENIGN_EXTENSIONS[rng.gen_range(0..BENIGN_EXTENSIONS.len())];
    let random_suffix: u32 = rng.gen_range(1000..9999);
    format!("{}_{}_{}{}", adj, noun, random_suffix, ext)
}

pub fn apply_disguise(
    encrypted_data: &[u8],
    target_dir: &Path,
) -> Result<PathBuf> {
    let filename = generate_disguised_name();
    let path = target_dir.join(filename);
    std::fs::write(&path, encrypted_data)?;
    Ok(path)
}

pub fn remove_disguise(path: &Path) -> Result<()> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}
