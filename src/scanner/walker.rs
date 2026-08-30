use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::crypto::cipher::is_encrypted_file;
use crate::error::Result;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ScannedFile {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub is_encrypted: bool,
    pub modified: std::time::SystemTime,
}

pub struct Scanner {
    base_dir: PathBuf,
    recursive: bool,
}

impl Scanner {
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            base_dir,
            recursive: false,
        }
    }

    pub fn with_recursive(mut self, recursive: bool) -> Self {
        self.recursive = recursive;
        self
    }

    pub fn scan(&self) -> Result<(Vec<ScannedFile>, Vec<ScannedFile>)> {
        let mut unencrypted = Vec::new();
        let mut encrypted = Vec::new();

        let walker = if self.recursive {
            WalkDir::new(&self.base_dir).follow_links(false)
        } else {
            WalkDir::new(&self.base_dir)
                .max_depth(1)
                .follow_links(false)
        };

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();

            if path == self.base_dir {
                continue;
            }

            if self.is_ignored(path) {
                continue;
            }

            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };

            if !metadata.is_file() {
                continue;
            }

            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            let modified = metadata
                .modified()
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

            let is_enc = self.check_if_encrypted(path)?;

            let file = ScannedFile {
                path: path.to_path_buf(),
                name,
                size: metadata.len(),
                is_encrypted: is_enc,
                modified,
            };

            if is_enc {
                encrypted.push(file);
            } else {
                unencrypted.push(file);
            }
        }

        unencrypted.sort_by(|a, b| a.name.cmp(&b.name));
        encrypted.sort_by(|a, b| a.name.cmp(&b.name));

        Ok((unencrypted, encrypted))
    }

    fn is_ignored(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        if path_str.contains(".lockdown") {
            return true;
        }

        if let Some(name) = path.file_name() {
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') && name_str != "." {
                return true;
            }
        }

        false
    }

    fn check_if_encrypted(&self, path: &Path) -> Result<bool> {
        let mut file = std::fs::File::open(path)?;
        let mut buffer = [0u8; 5];
        use std::io::Read;
        let bytes_read = file.read(&mut buffer)?;

        if bytes_read < 5 {
            return Ok(false);
        }

        Ok(is_encrypted_file(&buffer))
    }

    #[allow(dead_code)]
    pub fn validate_path(&self, path: &Path) -> Result<()> {
        let canonical_base = self.base_dir.canonicalize()?;
        let canonical_path = path.canonicalize()?;

        if !canonical_path.starts_with(&canonical_base) {
            return Err(crate::error::LockdownError::PathTraversal);
        }

        Ok(())
    }
}
