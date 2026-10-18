use std::path::{Path, PathBuf};
use std::time::SystemTime;
use walkdir::WalkDir;

use crate::crypto::cipher::is_encrypted_file;
use crate::error::Result;
use crate::stealth::get_vault_dir;

const LOCKDOWN_DIR: &str = ".lockdown";

#[derive(Debug, Clone)]
pub struct ScannedFile {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub is_encrypted: bool,
    pub modified: SystemTime,
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

    /// Classify files under the base directory into (unencrypted, encrypted).
    ///
    /// Skips: symlinks, the `.lockdown` state directory, and hidden dotfiles
    /// that are not Lockdown-encrypted (encrypted dotfiles, e.g. Ghost mode on
    /// Unix, are still listed). The Hide-mode vault is scanned separately so
    /// its contents stay visible to the app.
    ///
    /// Individual unreadable entries are skipped rather than failing the scan.
    pub fn scan(&self) -> Result<(Vec<ScannedFile>, Vec<ScannedFile>)> {
        let mut unencrypted = Vec::new();
        let mut encrypted = Vec::new();

        let walker = WalkDir::new(&self.base_dir)
            .max_depth(if self.recursive { usize::MAX } else { 1 })
            .follow_links(false);

        for entry in walker
            .into_iter()
            .filter_entry(|e| !(e.file_type().is_dir() && e.file_name() == LOCKDOWN_DIR))
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path == self.base_dir {
                continue;
            }

            let metadata = match entry.metadata() {
                Ok(m) if m.is_file() => m,
                _ => continue,
            };

            let name = match path.file_name() {
                Some(n) => n.to_string_lossy().to_string(),
                None => continue,
            };

            let hidden_dotfile = name.starts_with('.');
            let is_enc = self.check_if_encrypted(path);

            if hidden_dotfile && !is_enc {
                continue; // Ordinary hidden files are left alone.
            }

            let file = ScannedFile {
                path: path.to_path_buf(),
                name,
                size: metadata.len(),
                is_encrypted: is_enc,
                modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            };

            if is_enc {
                encrypted.push(file);
            } else {
                unencrypted.push(file);
            }
        }

        self.scan_vault(&mut encrypted);

        unencrypted.sort_by(|a, b| a.name.cmp(&b.name));
        encrypted.sort_by(|a, b| a.name.cmp(&b.name));

        Ok((unencrypted, encrypted))
    }

    /// Hide-mode vault: `.lockdown/vault`, files only, no recursion.
    fn scan_vault(&self, encrypted: &mut Vec<ScannedFile>) {
        let vault = get_vault_dir(&self.base_dir);
        let entries = match std::fs::read_dir(&vault) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let metadata = match entry.metadata() {
                Ok(m) if m.is_file() => m,
                _ => continue,
            };
            if !self.check_if_encrypted(&path) {
                continue;
            }

            encrypted.push(ScannedFile {
                name: entry.file_name().to_string_lossy().to_string(),
                path,
                size: metadata.len(),
                is_encrypted: true,
                modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            });
        }
    }

    fn check_if_encrypted(&self, path: &Path) -> bool {
        use std::io::Read;
        let mut buffer = [0u8; 5];
        match std::fs::File::open(path) {
            Ok(mut file) => matches!(file.read(&mut buffer), Ok(5)) && is_encrypted_file(&buffer),
            Err(_) => false,
        }
    }

    /// Ensure `path` resolves inside the base directory.
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
