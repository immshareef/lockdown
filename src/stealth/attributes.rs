use std::path::{Path, PathBuf};

use crate::error::{LockdownError, Result};

/// Hide `path` from casual browsing: hidden+system attributes on Windows,
/// dot-prefix rename elsewhere. Returns the (possibly renamed) path.
pub fn apply_ghost(path: &Path) -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let status = Command::new("attrib")
            .args(["+H", "+S"])
            .arg(path)
            .status()
            .map_err(|e| LockdownError::Stealth(format!("attrib failed to launch: {}", e)))?;
        if !status.success() {
            return Err(LockdownError::Stealth(format!(
                "attrib exited with {}",
                status
            )));
        }
        Ok(path.to_path_buf())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let file_name = path
            .file_name()
            .ok_or_else(|| LockdownError::Stealth("Invalid filename".to_string()))?
            .to_string_lossy();
        if file_name.starts_with('.') {
            return Ok(path.to_path_buf());
        }
        let new_path = path.with_file_name(format!(".{}", file_name));
        std::fs::rename(path, &new_path)?;
        Ok(new_path)
    }
}

pub fn get_vault_dir(base_dir: &Path) -> PathBuf {
    base_dir.join(".lockdown").join("vault")
}

pub fn ensure_vault_dir(base_dir: &Path) -> Result<PathBuf> {
    let vault = get_vault_dir(base_dir);
    std::fs::create_dir_all(&vault)?;
    Ok(vault)
}
