use std::path::{Path, PathBuf};

use crate::error::Result;

pub fn apply_ghost(path: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        Command::new("attrib")
            .args(["+H", "+S", &path.to_string_lossy()])
            .output()?;
    }

    #[cfg(not(target_os = "windows"))]
    {
        let file_name = path
            .file_name()
            .ok_or_else(|| crate::error::LockdownError::Stealth("Invalid filename".to_string()))?
            .to_string_lossy();
        if !file_name.starts_with('.') {
            let new_name = format!(".{}", file_name);
            let new_path = path.with_file_name(new_name);
            std::fs::rename(path, &new_path)?;
        }
    }

    Ok(())
}

pub fn remove_ghost(path: &Path) -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        Command::new("attrib")
            .args(["-H", "-S", &path.to_string_lossy()])
            .output()?;
        Ok(path.to_path_buf())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let file_name = path
            .file_name()
            .ok_or_else(|| crate::error::LockdownError::Stealth("Invalid filename".to_string()))?
            .to_string_lossy();
        if file_name.starts_with('.') {
            let new_name = file_name.trim_start_matches('.').to_string();
            let new_path = path.with_file_name(new_name);
            std::fs::rename(path, &new_path)?;
            Ok(new_path)
        } else {
            Ok(path.to_path_buf())
        }
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
