//! Crash-safe file writes and best-effort secure deletion.

use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::error::{LockdownError, Result};

const WIPE_CHUNK: usize = 1024 * 1024;

/// Write `data` to `path` via a temp file + rename, so a crash can never leave
/// a partially written file at `path`. `path` must not already exist (fresh
/// random targets or caller-checked destinations); the temp file lives in the
/// same directory so the rename stays on one filesystem.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    if path.exists() {
        return Err(LockdownError::Stealth(format!(
            "Refusing to overwrite existing file: {}",
            path.display()
        )));
    }

    let mut rand_suffix = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut rand_suffix);
    let tmp_name = format!(
        ".~lockdown_{}.tmp",
        rand_suffix.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    );
    let tmp_path = path.with_file_name(tmp_name);

    let write_result = (|| -> Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(data)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.into());
    }
    Ok(())
}

/// Best-effort secure delete: overwrite content with random bytes, flush to
/// disk, then unlink. Cannot guarantee erasure on CoW/journaling filesystems
/// or SSDs with wear leveling, but defeats naive undelete on common setups.
pub fn secure_delete(path: &Path) -> Result<()> {
    let len = match fs::metadata(path) {
        Ok(m) if m.is_file() => m.len(),
        _ => return Ok(()), // Already gone or not a regular file.
    };

    let mut rng = rand::thread_rng();
    let mut chunk = vec![0u8; WIPE_CHUNK.min(len.max(1) as usize)];

    {
        let mut file = OpenOptions::new().write(true).open(path)?;
        let mut remaining = len;
        while remaining > 0 {
            let n = remaining.min(chunk.len() as u64) as usize;
            rng.fill_bytes(&mut chunk[..n]);
            file.write_all(&chunk[..n])?;
            remaining -= n as u64;
        }
        file.sync_all()?;
    }

    fs::remove_file(path)?;
    Ok(())
}

/// Return `dir/file_name()` after checking it does not exist, regenerating up
/// to `attempts` times to dodge collisions.
pub fn unique_path(dir: &Path, mut name_fn: impl FnMut() -> String, attempts: usize) -> Result<PathBuf> {
    for _ in 0..attempts {
        let candidate = dir.join(name_fn());
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(LockdownError::Stealth(
        "Could not find a free filename after repeated attempts".to_string(),
    ))
}
