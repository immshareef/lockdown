use argon2::{
    password_hash::{PasswordHash, PasswordHasher, SaltString},
    Argon2, Params,
};
use rand::RngCore;
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

use crate::error::{LockdownError, Result};

const AUTH_FILE: &str = "auth";
const SALT_SIZE: usize = 16;

/// RFC 9106 first-recommended parameters: 64 MiB, 3 iterations, 4 lanes.
fn default_params() -> Params {
    Params::new(65536, 3, 4, Some(32)).expect("hardcoded Argon2 params are valid")
}

fn argon2(params: &Params) -> Argon2<'_> {
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params.clone())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub struct AuthManager {
    lockdown_dir: std::path::PathBuf,
}

impl AuthManager {
    pub fn new(base_dir: &Path) -> Self {
        Self {
            lockdown_dir: base_dir.join(".lockdown"),
        }
    }

    pub fn is_first_run(&self) -> bool {
        !self.lockdown_dir.join(AUTH_FILE).exists()
    }

    /// Hash and store a new master password. Returns the derived password key
    /// so the caller does not need a second Argon2 pass.
    pub fn setup_password(&self, password: &str) -> Result<Zeroizing<[u8; 32]>> {
        fs::create_dir_all(&self.lockdown_dir)?;

        let mut salt_bytes = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt_bytes);
        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|e| LockdownError::Auth(format!("Salt encoding failed: {}", e)))?;

        let hash = argon2(&default_params())
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| LockdownError::Auth(format!("Hashing failed: {}", e)))?;

        let key_bytes = hash
            .hash
            .as_ref()
            .and_then(|h| <&[u8; 32]>::try_from(h.as_bytes()).ok())
            .copied()
            .ok_or_else(|| LockdownError::Auth("Unexpected hash length".to_string()))?;

        fs::write(self.lockdown_dir.join(AUTH_FILE), hash.to_string())?;
        Ok(Zeroizing::new(key_bytes))
    }

    /// Verify the password and, on success, return the derived password key.
    /// One Argon2 pass total: the derived bytes are compared against the
    /// stored hash in constant time.
    ///
    /// Returns `Ok(None)` for a wrong password, `Err` for store problems.
    pub fn unlock(&self, password: &str) -> Result<Option<Zeroizing<[u8; 32]>>> {
        let hash_path = self.lockdown_dir.join(AUTH_FILE);
        if !hash_path.exists() {
            return Err(LockdownError::Auth("No password set".to_string()));
        }

        let stored_hash = fs::read_to_string(&hash_path)?;
        let parsed = PasswordHash::new(&stored_hash)
            .map_err(|e| LockdownError::Auth(format!("Invalid stored hash: {}", e)))?;

        let params = Params::try_from(&parsed).unwrap_or_else(|_| default_params());
        let salt = parsed
            .salt
            .ok_or_else(|| LockdownError::Auth("No salt in stored hash".to_string()))?;
        let expected = parsed
            .hash
            .ok_or_else(|| LockdownError::Auth("No hash in stored hash".to_string()))?;

        // `PasswordHasher::hash_password` B64-decodes the salt before the
        // Argon2 core; match that so the derived key equals the stored hash.
        let mut salt_buf = [0u8; 64];
        let raw_salt = salt
            .decode_b64(&mut salt_buf)
            .map_err(|e| LockdownError::Auth(format!("Invalid salt encoding: {}", e)))?;

        let mut key = Zeroizing::new([0u8; 32]);
        argon2(&params)
            .hash_password_into(password.as_bytes(), raw_salt, key.as_mut())
            .map_err(|e| LockdownError::Auth(format!("Key derivation failed: {}", e)))?;

        if constant_time_eq(key.as_ref(), expected.as_bytes()) {
            Ok(Some(key))
        } else {
            Ok(None)
        }
    }
}
