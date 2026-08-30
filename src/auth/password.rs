use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params,
};
use rand::RngCore;
use std::fs;
use std::path::Path;

use crate::error::{LockdownError, Result};

const AUTH_FILE: &str = "auth";
const SALT_SIZE: usize = 16;

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

    pub fn setup_password(&self, password: &str) -> Result<()> {
        fs::create_dir_all(&self.lockdown_dir)?;

        let mut salt_bytes = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt_bytes);
        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|e| LockdownError::Auth(format!("Salt encoding failed: {}", e)))?;

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            Params::new(65536, 3, 4, Some(32))
                .map_err(|e| LockdownError::Auth(format!("Invalid params: {}", e)))?,
        );

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| LockdownError::Auth(format!("Hashing failed: {}", e)))?
            .to_string();

        fs::write(self.lockdown_dir.join(AUTH_FILE), password_hash)?;
        Ok(())
    }

    pub fn verify_password(&self, password: &str) -> Result<bool> {
        let hash_path = self.lockdown_dir.join(AUTH_FILE);
        if !hash_path.exists() {
            return Err(LockdownError::Auth("No password set".to_string()));
        }

        let stored_hash = fs::read_to_string(&hash_path)?;
        let parsed_hash = PasswordHash::new(&stored_hash)
            .map_err(|e| LockdownError::Auth(format!("Invalid stored hash: {}", e)))?;

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            Params::new(65536, 3, 4, Some(32))
                .map_err(|e| LockdownError::Auth(format!("Invalid params: {}", e)))?,
        );

        Ok(argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    pub fn derive_password_key(&self, password: &str) -> Result<[u8; 32]> {
        let hash_path = self.lockdown_dir.join(AUTH_FILE);
        if !hash_path.exists() {
            return Err(LockdownError::Auth("No password set".to_string()));
        }

        let stored_hash = fs::read_to_string(&hash_path)?;
        let parsed_hash = PasswordHash::new(&stored_hash)
            .map_err(|e| LockdownError::Auth(format!("Invalid stored hash: {}", e)))?;

        let salt = parsed_hash.salt.ok_or_else(|| {
            LockdownError::Auth("No salt in stored hash".to_string())
        })?;

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            Params::new(65536, 3, 4, Some(32))
                .map_err(|e| LockdownError::Auth(format!("Invalid params: {}", e)))?,
        );

        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut key)
            .map_err(|e| LockdownError::Auth(format!("Key derivation failed: {}", e)))?;

        Ok(key)
    }
}