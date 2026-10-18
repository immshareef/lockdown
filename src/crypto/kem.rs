use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{LockdownError, Result};

pub struct KemKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl Drop for KemKeyPair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

pub fn generate_keypair() -> KemKeyPair {
    let (pk, sk) = kyber1024::keypair();
    KemKeyPair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: sk.as_bytes().to_vec(),
    }
}

pub fn encapsulate(public_key: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let pk = kyber1024::PublicKey::from_bytes(public_key)
        .map_err(|_| LockdownError::Crypto("Invalid ML-KEM public key".to_string()))?;
    let (shared_secret, ciphertext) = kyber1024::encapsulate(&pk);
    Ok((
        Zeroizing::new(shared_secret.as_bytes().to_vec()),
        ciphertext.as_bytes().to_vec(),
    ))
}

pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let sk = kyber1024::SecretKey::from_bytes(secret_key)
        .map_err(|_| LockdownError::Crypto("Invalid ML-KEM secret key".to_string()))?;
    let ct = kyber1024::Ciphertext::from_bytes(ciphertext)
        .map_err(|_| LockdownError::Crypto("Invalid ML-KEM ciphertext".to_string()))?;
    let shared_secret = kyber1024::decapsulate(&ct, &sk);
    Ok(Zeroizing::new(shared_secret.as_bytes().to_vec()))
}
