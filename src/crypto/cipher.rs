//! Lockdown v2 encrypted file format.
//!
//! Layout (all offsets fixed; nothing variable-length is parsed before
//! authentication):
//!
//! ```text
//! MAGIC(4) | VERSION(1) | KEM_CT(1568) | NONCE(12) |
//! ENC_SK(3168) | SK_NONCE(12) | SK_TAG(16) | PAYLOAD_CT(..) | TAG(16)
//! ```
//!
//! PAYLOAD_CT is AES-256-GCM over `meta_len(2, BE) || meta_json || plaintext`,
//! keyed by HKDF(shared_secret || password_key). ENC_SK is the ML-KEM secret
//! key encrypted under HKDF(password_key). The original filename and other
//! metadata exist only inside the authenticated payload.

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{LockdownError, Result};

pub const MAGIC: &[u8; 4] = b"LOCK";
pub const VERSION: u8 = 0x02;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const KEM_CT_SIZE: usize = 1568;
pub const KEM_SK_SIZE: usize = 3168;

/// Bytes before the payload ciphertext: magic, version, KEM ciphertext,
/// payload nonce, encrypted secret key, SK nonce, SK tag.
pub const HEADER_SIZE: usize =
    4 + 1 + KEM_CT_SIZE + NONCE_SIZE + KEM_SK_SIZE + NONCE_SIZE + TAG_SIZE;

// Fixed offsets into the header.
const OFF_VERSION: usize = 4;
const OFF_KEM_CT: usize = 5;
const OFF_NONCE: usize = OFF_KEM_CT + KEM_CT_SIZE;
const OFF_ENC_SK: usize = OFF_NONCE + NONCE_SIZE;
const OFF_SK_NONCE: usize = OFF_ENC_SK + KEM_SK_SIZE;
const OFF_SK_TAG: usize = OFF_SK_NONCE + NONCE_SIZE;
const OFF_PAYLOAD: usize = OFF_SK_TAG + TAG_SIZE; // == HEADER_SIZE

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileMetadata {
    pub original_name: String,
    pub original_path: String,
    pub original_size: u64,
    pub encrypted_at: u64,
}

pub struct DecryptionResult {
    pub metadata: FileMetadata,
    pub plaintext: Zeroizing<Vec<u8>>,
}

fn hkdf_32(ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, okm.as_mut())
        .expect("32 is a valid output length for HKDF-SHA-256");
    okm
}

/// Content-encryption key from the KEM shared secret and the password key.
fn derive_key(shared_secret: &[u8], password_key: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(shared_secret.len() + password_key.len()));
    ikm.extend_from_slice(shared_secret);
    ikm.extend_from_slice(password_key);
    hkdf_32(&ikm, b"lockdown-aes-key-v2")
}

/// Key used to encrypt the embedded ML-KEM secret key.
fn derive_sk_key(password_key: &[u8]) -> Zeroizing<[u8; 32]> {
    hkdf_32(password_key, b"lockdown-sk-key-v2")
}

/// Reject names that could escape the target directory when rejoined on disk.
/// Metadata is authenticated, so this is defense-in-depth against files
/// produced by tampered or buggy peers.
fn validate_original_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['/', '\\'])
        || name.contains('\0')
        || name.contains(':')
    {
        return Err(LockdownError::PathTraversal);
    }
    Ok(())
}

fn random_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Encrypt a secret key under the password-derived SK key.
/// Returns `ct || tag`.
fn encrypt_secret_key(secret_key: &[u8], password_key: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_SIZE])> {
    let sk_key = derive_sk_key(password_key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(sk_key.as_ref()));
    let nonce_bytes = random_nonce();

    let mut buf = Zeroizing::new(secret_key.to_vec());
    cipher
        .encrypt_in_place(
            Nonce::from_slice(&nonce_bytes),
            b"lockdown-sk",
            &mut *buf,
        )
        .map_err(|_| LockdownError::Crypto("SK encryption failed".to_string()))?;

    Ok((buf.to_vec(), nonce_bytes))
}

/// Decrypt an `ct || tag` secret-key blob. Authentication failure here means
/// the password is wrong or the file is corrupt.
fn decrypt_secret_key(
    encrypted_sk: &[u8],
    nonce: &[u8],
    password_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if encrypted_sk.len() != KEM_SK_SIZE + TAG_SIZE {
        return Err(LockdownError::InvalidFormat);
    }

    let sk_key = derive_sk_key(password_key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(sk_key.as_ref()));

    let mut buf = encrypted_sk.to_vec();
    cipher
        .decrypt_in_place(Nonce::from_slice(nonce), b"lockdown-sk", &mut buf)
        .map_err(|_| LockdownError::Crypto("Wrong password or corrupt file".to_string()))?;

    Ok(Zeroizing::new(buf))
}

/// Encrypt `plaintext` + `metadata` into a complete self-contained file image.
pub fn encrypt_file(
    plaintext: &[u8],
    metadata: &FileMetadata,
    password_key: &[u8],
) -> Result<Vec<u8>> {
    validate_original_name(&metadata.original_name)?;

    let keypair = crate::crypto::kem::generate_keypair();
    let (shared_secret, kem_ct) = crate::crypto::kem::encapsulate(&keypair.public_key)?;
    debug_assert_eq!(kem_ct.len(), KEM_CT_SIZE);

    let metadata_json = Zeroizing::new(serde_json::to_vec(metadata)?);
    if metadata_json.len() > u16::MAX as usize {
        return Err(LockdownError::Crypto("Metadata too large".to_string()));
    }

    // Payload: meta_len || meta_json || plaintext, encrypted in place.
    let mut payload = Zeroizing::new(Vec::with_capacity(2 + metadata_json.len() + plaintext.len()));
    payload.extend_from_slice(&(metadata_json.len() as u16).to_be_bytes());
    payload.extend_from_slice(&metadata_json);
    payload.extend_from_slice(plaintext);

    let key = derive_key(&shared_secret, password_key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
    let nonce_bytes = random_nonce();
    cipher
        .encrypt_in_place(Nonce::from_slice(&nonce_bytes), MAGIC, &mut *payload)
        .map_err(|_| LockdownError::Crypto("Encryption failed".to_string()))?;
    // key, shared_secret, keypair (secret key), metadata_json: zeroized on drop.

    let (encrypted_sk, sk_nonce) = encrypt_secret_key(&keypair.secret_key, password_key)?;
    debug_assert_eq!(encrypted_sk.len(), KEM_SK_SIZE + TAG_SIZE);

    let mut out = Vec::with_capacity(HEADER_SIZE + payload.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&kem_ct);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&encrypted_sk[..KEM_SK_SIZE]);
    out.extend_from_slice(&sk_nonce);
    out.extend_from_slice(&encrypted_sk[KEM_SK_SIZE..]);
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Decrypt a file image produced by [`encrypt_file`].
pub fn decrypt_file(encrypted_data: &[u8], password_key: &[u8]) -> Result<DecryptionResult> {
    if encrypted_data.len() < HEADER_SIZE + TAG_SIZE {
        return Err(LockdownError::InvalidFormat);
    }
    if &encrypted_data[0..4] != MAGIC {
        return Err(LockdownError::InvalidFormat);
    }
    if encrypted_data[OFF_VERSION] != VERSION {
        return Err(LockdownError::Crypto(format!(
            "Unsupported format version {:#04x} (expected {:#04x})",
            encrypted_data[OFF_VERSION], VERSION
        )));
    }

    let kem_ct = &encrypted_data[OFF_KEM_CT..OFF_KEM_CT + KEM_CT_SIZE];
    let nonce = &encrypted_data[OFF_NONCE..OFF_NONCE + NONCE_SIZE];
    let enc_sk = &encrypted_data[OFF_ENC_SK..OFF_ENC_SK + KEM_SK_SIZE];
    let sk_nonce = &encrypted_data[OFF_SK_NONCE..OFF_SK_NONCE + NONCE_SIZE];
    let sk_tag = &encrypted_data[OFF_SK_TAG..OFF_SK_TAG + TAG_SIZE];

    let mut sk_blob = Vec::with_capacity(KEM_SK_SIZE + TAG_SIZE);
    sk_blob.extend_from_slice(enc_sk);
    sk_blob.extend_from_slice(sk_tag);
    let secret_key = decrypt_secret_key(&sk_blob, sk_nonce, password_key)?;
    sk_blob.zeroize();

    let shared_secret = crate::crypto::kem::decapsulate(&secret_key, kem_ct)?;
    drop(secret_key);

    let key = derive_key(&shared_secret, password_key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));

    let mut payload = encrypted_data[OFF_PAYLOAD..].to_vec();
    cipher
        .decrypt_in_place(Nonce::from_slice(nonce), MAGIC, &mut payload)
        .map_err(|_| LockdownError::Crypto("Authentication failed: file was modified".to_string()))?;
    let payload = Zeroizing::new(payload);

    if payload.len() < 2 {
        return Err(LockdownError::InvalidFormat);
    }
    let meta_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if payload.len() < 2 + meta_len {
        return Err(LockdownError::InvalidFormat);
    }

    let metadata: FileMetadata = serde_json::from_slice(&payload[2..2 + meta_len])?;
    validate_original_name(&metadata.original_name)?;

    let plaintext = Zeroizing::new(payload[2 + meta_len..].to_vec());
    Ok(DecryptionResult { metadata, plaintext })
}

/// Content sniffing for the scanner. Accepts any LOCK version so legacy files
/// still classify as encrypted (decrypt then reports the version mismatch).
pub fn is_encrypted_file(data: &[u8]) -> bool {
    data.len() >= 5 && &data[0..4] == MAGIC && data[4] >= 0x01
}
