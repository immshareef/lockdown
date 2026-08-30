use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{LockdownError, Result};

pub const MAGIC: &[u8; 4] = b"LOCK";
pub const VERSION: u8 = 0x01;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const KEM_CT_SIZE: usize = 1568;
pub const KEM_SK_SIZE: usize = 3168;
pub const METADATA_LEN_SIZE: usize = 2;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileMetadata {
    pub original_name: String,
    pub original_path: String,
    pub original_size: u64,
    pub encrypted_at: u64,
}

pub struct EncryptionResult {
    pub kem_ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_SIZE],
    pub metadata_ciphertext: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: [u8; TAG_SIZE],
    pub encrypted_secret_key: Vec<u8>,
    pub sk_nonce: [u8; NONCE_SIZE],
    pub sk_tag: [u8; TAG_SIZE],
}

pub struct DecryptionResult {
    pub metadata: FileMetadata,
    pub plaintext: Vec<u8>,
}

pub fn derive_key(shared_secret: &[u8], password_key: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(shared_secret.len() + password_key.len());
    ikm.extend_from_slice(shared_secret);
    ikm.extend_from_slice(password_key);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"lockdown-aes-key", &mut okm)
        .expect("32 is a valid length for SHA-256 HKDF");

    ikm.zeroize();
    okm
}

pub fn derive_sk_encryption_key(password_key: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, password_key);
    let mut okm = [0u8; 32];
    hk.expand(b"lockdown-sk-key", &mut okm)
        .expect("32 is a valid length for SHA-256 HKDF");
    okm
}

pub fn encrypt_secret_key(secret_key: &[u8], password_key: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_SIZE], [u8; TAG_SIZE])> {
    let mut sk_key = derive_sk_encryption_key(password_key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sk_key));

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted = cipher
        .encrypt(nonce, Payload { msg: secret_key, aad: b"lockdown-sk" })
        .map_err(|e| LockdownError::Crypto(format!("SK encryption failed: {}", e)))?;

    let tag_start = encrypted.len() - TAG_SIZE;
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&encrypted[tag_start..]);

    let ciphertext = encrypted[..tag_start].to_vec();

    sk_key.zeroize();

    Ok((ciphertext, nonce_bytes, tag))
}

pub fn decrypt_secret_key(encrypted_sk: &[u8], nonce: &[u8; NONCE_SIZE], tag: &[u8; TAG_SIZE], password_key: &[u8]) -> Result<Vec<u8>> {
    let mut sk_key = derive_sk_encryption_key(password_key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sk_key));

    let nonce = Nonce::from_slice(nonce);

    let mut payload = Vec::with_capacity(encrypted_sk.len() + TAG_SIZE);
    payload.extend_from_slice(encrypted_sk);
    payload.extend_from_slice(tag);

    let decrypted = cipher
        .decrypt(nonce, Payload { msg: &payload, aad: b"lockdown-sk" })
        .map_err(|e| LockdownError::Crypto(format!("SK decryption failed: {}", e)))?;

    sk_key.zeroize();

    Ok(decrypted)
}

pub fn encrypt_file(
    plaintext: &[u8],
    metadata: &FileMetadata,
    password_key: &[u8],
) -> Result<EncryptionResult> {
    let keypair = crate::crypto::kem::generate_keypair();
    let (mut shared_secret, kem_ct) = crate::crypto::kem::encapsulate(&keypair.public_key)?;

    let mut key = derive_key(&shared_secret, password_key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let metadata_json = serde_json::to_vec(metadata)?;
    let metadata_len = metadata_json.len() as u16;

    let mut payload = Vec::with_capacity(METADATA_LEN_SIZE + metadata_json.len() + plaintext.len());
    payload.extend_from_slice(&metadata_len.to_be_bytes());
    payload.extend_from_slice(&metadata_json);
    payload.extend_from_slice(plaintext);

    let encrypted = cipher
        .encrypt(nonce, Payload { msg: &payload, aad: MAGIC })
        .map_err(|e| LockdownError::Crypto(format!("Encryption failed: {}", e)))?;

    let tag_start = encrypted.len() - TAG_SIZE;
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&encrypted[tag_start..]);

    let ciphertext = encrypted[..tag_start].to_vec();

    key.zeroize();
    shared_secret.zeroize();

    let (encrypted_sk, sk_nonce, sk_tag) = encrypt_secret_key(&keypair.secret_key, password_key)?;

    Ok(EncryptionResult {
        kem_ciphertext: kem_ct,
        nonce: nonce_bytes,
        metadata_ciphertext: metadata_json,
        ciphertext,
        tag,
        encrypted_secret_key: encrypted_sk,
        sk_nonce,
        sk_tag,
    })
}

pub fn decrypt_file(
    encrypted_data: &[u8],
    password_key: &[u8],
) -> Result<DecryptionResult> {
    if encrypted_data.len() < 4 + 1 + KEM_CT_SIZE + NONCE_SIZE + TAG_SIZE {
        return Err(LockdownError::InvalidFormat);
    }

    if &encrypted_data[0..4] != MAGIC {
        return Err(LockdownError::InvalidFormat);
    }

    let version = encrypted_data[4];
    if version != VERSION {
        return Err(LockdownError::InvalidFormat);
    }

    let kem_ct_start = 5;
    let kem_ct_end = kem_ct_start + KEM_CT_SIZE;
    let kem_ct = &encrypted_data[kem_ct_start..kem_ct_end];

    let nonce_start = kem_ct_end;
    let nonce_end = nonce_start + NONCE_SIZE;
    let nonce = Nonce::from_slice(&encrypted_data[nonce_start..nonce_end]);

    // Parse metadata length to find where the actual ciphertext starts
    let metadata_len_start = nonce_end;
    if encrypted_data.len() < metadata_len_start + METADATA_LEN_SIZE {
        return Err(LockdownError::InvalidFormat);
    }
    let metadata_len = u16::from_be_bytes([
        encrypted_data[metadata_len_start],
        encrypted_data[metadata_len_start + 1],
    ]) as usize;

    let metadata_start = metadata_len_start + METADATA_LEN_SIZE;
    let metadata_end = metadata_start + metadata_len;

    // Check if we have the new format with embedded SK
    let sk_total_size = KEM_SK_SIZE + NONCE_SIZE + TAG_SIZE;
    let has_embedded_sk = encrypted_data.len() >= metadata_end + sk_total_size + TAG_SIZE;

    let (ciphertext_start, secret_key) = if has_embedded_sk {
        // New format: METADATA | ENCRYPTED_SK | SK_NONCE | SK_TAG | CIPHERTEXT
        let sk_start = metadata_end;
        let sk_nonce_start = sk_start + KEM_SK_SIZE;
        let sk_tag_start = sk_nonce_start + NONCE_SIZE;
        let ciphertext_start = sk_tag_start + TAG_SIZE;

        let encrypted_sk = &encrypted_data[sk_start..sk_start + KEM_SK_SIZE];
        let sk_nonce: [u8; NONCE_SIZE] = encrypted_data[sk_nonce_start..sk_nonce_start + NONCE_SIZE]
            .try_into()
            .map_err(|_| LockdownError::InvalidFormat)?;
        let sk_tag: [u8; TAG_SIZE] = encrypted_data[sk_tag_start..sk_tag_start + TAG_SIZE]
            .try_into()
            .map_err(|_| LockdownError::InvalidFormat)?;

        let sk = decrypt_secret_key(encrypted_sk, &sk_nonce, &sk_tag, password_key)?;
        (ciphertext_start, sk)
    } else {
        // Old format: METADATA | CIPHERTEXT (no embedded SK)
        // We can't decrypt without the SK, so return an error
        return Err(LockdownError::Crypto(
            "No embedded secret key found. Use recovery tool with .sk file.".to_string(),
        ));
    };

    let ciphertext_end = encrypted_data.len() - TAG_SIZE;
    let ciphertext = &encrypted_data[ciphertext_start..ciphertext_end];

    let tag_start = encrypted_data.len() - TAG_SIZE;
    let tag = &encrypted_data[tag_start..];

    let mut shared_secret = crate::crypto::kem::decapsulate(&secret_key, kem_ct)?;
    let mut key = derive_key(&shared_secret, password_key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let mut payload = Vec::with_capacity(ciphertext.len() + TAG_SIZE);
    payload.extend_from_slice(ciphertext);
    payload.extend_from_slice(tag);

    let decrypted = cipher
        .decrypt(nonce, Payload { msg: &payload, aad: MAGIC })
        .map_err(|e| LockdownError::Crypto(format!("Decryption failed: {}", e)))?;

    key.zeroize();
    shared_secret.zeroize();

    if decrypted.len() < METADATA_LEN_SIZE {
        return Err(LockdownError::InvalidFormat);
    }

    let metadata_len = u16::from_be_bytes([decrypted[0], decrypted[1]]) as usize;
    if decrypted.len() < METADATA_LEN_SIZE + metadata_len {
        return Err(LockdownError::InvalidFormat);
    }

    let metadata_json = &decrypted[METADATA_LEN_SIZE..METADATA_LEN_SIZE + metadata_len];
    let metadata: FileMetadata = serde_json::from_slice(metadata_json)?;

    let plaintext = decrypted[METADATA_LEN_SIZE + metadata_len..].to_vec();

    Ok(DecryptionResult { metadata, plaintext })
}

#[allow(dead_code)]
pub fn decrypt_file_with_sk(
    encrypted_data: &[u8],
    secret_key: &[u8],
    password_key: &[u8],
) -> Result<DecryptionResult> {
    if encrypted_data.len() < 4 + 1 + KEM_CT_SIZE + NONCE_SIZE + TAG_SIZE {
        return Err(LockdownError::InvalidFormat);
    }

    if &encrypted_data[0..4] != MAGIC {
        return Err(LockdownError::InvalidFormat);
    }

    let version = encrypted_data[4];
    if version != VERSION {
        return Err(LockdownError::InvalidFormat);
    }

    let kem_ct_start = 5;
    let kem_ct_end = kem_ct_start + KEM_CT_SIZE;
    let kem_ct = &encrypted_data[kem_ct_start..kem_ct_end];

    let nonce_start = kem_ct_end;
    let nonce_end = nonce_start + NONCE_SIZE;
    let nonce = Nonce::from_slice(&encrypted_data[nonce_start..nonce_end]);

    // First, extract metadata length to find where actual ciphertext starts
    let metadata_len_start = nonce_end;
    if encrypted_data.len() < metadata_len_start + METADATA_LEN_SIZE {
        return Err(LockdownError::InvalidFormat);
    }
    let metadata_len = u16::from_be_bytes([
        encrypted_data[metadata_len_start],
        encrypted_data[metadata_len_start + 1],
    ]) as usize;

    let metadata_start = metadata_len_start + METADATA_LEN_SIZE;
    let metadata_end = metadata_start + metadata_len;
    if encrypted_data.len() < metadata_end + TAG_SIZE {
        return Err(LockdownError::InvalidFormat);
    }

    let ciphertext_start = metadata_end;
    let ciphertext_end = encrypted_data.len() - TAG_SIZE;
    let ciphertext = &encrypted_data[ciphertext_start..ciphertext_end];

    let tag_start = encrypted_data.len() - TAG_SIZE;
    let tag = &encrypted_data[tag_start..];

    let mut shared_secret = crate::crypto::kem::decapsulate(secret_key, kem_ct)?;
    let mut key = derive_key(&shared_secret, password_key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let mut payload = Vec::with_capacity(ciphertext.len() + TAG_SIZE);
    payload.extend_from_slice(ciphertext);
    payload.extend_from_slice(tag);

    let decrypted = cipher
        .decrypt(nonce, Payload { msg: &payload, aad: MAGIC })
        .map_err(|e| LockdownError::Crypto(format!("Decryption failed: {}", e)))?;

    key.zeroize();
    shared_secret.zeroize();

    if decrypted.len() < METADATA_LEN_SIZE {
        return Err(LockdownError::InvalidFormat);
    }

    let metadata_len = u16::from_be_bytes([decrypted[0], decrypted[1]]) as usize;
    if decrypted.len() < METADATA_LEN_SIZE + metadata_len {
        return Err(LockdownError::InvalidFormat);
    }

    let metadata_json = &decrypted[METADATA_LEN_SIZE..METADATA_LEN_SIZE + metadata_len];
    let metadata: FileMetadata = serde_json::from_slice(metadata_json)?;

    let plaintext = decrypted[METADATA_LEN_SIZE + metadata_len..].to_vec();

    Ok(DecryptionResult { metadata, plaintext })
}

#[allow(dead_code)]
pub fn serialize_encrypted(result: &EncryptionResult) -> Vec<u8> {
    let metadata_len = result.metadata_ciphertext.len() as u16;
    let mut out = Vec::with_capacity(
        4 + 1 + KEM_CT_SIZE + NONCE_SIZE + METADATA_LEN_SIZE
            + result.metadata_ciphertext.len() + result.ciphertext.len() + TAG_SIZE,
    );
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&result.kem_ciphertext);
    out.extend_from_slice(&result.nonce);
    out.extend_from_slice(&metadata_len.to_be_bytes());
    out.extend_from_slice(&result.metadata_ciphertext);
    out.extend_from_slice(&result.ciphertext);
    out.extend_from_slice(&result.tag);
    out
}

pub fn serialize_encrypted_with_sk(result: &EncryptionResult) -> Vec<u8> {
    let metadata_len = result.metadata_ciphertext.len() as u16;
    let mut out = Vec::with_capacity(
        4 + 1 + KEM_CT_SIZE + NONCE_SIZE + METADATA_LEN_SIZE
            + result.metadata_ciphertext.len()
            + KEM_SK_SIZE + NONCE_SIZE + TAG_SIZE  // encrypted SK
            + result.ciphertext.len() + TAG_SIZE,
    );
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&result.kem_ciphertext);
    out.extend_from_slice(&result.nonce);
    out.extend_from_slice(&metadata_len.to_be_bytes());
    out.extend_from_slice(&result.metadata_ciphertext);
    out.extend_from_slice(&result.encrypted_secret_key);
    out.extend_from_slice(&result.sk_nonce);
    out.extend_from_slice(&result.sk_tag);
    out.extend_from_slice(&result.ciphertext);
    out.extend_from_slice(&result.tag);
    out
}

pub fn is_encrypted_file(data: &[u8]) -> bool {
    data.len() >= 5 && &data[0..4] == MAGIC && data[4] == VERSION
}
