use std::fs;
use std::path::PathBuf;

use lockdown::auth::AuthManager;
use lockdown::crypto::cipher::{
    decrypt_file, encrypt_file, is_encrypted_file, FileMetadata, HEADER_SIZE, MAGIC, VERSION,
};
use lockdown::fileutil::{secure_delete, unique_path, write_atomic};
use lockdown::scanner::Scanner;
use lockdown::stealth::ensure_vault_dir;

struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "lockdown_test_{}_{:08x}",
            name,
            rand::random::<u32>()
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn metadata(name: &str, size: u64) -> FileMetadata {
    FileMetadata {
        original_name: name.to_string(),
        original_path: format!("/tmp/{}", name),
        original_size: size,
        encrypted_at: 1_700_000_000,
    }
}

const KEY: [u8; 32] = [7u8; 32];

// ---------- crypto ----------

#[test]
fn crypto_roundtrip_restores_exact_bytes_and_metadata() {
    for plaintext in [b"tiny".to_vec(), vec![0xABu8; 1024 * 1024]] {
        let meta = metadata("report.pdf", plaintext.len() as u64);
        let blob = encrypt_file(&plaintext, &meta, &KEY).unwrap();

        assert!(is_encrypted_file(&blob));
        assert_eq!(&blob[0..4], MAGIC);
        assert_eq!(blob[4], VERSION);
        assert!(blob.len() > HEADER_SIZE);

        let out = decrypt_file(&blob, &KEY).unwrap();
        assert_eq!(&*out.plaintext, &plaintext);
        assert_eq!(out.metadata.original_name, "report.pdf");
        assert_eq!(out.metadata.original_size, plaintext.len() as u64);
    }
}

#[test]
fn encrypted_file_does_not_leak_plaintext_metadata() {
    let plaintext = b"secret contents".to_vec();
    let meta = metadata("diary_2026_private.docx", plaintext.len() as u64);
    let blob = encrypt_file(&plaintext, &meta, &KEY).unwrap();

    for needle in [
        b"diary_2026_private.docx".as_slice(),
        b"/tmp/".as_slice(),
        b"secret contents".as_slice(),
    ] {
        let found = blob
            .windows(needle.len())
            .any(|window| window == needle);
        assert!(
            !found,
            "encrypted blob contains plaintext fragment {:?}",
            String::from_utf8_lossy(needle)
        );
    }
}

#[test]
fn tampering_anywhere_is_detected() {
    let plaintext = b"integrity matters".to_vec();
    let blob = encrypt_file(&plaintext, &metadata("a.txt", 17), &KEY).unwrap();

    for offset in [0, 4, 5, HEADER_SIZE - 1, HEADER_SIZE, blob.len() - 1] {
        let mut forged = blob.clone();
        forged[offset] ^= 0x01;
        assert!(
            decrypt_file(&forged, &KEY).is_err(),
            "tampered byte at offset {} went undetected",
            offset
        );
    }
}

#[test]
fn wrong_password_cannot_decrypt() {
    let blob = encrypt_file(b"data", &metadata("a.txt", 4), &KEY).unwrap();
    let other_key = [9u8; 32];
    assert!(decrypt_file(&blob, &other_key).is_err());
}

#[test]
fn path_traversal_names_are_rejected() {
    for bad in ["../evil.txt", "..\\evil.txt", "a/b.txt", ".", "..", "C:\\x"] {
        assert!(
            encrypt_file(b"x", &metadata(bad, 1), &KEY).is_err(),
            "dangerous name accepted: {}",
            bad
        );
    }
}

// ---------- auth ----------

#[test]
fn auth_setup_and_unlock_roundtrip() {
    let dir = TestDir::new("auth");
    let auth = AuthManager::new(&dir.0);
    assert!(auth.is_first_run());

    let setup_key = auth.setup_password("correct horse battery staple").unwrap();
    assert!(!auth.is_first_run());

    let unlocked = auth
        .unlock("correct horse battery staple")
        .unwrap()
        .expect("correct password must unlock");
    assert_eq!(setup_key, unlocked);

    assert!(auth.unlock("wrong password").unwrap().is_none());
}

// ---------- scanner ----------

#[test]
fn scanner_classifies_and_finds_stealth_files() {
    let dir = TestDir::new("scan");

    fs::write(dir.0.join("plain.txt"), b"hello").unwrap();
    fs::write(dir.0.join(".hidden_notes"), b"plain dotfile").unwrap();

    let blob = encrypt_file(b"x", &metadata("doc.pdf", 1), &KEY).unwrap();
    fs::write(dir.0.join("cache_a1_4242.tmp"), &blob).unwrap(); // Disguise-style
    fs::write(dir.0.join(".ghosted"), &blob).unwrap(); // Ghost-on-Unix-style

    let vault = ensure_vault_dir(&dir.0).unwrap();
    fs::write(vault.join("deadbeef.lock"), &blob).unwrap(); // Hide-style

    let (unencrypted, encrypted) = Scanner::new(dir.0.clone()).scan().unwrap();

    let un_names: Vec<_> = unencrypted.iter().map(|f| f.name.as_str()).collect();
    let en_names: Vec<_> = encrypted.iter().map(|f| f.name.as_str()).collect();

    assert_eq!(un_names, ["plain.txt"], "dotfile must stay hidden, plaintext listed");
    assert_eq!(
        en_names.len(),
        3,
        "disguised, ghost-dotfile, and vault files must all be found: {:?}",
        en_names
    );
    assert!(en_names.contains(&"cache_a1_4242.tmp"));
    assert!(en_names.contains(&".ghosted"));
    assert!(en_names.contains(&"deadbeef.lock"));
}

// ---------- file utilities ----------

#[test]
fn write_atomic_refuses_overwrite_and_roundtrips() {
    let dir = TestDir::new("atomic");
    let path = dir.0.join("f.bin");

    write_atomic(&path, b"v1").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"v1");

    assert!(write_atomic(&path, b"v2").is_err());
    assert_eq!(fs::read(&path).unwrap(), b"v1", "failed write must not clobber");

    // No temp files linger.
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
}

#[test]
fn unique_path_dodges_collisions() {
    let dir = TestDir::new("unique");
    fs::write(dir.0.join("taken"), b"").unwrap();

    let mut tries = 0;
    let path = unique_path(
        &dir.0,
        || {
            tries += 1;
            if tries == 1 {
                "taken".to_string()
            } else {
                "free".to_string()
            }
        },
        4,
    )
    .unwrap();
    assert_eq!(path.file_name().unwrap(), "free");
}

#[test]
fn full_disk_cycle_encrypt_scan_decrypt_restore() {
    let dir = TestDir::new("cycle");
    let original = dir.0.join("notes.txt");
    let content = b"round trip through the filesystem".to_vec();
    fs::write(&original, &content).unwrap();

    // Encrypt: same flow as the app (encrypt -> atomic write -> wipe original).
    let meta = FileMetadata {
        original_name: "notes.txt".to_string(),
        original_path: original.to_string_lossy().to_string(),
        original_size: content.len() as u64,
        encrypted_at: 0,
    };
    let blob = encrypt_file(&content, &meta, &KEY).unwrap();
    let disguised = unique_path(&dir.0, || "cache_x7_1234.tmp".to_string(), 4).unwrap();
    write_atomic(&disguised, &blob).unwrap();
    secure_delete(&original).unwrap();

    // Scan: original gone, disguised blob classified as encrypted.
    let (unencrypted, encrypted) = Scanner::new(dir.0.clone()).scan().unwrap();
    assert!(unencrypted.is_empty());
    assert_eq!(encrypted.len(), 1);
    assert_eq!(encrypted[0].path, disguised);

    // Decrypt: read back, restore under original name, remove blob.
    let stored = fs::read(&encrypted[0].path).unwrap();
    let out = decrypt_file(&stored, &KEY).unwrap();
    let restored = dir.0.join(&out.metadata.original_name);
    write_atomic(&restored, &out.plaintext).unwrap();
    fs::remove_file(&encrypted[0].path).unwrap();

    assert_eq!(fs::read(&restored).unwrap(), content);
    let (unencrypted, encrypted) = Scanner::new(dir.0.clone()).scan().unwrap();
    assert_eq!(unencrypted.len(), 1);
    assert!(encrypted.is_empty());
}

#[test]
fn secure_delete_removes_file() {
    let dir = TestDir::new("wipe");
    let path = dir.0.join("gone.bin");
    fs::write(&path, vec![0xCCu8; 4096]).unwrap();

    secure_delete(&path).unwrap();
    assert!(!path.exists());

    // Deleting twice is a no-op, not an error.
    secure_delete(&path).unwrap();
}
