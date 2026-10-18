# Lockdown

A password-protected, post-quantum file encryption app for the current directory. Fully offline, portable, and cross-platform.

## What It Does

Lockdown scans the folder it runs in and shows two panes:

- Left: unencrypted files
- Right: encrypted files

Select any file and click to encrypt or decrypt it. Encrypted files stay in the same folder as the original, just disguised to look like ordinary system files, hidden from file managers, or tucked away in a vault folder.

## How It Works

### The Encryption Stack

Lockdown uses a hybrid cryptosystem designed to survive quantum computers:

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key Encapsulation | ML-KEM-1024 (Kyber) | Post-quantum secure key exchange |
| Key Derivation | HKDF-SHA256 | Stretches shared secret into AES key |
| Encryption | AES-256-GCM | Fast, authenticated symmetric encryption |
| Password Hashing | Argon2id | Memory-hard password protection |

### Encrypting a File

1. You pick a file and click "Encrypt"
2. Lockdown generates a random ML-KEM-1024 keypair
3. It encapsulates a shared secret using the public key
4. HKDF mixes the shared secret with your password-derived key
5. AES-256-GCM encrypts the file content plus metadata (original name, path, size)
6. The encrypted secret key is itself encrypted with your password and embedded in the file
7. The result is written to the same folder as the original, with a stealth disguise applied
8. The original file is deleted

### Decrypting a File

1. You pick an encrypted file and click "Decrypt"
2. Lockdown reads the ML-KEM ciphertext from the file header
3. It extracts the embedded encrypted secret key and decrypts it with your password
4. It decapsulates the shared secret using the secret key
5. HKDF derives the same AES key
6. AES-256-GCM decrypts and verifies the authentication tag
7. The original filename is extracted from the encrypted metadata
8. The plaintext is written back to the original name in the same folder
9. The encrypted file is removed

### The `.lock` File Format (v2)

Every encrypted file is a self-contained binary blob with a fixed 4781-byte header. Nothing variable-length is parsed before authentication:

```
┌─────────────┬──────────┬─────────────────────────────────────┐
│   Field     │   Size   │           Description               │
├─────────────┼──────────┼─────────────────────────────────────┤
│ Magic       │ 4 bytes  │ "LOCK" (0x4C4F434B)                 │
│ Version     │ 1 byte   │ 0x02                                │
│ KEM CT      │ 1568 B   │ ML-KEM-1024 encapsulated key        │
│ Nonce       │ 12 bytes │ Random AES-GCM nonce                │
│ Encrypted SK│ 3168 B   │ ML-KEM secret key, AES-encrypted    │
│ SK Nonce    │ 12 bytes │ Nonce for SK encryption             │
│ SK Tag      │ 16 bytes │ GCM tag for SK encryption           │
│ Ciphertext  │ Variable │ Encrypted: meta_len(2B) + JSON      │
│             │          │ metadata (name, path, size) +       │
│             │          │ file content                        │
│ Tag         │ 16 bytes │ GCM authentication tag              │
└─────────────┴──────────┴─────────────────────────────────────┘
```

Metadata lives only inside the authenticated ciphertext, so the original filename is never exposed on disk — not even in the header. (v0.1 wrote plaintext metadata into the header; v0.2 files are not compatible with v0.1.)

Writes are atomic (temp file + rename), so a crash mid-operation can never leave a truncated file behind.

## Stealth Modes

Lockdown offers three ways to hide encrypted files:

### Disguise (Default)

Encrypted files get random benign names like `sys_32_4821.dat` or `cache_a1_9034.tmp`. They stay in the same folder as the original file and blend in with ordinary system files.

### Hide

Encrypted files are moved into `.lockdown/vault/` inside the same folder as the original. The vault folder is hidden from file managers by default.

### Ghost

- Windows: files get `FILE_ATTRIBUTE_HIDDEN` and `FILE_ATTRIBUTE_SYSTEM` (like `pagefile.sys`)
- macOS/Linux: files are renamed with a dot prefix (`.filename`) making them hidden in Finder and most file managers

## Security Model

### What Protects Your Files

1. Post-quantum key exchange: ML-KEM-1024 is NIST-standardized and believed secure against Shor's algorithm
2. Authenticated encryption: AES-256-GCM detects any tampering
3. Password-derived key: your password is mixed into every encryption via HKDF
4. No plaintext metadata: original filenames are encrypted inside the file
5. Embedded secret key: the ML-KEM secret key is encrypted with your password and stored inside the file, not in a separate file

### What Doesn't Protect Your Files

- Physical access: if someone copies the encrypted file and knows your password, they can decrypt it
- Memory dumps: keys are zeroized after use, but a determined attacker with a debugger could extract them during operation
- Weak passwords: Argon2id slows down brute force, but a short password like "1234" is still easy to guess

### Password Storage

Your master password is hashed with Argon2id (64 MB memory, 3 iterations, 4 lanes) and stored in `.lockdown/auth`. The hash never leaves your machine.

## Portability

Lockdown is designed to be fully portable:

- Single binary: no installer, no registry changes, no AppData writes
- Relative paths: all state lives in `.lockdown/` next to the executable
- USB-friendly: copy the folder to a USB drive and run it on any Windows machine
- Cross-platform source: the same Rust code builds on Windows, macOS, and Linux

### Moving to a New Machine

1. Copy the entire folder (including `.lockdown/`) to the new machine
2. Run `lockdown.exe`
3. Enter your password
4. All encrypted files are recognized and decryptable

## Building from Source

### Prerequisites

- Rust 1.70+ (`rustup`)
- Windows: Visual Studio Build Tools with C++ workload
- macOS: Xcode Command Line Tools
- Linux: `build-essential` or equivalent

### Build Commands

```bash
# Debug build
cargo build

# Release build (optimized, stripped)
cargo build --release

# Run tests
cargo test
```

### Windows One-Liner

```powershell
powershell -File build.ps1
```

This script auto-detects VS Build Tools and builds a release binary.

## Project Structure

```
lockdown/
├── Cargo.toml              # Dependencies and build config
├── PLAN.md                 # Detailed design document
├── README.md               # This file
├── build.ps1               # Windows build script
├── src/
│   ├── main.rs             # App entry point
│   ├── lib.rs              # Library exports
│   ├── error.rs            # Error types
│   ├── fileutil.rs         # Atomic writes, secure delete
│   ├── auth/
│   │   ├── mod.rs
│   │   └── password.rs     # Argon2id password handling
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── kem.rs          # ML-KEM-1024 key encapsulation
│   │   └── cipher.rs       # AES-256-GCM and file format
│   ├── scanner/
│   │   ├── mod.rs
│   │   └── walker.rs       # Directory scanning and classification
│   ├── stealth/
│   │   ├── mod.rs
│   │   ├── disguise.rs     # Random name generation
│   │   └── attributes.rs   # Hidden/system file attributes
│   └── ui/
│       ├── mod.rs
│       └── app.rs          # egui application logic
├── tests/
│   └── integration.rs      # Crypto, auth, scanner, I/O round-trips
└── .lockdown/              # Created at runtime
    ├── auth                # Argon2id password hash
    └── vault/              # Hidden storage for Hide mode
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `eframe` / `egui` | Cross-platform GUI |
| `pqcrypto-kyber` | ML-KEM-1024 post-quantum KEM |
| `aes-gcm` | AES-256-GCM authenticated encryption |
| `argon2` | Password hashing |
| `hkdf` and `sha2` | Key derivation |
| `zeroize` | Secure memory clearing |
| `walkdir` | Directory traversal |
| `rand` | Random name generation |

## Known Limitations

1. Secure delete is best-effort: originals are overwritten with random bytes before unlink, but CoW filesystems and wear-leveled SSDs may retain copies.
2. Whole-file operation: files are encrypted in memory, so very large files need roughly 2× their size in RAM.
3. No drag-and-drop: you have to click to select files, then click encrypt or decrypt.

## Roadmap

- [x] Secure delete (random-overwrite before unlink)
- [x] Auto-lock after idle timeout (5 minutes)
- [x] Unlock rate-limiting with exponential backoff
- [ ] Drag-and-drop between panes
- [ ] File search and filtering
- [ ] Streaming encryption for very large files
- [ ] CLI mode for scripting

## License

MIT
