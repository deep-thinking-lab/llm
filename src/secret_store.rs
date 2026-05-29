use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const DEFAULT_PROVIDER_KEY: &str = "default";
const MAGIC: [u8; 4] = [b'L', b'L', b'M', b'S'];
const VERSION: u8 = 1;
const NONCE_SIZE: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("encryption error: {0}")]
    Crypto(String),
    #[error("invalid file format: {0}")]
    InvalidFormat(String),
    #[error("keyring error: {0}")]
    Keyring(String),
    #[error("no encryption key available — set LLM_SECRET_STORE_KEY, LLM_SECRET_STORE_KEY_FILE, or use OS keyring")]
    NoKey,
    #[error("plaintext secrets file detected; use SecretStore::migrate_from_plaintext to import")]
    PlaintextDetected,
    #[error("insecure key file permissions on {path}: expected 0600, got {mode:o}")]
    InsecureKeyFilePermissions { path: PathBuf, mode: u32 },
}

#[derive(Debug)]
pub struct SecretStore {
    secrets: HashMap<String, SecretString>,
    file_path: PathBuf,
    key: Key,
}

impl SecretStore {
    pub fn new() -> Result<Self, SecretStoreError> {
        let home_dir = dirs::home_dir().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Could not find home directory")
        })?;
        Self::with_path(home_dir.join(".llm").join("secrets.bin"))
    }

    pub fn with_path(file_path: impl Into<PathBuf>) -> Result<Self, SecretStoreError> {
        let file_path = file_path.into();
        let key = Self::load_or_create_key()?;
        Self::with_path_and_key(file_path, key)
    }

    #[doc(hidden)]
    pub fn with_path_and_key(file_path: impl Into<PathBuf>, key: Key) -> Result<Self, SecretStoreError> {
        let file_path = file_path.into();
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut store = SecretStore { secrets: HashMap::new(), file_path, key };
        store.load()?;
        Ok(store)
    }

    fn load_or_create_key() -> Result<Key, SecretStoreError> {
        // 1. Environment variable (hex-encoded 32 bytes).
        if let Ok(hex_key) = std::env::var("LLM_SECRET_STORE_KEY") {
            let bytes = hex_decode(&hex_key)
                .map_err(|e| SecretStoreError::Crypto(format!("invalid hex: {e}")))?;
            if bytes.len() != 32 {
                return Err(SecretStoreError::Crypto("key must be 32 bytes (64 hex chars)".into()));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(Key::from(key));
        }

        // 2. OS keyring (if compiled in). Any keyring failure falls through
        //    to the file-based fallback so the store still works on headless
        //    Linux, in containers, and on CI where no secret service exists.
        #[cfg(feature = "keyring")]
        {
            use base64::Engine;
            if let Ok(entry) = keyring::Entry::new("llm-secret-store", "encryption-key") {
                match entry.get_secret() {
                    Ok(stored) => {
                        let decoded = base64::engine::general_purpose::STANDARD
                            .decode(&stored)
                            .map_err(|e| SecretStoreError::Crypto(format!("bad base64: {e}")))?;
                        if decoded.len() != 32 {
                            return Err(SecretStoreError::Crypto("key must be 32 bytes".into()));
                        }
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&decoded);
                        return Ok(Key::from(key));
                    }
                    Err(keyring::Error::NoEntry) => {
                        let key = Self::generate_key();
                        let encoded = base64::engine::general_purpose::STANDARD
                            .encode(key.as_slice());
                        if entry.set_secret(encoded.as_bytes()).is_ok() {
                            return Ok(key);
                        }
                        // If we can't write to the keyring, fall through to
                        // file fallback rather than burning the freshly
                        // generated key.
                    }
                    Err(_) => {
                        // Keyring unreachable (e.g. no D-Bus session) — fall
                        // through to file.
                    }
                }
            }
        }

        // 3. File fallback. Path comes from $LLM_SECRET_STORE_KEY_FILE or
        //    defaults to ~/.llm/key. File must be 0600 on unix; we create it
        //    with 0600 on first use. This gives a working store on systems
        //    without a keyring (Linux servers, CI) while keeping the key off
        //    the process environment.
        Self::load_or_create_key_file()
    }

    fn load_or_create_key_file() -> Result<Key, SecretStoreError> {
        let key_path = if let Ok(p) = std::env::var("LLM_SECRET_STORE_KEY_FILE") {
            PathBuf::from(p)
        } else {
            let home_dir = dirs::home_dir().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "Could not find home directory")
            })?;
            home_dir.join(".llm").join("key")
        };

        match File::open(&key_path) {
            Ok(mut file) => {
                // Refuse to read a world/group readable key file.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = file.metadata()?.permissions().mode() & 0o777;
                    if mode != 0o600 {
                        return Err(SecretStoreError::InsecureKeyFilePermissions {
                            path: key_path.clone(),
                            mode,
                        });
                    }
                }
                let mut buf = Vec::new();
                file.read_to_end(&mut buf)?;
                let bytes = parse_key_file_contents(&buf)?;
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Ok(Key::from(key))
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                if let Some(parent) = key_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let key = Self::generate_key();
                let hex = hex_encode(key.as_slice());

                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut f = options.open(&key_path)?;
                f.write_all(hex.as_bytes())?;
                f.sync_all()?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
                }
                Ok(key)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn generate_key() -> Key {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        Key::from(key_bytes)
    }

    fn load(&mut self) -> Result<(), SecretStoreError> {
        match File::open(&self.file_path) {
            Ok(mut file) => {
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;
                let plaintext = self.decrypt(&buffer)?;
                let secrets: HashMap<String, String> = serde_json::from_slice(&plaintext)
                    .map_err(|e| SecretStoreError::InvalidFormat(format!("invalid JSON: {e}")))?;
                self.secrets = secrets.into_iter().map(|(k, v)| (k, SecretString::new(v))).collect();
                Ok(())
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self) -> Result<(), SecretStoreError> {
        let secrets: HashMap<String, String> = self.secrets.iter()
            .map(|(k, v)| (k.clone(), v.expose_secret().clone())).collect();
        let plaintext = serde_json::to_vec(&secrets)
            .map_err(|e| SecretStoreError::InvalidFormat(format!("serialization: {e}")))?;
        let ciphertext = self.encrypt(&plaintext)?;

        // Atomic write: write to temp file in the same directory, fsync,
        // rename over the destination, then fsync the parent directory so the
        // rename itself is durable.
        let parent = self.file_path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "file_path has no parent")
        })?;
        let file_name = self.file_path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "file_path has no file name")
        })?;

        let mut suffix_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut suffix_bytes);
        let suffix = hex_encode(&suffix_bytes);
        let tmp_name = format!(
            "{}.tmp.{}.{}",
            file_name.to_string_lossy(),
            std::process::id(),
            suffix
        );
        let tmp_path = parent.join(tmp_name);

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        // Scope the file handle so it's closed before rename on Windows.
        {
            let mut file = options.open(&tmp_path)?;
            // If anything fails between here and rename, try to clean up.
            let write_result: Result<(), SecretStoreError> = (|| {
                file.write_all(&ciphertext)?;
                file.sync_all()?;
                Ok(())
            })();
            if let Err(e) = write_result {
                let _ = fs::remove_file(&tmp_path);
                return Err(e);
            }
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e.into());
            }
        }

        if let Err(e) = fs::rename(&tmp_path, &self.file_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e.into());
        }

        // fsync the parent directory so the rename is durable on unix.
        #[cfg(unix)]
        {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }

        Ok(())
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
        let cipher = ChaCha20Poly1305::new(&self.key);
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| SecretStoreError::Crypto(format!("encrypt: {e}")))?;
        let mut output = Vec::with_capacity(4 + 1 + NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&MAGIC);
        output.push(VERSION);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    fn decrypt(&self, buffer: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
        if buffer.len() < 4 + 1 + NONCE_SIZE {
            return Err(SecretStoreError::InvalidFormat("file too small".into()));
        }
        if buffer[..4] != MAGIC {
            // Detect a JSON-looking blob and surface a typed error so callers
            // can call migrate_from_plaintext explicitly. We never silently
            // accept plaintext — that would let a disk-swap attacker bypass
            // the AEAD entirely.
            return if buffer.first() == Some(&b'{') {
                Err(SecretStoreError::PlaintextDetected)
            } else {
                Err(SecretStoreError::InvalidFormat("unknown format".into()))
            };
        }
        if buffer[4] != VERSION {
            return Err(SecretStoreError::InvalidFormat(format!("unsupported version: {}", buffer[4])));
        }
        let nonce = Nonce::from_slice(&buffer[5..5 + NONCE_SIZE]);
        let ciphertext = &buffer[5 + NONCE_SIZE..];
        let cipher = ChaCha20Poly1305::new(&self.key);
        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| SecretStoreError::Crypto(format!("decrypt: {e}")))
    }

    pub fn migrate_from_plaintext(plaintext_path: &Path) -> Result<Self, SecretStoreError> {
        let mut file = File::open(plaintext_path)?;
        let mut plaintext = Vec::new();
        file.read_to_end(&mut plaintext)?;
        let secrets: HashMap<String, String> = serde_json::from_slice(&plaintext)
            .map_err(|e| SecretStoreError::InvalidFormat(format!("invalid JSON: {e}")))?;
        let encrypted_path = plaintext_path.with_extension("bin");
        let key = Self::load_or_create_key()?;
        let store = SecretStore {
            secrets: secrets.into_iter().map(|(k, v)| (k, SecretString::new(v))).collect(),
            file_path: encrypted_path,
            key,
        };
        store.save()?;
        // Overwrite plaintext with zeros, fsync, then remove. Without the
        // sync_all() the zero-write can sit in the page cache while the
        // unlink races ahead, leaving the original blocks on disk recoverable.
        // Use a fixed-size buffer rather than allocating the full file length
        // so a malicious or accidental oversized plaintext file can't OOM us.
        if let Ok(mut f) = OpenOptions::new().write(true).open(plaintext_path) {
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            const CHUNK: usize = 64 * 1024;
            let zeros = [0u8; CHUNK];
            let mut written: u64 = 0;
            while written < len {
                let to_write = std::cmp::min(CHUNK as u64, len - written) as usize;
                if f.write_all(&zeros[..to_write]).is_err() {
                    break;
                }
                written += to_write as u64;
            }
            let _ = f.sync_all();
        }
        if let Err(e) = std::fs::remove_file(plaintext_path) {
            log::warn!("Failed to remove plaintext secrets file after migration: {e}");
        }
        Ok(store)
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<(), SecretStoreError> {
        self.secrets.insert(key.to_string(), SecretString::new(value.to_string()));
        self.save()
    }

    pub fn get(&self, key: &str) -> Option<&SecretString> {
        self.secrets.get(key)
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.secrets.get(key).map(|s| s.expose_secret().as_str())
    }

    pub fn delete(&mut self, key: &str) -> Result<(), SecretStoreError> {
        self.secrets.remove(key);
        self.save()
    }

    pub fn set_default_provider(&mut self, provider: &str) -> Result<(), SecretStoreError> {
        self.set(DEFAULT_PROVIDER_KEY, provider)
    }

    pub fn get_default_provider(&self) -> Option<&SecretString> {
        self.get(DEFAULT_PROVIDER_KEY)
    }

    pub fn get_default_provider_str(&self) -> Option<&str> {
        self.get_str(DEFAULT_PROVIDER_KEY)
    }

    pub fn delete_default_provider(&mut self) -> Result<(), SecretStoreError> {
        self.delete(DEFAULT_PROVIDER_KEY)
    }
}

fn hex_decode(hex_str: &str) -> Result<Vec<u8>, String> {
    if hex_str.len() % 2 != 0 { return Err("odd length".into()); }
    (0..hex_str.len()).step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i+2], 16).map_err(|e| format!("bad hex: {e}")))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Parse the key file contents. We accept either 64 hex chars (with optional
/// surrounding whitespace) or 32 raw bytes, matching what users might generate
/// with `openssl rand -hex 32 > ~/.llm/key` or `head -c 32 /dev/urandom`.
fn parse_key_file_contents(buf: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
    let trimmed: Vec<u8> = buf
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if trimmed.len() == 64 && trimmed.iter().all(|b| b.is_ascii_hexdigit()) {
        let s = std::str::from_utf8(&trimmed)
            .map_err(|e| SecretStoreError::Crypto(format!("key file utf8: {e}")))?;
        let bytes = hex_decode(s)
            .map_err(|e| SecretStoreError::Crypto(format!("key file hex: {e}")))?;
        return Ok(bytes);
    }
    if buf.len() == 32 {
        return Ok(buf.to_vec());
    }
    Err(SecretStoreError::Crypto(
        "key file must contain 32 raw bytes or 64 hex chars".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(hex: &str) -> Key {
        let bytes = hex_decode(hex).unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Key::from(arr)
    }

    const KA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const KB: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const KC: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const KE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const KF: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const KG: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const KH: &str = "4444444444444444444444444444444444444444444444444444444444444444";
    const KI: &str = "5555555555555555555555555555555555555555555555555555555555555555";
    const KJ: &str = "6666666666666666666666666666666666666666666666666666666666666666";
    const KK: &str = "7777777777777777777777777777777777777777777777777777777777777777";

    #[test]
    fn saved_secret_file_does_not_contain_plaintext_value() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SecretStore::with_path_and_key(dir.path().join("s.bin"), test_key(KA)).unwrap();
        store.set("OPENAI_API_KEY", "sk-thisisthesecretvalue").unwrap();
        let data = std::fs::read(dir.path().join("s.bin")).unwrap();
        let raw = String::from_utf8_lossy(&data);
        assert!(!raw.contains("sk-thisisthesecretvalue"), "secret leaked: {raw}");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.bin");
        let key = test_key(KB);
        let mut store = SecretStore::with_path_and_key(&path, key).unwrap();
        store.set("API_KEY", "my-secret-key").unwrap();
        store.set("DB_PASSWORD", "s3cr3t").unwrap();
        let store2 = SecretStore::with_path_and_key(&path, key).unwrap();
        assert_eq!(store2.get_str("API_KEY"), Some("my-secret-key"));
        assert_eq!(store2.get_str("DB_PASSWORD"), Some("s3cr3t"));
    }

    #[test]
    fn file_has_0600_permissions_on_unix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.bin");
        let mut store = SecretStore::with_path_and_key(&path, test_key(KC)).unwrap();
        store.set("key", "value").unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn migrate_from_plaintext_preserves_data_and_wipes_source() {
        // Exercise the real `migrate_from_plaintext` path, not a hand-rolled
        // copy. This is the only test that validates the zero-overwrite and
        // sync_all behavior on the plaintext source.
        //
        // We pin the key via $LLM_SECRET_STORE_KEY (highest precedence, beats
        // both keyring and file fallback) so the test is deterministic on any
        // host. The env var is process-global; we serialize via a Mutex.
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let plaintext_path = dir.path().join("secrets.json");
        let secrets: HashMap<String, String> = [
            ("KEY1".to_string(), "val1".to_string()),
            ("KEY2".to_string(), "val2".to_string()),
        ].into();
        std::fs::write(&plaintext_path, serde_json::to_vec(&secrets).unwrap()).unwrap();

        let pinned_key_hex =
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let prev = std::env::var("LLM_SECRET_STORE_KEY").ok();
        std::env::set_var("LLM_SECRET_STORE_KEY", pinned_key_hex);

        let store = SecretStore::migrate_from_plaintext(&plaintext_path).unwrap();
        assert_eq!(store.get_str("KEY1"), Some("val1"));
        assert_eq!(store.get_str("KEY2"), Some("val2"));

        // Plaintext source should be gone (proves remove_file path ran after
        // the zero-overwrite + sync_all).
        assert!(!plaintext_path.exists(), "plaintext file not removed");

        // Encrypted blob exists and decrypts under the pinned key.
        let ep = dir.path().join("secrets.bin");
        assert!(ep.exists(), "encrypted file not created");
        let s2 = SecretStore::with_path_and_key(&ep, test_key(pinned_key_hex)).unwrap();
        assert_eq!(s2.get_str("KEY1"), Some("val1"));
        assert_eq!(s2.get_str("KEY2"), Some("val2"));

        match prev {
            Some(v) => std::env::set_var("LLM_SECRET_STORE_KEY", v),
            None => std::env::remove_var("LLM_SECRET_STORE_KEY"),
        }
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.bin");
        let mut store = SecretStore::with_path_and_key(&path, test_key(KE)).unwrap();
        store.set("key", "value").unwrap();
        assert!(SecretStore::with_path_and_key(&path, test_key(KF)).is_err());
    }

    #[test]
    fn set_and_get_preserves_secret_wrapping() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SecretStore::with_path_and_key(dir.path().join("s.bin"), test_key(KG)).unwrap();
        store.set("test", "secret-value").unwrap();
        assert_eq!(store.get("test").unwrap().expose_secret(), "secret-value");
    }

    #[test]
    fn delete_removes_key_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.bin");
        let key = test_key(KH);
        let mut store = SecretStore::with_path_and_key(&path, key).unwrap();
        store.set("temp_key", "temp_val").unwrap();
        assert!(store.get("temp_key").is_some());
        store.delete("temp_key").unwrap();
        assert!(store.get("temp_key").is_none());
        assert!(SecretStore::with_path_and_key(&path, key).unwrap().get("temp_key").is_none());
    }

    #[test]
    fn tampered_ciphertext_fails_decryption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.bin");
        let key = test_key(KI);
        let mut store = SecretStore::with_path_and_key(&path, key).unwrap();
        store.set("API_KEY", "the-real-secret").unwrap();

        // Flip a byte inside the ciphertext body (after MAGIC + VERSION + NONCE).
        let mut data = std::fs::read(&path).unwrap();
        let tamper_idx = 4 + 1 + NONCE_SIZE + 1;
        assert!(data.len() > tamper_idx, "file shorter than header");
        data[tamper_idx] ^= 0x01;
        std::fs::write(&path, &data).unwrap();

        let result = SecretStore::with_path_and_key(&path, key);
        assert!(result.is_err(), "tampered ciphertext must not decrypt");
        match result {
            Err(SecretStoreError::Crypto(_)) => {}
            other => panic!("expected Crypto error, got {other:?}"),
        }
    }

    #[test]
    fn successive_saves_produce_distinct_ciphertexts() {
        // Nonce-freshness check: saving the same plaintext under the same key
        // twice must yield different bytes on disk, otherwise the nonce is
        // being reused and confidentiality is broken.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.bin");
        let key = test_key(KJ);
        let mut store = SecretStore::with_path_and_key(&path, key).unwrap();
        store.set("X", "same-value").unwrap();
        let first = std::fs::read(&path).unwrap();
        store.save().unwrap();
        let second = std::fs::read(&path).unwrap();
        assert_ne!(first, second, "two saves produced identical ciphertext (nonce reuse)");
        // The nonce lives at bytes 5..5+NONCE_SIZE; compare those explicitly too.
        assert_ne!(
            &first[5..5 + NONCE_SIZE],
            &second[5..5 + NONCE_SIZE],
            "nonces are identical across saves"
        );
    }

    #[test]
    fn plaintext_file_returns_typed_error_instead_of_silent_load() {
        // Regression test for the removed plaintext escape hatch in load().
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.bin");
        // Write a JSON-looking plaintext blob long enough to pass the
        // length check in decrypt() (>= 4 + 1 + NONCE_SIZE = 17 bytes).
        let blob = br#"{"OPENAI_API_KEY":"sk-fake-injected"}"#;
        std::fs::write(&path, blob).unwrap();

        let result = SecretStore::with_path_and_key(&path, test_key(KK));
        match result {
            Err(SecretStoreError::PlaintextDetected) => {}
            other => panic!("expected PlaintextDetected, got {other:?}"),
        }
    }
}
