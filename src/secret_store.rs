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
    #[error("no encryption key available — set LLM_SECRET_STORE_KEY or use OS keyring")]
    NoKey,
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
        #[cfg(feature = "keyring")]
        {
            let entry = keyring::Entry::new("llm-secret-store", "encryption-key")
                .map_err(|e| SecretStoreError::Keyring(e.to_string()))?;
            match entry.get_secret() {
                Ok(stored) => {
                    let decoded = base64::decode(&stored)
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
                    entry.set_secret(&base64::encode(key.as_slice()))
                        .map_err(|e| SecretStoreError::Keyring(e.to_string()))?;
                    return Ok(key);
                }
                Err(e) => return Err(SecretStoreError::Keyring(e.to_string())),
            }
        }
        Err(SecretStoreError::NoKey)
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

        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        let mut file = options.open(&self.file_path)?;
        file.write_all(&ciphertext)?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.file_path, fs::Permissions::from_mode(0o600))?;
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
            return if buffer.first() == Some(&b'{') {
                Ok(buffer.to_vec()) // plaintext migration
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
        let mut store = SecretStore {
            secrets: secrets.into_iter().map(|(k, v)| (k, SecretString::new(v))).collect(),
            file_path: encrypted_path,
            key,
        };
        store.save()?;
        let _ = std::fs::remove_file(plaintext_path);
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
    const KD: &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    const KE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const KF: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const KG: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const KH: &str = "4444444444444444444444444444444444444444444444444444444444444444";

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
    fn migrate_from_plaintext_preserves_data() {
        let dir = tempfile::tempdir().unwrap();
        let plaintext_path = dir.path().join("secrets.json");
        let secrets: HashMap<String, String> = [
            ("KEY1".to_string(), "val1".to_string()),
            ("KEY2".to_string(), "val2".to_string()),
        ].into();
        std::fs::write(&plaintext_path, serde_json::to_vec(&secrets).unwrap()).unwrap();
        let key = test_key(KD);
        // Simulate migration manually
        let mut file = File::open(&plaintext_path).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        let s: HashMap<String, String> = serde_json::from_slice(&buf).unwrap();
        let ep = dir.path().join("secrets.bin");
        let mut store = SecretStore::with_path_and_key(&ep, key).unwrap();
        for (k, v) in &s { store.secrets.insert(k.clone(), SecretString::new(v.clone())); }
        store.save().unwrap();
        let store2 = SecretStore::with_path_and_key(&ep, key).unwrap();
        assert_eq!(store2.get_str("KEY1"), Some("val1"));
        assert_eq!(store2.get_str("KEY2"), Some("val2"));
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
}
