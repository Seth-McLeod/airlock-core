use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Argon2, password_hash::rand_core::OsRng};
use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedVault {
    salt: String,
    nonce: String,
    ciphertext: String,
}

/// Represents one stored login/account entry
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Entry {
    pub id: String,
    pub name: String,
    pub username: String,
    pub password: String,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Vault {
    pub entries: Vec<Entry>,
}

impl Vault {
    /// Create a new empty Vault
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// List all entries (metadata only, no password)
    pub fn list_entries(&self) -> Vec<&Entry> {
        self.entries.iter().collect()
    }

    /// Returns owned entries for safe printing outside of locks
    pub fn list_entries_owned(&self) -> Vec<Entry> {
        self.entries.clone()
    }

    /// Add a new entry
    pub fn add_entry(&mut self, entry: Entry) {
        self.entries.push(entry);
    }

    /// Remove entry by ID
    pub fn remove_entry(&mut self, id: &str) -> bool {
        let len_before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        self.entries.len() != len_before
    }

    /// Get entry by name or id
    pub fn get_entry(&self, id_or_name: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|e| e.id == id_or_name || e.name == id_or_name)
    }

    pub fn get_entry_mut(&mut self, id_or_name: &str) -> Option<&mut Entry> {
        self.entries
            .iter_mut()
            .find(|e| e.id == id_or_name || e.name == id_or_name)
    }

    fn derive_key(master_password: &Secret<String>, salt: &[u8]) -> [u8; 32] {
        let argon2 = Argon2::default();
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(master_password.expose_secret().as_bytes(), salt, &mut key)
            .expect("Failed to derive key");

        key
    }

    fn encrypt_vault(vault_json: &str, key: &[u8; 32]) -> (String, String) {
        let cipher = Aes256Gcm::new_from_slice(key).expect("Key must be 32 bytes for AES-256");

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, vault_json.as_bytes())
            .expect("Encryption failed");

        (
            general_purpose::STANDARD.encode(&nonce_bytes),
            general_purpose::STANDARD.encode(&ciphertext),
        )
    }

    fn decrypt_vault(encrypted: &EncryptedVault, key: &[u8; 32]) -> String {
        let cipher = Aes256Gcm::new_from_slice(key).expect("Key must be 32 bytes for AES-256");
        let nonce_bytes = general_purpose::STANDARD
            .decode(&encrypted.nonce)
            .expect("Failed to decode nonce");
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = general_purpose::STANDARD
            .decode(&encrypted.ciphertext)
            .expect("Failed to decode ciphertext");

        let decrypted = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .expect("Decryption failed");

        String::from_utf8(decrypted).expect("UTF-8 decoding failed")
    }

    pub fn save_encrypted(
        &self,
        path: &Path,
        master_password: &Secret<String>,
    ) -> Result<(), VaultError> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let key = Self::derive_key(master_password, &salt);
        let vault_json = serde_json::to_string(&self)?;
        let (nonce_b64, ciphertext_b64) = Self::encrypt_vault(&vault_json, &key);

        let encrypted_vault = EncryptedVault {
            salt: general_purpose::STANDARD.encode(&salt),
            nonce: nonce_b64,
            ciphertext: ciphertext_b64,
        };

        let data = serde_json::to_string_pretty(&encrypted_vault)?;
        fs::write(path, data)?;

        Ok(())
    }

    pub fn load_encrypted(
        path: &Path,
        master_password: &Secret<String>,
    ) -> Result<Self, VaultError> {
        let data = fs::read_to_string(path)?;
        let encrypted: EncryptedVault = serde_json::from_str(&data)?;

        let salt = general_purpose::STANDARD
            .decode(&encrypted.salt)
            .expect("Failed to decode salt");
        let key = Self::derive_key(master_password, &salt);

        let vault_json = Self::decrypt_vault(&encrypted, &key);
        let vault: Vault = serde_json::from_str(&vault_json)?;

        Ok(vault)
    }
}
