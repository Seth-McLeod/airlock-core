use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Argon2, password_hash::rand_core::OsRng};
use base64::{Engine as _, engine::general_purpose};
use parking_lot::RwLock;
use rand::RngCore;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::time::interval;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Session is locked")]
    SessionLocked,

    #[error("Session timeout")]
    SessionTimeout,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedVault {
    salt: String,
    nonce: String,
    ciphertext: String,
}

/// Basic entry information without sensitive data
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EntryInfo {
    pub id: String,
    pub name: String,
    pub username: String,
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

impl Entry {
    /// Convert to EntryInfo (basic information without sensitive data)
    pub fn to_info(&self) -> EntryInfo {
        EntryInfo {
            id: self.id.clone(),
            name: self.name.clone(),
            username: self.username.clone(),
        }
    }
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

    /// List all entries (basic information only, no sensitive data)
    pub fn list_entries(&self) -> Vec<EntryInfo> {
        self.entries.iter().map(|entry| entry.to_info()).collect()
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

#[derive(Debug)]
struct SessionState {
    vault: Option<Vault>,
    master_password: Option<Secret<String>>,
    last_activity: Instant,
    vault_path: Option<PathBuf>,
    auto_save: bool,
}

impl SessionState {
    fn new(auto_save: bool) -> Self {
        Self {
            vault: None,
            master_password: None,
            last_activity: Instant::now(),
            vault_path: None,
            auto_save,
        }
    }

    fn is_locked(&self) -> bool {
        self.vault.is_none()
    }

    fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    fn lock(&mut self) -> Result<(), VaultError> {
        if let (Some(vault), Some(path), Some(password)) =
            (&self.vault, &self.vault_path, &self.master_password)
        {
            if self.auto_save {
                vault.save_encrypted(path, password)?;
            }
        }

        self.vault = None;
        self.master_password = None;
        Ok(())
    }
}

pub struct VaultSession {
    state: Arc<RwLock<SessionState>>,
    timeout_duration: Duration,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl VaultSession {
    pub fn new(timeout_duration: Duration) -> Self {
        Self::new_with_auto_save(timeout_duration, true)
    }

    pub fn new_with_auto_save(timeout_duration: Duration, auto_save: bool) -> Self {
        Self {
            state: Arc::new(RwLock::new(SessionState::new(auto_save))),
            timeout_duration,
            shutdown_tx: None,
        }
    }

    pub async fn unlock<P: AsRef<Path>>(
        &mut self,
        path: P,
        master_password: Secret<String>,
    ) -> Result<(), VaultError> {
        let path = path.as_ref().to_path_buf();
        let vault = Vault::load_encrypted(&path, &master_password)?;

        {
            let mut state = self.state.write();
            state.vault = Some(vault);
            state.master_password = Some(master_password);
            state.vault_path = Some(path);
            state.update_activity();
        }

        self.start_timeout_monitor().await;
        Ok(())
    }

    pub async fn lock(&self) -> Result<(), VaultError> {
        self.state.write().lock()
    }

    pub fn is_locked(&self) -> bool {
        self.state.read().is_locked()
    }

    fn extend_session(&self) -> Result<(), VaultError> {
        if self.is_locked() {
            return Err(VaultError::SessionLocked);
        }
        self.state.write().update_activity();
        Ok(())
    }

    async fn start_timeout_monitor(&mut self) {
        if self.shutdown_tx.is_some() {
            return;
        }

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        let state = self.state.clone();
        let timeout_duration = self.timeout_duration;

        tokio::spawn(async move {
            let mut check_interval = interval(Duration::from_secs(30));

            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    _ = check_interval.tick() => {
                        let should_lock = {
                            let state_read = state.read();
                            !state_read.is_locked() &&
                            state_read.last_activity.elapsed() >= timeout_duration
                        };

                        if should_lock {
                            if let Err(_) = state.write().lock() {
                                eprintln!("Warning: Failed to auto-save vault during timeout");
                            }
                        }
                    }
                }
            }
        });
    }

    pub fn list_entries(&self) -> Result<Vec<EntryInfo>, VaultError> {
        self.extend_session()?;
        let state = self.state.read();
        match &state.vault {
            Some(vault) => Ok(vault.list_entries()),
            None => Err(VaultError::SessionLocked),
        }
    }

    pub fn add_entry(&self, entry: Entry) -> Result<(), VaultError> {
        self.extend_session()?;
        let mut state = self.state.write();
        match &mut state.vault {
            Some(vault) => {
                vault.add_entry(entry);
                state.update_activity();
                Ok(())
            }
            None => Err(VaultError::SessionLocked),
        }
    }

    pub fn remove_entry(&self, id: &str) -> Result<bool, VaultError> {
        self.extend_session()?;
        let mut state = self.state.write();
        match &mut state.vault {
            Some(vault) => {
                let removed = vault.remove_entry(id);
                if removed {
                    state.update_activity();
                }
                Ok(removed)
            }
            None => Err(VaultError::SessionLocked),
        }
    }

    pub fn get_entry(&self, id_or_name: &str) -> Result<Option<Entry>, VaultError> {
        self.extend_session()?;
        let state = self.state.read();
        match &state.vault {
            Some(vault) => Ok(vault.get_entry(id_or_name).cloned()),
            None => Err(VaultError::SessionLocked),
        }
    }

    pub fn update_entry<F>(&self, id_or_name: &str, update_fn: F) -> Result<bool, VaultError>
    where
        F: FnOnce(&mut Entry),
    {
        self.extend_session()?;
        let mut state = self.state.write();
        match &mut state.vault {
            Some(vault) => {
                if let Some(entry) = vault.get_entry_mut(id_or_name) {
                    update_fn(entry);
                    state.update_activity();
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            None => Err(VaultError::SessionLocked),
        }
    }

    pub async fn save(&self) -> Result<(), VaultError> {
        self.extend_session()?;
        let state = self.state.read();
        match (&state.vault, &state.vault_path, &state.master_password) {
            (Some(vault), Some(path), Some(password)) => vault.save_encrypted(path, password),
            _ => Err(VaultError::SessionLocked),
        }
    }
}

impl Drop for VaultSession {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }

        if let Err(_) = self.state.write().lock() {
            eprintln!("Warning: Failed to save vault during session cleanup");
        }
    }
}
