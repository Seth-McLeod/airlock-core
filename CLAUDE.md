# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is `airlock-core`, a Rust library for secure password vault functionality. It's a single-library crate that provides encrypted storage and retrieval of login credentials using industry-standard cryptography.

## Common Commands

- **Build the project**: `cargo build`
- **Run tests**: `cargo test` (currently no tests defined)
- **Build for release**: `cargo build --release`
- **Check code without building**: `cargo check`
- **Format code**: `cargo fmt`
- **Run clippy linter**: `cargo clippy`

## Architecture

The library is contained entirely in `src/lib.rs` and provides:

### Core Types
- `Vault`: Main container for password entries with CRUD operations
- `Entry`: Individual login credentials (id, name, username, password, notes)
- `EncryptedVault`: Serialized format for secure storage
- `VaultSession`: Session-based access manager with automatic timeout
- `VaultError`: Error handling for IO, serialization, crypto operations, and session states

### Security Implementation
- **Key Derivation**: Uses Argon2 for deriving encryption keys from master passwords
- **Encryption**: AES-256-GCM for authenticated encryption
- **Random Generation**: Cryptographically secure random salt and nonce generation
- **Secret Handling**: Uses `secrecy` crate to protect sensitive data in memory
- **Session Security**: Automatic timeout, memory clearing on lock, and secure session state management

### Session Management
- **VaultSession**: Thread-safe session wrapper that manages unlocked vault access
- **Automatic Timeout**: Configurable inactivity timeout with background monitoring
- **Auto-save**: Optional automatic saving before lock/timeout
- **Activity Extension**: Session timeout resets on each operation
- **Manual Control**: Explicit lock/unlock methods for application control

### Key Dependencies
- `aes-gcm`: AES-256-GCM encryption
- `argon2`: Key derivation function
- `secrecy`: Secure secret handling
- `serde`/`serde_json`: Serialization
- `base64`: Encoding for storage
- `thiserror`: Error handling
- `tokio`: Async runtime for session timeout monitoring
- `parking_lot`: Efficient RwLock for thread-safe session state

## Development Notes

- The project uses Rust 2024 edition
- All cryptographic operations are in the `Vault` implementation
- Entry lookup supports both ID and name matching
- Encrypted vaults are stored as JSON with base64-encoded crypto materials

## Usage Patterns

### Direct Vault Access (Original API)
```rust
let vault = Vault::load_encrypted(&path, &master_password)?;
let entries = vault.list_entries();
vault.save_encrypted(&path, &master_password)?;
```

### Session-Based Access (Recommended for Applications)
```rust
let mut session = VaultSession::new(Duration::from_secs(900)); // 15 minutes
session.unlock(&path, master_password).await?;

// Operations automatically extend session timeout
let entries = session.list_entries()?;
session.add_entry(entry)?;
session.update_entry("entry-id", |entry| {
    entry.password = "new-password".to_string();
})?;

// Manual save (auto-save happens on timeout/lock if enabled)
session.save().await?;
```

Both APIs are available - use `Vault` for simple one-off operations and `VaultSession` for interactive applications.