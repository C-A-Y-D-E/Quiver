//! Core of KeyVault: per-wallet encrypted private key storage.
//!
//! No GUI code lives here, so the security-relevant logic can be tested and
//! audited on its own.

pub mod chain;
pub mod crypto;
pub mod export;
pub mod master;
pub mod store;

pub use chain::{derive_address, generate_secret, secp256k1_key, solana_signing_key, Chain};
pub use ed25519_dalek;
pub use k256;
pub use master::{generate_device_key, Keyring, MasterKey};
pub use store::{check_new_password, parse_tags, NewWallet, Vault, VaultError, WalletEntry, WalletMeta};
pub use uuid::Uuid;
pub use zeroize::Zeroizing;
