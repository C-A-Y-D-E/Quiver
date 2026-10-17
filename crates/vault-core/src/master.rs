//! The vault key: one random 256-bit key that protects every wallet, so you
//! unlock once instead of typing a password per wallet.
//!
//! The vault key itself is never stored in the clear. It is kept in "slots",
//! each an independent way to unlock:
//!
//! * **passphrase** — Argon2id(passphrase) → XChaCha20-Poly1305 (always present)
//! * **recovery key** — a 160-bit random code shown once at setup (always present)
//! * **device** — wrapped under a random device key that lives in the OS
//!   keychain behind Touch ID / Windows Hello (optional)
//!
//! Each wallet's private key is encrypted under the vault key with its own
//! random nonce and authenticated together with the wallet's id, chain and
//! address. Wallets can still opt into an *extra lock* (their own password).

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, Sealed, Wrapped};
use crate::store::{Result, VaultError};

/// Recovery codes are high-entropy, so a lighter KDF is plenty.
pub const RECOVERY_KDF: KdfParams = KdfParams { m_cost_kib: 16 * 1024, t_cost: 2, p_cost: 1 };
const RECOVERY_BYTES: usize = 20; // 160 bits
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The unlocked vault key. Wiped from memory on drop.
#[derive(Clone)]
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(…)")
    }
}

impl MasterKey {
    pub fn generate() -> Self {
        let mut k = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(k.as_mut());
        MasterKey(k)
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_slice(b: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = b.try_into().map_err(|_| VaultError::Format("vault key has wrong length".into()))?;
        Ok(MasterKey(Zeroizing::new(arr)))
    }
}

/// A random key for the OS keychain (Touch ID / Windows Hello slot).
pub fn generate_device_key() -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(k.as_mut());
    k
}

/// "XXXX-XXXX-…" (8 groups of 4, Crockford base32, 160 bits).
pub fn generate_recovery_code() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; RECOVERY_BYTES]);
    OsRng.fill_bytes(bytes.as_mut());
    let mut bits: u64 = 0;
    let mut nbits = 0;
    let mut chars = Zeroizing::new(String::with_capacity(39));
    let mut count = 0;
    for &b in bytes.iter() {
        bits = (bits << 8) | b as u64;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            if count > 0 && count % 4 == 0 {
                chars.push('-');
            }
            chars.push(CROCKFORD[((bits >> nbits) & 31) as usize] as char);
            count += 1;
        }
    }
    chars
}

/// Uppercase, drop separators, map look-alikes (O→0, I/L→1). Returns
/// `None` unless it is exactly 32 valid characters.
pub fn normalize_recovery_code(input: &str) -> Option<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(32));
    for c in input.chars() {
        let c = match c.to_ascii_uppercase() {
            ' ' | '-' | '_' | '\n' | '\t' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        if !CROCKFORD.contains(&(c as u8)) || !c.is_ascii() {
            return None;
        }
        out.push(c);
    }
    (out.len() == 32).then_some(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSlot {
    /// "macos" / "windows" — informational.
    pub platform: String,
    /// What to call it in the UI ("Touch ID", "Windows Hello").
    pub label: String,
    pub wrapped: Wrapped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyring {
    pub vault_id: Uuid,
    pub passphrase: Sealed,
    pub recovery: Sealed,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceSlot>,
}

fn slot_aad(vault_id: Uuid, slot: &str) -> Vec<u8> {
    format!("keyvault/vault-key|{vault_id}|{slot}").into_bytes()
}

impl Keyring {
    /// New vault key + slots. Slow (two Argon2 runs). Returns the keyring,
    /// the unlocked key, and the recovery code to show the user once.
    pub fn create(passphrase: &str) -> Result<(Keyring, MasterKey, Zeroizing<String>)> {
        Self::create_with_params(passphrase, KdfParams::DEFAULT, RECOVERY_KDF)
    }

    pub fn create_with_params(
        passphrase: &str,
        pass_kdf: KdfParams,
        recovery_kdf: KdfParams,
    ) -> Result<(Keyring, MasterKey, Zeroizing<String>)> {
        let vault_id = Uuid::new_v4();
        let mk = MasterKey::generate();
        let code = generate_recovery_code();
        let norm = normalize_recovery_code(&code).expect("generated code is valid");
        let keyring = Keyring {
            vault_id,
            passphrase: crypto::seal(mk.bytes(), passphrase, &slot_aad(vault_id, "passphrase"), pass_kdf)?,
            recovery: crypto::seal(mk.bytes(), &norm, &slot_aad(vault_id, "recovery"), recovery_kdf)?,
            device: None,
        };
        Ok((keyring, mk, code))
    }

    /// Slow (Argon2).
    pub fn open_passphrase(&self, passphrase: &str) -> Result<MasterKey> {
        let raw = crypto::open(&self.passphrase, passphrase, &slot_aad(self.vault_id, "passphrase"))
            .map_err(|e| match VaultError::from(e) {
                VaultError::WrongPassword => VaultError::WrongPassword,
                other => other,
            })?;
        MasterKey::from_slice(&raw)
    }

    /// Slow (Argon2).
    pub fn open_recovery(&self, code: &str) -> Result<MasterKey> {
        let norm = normalize_recovery_code(code)
            .ok_or_else(|| VaultError::InvalidInput("a recovery key is 32 characters (8 groups of 4)".into()))?;
        let raw = crypto::open(&self.recovery, &norm, &slot_aad(self.vault_id, "recovery"))
            .map_err(|_| VaultError::InvalidInput("that recovery key doesn't match this vault".into()))?;
        MasterKey::from_slice(&raw)
    }

    /// Fast.
    pub fn open_device(&self, device_key: &[u8; 32]) -> Result<MasterKey> {
        let slot = self.device.as_ref().ok_or_else(|| VaultError::InvalidInput("device unlock isn't set up".into()))?;
        let raw = crypto::open_with_key(&slot.wrapped, device_key, &slot_aad(self.vault_id, "device"))
            .map_err(|_| VaultError::InvalidInput("device unlock no longer matches — use your passphrase".into()))?;
        MasterKey::from_slice(&raw)
    }

    pub fn with_device(&self, mk: &MasterKey, device_key: &[u8; 32], platform: &str, label: &str) -> Result<Keyring> {
        let wrapped = crypto::seal_with_key(mk.bytes(), device_key, &slot_aad(self.vault_id, "device"))?;
        Ok(Keyring {
            device: Some(DeviceSlot { platform: platform.into(), label: label.into(), wrapped }),
            ..self.clone()
        })
    }

    pub fn without_device(&self) -> Keyring {
        Keyring { device: None, ..self.clone() }
    }

    /// Slow (Argon2).
    pub fn with_passphrase(&self, mk: &MasterKey, new_passphrase: &str) -> Result<Keyring> {
        self.with_passphrase_params(mk, new_passphrase, KdfParams::DEFAULT)
    }

    pub fn with_passphrase_params(&self, mk: &MasterKey, new_passphrase: &str, kdf: KdfParams) -> Result<Keyring> {
        let passphrase = crypto::seal(mk.bytes(), new_passphrase, &slot_aad(self.vault_id, "passphrase"), kdf)?;
        Ok(Keyring { passphrase, ..self.clone() })
    }

    /// New recovery code (the old one stops working). Slow (Argon2).
    pub fn with_new_recovery(&self, mk: &MasterKey) -> Result<(Keyring, Zeroizing<String>)> {
        self.with_new_recovery_params(mk, RECOVERY_KDF)
    }

    pub fn with_new_recovery_params(&self, mk: &MasterKey, kdf: KdfParams) -> Result<(Keyring, Zeroizing<String>)> {
        let code = generate_recovery_code();
        let norm = normalize_recovery_code(&code).expect("generated code is valid");
        let recovery = crypto::seal(mk.bytes(), &norm, &slot_aad(self.vault_id, "recovery"), kdf)?;
        Ok((Keyring { recovery, ..self.clone() }, code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams { m_cost_kib: 256, t_cost: 1, p_cost: 1 };

    #[test]
    fn recovery_codes() {
        let c = generate_recovery_code();
        assert_eq!(c.len(), 39); // 32 chars + 7 dashes
        assert!(normalize_recovery_code(&c).is_some());
        let sloppy = c.to_lowercase().replace('-', " ").replace('0', "o");
        assert_eq!(normalize_recovery_code(&sloppy).unwrap().as_str(), normalize_recovery_code(&c).unwrap().as_str());
        assert!(normalize_recovery_code("too short").is_none());
        assert!(normalize_recovery_code(&format!("{}U", &c[..38])).is_none()); // U not in alphabet
        assert_ne!(*generate_recovery_code(), *generate_recovery_code());
    }

    #[test]
    fn slots_all_open_the_same_key() {
        let (kr, mk, code) = Keyring::create_with_params("correct horse battery", FAST, FAST).unwrap();
        let a = kr.open_passphrase("correct horse battery").unwrap();
        let b = kr.open_recovery(&code.to_lowercase()).unwrap();
        assert_eq!(a.bytes(), mk.bytes());
        assert_eq!(b.bytes(), mk.bytes());
        assert!(matches!(kr.open_passphrase("wrong"), Err(VaultError::WrongPassword)));
        assert!(kr.open_recovery(&generate_recovery_code()).is_err());

        let dk = generate_device_key();
        let kr2 = kr.with_device(&mk, &dk, "macos", "Touch ID").unwrap();
        assert_eq!(kr2.open_device(&dk).unwrap().bytes(), mk.bytes());
        assert!(kr2.open_device(&generate_device_key()).is_err());
        assert!(kr2.without_device().open_device(&dk).is_err());

        let kr3 = kr2.with_passphrase_params(&mk, "new passphrase!", FAST).unwrap();
        assert!(kr3.open_passphrase("correct horse battery").is_err());
        assert_eq!(kr3.open_passphrase("new passphrase!").unwrap().bytes(), mk.bytes());
        assert_eq!(kr3.open_device(&dk).unwrap().bytes(), mk.bytes()); // other slots untouched

        let (kr4, code2) = kr3.with_new_recovery_params(&mk, FAST).unwrap();
        assert!(kr4.open_recovery(&code).is_err());
        assert_eq!(kr4.open_recovery(&code2).unwrap().bytes(), mk.bytes());
    }

    #[test]
    fn slots_are_bound_to_their_vault() {
        let (a, _, code_a) = Keyring::create_with_params("passphrase-one", FAST, FAST).unwrap();
        let (b, _, _) = Keyring::create_with_params("passphrase-one", FAST, FAST).unwrap();
        // Swapping a slot from another vault doesn't work.
        let franken = Keyring { recovery: a.recovery.clone(), ..b.clone() };
        assert!(franken.open_recovery(&code_a).is_err());
    }
}
