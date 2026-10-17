//! Password-based authenticated encryption.
//!
//! Every wallet secret is sealed independently:
//!
//! * a fresh 16-byte random salt feeds **Argon2id** (memory-hard KDF) to turn the
//!   wallet's password into a 256-bit key, and
//! * a fresh 24-byte random nonce is used with **XChaCha20-Poly1305** (AEAD) to
//!   encrypt the secret.
//!
//! The Poly1305 tag authenticates both the ciphertext and the "associated data"
//! (wallet id, chain and address), so a wrong password *or* any tampering with
//! the file is detected and reported as [`CryptoError::Decrypt`].

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const KDF_ALGORITHM: &str = "argon2id-v19";
pub const CIPHER_ALGORITHM: &str = "xchacha20poly1305";

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Upper bounds accepted when *reading* a file, so a corrupted or malicious
/// vault can't make us allocate gigabytes or spin for minutes.
const MAX_M_COST_KIB: u32 = 1024 * 1024; // 1 GiB
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u32 = 16;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("Wrong password (or the stored data was modified).")]
    Decrypt,
    #[error("unsupported or invalid encryption parameters: {0}")]
    BadParams(String),
    #[error("encryption failed")]
    Encrypt,
}

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_cost_kib: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Lanes.
    pub p_cost: u32,
}

impl KdfParams {
    /// 64 MiB, 3 passes, 1 lane — OWASP's recommended Argon2id baseline,
    /// roughly 0.2–0.6 s on a desktop CPU.
    pub const DEFAULT: KdfParams = KdfParams { m_cost_kib: 64 * 1024, t_cost: 3, p_cost: 1 };

    /// Cheap parameters for unit tests only.
    #[cfg(test)]
    pub const TEST: KdfParams = KdfParams { m_cost_kib: 256, t_cost: 1, p_cost: 1 };

    fn validate(&self) -> Result<Params, CryptoError> {
        if self.m_cost_kib > MAX_M_COST_KIB || self.t_cost > MAX_T_COST || self.p_cost > MAX_P_COST {
            return Err(CryptoError::BadParams(format!("{self:?} exceeds safety limits")));
        }
        Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|e| CryptoError::BadParams(e.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfSpec {
    pub algorithm: String,
    #[serde(flatten)]
    pub params: KdfParams,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherSpec {
    pub algorithm: String,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

/// A sealed (encrypted + authenticated) secret, safe to write to disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub kdf: KdfSpec,
    pub cipher: CipherSpec,
}

fn derive_key(password: &str, salt: &[u8], params: &KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.validate()?);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| CryptoError::BadParams(e.to_string()))?;
    Ok(key)
}

/// Encrypt `plaintext` under `password`, binding `aad` to the ciphertext.
pub fn seal(plaintext: &[u8], password: &str, aad: &[u8], params: KdfParams) -> Result<Sealed, CryptoError> {
    let mut salt = vec![0u8; SALT_LEN];
    let mut nonce = vec![0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let key = derive_key(password, &salt, &params)?;
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Encrypt)?;

    Ok(Sealed {
        kdf: KdfSpec { algorithm: KDF_ALGORITHM.into(), params, salt },
        cipher: CipherSpec { algorithm: CIPHER_ALGORITHM.into(), nonce, ciphertext },
    })
}

/// Decrypt a [`Sealed`] blob. Fails with [`CryptoError::Decrypt`] on a wrong
/// password or if the ciphertext / associated data has been altered.
pub fn open(sealed: &Sealed, password: &str, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if sealed.kdf.algorithm != KDF_ALGORITHM {
        return Err(CryptoError::BadParams(format!("unknown KDF '{}'", sealed.kdf.algorithm)));
    }
    if sealed.cipher.algorithm != CIPHER_ALGORITHM {
        return Err(CryptoError::BadParams(format!("unknown cipher '{}'", sealed.cipher.algorithm)));
    }
    if sealed.kdf.salt.len() < 8 || sealed.cipher.nonce.len() != NONCE_LEN {
        return Err(CryptoError::BadParams("bad salt or nonce length".into()));
    }

    let key = derive_key(password, &sealed.kdf.salt, &sealed.kdf.params)?;
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    cipher
        .decrypt(
            XNonce::from_slice(&sealed.cipher.nonce),
            Payload { msg: &sealed.cipher.ciphertext, aad },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decrypt)
}

/// Data encrypted directly under a 256-bit key (no password KDF): used for
/// wallet secrets under the vault key, and the vault key under a device key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wrapped {
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

pub fn seal_with_key(plaintext: &[u8], key: &[u8; KEY_LEN], aad: &[u8]) -> Result<Wrapped, CryptoError> {
    let mut nonce = vec![0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Encrypt)?;
    Ok(Wrapped { nonce, ciphertext })
}

pub fn open_with_key(wrapped: &Wrapped, key: &[u8; KEY_LEN], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if wrapped.nonce.len() != NONCE_LEN {
        return Err(CryptoError::BadParams("bad nonce length".into()));
    }
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(&wrapped.nonce), Payload { msg: &wrapped.ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decrypt)
}

mod b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let s = seal(b"top secret", "hunter22!", b"aad", KdfParams::TEST).unwrap();
        assert_eq!(&open(&s, "hunter22!", b"aad").unwrap()[..], b"top secret");
    }

    #[test]
    fn wrong_password_fails() {
        let s = seal(b"x", "correct horse", b"aad", KdfParams::TEST).unwrap();
        assert_eq!(open(&s, "Correct horse", b"aad").unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn tampering_is_detected() {
        let mut s = seal(b"secret", "pw123456", b"aad", KdfParams::TEST).unwrap();
        assert_eq!(open(&s, "pw123456", b"other").unwrap_err(), CryptoError::Decrypt);
        s.cipher.ciphertext[0] ^= 1;
        assert_eq!(open(&s, "pw123456", b"aad").unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn salts_and_nonces_are_unique() {
        let a = seal(b"same", "same-password", b"", KdfParams::TEST).unwrap();
        let b = seal(b"same", "same-password", b"", KdfParams::TEST).unwrap();
        assert_ne!(a.kdf.salt, b.kdf.salt);
        assert_ne!(a.cipher.nonce, b.cipher.nonce);
        assert_ne!(a.cipher.ciphertext, b.cipher.ciphertext);
    }

    #[test]
    fn rejects_absurd_params() {
        let mut s = seal(b"x", "password", b"", KdfParams::TEST).unwrap();
        s.kdf.params.m_cost_kib = u32::MAX;
        assert!(matches!(open(&s, "password", b""), Err(CryptoError::BadParams(_))));
    }
}
