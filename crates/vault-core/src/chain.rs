//! Chain-specific key parsing and address derivation.
//!
//! Deriving the address from the key (instead of trusting a pasted address)
//! validates the key format on import and guarantees the address shown in the
//! list really belongs to the stored key.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    /// Ethereum and every EVM chain (BSC, Base, Arbitrum, Polygon, …).
    Evm,
    Solana,
    Tron,
    /// Any other secret (seed phrase, BTC WIF, API key…). Stored as-is; the
    /// address, if any, is entered by the user.
    Other,
}

impl Chain {
    pub const ALL: [Chain; 4] = [Chain::Evm, Chain::Solana, Chain::Tron, Chain::Other];

    pub fn label(self) -> &'static str {
        match self {
            Chain::Evm => "EVM",
            Chain::Solana => "Solana",
            Chain::Tron => "Tron",
            Chain::Other => "Other",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Chain::Evm => "Ethereum, BSC, Base, Arbitrum… — 64 hex chars, 0x optional",
            Chain::Solana => "Base58 keypair (Phantom export) or [u8; 64] JSON array",
            Chain::Tron => "64 hex chars",
            Chain::Other => "Seed phrase or any other secret, stored verbatim",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Chain::Evm => "evm",
            Chain::Solana => "solana",
            Chain::Tron => "tron",
            Chain::Other => "other",
        }
    }

    /// Whether the address is computed from the key (true) or typed in (false).
    pub fn derives_address(self) -> bool {
        !matches!(self, Chain::Other)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("{0}")]
    Invalid(String),
}

fn invalid(msg: impl Into<String>) -> KeyError {
    KeyError::Invalid(msg.into())
}

/// Validate `secret` for `chain` and return the derived public address
/// (`None` for [`Chain::Other`]).
pub fn derive_address(chain: Chain, secret: &str) -> Result<Option<String>, KeyError> {
    let secret = secret.trim();
    if secret.is_empty() {
        return Err(invalid("private key is empty"));
    }
    match chain {
        Chain::Evm => {
            let key = parse_secp256k1(secret)?;
            Ok(Some(eip55(&evm_address_bytes(&key))))
        }
        Chain::Tron => {
            let key = parse_secp256k1(secret)?;
            Ok(Some(tron_address(&evm_address_bytes(&key))))
        }
        Chain::Solana => Ok(Some(solana_address(secret)?)),
        Chain::Other => Ok(None),
    }
}

/// Parse an EVM / Tron private key (64 hex chars, `0x` optional).
pub fn secp256k1_key(secret: &str) -> Result<k256::SecretKey, KeyError> {
    parse_secp256k1(secret.trim())
}

/// Parse a Solana key (base58 keypair/seed or JSON byte array) into a signer.
pub fn solana_signing_key(secret: &str) -> Result<ed25519_dalek::SigningKey, KeyError> {
    let secret = secret.trim();
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(if secret.starts_with('[') {
        serde_json::from_str::<Vec<u8>>(secret).map_err(|_| invalid("JSON key must be an array of numbers 0-255"))?
    } else {
        bs58::decode(secret).into_vec().map_err(|_| invalid("key is not valid base58"))?
    });

    let mut seed = Zeroizing::new([0u8; 32]);
    match bytes.len() {
        64 | 32 => seed.copy_from_slice(&bytes[..32]),
        n => return Err(invalid(format!("expected a 64-byte keypair or 32-byte seed, got {n} bytes"))),
    }
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    if bytes.len() == 64 && bytes[32..] != key.verifying_key().to_bytes() {
        return Err(invalid("keypair is corrupt: public half doesn't match the secret half"));
    }
    Ok(key)
}

/// Generate a fresh private key with the OS CSPRNG, in the format the app
/// stores for `chain`. Returns `None` for [`Chain::Other`].
pub fn generate_secret(chain: Chain) -> Option<Zeroizing<String>> {
    use rand::rngs::OsRng;
    match chain {
        Chain::Evm | Chain::Tron => {
            let key = k256::SecretKey::random(&mut OsRng);
            let bytes = Zeroizing::new(key.to_bytes());
            Some(Zeroizing::new(format!("0x{}", hex::encode(bytes.as_slice()))))
        }
        Chain::Solana => {
            let mut seed = Zeroizing::new([0u8; 32]);
            rand::RngCore::fill_bytes(&mut OsRng, seed.as_mut());
            let key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let pair = Zeroizing::new(key.to_keypair_bytes());
            Some(Zeroizing::new(bs58::encode(pair.as_slice()).into_string()))
        }
        Chain::Other => None,
    }
}

fn parse_secp256k1(secret: &str) -> Result<k256::SecretKey, KeyError> {
    let hex_str = secret.strip_prefix("0x").or_else(|| secret.strip_prefix("0X")).unwrap_or(secret);
    if hex_str.len() != 64 {
        return Err(invalid(format!("expected 64 hex characters, got {}", hex_str.len())));
    }
    let bytes = Zeroizing::new(hex::decode(hex_str).map_err(|_| invalid("key contains non-hex characters"))?);
    k256::SecretKey::from_slice(&bytes).map_err(|_| invalid("not a valid secp256k1 private key"))
}

fn evm_address_bytes(key: &k256::SecretKey) -> [u8; 20] {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let point = key.public_key().to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

/// EIP-55 mixed-case checksum encoding.
pub fn eip55(addr: &[u8; 20]) -> String {
    let lower = hex::encode(addr);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
        out.push(if c.is_ascii_alphabetic() && nibble >= 8 { c.to_ascii_uppercase() } else { c });
    }
    out
}

fn tron_address(addr20: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(25);
    payload.push(0x41);
    payload.extend_from_slice(addr20);
    let checksum = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&checksum[..4]);
    bs58::encode(payload).into_string()
}

fn solana_address(secret: &str) -> Result<String, KeyError> {
    Ok(bs58::encode(solana_signing_key(secret)?.verifying_key().to_bytes()).into_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evm_known_vectors() {
        // web3.js documentation vector
        assert_eq!(
            derive_address(Chain::Evm, "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318").unwrap(),
            Some("0x2c7536E3605D9C16a7a3D7b1898e529396a65c23".into())
        );
        // private key = 1
        assert_eq!(
            derive_address(Chain::Evm, &format!("{:064x}", 1)).unwrap(),
            Some("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf".into())
        );
    }

    #[test]
    fn evm_rejects_bad_keys() {
        assert!(derive_address(Chain::Evm, "0x1234").is_err());
        assert!(derive_address(Chain::Evm, &"zz".repeat(32)).is_err());
        assert!(derive_address(Chain::Evm, &"0".repeat(64)).is_err()); // zero scalar
        assert!(derive_address(Chain::Evm, &"f".repeat(64)).is_err()); // >= curve order
    }

    #[test]
    fn tron_key_one() {
        // Independently computed: base58check(0x41 || 7e5f4552…5bdf)
        assert_eq!(
            derive_address(Chain::Tron, &format!("{:064x}", 1)).unwrap(),
            Some("TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC".into())
        );
    }

    #[test]
    fn solana_rfc8032_vector() {
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
        let public = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
        let expected = bs58::encode(&public).into_string();
        assert_eq!(expected, "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z");

        let keypair: Vec<u8> = [seed.clone(), public.clone()].concat();
        // base58 keypair (Phantom style)
        let b58 = bs58::encode(&keypair).into_string();
        assert_eq!(derive_address(Chain::Solana, &b58).unwrap(), Some(expected.clone()));
        // JSON array (solana-keygen style)
        let json = serde_json::to_string(&keypair).unwrap();
        assert_eq!(derive_address(Chain::Solana, &json).unwrap(), Some(expected.clone()));
        // 32-byte seed
        let seed_b58 = bs58::encode(&seed).into_string();
        assert_eq!(derive_address(Chain::Solana, &seed_b58).unwrap(), Some(expected));
    }

    #[test]
    fn solana_rejects_mismatched_keypair() {
        let mut keypair = vec![7u8; 64];
        keypair[63] ^= 1;
        assert!(derive_address(Chain::Solana, &bs58::encode(keypair).into_string()).is_err());
        assert!(derive_address(Chain::Solana, "0OIl").is_err()); // not base58
    }

    #[test]
    fn generated_keys_are_valid_and_unique() {
        for chain in [Chain::Evm, Chain::Tron, Chain::Solana] {
            let a = generate_secret(chain).unwrap();
            let b = generate_secret(chain).unwrap();
            assert_ne!(*a, *b);
            assert!(derive_address(chain, &a).unwrap().is_some(), "{chain:?}");
        }
        assert!(generate_secret(Chain::Other).is_none());
    }

    #[test]
    fn other_accepts_anything() {
        assert_eq!(derive_address(Chain::Other, "abandon abandon … about").unwrap(), None);
        assert!(derive_address(Chain::Other, "   ").is_err());
    }
}
