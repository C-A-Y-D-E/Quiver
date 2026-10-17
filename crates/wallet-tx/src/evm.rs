//! EVM transfers: native coin and ERC-20 / BEP-20 tokens.
//!
//! Uses legacy EIP-155 transactions (accepted by every EVM chain, including
//! BSC and L2s), signed locally with the wallet's secp256k1 key.

use ethnum::U256;
use k256::ecdsa::{RecoveryId, SigningKey};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

use crate::amount::{format_short, format_units};
use crate::network::Network;
use crate::rpc::json_rpc;
use crate::{AmountSpec, Asset, Quote, TxError};

pub type Address = [u8; 20];

const NATIVE_DECIMALS: u8 = 18;

// ── addresses ─────────────────────────────────────────────────────────────

/// Parse a `0x…` address. Mixed-case input must carry a valid EIP-55
/// checksum, which catches most typos.
pub fn parse_address(input: &str) -> Result<Address, TxError> {
    let s = input.trim();
    let hex_part = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| TxError::Input("EVM addresses start with 0x".into()))?;
    if hex_part.len() != 40 {
        return Err(TxError::Input(format!("address must have 40 hex characters, got {}", hex_part.len())));
    }
    let mut out = [0u8; 20];
    hex::decode_to_slice(hex_part, &mut out).map_err(|_| TxError::Input("address contains non-hex characters".into()))?;
    let has_upper = hex_part.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = hex_part.chars().any(|c| c.is_ascii_lowercase());
    if has_upper && has_lower && vault_core::chain::eip55(&out) != format!("0x{hex_part}") {
        return Err(TxError::Input("address checksum doesn't match — check it for typos".into()));
    }
    Ok(out)
}

pub fn to_checksum(addr: &Address) -> String {
    vault_core::chain::eip55(addr)
}

pub fn address_of(key: &k256::SecretKey) -> Address {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let point = key.public_key().to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

// ── RLP + transaction ─────────────────────────────────────────────────────

fn rlp_len_prefix(len: usize, short: u8, long: u8) -> Vec<u8> {
    if len <= 55 {
        vec![short + len as u8]
    } else {
        let be = (len as u64).to_be_bytes();
        let skip = be.iter().take_while(|b| **b == 0).count();
        let mut v = vec![long + (8 - skip) as u8];
        v.extend_from_slice(&be[skip..]);
        v
    }
}

fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] < 0x80 {
        return vec![b[0]];
    }
    let mut v = rlp_len_prefix(b.len(), 0x80, 0xb7);
    v.extend_from_slice(b);
    v
}

fn rlp_uint(v: U256) -> Vec<u8> {
    let be = v.to_be_bytes();
    let skip = be.iter().take_while(|b| **b == 0).count();
    rlp_bytes(&be[skip..])
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.concat();
    let mut v = rlp_len_prefix(payload.len(), 0xc0, 0xf7);
    v.extend(payload);
    v
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyTx {
    pub nonce: u64,
    pub gas_price: U256,
    pub gas_limit: u64,
    pub to: Address,
    pub value: U256,
    pub data: Vec<u8>,
    pub chain_id: u64,
}

impl LegacyTx {
    fn fields(&self) -> Vec<Vec<u8>> {
        vec![
            rlp_uint(U256::from(self.nonce)),
            rlp_uint(self.gas_price),
            rlp_uint(U256::from(self.gas_limit)),
            rlp_bytes(&self.to),
            rlp_uint(self.value),
            rlp_bytes(&self.data),
        ]
    }

    /// EIP-155 signing hash.
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut f = self.fields();
        f.extend([rlp_uint(U256::from(self.chain_id)), rlp_bytes(&[]), rlp_bytes(&[])]);
        Keccak256::digest(rlp_list(&f)).into()
    }

    /// Sign (RFC 6979 deterministic, low-S) and return the raw transaction.
    pub fn sign(&self, key: &k256::SecretKey) -> Result<Vec<u8>, TxError> {
        let signer = SigningKey::from(key.clone());
        let (mut sig, mut recid) = signer
            .sign_prehash_recoverable(&self.signing_hash())
            .map_err(|e| TxError::Sign(e.to_string()))?;
        if let Some(normalized) = sig.normalize_s() {
            sig = normalized;
            recid = RecoveryId::new(!recid.is_y_odd(), recid.is_x_reduced());
        }
        let v = U256::from(self.chain_id) * 2 + 35 + U256::from(recid.is_y_odd() as u8);
        let r = U256::from_be_bytes(sig.r().to_bytes().into());
        let s = U256::from_be_bytes(sig.s().to_bytes().into());
        let mut f = self.fields();
        f.extend([rlp_uint(v), rlp_uint(r), rlp_uint(s)]);
        Ok(rlp_list(&f))
    }
}

// ── ERC-20 ABI ────────────────────────────────────────────────────────────

const SEL_BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
const SEL_DECIMALS: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];
const SEL_SYMBOL: [u8; 4] = [0x95, 0xd8, 0x9b, 0x41];
const SEL_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

fn abi_address(a: &Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

pub fn erc20_transfer_data(to: &Address, amount: U256) -> Vec<u8> {
    let mut d = SEL_TRANSFER.to_vec();
    d.extend_from_slice(&abi_address(to));
    d.extend_from_slice(&amount.to_be_bytes());
    d
}

fn decode_abi_string(b: &[u8]) -> Option<String> {
    if b.len() >= 64 {
        let off = U256::from_be_bytes(b[0..32].try_into().ok()?).as_usize();
        let len = U256::from_be_bytes(b.get(off..off + 32)?.try_into().ok()?).as_usize();
        let s = b.get(off + 32..off + 32 + len)?;
        return Some(String::from_utf8_lossy(s).to_string());
    }
    if b.len() == 32 {
        // Old tokens (e.g. MKR) return bytes32.
        let end = b.iter().position(|c| *c == 0).unwrap_or(32);
        return Some(String::from_utf8_lossy(&b[..end]).to_string());
    }
    None
}

// ── RPC helpers ───────────────────────────────────────────────────────────

fn hex_quantity(v: &Value) -> Result<U256, TxError> {
    let s = v.as_str().ok_or_else(|| TxError::Rpc(format!("expected hex quantity, got {v}")))?;
    let digits = s.trim_start_matches("0x");
    if digits.is_empty() {
        return Ok(U256::ZERO);
    }
    U256::from_str_radix(digits, 16).map_err(|_| TxError::Rpc(format!("bad hex quantity {s}")))
}

fn hex_bytes(v: &Value) -> Result<Vec<u8>, TxError> {
    let s = v.as_str().ok_or_else(|| TxError::Rpc(format!("expected hex data, got {v}")))?;
    hex::decode(s.trim_start_matches("0x")).map_err(|_| TxError::Rpc("bad hex data".into()))
}

fn qty(v: U256) -> String {
    format!("0x{v:x}")
}

fn addr_hex(a: &Address) -> String {
    format!("0x{}", hex::encode(a))
}

pub struct EvmRpc<'a> {
    pub url: &'a str,
}

impl EvmRpc<'_> {
    fn call(&self, method: &str, params: Value) -> Result<Value, TxError> {
        json_rpc(self.url, method, params)
    }
    pub fn chain_id(&self) -> Result<u64, TxError> {
        Ok(hex_quantity(&self.call("eth_chainId", json!([]))?)?.as_u64())
    }
    pub fn balance(&self, a: &Address) -> Result<U256, TxError> {
        hex_quantity(&self.call("eth_getBalance", json!([addr_hex(a), "latest"]))?)
    }
    pub fn nonce(&self, a: &Address) -> Result<u64, TxError> {
        Ok(hex_quantity(&self.call("eth_getTransactionCount", json!([addr_hex(a), "pending"]))?)?.as_u64())
    }
    pub fn gas_price(&self) -> Result<U256, TxError> {
        hex_quantity(&self.call("eth_gasPrice", json!([]))?)
    }
    pub fn code_len(&self, a: &Address) -> Result<usize, TxError> {
        Ok(hex_bytes(&self.call("eth_getCode", json!([addr_hex(a), "latest"]))?)?.len())
    }
    pub fn eth_call(&self, to: &Address, data: &[u8]) -> Result<Vec<u8>, TxError> {
        hex_bytes(&self.call(
            "eth_call",
            json!([{ "to": addr_hex(to), "data": format!("0x{}", hex::encode(data)) }, "latest"]),
        )?)
    }
    pub fn estimate_gas(&self, from: &Address, to: &Address, value: U256, data: &[u8]) -> Result<u64, TxError> {
        let v = self.call(
            "eth_estimateGas",
            json!([{ "from": addr_hex(from), "to": addr_hex(to), "value": qty(value), "data": format!("0x{}", hex::encode(data)) }]),
        )?;
        Ok(hex_quantity(&v)?.as_u64())
    }
    pub fn send_raw(&self, raw: &[u8]) -> Result<String, TxError> {
        let v = self.call("eth_sendRawTransaction", json!([format!("0x{}", hex::encode(raw))]))?;
        v.as_str().map(String::from).ok_or_else(|| TxError::Rpc("node returned no tx hash".into()))
    }

    pub fn token_decimals(&self, token: &Address) -> Result<u8, TxError> {
        let out = self.eth_call(token, &SEL_DECIMALS)?;
        if out.len() < 32 {
            return Err(TxError::Input("that address doesn't look like an ERC-20 token (no decimals())".into()));
        }
        let d = U256::from_be_bytes(out[..32].try_into().unwrap());
        if d > 77 {
            return Err(TxError::Input("token reports nonsensical decimals".into()));
        }
        Ok(d.as_u8())
    }
    pub fn token_symbol(&self, token: &Address) -> String {
        self.eth_call(token, &SEL_SYMBOL)
            .ok()
            .and_then(|b| decode_abi_string(&b))
            .map(|s| s.trim().chars().filter(|c| !c.is_control()).take(16).collect::<String>())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "TOKEN".into())
    }
    pub fn token_balance(&self, token: &Address, owner: &Address) -> Result<U256, TxError> {
        let mut data = SEL_BALANCE_OF.to_vec();
        data.extend_from_slice(&abi_address(owner));
        let out = self.eth_call(token, &data)?;
        if out.len() < 32 {
            return Err(TxError::Input("that address doesn't look like an ERC-20 token (no balanceOf())".into()));
        }
        Ok(U256::from_be_bytes(out[..32].try_into().unwrap()))
    }
}

// ── quote / send ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmPlan {
    pub chain_id: u64,
    pub from: Address,
    /// Recipient for native sends, token contract for token sends.
    pub call_to: Address,
    pub value: U256,
    pub data: Vec<u8>,
    pub gas_limit: u64,
    pub gas_price: U256,
}

pub fn quote(net: &Network, from: &str, asset: &Asset, to: &str, amount: &AmountSpec) -> Result<Quote, TxError> {
    let rpc = EvmRpc { url: &net.rpc_url };
    let from_addr = parse_address(from)?;
    let to_addr = parse_address(to)?;

    let chain_id = rpc.chain_id()?;
    if let Some(expected) = net.chain_id {
        if chain_id != expected {
            return Err(TxError::Input(format!(
                "this RPC is for chain id {chain_id}, but {} is chain id {expected}",
                net.name
            )));
        }
    }

    let native_balance = rpc.balance(&from_addr)?;
    // +10% so the transaction isn't stuck if fees tick up before it lands.
    let gas_price = (rpc.gas_price()? * 11 / 10).max(U256::ONE);
    let mut warnings = Vec::new();
    if from_addr == to_addr {
        warnings.push("You're sending to the same wallet.".to_string());
    }

    let (symbol, decimals, asset_balance, value, data, call_to, gas_limit, amount_raw, token) = match asset {
        Asset::Native => {
            if rpc.code_len(&to_addr)? > 0 {
                warnings.push("The recipient is a smart contract. Make sure it can accept native coins.".into());
            }
            let gas_limit = match amount {
                AmountSpec::Max => rpc.estimate_gas(&from_addr, &to_addr, U256::ZERO, &[])?,
                AmountSpec::Exact(s) => {
                    let v = crate::amount::parse_units(s, NATIVE_DECIMALS)?;
                    if v > native_balance {
                        return Err(TxError::Input(format!(
                            "insufficient {}: balance is {}",
                            net.symbol,
                            format_short(native_balance, NATIVE_DECIMALS, 8)
                        )));
                    }
                    rpc.estimate_gas(&from_addr, &to_addr, v, &[])?
                }
            };
            let fee = gas_price * U256::from(gas_limit);
            let value = match amount {
                AmountSpec::Max => {
                    if native_balance <= fee {
                        return Err(TxError::Input(format!("balance doesn't cover the network fee ({} {})", format_short(fee, NATIVE_DECIMALS, 8), net.symbol)));
                    }
                    native_balance - fee
                }
                AmountSpec::Exact(s) => crate::amount::parse_units(s, NATIVE_DECIMALS)?,
            };
            if value + fee > native_balance {
                return Err(TxError::Input(format!(
                    "amount + fee exceeds balance ({} {})",
                    format_short(native_balance, NATIVE_DECIMALS, 8),
                    net.symbol
                )));
            }
            (net.symbol.clone(), NATIVE_DECIMALS, native_balance, value, vec![], to_addr, gas_limit, value, None)
        }
        Asset::Token(token) => {
            let token_addr = parse_address(token)?;
            if rpc.code_len(&token_addr)? == 0 {
                return Err(TxError::Input("no contract at that token address on this network".into()));
            }
            if token_addr == to_addr {
                warnings.push("You're sending tokens to the token contract itself — they are usually lost forever.".into());
            }
            let decimals = rpc.token_decimals(&token_addr)?;
            let symbol = rpc.token_symbol(&token_addr);
            let balance = rpc.token_balance(&token_addr, &from_addr)?;
            let amount_raw = match amount {
                AmountSpec::Max => balance,
                AmountSpec::Exact(s) => crate::amount::parse_units(s, decimals)?,
            };
            if amount_raw == U256::ZERO {
                return Err(TxError::Input(format!("this wallet holds no {symbol}")));
            }
            if amount_raw > balance {
                return Err(TxError::Input(format!("insufficient {symbol}: balance is {}", format_units(balance, decimals))));
            }
            let data = erc20_transfer_data(&to_addr, amount_raw);
            let estimate = rpc.estimate_gas(&from_addr, &token_addr, U256::ZERO, &data)?;
            // Tax / reflection tokens vary gas between estimate and execution.
            let gas_limit = estimate + estimate / 4;
            (symbol, decimals, balance, U256::ZERO, data, token_addr, gas_limit, amount_raw, Some(to_checksum(&token_addr)))
        }
    };

    let fee = gas_price * U256::from(gas_limit);
    if fee > native_balance.saturating_sub(value) {
        return Err(TxError::Input(format!(
            "not enough {} for the network fee (needs ≈{}, has {})",
            net.symbol,
            format_short(fee, NATIVE_DECIMALS, 8),
            format_short(native_balance, NATIVE_DECIMALS, 8)
        )));
    }

    Ok(Quote {
        network: net.clone(),
        from: to_checksum(&from_addr),
        to: to_checksum(&to_addr),
        symbol,
        decimals,
        token,
        amount: amount_raw,
        amount_display: format_units(amount_raw, decimals),
        balance_display: format_short(asset_balance, decimals, 6),
        native_balance_display: format_short(native_balance, NATIVE_DECIMALS, 6),
        fee_display: format!("≈ {} {}", format_short(fee, NATIVE_DECIMALS, 8), net.symbol),
        warnings,
        plan: crate::Plan::Evm(EvmPlan { chain_id, from: from_addr, call_to, value, data, gas_limit, gas_price }),
    })
}

pub fn send(net: &Network, plan: &EvmPlan, secret: &str) -> Result<String, TxError> {
    let key = vault_core::secp256k1_key(secret).map_err(|e| TxError::Sign(e.to_string()))?;
    if address_of(&key) != plan.from {
        return Err(TxError::Sign("the unlocked key doesn't match this wallet's address".into()));
    }
    let rpc = EvmRpc { url: &net.rpc_url };
    let tx = LegacyTx {
        nonce: rpc.nonce(&plan.from)?,
        gas_price: plan.gas_price,
        gas_limit: plan.gas_limit,
        to: plan.call_to,
        value: plan.value,
        data: plan.data.clone(),
        chain_id: plan.chain_id,
    };
    let raw = tx.sign(&key)?;
    rpc.send_raw(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example from the EIP-155 specification.
    #[test]
    fn eip155_spec_vector() {
        let tx = LegacyTx {
            nonce: 9,
            gas_price: U256::from(20_000_000_000u64),
            gas_limit: 21000,
            to: parse_address("0x3535353535353535353535353535353535353535").unwrap(),
            value: U256::from(1_000_000_000_000_000_000u128),
            data: vec![],
            chain_id: 1,
        };
        assert_eq!(
            hex::encode(tx.signing_hash()),
            "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
        );
        let key = k256::SecretKey::from_slice(&[0x46; 32]).unwrap();
        assert_eq!(
            hex::encode(tx.sign(&key).unwrap()),
            "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
        );
    }

    #[test]
    fn addresses() {
        assert!(parse_address("0x2c7536E3605D9C16a7a3D7b1898e529396a65c23").is_ok());
        assert!(parse_address("0x2c7536e3605d9c16a7a3d7b1898e529396a65c23").is_ok()); // all-lower: no checksum
        assert!(parse_address("0x2c7536E3605D9C16a7a3D7b1898e529396a65C23").is_err()); // bad checksum
        assert!(parse_address("2c7536e3605d9c16a7a3d7b1898e529396a65c23").is_err());
        assert!(parse_address("0x1234").is_err());
    }

    #[test]
    fn erc20_calldata() {
        let to = parse_address("0x000000000000000000000000000000000000dead").unwrap();
        let data = erc20_transfer_data(&to, U256::from(1000u32));
        assert_eq!(
            hex::encode(data),
            "a9059cbb000000000000000000000000000000000000000000000000000000000000dead00000000000000000000000000000000000000000000000000000000000003e8"
        );
    }

    #[test]
    fn abi_strings() {
        let mut b = vec![0u8; 96];
        b[31] = 32;
        b[63] = 4;
        b[64..68].copy_from_slice(b"USDT");
        assert_eq!(decode_abi_string(&b).as_deref(), Some("USDT"));
        let mut b32 = [0u8; 32];
        b32[..3].copy_from_slice(b"MKR");
        assert_eq!(decode_abi_string(&b32).as_deref(), Some("MKR"));
    }

    #[test]
    fn rlp_long_payload() {
        let data = vec![0xab; 100];
        let enc = rlp_bytes(&data);
        assert_eq!(&enc[..2], &[0xb8, 100]);
        assert_eq!(rlp_bytes(&[0x05]), vec![0x05]);
        assert_eq!(rlp_bytes(&[]), vec![0x80]);
        assert_eq!(rlp_uint(U256::ZERO), vec![0x80]);
    }
}
