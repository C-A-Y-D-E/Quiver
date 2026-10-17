//! Solana transfers: SOL and SPL tokens (classic Token program and Token-2022).
//!
//! Builds legacy-format transactions by hand (no solana-sdk dependency) and
//! signs them with the wallet's ed25519 key.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signer, SigningKey};
use ethnum::U256;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::amount::{format_short, format_units, parse_units};
use crate::network::Network;
use crate::rpc::json_rpc;
use crate::{AmountSpec, Asset, Quote, TxError};

pub type Pubkey = [u8; 32];

pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";

const LAMPORTS_DECIMALS: u8 = 9;
const SIGNATURE_FEE: u64 = 5_000;
/// Rent-exempt minimum for a 0-byte system account.
const RENT_EXEMPT_MIN: u64 = 890_880;
/// Rent for a 165-byte SPL token account (what creating the recipient's ATA costs).
const TOKEN_ACCOUNT_RENT: u64 = 2_039_280;
/// Priority fee in micro-lamports per compute unit — enough to land promptly
/// without being expensive.
const CU_PRICE_MICRO_LAMPORTS: u64 = 50_000;

pub fn pk(s: &str) -> Pubkey {
    parse_pubkey(s).expect("valid built-in program id")
}

pub fn parse_pubkey(input: &str) -> Result<Pubkey, TxError> {
    let bytes = bs58::decode(input.trim())
        .into_vec()
        .map_err(|_| TxError::Input("Solana addresses are base58 — that isn't valid base58".into()))?;
    bytes
        .try_into()
        .map_err(|_| TxError::Input("a Solana address is 32 bytes (32–44 base58 characters)".into()))
}

pub fn b58(k: &Pubkey) -> String {
    bs58::encode(k).into_string()
}

pub fn is_on_curve(k: &Pubkey) -> bool {
    CompressedEdwardsY(*k).decompress().is_some()
}

/// Program-derived address: the first bump (from 255 down) whose hash is
/// *not* a valid ed25519 point.
pub fn find_program_address(seeds: &[&[u8]], program: &Pubkey) -> (Pubkey, u8) {
    for bump in (0..=255u8).rev() {
        let mut h = Sha256::new();
        for s in seeds {
            h.update(s);
        }
        h.update([bump]);
        h.update(program);
        h.update(b"ProgramDerivedAddress");
        let candidate: Pubkey = h.finalize().into();
        if !is_on_curve(&candidate) {
            return (candidate, bump);
        }
    }
    unreachable!("no viable bump seed")
}

pub fn associated_token_address(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    find_program_address(&[owner, token_program, mint], &pk(ATA_PROGRAM)).0
}

// ── message compilation ───────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct AccountMeta {
    pub key: Pubkey,
    pub signer: bool,
    pub writable: bool,
}

impl AccountMeta {
    fn new(key: Pubkey, signer: bool, writable: bool) -> Self {
        AccountMeta { key, signer, writable }
    }
}

#[derive(Clone, Debug)]
pub struct Instruction {
    pub program: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

fn compact_u16(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        byte |= 0x80;
        out.push(byte);
    }
}

/// Serialize a legacy message. Account order matches solana-sdk: fee payer,
/// then writable signers, readonly signers, writable, readonly — each group
/// sorted by key.
pub fn compile_message(payer: &Pubkey, ixs: &[Instruction], blockhash: &Pubkey) -> Vec<u8> {
    let mut metas: Vec<AccountMeta> = Vec::new();
    let mut upsert = |m: AccountMeta| {
        if let Some(e) = metas.iter_mut().find(|e| e.key == m.key) {
            e.signer |= m.signer;
            e.writable |= m.writable;
        } else {
            metas.push(m);
        }
    };
    upsert(AccountMeta::new(*payer, true, true));
    for ix in ixs {
        upsert(AccountMeta::new(ix.program, false, false));
        for a in &ix.accounts {
            upsert(*a);
        }
    }
    let payer_meta = metas.remove(0);
    let group = |m: &AccountMeta| match (m.signer, m.writable) {
        (true, true) => 0,
        (true, false) => 1,
        (false, true) => 2,
        (false, false) => 3,
    };
    metas.sort_by(|a, b| group(a).cmp(&group(b)).then(a.key.cmp(&b.key)));
    metas.insert(0, payer_meta);

    let signers = metas.iter().filter(|m| m.signer).count();
    let ro_signed = metas.iter().filter(|m| m.signer && !m.writable).count();
    let ro_unsigned = metas.iter().filter(|m| !m.signer && !m.writable).count();
    let index = |k: &Pubkey| metas.iter().position(|m| m.key == *k).unwrap() as u8;

    let mut out = vec![signers as u8, ro_signed as u8, ro_unsigned as u8];
    compact_u16(metas.len(), &mut out);
    for m in &metas {
        out.extend_from_slice(&m.key);
    }
    out.extend_from_slice(blockhash);
    compact_u16(ixs.len(), &mut out);
    for ix in ixs {
        out.push(index(&ix.program));
        compact_u16(ix.accounts.len(), &mut out);
        for a in &ix.accounts {
            out.push(index(&a.key));
        }
        compact_u16(ix.data.len(), &mut out);
        out.extend_from_slice(&ix.data);
    }
    out
}

pub fn sign_transaction(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let sig = key.sign(message);
    let mut out = Vec::with_capacity(1 + 64 + message.len());
    compact_u16(1, &mut out);
    out.extend_from_slice(&sig.to_bytes());
    out.extend_from_slice(message);
    out
}

// ── instructions ──────────────────────────────────────────────────────────

pub fn ix_set_cu_limit(units: u32) -> Instruction {
    let mut data = vec![2u8];
    data.extend_from_slice(&units.to_le_bytes());
    Instruction { program: pk(COMPUTE_BUDGET_PROGRAM), accounts: vec![], data }
}

pub fn ix_set_cu_price(micro_lamports: u64) -> Instruction {
    let mut data = vec![3u8];
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    Instruction { program: pk(COMPUTE_BUDGET_PROGRAM), accounts: vec![], data }
}

pub fn ix_system_transfer(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program: pk(SYSTEM_PROGRAM),
        accounts: vec![AccountMeta::new(*from, true, true), AccountMeta::new(*to, false, true)],
        data,
    }
}

pub fn ix_create_ata_idempotent(payer: &Pubkey, owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Instruction {
    Instruction {
        program: pk(ATA_PROGRAM),
        accounts: vec![
            AccountMeta::new(*payer, true, true),
            AccountMeta::new(associated_token_address(owner, mint, token_program), false, true),
            AccountMeta::new(*owner, false, false),
            AccountMeta::new(*mint, false, false),
            AccountMeta::new(pk(SYSTEM_PROGRAM), false, false),
            AccountMeta::new(*token_program, false, false),
        ],
        data: vec![1],
    }
}

#[allow(clippy::too_many_arguments)]
pub fn ix_transfer_checked(
    token_program: &Pubkey,
    source: &Pubkey,
    mint: &Pubkey,
    dest: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = vec![12u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program: *token_program,
        accounts: vec![
            AccountMeta::new(*source, false, true),
            AccountMeta::new(*mint, false, false),
            AccountMeta::new(*dest, false, true),
            AccountMeta::new(*owner, true, false),
        ],
        data,
    }
}

// ── plan ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolTransfer {
    Native { to: Pubkey, lamports: u64 },
    Token { mint: Pubkey, token_program: Pubkey, decimals: u8, to_owner: Pubkey, amount: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolPlan {
    pub from: Pubkey,
    pub transfer: SolTransfer,
    pub cu_limit: u32,
    pub cu_price: u64,
}

impl SolPlan {
    pub fn instructions(&self) -> Vec<Instruction> {
        let mut ixs = vec![ix_set_cu_limit(self.cu_limit), ix_set_cu_price(self.cu_price)];
        match &self.transfer {
            SolTransfer::Native { to, lamports } => ixs.push(ix_system_transfer(&self.from, to, *lamports)),
            SolTransfer::Token { mint, token_program, decimals, to_owner, amount } => {
                let source = associated_token_address(&self.from, mint, token_program);
                let dest = associated_token_address(to_owner, mint, token_program);
                ixs.push(ix_create_ata_idempotent(&self.from, to_owner, mint, token_program));
                ixs.push(ix_transfer_checked(token_program, &source, mint, &dest, &self.from, *amount, *decimals));
            }
        }
        ixs
    }

    pub fn fee_lamports(&self) -> u64 {
        SIGNATURE_FEE + (self.cu_limit as u64 * self.cu_price).div_ceil(1_000_000)
    }

    pub fn build(&self, key: &SigningKey, blockhash: &Pubkey) -> Vec<u8> {
        let msg = compile_message(&self.from, &self.instructions(), blockhash);
        sign_transaction(key, &msg)
    }
}

// ── RPC ───────────────────────────────────────────────────────────────────

pub struct SolRpc<'a> {
    pub url: &'a str,
}

impl SolRpc<'_> {
    fn call(&self, method: &str, params: Value) -> Result<Value, TxError> {
        json_rpc(self.url, method, params)
    }
    pub fn balance(&self, k: &Pubkey) -> Result<u64, TxError> {
        let v = self.call("getBalance", json!([b58(k), {"commitment": "confirmed"}]))?;
        v["value"].as_u64().ok_or_else(|| TxError::Rpc("bad getBalance response".into()))
    }
    pub fn latest_blockhash(&self) -> Result<Pubkey, TxError> {
        let v = self.call("getLatestBlockhash", json!([{"commitment": "confirmed"}]))?;
        let s = v["value"]["blockhash"].as_str().ok_or_else(|| TxError::Rpc("bad blockhash response".into()))?;
        parse_pubkey(s)
    }
    pub fn account(&self, k: &Pubkey) -> Result<Option<Value>, TxError> {
        let v = self.call("getAccountInfo", json!([b58(k), {"encoding": "jsonParsed", "commitment": "confirmed"}]))?;
        Ok(Some(v["value"].clone()).filter(|a| !a.is_null()))
    }
    pub fn token_balance(&self, token_account: &Pubkey) -> Result<u64, TxError> {
        match self.call("getTokenAccountBalance", json!([b58(token_account), {"commitment": "confirmed"}])) {
            Ok(v) => v["value"]["amount"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| TxError::Rpc("bad token balance response".into())),
            // Missing account → the wallet has never held this token.
            Err(TxError::Rpc(_)) => Ok(0),
            Err(e) => Err(e),
        }
    }
    pub fn send(&self, raw: &[u8]) -> Result<String, TxError> {
        let v = self.call(
            "sendTransaction",
            json!([B64.encode(raw), {"encoding": "base64", "preflightCommitment": "confirmed", "maxRetries": 5}]),
        )?;
        v.as_str().map(String::from).ok_or_else(|| TxError::Rpc("node returned no signature".into()))
    }
}

// ── quote / send ──────────────────────────────────────────────────────────

fn sol(lamports: u64) -> String {
    format_short(U256::from(lamports), LAMPORTS_DECIMALS, 9)
}

pub fn quote(net: &Network, from: &str, asset: &Asset, to: &str, amount: &AmountSpec) -> Result<Quote, TxError> {
    let rpc = SolRpc { url: &net.rpc_url };
    let from_pk = parse_pubkey(from)?;
    let to_pk = parse_pubkey(to)?;
    let native = rpc.balance(&from_pk)?;
    let mut warnings = Vec::new();
    if from_pk == to_pk {
        warnings.push("You're sending to the same wallet.".to_string());
    }
    let recipient = rpc.account(&to_pk)?;
    let recipient_owner = recipient.as_ref().and_then(|a| a["owner"].as_str().map(String::from));
    if matches!(recipient_owner.as_deref(), Some(TOKEN_PROGRAM) | Some(TOKEN_2022_PROGRAM)) {
        return Err(TxError::Input(
            "that address is a token account, not a wallet — paste the recipient's wallet address".into(),
        ));
    }
    if !is_on_curve(&to_pk) {
        warnings.push("The recipient is a program-derived address (not a normal wallet). Double-check it.".into());
    }

    match asset {
        Asset::Native => {
            let mut plan = SolPlan {
                from: from_pk,
                transfer: SolTransfer::Native { to: to_pk, lamports: 0 },
                cu_limit: 5_000,
                cu_price: CU_PRICE_MICRO_LAMPORTS,
            };
            let fee = plan.fee_lamports();
            let lamports = match amount {
                AmountSpec::Max => native
                    .checked_sub(fee)
                    .filter(|l| *l > 0)
                    .ok_or_else(|| TxError::Input(format!("balance doesn't cover the fee ({} SOL)", sol(fee))))?,
                AmountSpec::Exact(s) => {
                    let v = parse_units(s, LAMPORTS_DECIMALS)?;
                    u64::try_from(v).map_err(|_| TxError::Input("amount is too large".into()))?
                }
            };
            let total = lamports.saturating_add(fee);
            if total > native {
                return Err(TxError::Input(format!("amount + fee exceeds balance ({} SOL)", sol(native))));
            }
            let left = native - total;
            if left > 0 && left < RENT_EXEMPT_MIN {
                return Err(TxError::Input(format!(
                    "this would leave {} SOL, below the rent minimum (0.00089088). Send Max or leave more.",
                    sol(left)
                )));
            }
            let recipient_lamports = recipient.as_ref().and_then(|a| a["lamports"].as_u64()).unwrap_or(0);
            if recipient_lamports == 0 && lamports < RENT_EXEMPT_MIN {
                return Err(TxError::Input(
                    "the recipient is a new account; send at least 0.00089088 SOL (rent minimum)".into(),
                ));
            }
            plan.transfer = SolTransfer::Native { to: to_pk, lamports };
            Ok(Quote {
                network: net.clone(),
                from: b58(&from_pk),
                to: b58(&to_pk),
                symbol: "SOL".into(),
                decimals: LAMPORTS_DECIMALS,
                token: None,
                amount: U256::from(lamports),
                amount_display: format_units(U256::from(lamports), LAMPORTS_DECIMALS),
                balance_display: sol(native),
                native_balance_display: sol(native),
                fee_display: format!("{} SOL", sol(fee)),
                warnings,
                plan: crate::Plan::Solana(plan),
            })
        }
        Asset::Token(mint_str) => {
            let mint = parse_pubkey(mint_str)?;
            let mint_acc = rpc
                .account(&mint)?
                .ok_or_else(|| TxError::Input("no token mint at that address on this network".into()))?;
            let owner = mint_acc["owner"].as_str().unwrap_or_default();
            let token_program = match owner {
                TOKEN_PROGRAM | TOKEN_2022_PROGRAM => pk(owner),
                _ => return Err(TxError::Input("that address isn't an SPL token mint".into())),
            };
            if mint_acc["data"]["parsed"]["type"].as_str() != Some("mint") {
                return Err(TxError::Input("that address is a token account, not a mint — paste the token's mint address".into()));
            }
            let decimals = mint_acc["data"]["parsed"]["info"]["decimals"]
                .as_u64()
                .filter(|d| *d <= 19)
                .ok_or_else(|| TxError::Rpc("couldn't read token decimals".into()))? as u8;

            let source = associated_token_address(&from_pk, &mint, &token_program);
            let balance = rpc.token_balance(&source)?;
            let short_mint = format!("{}…", &mint_str.trim()[..4.min(mint_str.trim().len())]);
            let symbol = format!("tokens ({short_mint})");
            let raw = match amount {
                AmountSpec::Max => balance,
                AmountSpec::Exact(s) => u64::try_from(parse_units(s, decimals)?)
                    .map_err(|_| TxError::Input("amount is too large".into()))?,
            };
            if raw == 0 {
                return Err(TxError::Input("this wallet holds none of that token".into()));
            }
            if raw > balance {
                return Err(TxError::Input(format!(
                    "insufficient balance: {}",
                    format_units(U256::from(balance), decimals)
                )));
            }

            let plan = SolPlan {
                from: from_pk,
                transfer: SolTransfer::Token { mint, token_program, decimals, to_owner: to_pk, amount: raw },
                cu_limit: 100_000,
                cu_price: CU_PRICE_MICRO_LAMPORTS,
            };
            let dest = associated_token_address(&to_pk, &mint, &token_program);
            let creates_ata = rpc.account(&dest)?.is_none();
            let mut fee = plan.fee_lamports();
            if creates_ata {
                fee += TOKEN_ACCOUNT_RENT;
                warnings.push("The recipient has no account for this token yet; it will be created (≈0.00204 SOL rent, paid by you).".into());
            }
            if fee > native {
                return Err(TxError::Input(format!("not enough SOL for fees (needs ≈{} SOL, has {})", sol(fee), sol(native))));
            }
            Ok(Quote {
                network: net.clone(),
                from: b58(&from_pk),
                to: b58(&to_pk),
                symbol,
                decimals,
                token: Some(b58(&mint)),
                amount: U256::from(raw),
                amount_display: format_units(U256::from(raw), decimals),
                balance_display: format_short(U256::from(balance), decimals, 6),
                native_balance_display: sol(native),
                fee_display: format!("≈ {} SOL", sol(fee)),
                warnings,
                plan: crate::Plan::Solana(plan),
            })
        }
    }
}

pub fn send(net: &Network, plan: &SolPlan, secret: &str) -> Result<String, TxError> {
    let key = vault_core::solana_signing_key(secret).map_err(|e| TxError::Sign(e.to_string()))?;
    if key.verifying_key().to_bytes() != plan.from {
        return Err(TxError::Sign("the unlocked key doesn't match this wallet's address".into()));
    }
    let rpc = SolRpc { url: &net.rpc_url };
    let blockhash = rpc.latest_blockhash()?;
    rpc.send(&plan.build(&key, &blockhash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_ids_are_off_curve_constants() {
        for p in [SYSTEM_PROGRAM, TOKEN_PROGRAM, TOKEN_2022_PROGRAM, ATA_PROGRAM, COMPUTE_BUDGET_PROGRAM] {
            assert_eq!(b58(&pk(p)), p);
        }
    }

    #[test]
    fn compact_u16_encoding() {
        for (n, want) in [(0usize, vec![0u8]), (127, vec![0x7f]), (128, vec![0x80, 0x01]), (16383, vec![0xff, 0x7f]), (16384, vec![0x80, 0x80, 0x01])] {
            let mut v = vec![];
            compact_u16(n, &mut v);
            assert_eq!(v, want, "{n}");
        }
    }

    #[test]
    fn fee() {
        let plan = SolPlan {
            from: [1; 32],
            transfer: SolTransfer::Native { to: [2; 32], lamports: 1 },
            cu_limit: 100_000,
            cu_price: 50_000,
        };
        assert_eq!(plan.fee_lamports(), 5_000 + 5_000);
    }
}
