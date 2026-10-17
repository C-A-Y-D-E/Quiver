//! Send native coins and tokens from KeyVault wallets.
//!
//! Flow: [`quote`] (read-only: balances, decimals, fee, sanity checks — needs
//! no key) → user confirms → [`send`] (decrypted key signs locally, raw
//! transaction is broadcast). Keys never leave the process.
//!
//! All functions block on network I/O; call them from a background thread.

pub mod amount;
pub mod evm;
pub mod network;
mod rpc;
pub mod solana;

pub use ethnum::U256;
pub use network::{Family, Network};

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum TxError {
    #[error("{0}")]
    Input(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("RPC error: {0}")]
    Rpc(String),
    #[error("signing failed: {0}")]
    Sign(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asset {
    Native,
    /// ERC-20 contract address or SPL mint address.
    Token(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmountSpec {
    Exact(String),
    /// Everything (native: balance minus fee).
    Max,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    Evm(evm::EvmPlan),
    Solana(solana::SolPlan),
}

/// A reviewed, ready-to-sign transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quote {
    pub network: Network,
    pub from: String,
    pub to: String,
    pub symbol: String,
    pub decimals: u8,
    pub token: Option<String>,
    pub amount: U256,
    pub amount_display: String,
    pub balance_display: String,
    pub native_balance_display: String,
    pub fee_display: String,
    pub warnings: Vec<String>,
    pub plan: Plan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    pub tx: String,
    pub explorer_url: Option<String>,
}

pub fn quote(net: &Network, from: &str, asset: &Asset, to: &str, amount: &AmountSpec) -> Result<Quote, TxError> {
    match net.family {
        Family::Evm => evm::quote(net, from, asset, to, amount),
        Family::Solana => solana::quote(net, from, asset, to, amount),
    }
}

/// Sign and broadcast a quote with the decrypted wallet secret.
pub fn send(quote: &Quote, secret: &str) -> Result<Sent, TxError> {
    let tx = match &quote.plan {
        Plan::Evm(p) => evm::send(&quote.network, p, secret)?,
        Plan::Solana(p) => solana::send(&quote.network, p, secret)?,
    };
    Ok(Sent { explorer_url: quote.network.explorer_url(&tx), tx })
}
