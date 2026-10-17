//! Built-in networks. RPC URLs are editable in the app; these are public
//! endpoints that work without an API key (rate-limited — use your own RPC
//! for heavy use).

use vault_core::Chain;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Evm,
    Solana,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    pub id: &'static str,
    pub name: String,
    pub family: Family,
    pub rpc_url: String,
    /// Expected EVM chain id; checked against the RPC before sending.
    pub chain_id: Option<u64>,
    pub symbol: String,
    /// Explorer URL with `{tx}` placeholder.
    pub explorer: Option<String>,
    pub testnet: bool,
}

fn evm(id: &'static str, name: &str, rpc: &str, chain_id: u64, symbol: &str, explorer: &str, testnet: bool) -> Network {
    Network {
        id,
        name: name.into(),
        family: Family::Evm,
        rpc_url: rpc.into(),
        chain_id: Some(chain_id),
        symbol: symbol.into(),
        explorer: Some(format!("{explorer}/tx/{{tx}}")),
        testnet,
    }
}

pub fn presets() -> Vec<Network> {
    vec![
        evm("eth", "Ethereum", "https://ethereum-rpc.publicnode.com", 1, "ETH", "https://etherscan.io", false),
        evm("bsc", "BNB Smart Chain", "https://bsc-dataseed.bnbchain.org", 56, "BNB", "https://bscscan.com", false),
        evm("base", "Base", "https://mainnet.base.org", 8453, "ETH", "https://basescan.org", false),
        evm("arb", "Arbitrum One", "https://arb1.arbitrum.io/rpc", 42161, "ETH", "https://arbiscan.io", false),
        evm("op", "Optimism", "https://mainnet.optimism.io", 10, "ETH", "https://optimistic.etherscan.io", false),
        evm("polygon", "Polygon", "https://polygon-bor-rpc.publicnode.com", 137, "POL", "https://polygonscan.com", false),
        evm("avax", "Avalanche C-Chain", "https://api.avax.network/ext/bc/C/rpc", 43114, "AVAX", "https://snowtrace.io", false),
        evm("sepolia", "Sepolia (testnet)", "https://ethereum-sepolia-rpc.publicnode.com", 11155111, "ETH", "https://sepolia.etherscan.io", true),
        evm("bsc-test", "BSC Testnet", "https://bsc-testnet-rpc.publicnode.com", 97, "tBNB", "https://testnet.bscscan.com", true),
        Network {
            id: "sol",
            name: "Solana".into(),
            family: Family::Solana,
            rpc_url: "https://api.mainnet-beta.solana.com".into(),
            chain_id: None,
            symbol: "SOL".into(),
            explorer: Some("https://solscan.io/tx/{tx}".into()),
            testnet: false,
        },
        Network {
            id: "sol-dev",
            name: "Solana Devnet".into(),
            family: Family::Solana,
            rpc_url: "https://api.devnet.solana.com".into(),
            chain_id: None,
            symbol: "SOL".into(),
            explorer: Some("https://solscan.io/tx/{tx}?cluster=devnet".into()),
            testnet: true,
        },
    ]
}

/// Networks usable by a wallet of the given chain (empty = sending unsupported).
pub fn for_chain(chain: Chain) -> Vec<Network> {
    let family = match chain {
        Chain::Evm => Family::Evm,
        Chain::Solana => Family::Solana,
        Chain::Tron | Chain::Other => return vec![],
    };
    presets().into_iter().filter(|n| n.family == family).collect()
}

/// A user-supplied EVM RPC; the chain id is read from the node.
pub fn custom_evm(rpc_url: &str, symbol: &str) -> Network {
    Network {
        id: "custom",
        name: "Custom EVM".into(),
        family: Family::Evm,
        rpc_url: rpc_url.trim().into(),
        chain_id: None,
        symbol: if symbol.trim().is_empty() { "ETH".into() } else { symbol.trim().to_uppercase() },
        explorer: None,
        testnet: false,
    }
}

impl Network {
    pub fn explorer_url(&self, tx: &str) -> Option<String> {
        self.explorer.as_ref().map(|e| e.replace("{tx}", tx))
    }
}
