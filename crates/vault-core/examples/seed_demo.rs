//! Create a demo vault filled with throwaway random keys, to try the app safely:
//!
//!     cargo run -p vault-core --example seed_demo -- /tmp/demo-vault.json
//!     KEYVAULT_PATH=/tmp/demo-vault.json cargo run -p keyvault-app
//!
//! Vault passphrase: `demo-passphrase`. "Treasury" also has an extra lock with
//! password `demo-password`. Never send real funds to these throwaway keys.

use rand::RngCore;
use vault_core::{Chain, NewWallet, Vault, WalletEntry, Zeroizing};

fn main() {
    let path = std::env::args().nth(1).expect("usage: seed_demo <path/to/vault.json>");
    let mut vault = Vault::open(&path).expect("open vault");
    let mk = match vault.keyring() {
        Some(kr) => kr.open_passphrase("demo-passphrase").expect("existing demo vault"),
        None => {
            let (kr, mk, code) = vault_core::Keyring::create("demo-passphrase").expect("keyring");
            vault.set_keyring(kr).expect("save keyring");
            println!("recovery key: {}", code.as_str());
            mk
        }
    };
    let mut rng = rand::rngs::OsRng;

    let demo: &[(&str, Chain, Option<&str>, &str, &str)] = &[
        ("Main deployer", Chain::Evm, Some("Deployers"), "bsc, hot", "Deploys tax tokens"),
        ("Treasury", Chain::Evm, Some("Cold storage"), "cold, eth", "Multisig signer #2"),
        ("Pump sniper", Chain::Solana, Some("Trading bots"), "sol, hot, bot", ""),
        ("Market maker A", Chain::Evm, Some("Trading bots"), "bsc, bot", "PancakeSwap MM"),
        ("Phantom main", Chain::Solana, None, "sol", ""),
        ("USDT payouts", Chain::Tron, Some("Cold storage"), "tron, payouts", ""),
        ("Ledger seed backup", Chain::Other, Some("Cold storage"), "cold, seed", "Paper copy in safe"),
        ("Airdrop farm 01", Chain::Evm, Some("Airdrops"), "farm", ""),
        ("Airdrop farm 02", Chain::Evm, Some("Airdrops"), "farm", ""),
    ];

    for (label, chain, folder, tags, note) in demo {
        let secret = match chain {
            Chain::Evm | Chain::Tron => {
                let mut k = [0u8; 32];
                rng.fill_bytes(&mut k);
                format!("0x{}", hex::encode(k))
            }
            Chain::Solana => {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
                bs58::encode(sk.to_keypair_bytes()).into_string()
            }
            Chain::Other => "abandon ability able about above absent absorb abstract absurd abuse access accident".into(),
        };
        let entry = WalletEntry::create(NewWallet {
            label: label.to_string(),
            folder: folder.map(String::from),
            tags: vault_core::parse_tags(tags),
            note: note.to_string(),
            chain: *chain,
            secret: Zeroizing::new(secret),
            address: matches!(chain, Chain::Other).then(|| "bc1qdemo0example0address0only".to_string()),
            password: (*label == "Treasury").then(|| Zeroizing::new("demo-password".into())),
        }, Some(&mk))
        .expect("create");
        let id = entry.id;
        vault.insert(entry).expect("insert");
        if *label == "Main deployer" || *label == "Treasury" {
            vault.set_favorite(id, true).unwrap();
        }
        println!("added {label}");
    }
    println!("demo vault written to {path} (vault passphrase: demo-passphrase; Treasury extra lock: demo-password)");
}
