//! Developer tool used by the end-to-end tests.
//!
//!   cli quote-send <rpc> <evm|solana> <secret> <to> <amount|max> [token]
//!   cli sol-build  <secret> <blockhash> native <to> <lamports>
//!   cli sol-build  <secret> <blockhash> token <to> <amount> <mint> <token-program> <decimals>
//!   cli ata <owner> <mint> <token-program>

use wallet_tx::solana::{self, SolPlan, SolTransfer};
use wallet_tx::{network, AmountSpec, Asset};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a[0].as_str() {
        "quote-send" => {
            let net = match a[2].as_str() {
                "evm" => network::custom_evm(&a[1], "ETH"),
                _ => network::Network { rpc_url: a[1].clone(), ..network::for_chain(vault_core::Chain::Solana)[0].clone() },
            };
            let chain = if a[2] == "evm" { vault_core::Chain::Evm } else { vault_core::Chain::Solana };
            let from = vault_core::derive_address(chain, &a[3]).unwrap().unwrap();
            let amount = if a[5] == "max" { AmountSpec::Max } else { AmountSpec::Exact(a[5].clone()) };
            let asset = a.get(6).map(|t| Asset::Token(t.clone())).unwrap_or(Asset::Native);
            match wallet_tx::quote(&net, &from, &asset, &a[4], &amount) {
                Ok(q) => {
                    println!("QUOTE {} {} -> {} | balance {} | fee {} | warnings {:?}", q.amount_display, q.symbol, q.to, q.balance_display, q.fee_display, q.warnings);
                    match wallet_tx::send(&q, &a[3]) {
                        Ok(s) => println!("SENT {}", s.tx),
                        Err(e) => println!("SEND-ERROR {e}"),
                    }
                }
                Err(e) => println!("QUOTE-ERROR {e}"),
            }
        }
        "sol-build" => {
            let key = vault_core::solana_signing_key(&a[1]).unwrap();
            let blockhash = solana::parse_pubkey(&a[2]).unwrap();
            let to = solana::parse_pubkey(&a[4]).unwrap();
            let transfer = if a[3] == "native" {
                SolTransfer::Native { to, lamports: a[5].parse().unwrap() }
            } else {
                SolTransfer::Token {
                    mint: solana::parse_pubkey(&a[6]).unwrap(),
                    token_program: solana::parse_pubkey(&a[7]).unwrap(),
                    decimals: a[8].parse().unwrap(),
                    to_owner: to,
                    amount: a[5].parse().unwrap(),
                }
            };
            let plan = SolPlan {
                from: key.verifying_key().to_bytes(),
                cu_limit: if a[3] == "native" { 5_000 } else { 100_000 },
                cu_price: 50_000,
                transfer,
            };
            use base64::Engine;
            println!("{}", base64::engine::general_purpose::STANDARD.encode(plan.build(&key, &blockhash)));
        }
        "ata" => {
            let p = |s: &str| solana::parse_pubkey(s).unwrap();
            println!("{}", solana::b58(&solana::associated_token_address(&p(&a[1]), &p(&a[2]), &p(&a[3]))));
        }
        _ => eprintln!("unknown command"),
    }
}
