//! Turn wallets into CSV or plain-text lines for importing elsewhere.
//!
//! The caller decrypts the keys (so it can ask for Touch ID / passwords) and
//! passes plain rows here; this module only formats.

use zeroize::Zeroizing;

use crate::store::WalletEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Field {
    Name,
    Address,
    PrivateKey,
    Chain,
    Folder,
    Tags,
    Note,
    Created,
}

impl Field {
    /// Display / output order.
    pub const ALL: [Field; 8] = [
        Field::Name,
        Field::Address,
        Field::PrivateKey,
        Field::Chain,
        Field::Folder,
        Field::Tags,
        Field::Note,
        Field::Created,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Field::Name => "Name",
            Field::Address => "Address",
            Field::PrivateKey => "Private key",
            Field::Chain => "Chain",
            Field::Folder => "Folder",
            Field::Tags => "Tags",
            Field::Note => "Note",
            Field::Created => "Created",
        }
    }

    /// CSV header name (lowercase, snake case — what most importers expect).
    pub fn column(self) -> &'static str {
        match self {
            Field::Name => "name",
            Field::Address => "address",
            Field::PrivateKey => "private_key",
            Field::Chain => "chain",
            Field::Folder => "folder",
            Field::Tags => "tags",
            Field::Note => "note",
            Field::Created => "created",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// RFC 4180 CSV.
    Csv { header: bool },
    /// One wallet per line, fields joined by `sep`.
    Txt { sep: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub format: Format,
    /// Write EVM / Tron keys as raw hex without the `0x` prefix.
    pub strip_0x: bool,
}

/// One wallet ready to export. `secret` is `None` if it couldn't be decrypted
/// (the private-key cell is left empty and the caller reports it).
pub struct Row<'a> {
    pub wallet: &'a WalletEntry,
    pub secret: Option<Zeroizing<String>>,
}

fn csv_cell(v: &str) -> String {
    if v.contains([',', '"', '\n', '\r']) || v.starts_with(' ') || v.ends_with(' ') {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
    }
}

fn value(row: &Row, field: Field, opts: &Options) -> String {
    let w = row.wallet;
    match field {
        Field::Name => w.label.clone(),
        Field::Address => w.address.clone().unwrap_or_default(),
        Field::PrivateKey => match &row.secret {
            Some(s) => {
                let s = s.trim();
                let evm_like = matches!(w.chain, crate::Chain::Evm | crate::Chain::Tron);
                match (opts.strip_0x, evm_like) {
                    (true, true) => s.trim_start_matches("0x").trim_start_matches("0X").to_string(),
                    (false, true) if !s.starts_with("0x") && !s.starts_with("0X") => format!("0x{s}"),
                    _ => s.to_string(),
                }
            }
            None => String::new(),
        },
        Field::Chain => w.chain.label().to_string(),
        Field::Folder => w.folder.clone().unwrap_or_default(),
        Field::Tags => w.tags.join(" "),
        Field::Note => w.note.replace(['\n', '\r'], " "),
        Field::Created => w.created_at.date().to_string(),
    }
}

/// Render the export. Output is wiped from memory on drop.
pub fn render(rows: &[Row], fields: &[Field], opts: &Options) -> Zeroizing<String> {
    // Always emit fields in the canonical order, whatever order they were picked.
    let fields: Vec<Field> = Field::ALL.into_iter().filter(|f| fields.contains(f)).collect();
    let mut out = Zeroizing::new(String::new());
    match opts.format {
        Format::Csv { header } => {
            if header {
                out.push_str(&fields.iter().map(|f| f.column()).collect::<Vec<_>>().join(","));
                out.push_str("\r\n");
            }
            for row in rows {
                let line = Zeroizing::new(fields.iter().map(|f| csv_cell(&value(row, *f, opts))).collect::<Vec<_>>().join(","));
                out.push_str(&line);
                out.push_str("\r\n");
            }
        }
        Format::Txt { sep } => {
            for row in rows {
                let line = Zeroizing::new(
                    fields
                        .iter()
                        .map(|f| {
                            let v = value(row, *f, opts);
                            // Keep each wallet on one line and the separator unambiguous.
                            if sep == " " { v.replace(' ', "_") } else { v.replace(sep, " ") }
                        })
                        .collect::<Vec<_>>()
                        .join(sep),
                );
                out.push_str(&line);
                out.push('\n');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::{Chain, MasterKey, NewWallet, WalletEntry};

    fn wallet(label: &str, chain: Chain, secret: &str, note: &str) -> WalletEntry {
        let mk = MasterKey::generate();
        WalletEntry::create_with_params(
            NewWallet {
                label: label.into(),
                folder: Some("Farm, main".into()),
                tags: vec!["bsc".into(), "hot".into()],
                note: note.into(),
                chain,
                secret: Zeroizing::new(secret.into()),
                address: None,
                password: None,
            },
            Some(&mk),
            KdfParams::DEFAULT,
        )
        .unwrap()
    }

    const KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

    #[test]
    fn csv_with_header_and_quoting() {
        let w = wallet("Main \"deployer\"", Chain::Evm, KEY, "line1\nline2");
        let rows = [Row { wallet: &w, secret: Some(Zeroizing::new(KEY.into())) }];
        let out = render(
            &rows,
            &[Field::PrivateKey, Field::Name, Field::Address, Field::Folder, Field::Note],
            &Options { format: Format::Csv { header: true }, strip_0x: false },
        );
        let mut lines = out.split("\r\n");
        assert_eq!(lines.next().unwrap(), "name,address,private_key,folder,note");
        assert_eq!(
            lines.next().unwrap(),
            format!("\"Main \"\"deployer\"\"\",0x2c7536E3605D9C16a7a3D7b1898e529396a65c23,{KEY},\"Farm, main\",line1 line2")
        );
    }

    #[test]
    fn txt_address_colon_key_without_0x() {
        let w = wallet("A", Chain::Evm, KEY, "");
        let rows = [Row { wallet: &w, secret: Some(Zeroizing::new(KEY.into())) }];
        let out = render(&rows, &[Field::Address, Field::PrivateKey], &Options { format: Format::Txt { sep: ":" }, strip_0x: true });
        assert_eq!(out.as_str(), format!("0x2c7536E3605D9C16a7a3D7b1898e529396a65c23:{}\n", &KEY[2..]));
    }

    #[test]
    fn solana_keys_untouched_and_missing_secret_blank() {
        let seed = bs58::encode([7u8; 32]).into_string();
        let w = wallet("Sol", Chain::Solana, &seed, "");
        let rows = [
            Row { wallet: &w, secret: Some(Zeroizing::new(seed.clone())) },
            Row { wallet: &w, secret: None },
        ];
        let out = render(&rows, &[Field::Name, Field::PrivateKey], &Options { format: Format::Txt { sep: "\t" }, strip_0x: true });
        assert_eq!(out.as_str(), format!("Sol\t{seed}\nSol\t\n"));
    }

    #[test]
    fn space_separator_keeps_columns() {
        let w = wallet("My wallet", Chain::Evm, KEY, "");
        let rows = [Row { wallet: &w, secret: None }];
        let out = render(&rows, &[Field::Name, Field::Tags], &Options { format: Format::Txt { sep: " " }, strip_0x: false });
        assert_eq!(out.as_str(), "My_wallet bsc_hot\n");
    }
}
