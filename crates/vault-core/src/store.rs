//! The on-disk vault: a JSON file holding one sealed entry per wallet.
//!
//! Only non-secret metadata (label, chain, public address, timestamps) is in
//! plaintext. Private keys exist only inside each entry's [`Sealed`] blob, each
//! encrypted with its own password, salt and nonce.
//!
//! The slow, CPU-heavy operations ([`WalletEntry::create`],
//! [`WalletEntry::unseal`], [`WalletEntry::reseal`]) are pure functions on
//! cloneable data so a UI can run them on a background thread and then apply
//! the result to the [`Vault`] (fast) on the main thread.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::chain::{derive_address, Chain, KeyError};
use crate::crypto::{self, CryptoError, KdfParams, Sealed, Wrapped};
use crate::master::{Keyring, MasterKey};

pub const FILE_FORMAT: &str = "keyvault";
/// v1: per-wallet passwords only. v2: adds the vault key (keyring).
pub const FILE_VERSION: u32 = 2;
pub const MIN_PASSWORD_LEN: usize = 8;
pub const MAX_LABEL_LEN: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Wrong password.")]
    WrongPassword,
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("{0}")]
    WeakPassword(String),
    #[error("{0}")]
    InvalidInput(String),
    #[error("a wallet with address {0} is already in the vault")]
    Duplicate(String),
    #[error("Wallet not found.")]
    NotFound,
    #[error("Unlock the vault first.")]
    Locked,
    #[error("vault file is corrupt or from a newer version: {0}")]
    Format(String),
    #[error("encryption error: {0}")]
    Crypto(String),
    #[error("file error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Decrypt => VaultError::WrongPassword,
            other => VaultError::Crypto(other.to_string()),
        }
    }
}

impl From<KeyError> for VaultError {
    fn from(e: KeyError) -> Self {
        let KeyError::Invalid(msg) = e;
        VaultError::InvalidKey(msg)
    }
}

pub type Result<T, E = VaultError> = std::result::Result<T, E>;

/// Basic password policy. Returns a human-readable reason on failure.
pub fn check_new_password(password: &str, confirm: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(VaultError::WeakPassword(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    if password.trim().is_empty() {
        return Err(VaultError::WeakPassword("password can't be only whitespace".into()));
    }
    if password != confirm {
        return Err(VaultError::WeakPassword("passwords don't match".into()));
    }
    Ok(())
}

/// Request to add a wallet. Secret and password are wiped on drop.
pub struct NewWallet {
    pub label: String,
    pub folder: Option<String>,
    pub tags: Vec<String>,
    pub note: String,
    pub chain: Chain,
    pub secret: Zeroizing<String>,
    /// Only used for [`Chain::Other`]; for other chains the address is derived.
    pub address: Option<String>,
    /// `Some` = extra lock: protected by this password instead of the vault key.
    pub password: Option<Zeroizing<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletEntry {
    pub id: Uuid,
    pub label: String,
    pub chain: Chain,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Organisation metadata. Not secret and not authenticated, so it can be
    /// edited without a password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub favorite: bool,
    /// Plain-text note (NOT encrypted — don't put secrets here).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// Protected by its own password (v1 wallets, or "extra lock").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<Sealed>,
    /// Protected by the vault key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_sealed: Option<Wrapped>,
}

/// Editable, non-secret metadata of a wallet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalletMeta {
    pub label: String,
    pub folder: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub note: String,
}

pub const MAX_TAGS: usize = 16;
pub const MAX_TAG_LEN: usize = 24;
pub const MAX_NOTE_LEN: usize = 2000;

/// Parse "defi, Main  ,bsc,defi" → ["defi", "main", "bsc"] (lowercase, unique,
/// order preserved). Accepts commas, spaces or '#' as separators.
pub fn parse_tags(input: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in input.split(|c: char| c == ',' || c == '#' || c.is_whitespace()) {
        let tag: String = raw
            .trim()
            .to_lowercase()
            .chars()
            .filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
            .take(MAX_TAG_LEN)
            .collect();
        if !tag.is_empty() && !out.contains(&tag) && out.len() < MAX_TAGS {
            out.push(tag);
        }
    }
    out
}

fn normalize_folder(folder: Option<&str>) -> Result<Option<String>> {
    let Some(f) = folder.map(str::trim).filter(|f| !f.is_empty()) else { return Ok(None) };
    if f.chars().count() > MAX_LABEL_LEN {
        return Err(VaultError::InvalidInput(format!("folder name is longer than {MAX_LABEL_LEN} characters")));
    }
    Ok(Some(f.to_string()))
}

impl WalletMeta {
    fn normalized(self) -> Result<Self> {
        if self.note.chars().count() > MAX_NOTE_LEN {
            return Err(VaultError::InvalidInput(format!("note is longer than {MAX_NOTE_LEN} characters")));
        }
        Ok(WalletMeta {
            label: normalize_label(&self.label)?,
            folder: normalize_folder(self.folder.as_deref())?,
            tags: parse_tags(&self.tags.join(",")),
            favorite: self.favorite,
            note: self.note.trim().to_string(),
        })
    }
}

impl WalletEntry {
    /// Validate, derive the address and encrypt — under the vault key
    /// (instant), or under the wallet's own password if one is given (slow,
    /// Argon2).
    pub fn create(new: NewWallet, mk: Option<&MasterKey>) -> Result<Self> {
        Self::create_with_params(new, mk, KdfParams::DEFAULT)
    }

    pub fn create_with_params(new: NewWallet, mk: Option<&MasterKey>, params: KdfParams) -> Result<Self> {
        let meta = WalletMeta {
            label: new.label.clone(),
            folder: new.folder.clone(),
            tags: new.tags.clone(),
            favorite: false,
            note: new.note.clone(),
        }
        .normalized()?;
        if let Some(pw) = &new.password {
            if pw.chars().count() < MIN_PASSWORD_LEN {
                return Err(VaultError::WeakPassword(format!(
                    "password must be at least {MIN_PASSWORD_LEN} characters"
                )));
            }
        }
        let secret = Zeroizing::new(new.secret.trim().to_string());
        let address = match derive_address(new.chain, &secret)? {
            Some(derived) => Some(derived),
            None => new.address.map(|a| a.trim().to_string()).filter(|a| !a.is_empty()),
        };

        let id = Uuid::new_v4();
        let (sealed, vault_sealed) = match &new.password {
            Some(pw) => (Some(crypto::seal(secret.as_bytes(), pw, &aad(id, new.chain, address.as_deref()), params)?), None),
            None => {
                let mk = mk.ok_or(VaultError::Locked)?;
                (None, Some(crypto::seal_with_key(secret.as_bytes(), mk.bytes(), &vault_aad(id, new.chain, address.as_deref()))?))
            }
        };
        let now = OffsetDateTime::now_utc();
        Ok(WalletEntry {
            id,
            label: meta.label,
            chain: new.chain,
            address,
            folder: meta.folder,
            tags: meta.tags,
            favorite: false,
            note: meta.note,
            created_at: now,
            updated_at: now,
            sealed,
            vault_sealed,
        })
    }

    /// True if this wallet has its own password (extra lock or a v1 wallet).
    pub fn needs_password(&self) -> bool {
        self.sealed.is_some()
    }

    pub fn meta(&self) -> WalletMeta {
        WalletMeta {
            label: self.label.clone(),
            folder: self.folder.clone(),
            tags: self.tags.clone(),
            favorite: self.favorite,
            note: self.note.clone(),
        }
    }

    /// Case-insensitive match against name, address, chain, folder, tags, note.
    pub fn matches(&self, query: &str) -> bool {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return true;
        }
        q.split_whitespace().all(|term| {
            let term = term.trim_start_matches('#');
            self.label.to_lowercase().contains(term)
                || self.address.as_deref().is_some_and(|a| a.to_lowercase().contains(term))
                || self.chain.label().to_lowercase().contains(term)
                || self.folder.as_deref().is_some_and(|f| f.to_lowercase().contains(term))
                || self.tags.iter().any(|t| t.contains(term))
                || self.note.to_lowercase().contains(term)
        })
    }

    /// Decrypt a password-protected wallet. Slow (runs Argon2).
    pub fn unseal(&self, password: &str) -> Result<Zeroizing<String>> {
        let sealed = self
            .sealed
            .as_ref()
            .ok_or_else(|| VaultError::InvalidInput("this wallet is unlocked by the vault, not a password".into()))?;
        let plain = crypto::open(sealed, password, &aad(self.id, self.chain, self.address.as_deref()))?;
        to_secret(&plain)
    }

    /// Decrypt a vault-protected wallet. Instant.
    pub fn unseal_vault(&self, mk: &MasterKey) -> Result<Zeroizing<String>> {
        let wrapped = self
            .vault_sealed
            .as_ref()
            .ok_or_else(|| VaultError::InvalidInput("this wallet has its own password".into()))?;
        let plain = crypto::open_with_key(wrapped, mk.bytes(), &vault_aad(self.id, self.chain, self.address.as_deref()))
            .map_err(|_| VaultError::Format("couldn't decrypt with the vault key (file modified?)".into()))?;
        to_secret(&plain)
    }

    /// Return a copy re-encrypted under `new_password` (fresh salt + nonce).
    pub fn reseal(&self, old_password: &str, new_password: &str) -> Result<Self> {
        self.reseal_with_params(old_password, new_password, KdfParams::DEFAULT)
    }

    pub fn reseal_with_params(&self, old_password: &str, new_password: &str, params: KdfParams) -> Result<Self> {
        let secret = self.unseal(old_password)?;
        let sealed = crypto::seal(
            secret.as_bytes(),
            new_password,
            &aad(self.id, self.chain, self.address.as_deref()),
            params,
        )?;
        Ok(WalletEntry { sealed: Some(sealed), vault_sealed: None, updated_at: OffsetDateTime::now_utc(), ..self.clone() })
    }

    /// Password wallet → vault-key wallet (drops its own password). Slow once.
    pub fn to_vault(&self, password: &str, mk: &MasterKey) -> Result<Self> {
        let secret = self.unseal(password)?;
        let wrapped = crypto::seal_with_key(secret.as_bytes(), mk.bytes(), &vault_aad(self.id, self.chain, self.address.as_deref()))?;
        Ok(WalletEntry { sealed: None, vault_sealed: Some(wrapped), updated_at: OffsetDateTime::now_utc(), ..self.clone() })
    }

    /// Vault-key wallet → protected by its own password ("extra lock"). Slow.
    pub fn with_extra_lock(&self, mk: &MasterKey, password: &str) -> Result<Self> {
        self.with_extra_lock_params(mk, password, KdfParams::DEFAULT)
    }

    pub fn with_extra_lock_params(&self, mk: &MasterKey, password: &str, params: KdfParams) -> Result<Self> {
        let secret = self.unseal_vault(mk)?;
        let sealed = crypto::seal(secret.as_bytes(), password, &aad(self.id, self.chain, self.address.as_deref()), params)?;
        Ok(WalletEntry { sealed: Some(sealed), vault_sealed: None, updated_at: OffsetDateTime::now_utc(), ..self.clone() })
    }

    pub fn short_address(&self) -> String {
        match &self.address {
            Some(a) if a.chars().count() > 14 => {
                let head: String = a.chars().take(6).collect();
                let tail: String = a.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
                format!("{head}…{tail}")
            }
            Some(a) => a.clone(),
            None => "—".into(),
        }
    }
}

/// Associated data authenticated with the ciphertext. Binding the address
/// means nobody can edit the plaintext address in the file to point at
/// their own wallet without unlocking failing.
fn aad(id: Uuid, chain: Chain, address: Option<&str>) -> Vec<u8> {
    // Fixed "v1": changing it would make every existing wallet undecryptable.
    format!("keyvault/v1|{id}|{}|{}", chain.as_str(), address.unwrap_or("")).into_bytes()
}

fn vault_aad(id: Uuid, chain: Chain, address: Option<&str>) -> Vec<u8> {
    format!("keyvault/vault-wallet|{id}|{}|{}", chain.as_str(), address.unwrap_or("")).into_bytes()
}

fn to_secret(plain: &[u8]) -> Result<Zeroizing<String>> {
    let text = std::str::from_utf8(plain).map_err(|_| VaultError::Format("secret is not UTF-8".into()))?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn normalize_label(label: &str) -> Result<String> {
    let label = label.trim();
    if label.is_empty() {
        return Err(VaultError::InvalidInput("give the wallet a name".into()));
    }
    if label.chars().count() > MAX_LABEL_LEN {
        return Err(VaultError::InvalidInput(format!("name is longer than {MAX_LABEL_LEN} characters")));
    }
    Ok(label.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultFile {
    format: String,
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keyring: Option<Keyring>,
    wallets: Vec<WalletEntry>,
}

/// The vault file plus its in-memory state. Every mutation is persisted
/// immediately with an atomic write.
#[derive(Debug)]
pub struct Vault {
    path: PathBuf,
    keyring: Option<Keyring>,
    wallets: Vec<WalletEntry>,
}

impl Vault {
    /// `~/.local/share/keyvault/vault.json` on Linux,
    /// `~/Library/Application Support/keyvault/vault.json` on macOS,
    /// `%APPDATA%\keyvault\vault.json` on Windows.
    pub fn default_path() -> PathBuf {
        dirs::data_dir().unwrap_or_else(|| PathBuf::from(".")).join("keyvault").join("vault.json")
    }

    /// Open the vault at `path`, or start an empty one if it doesn't exist yet.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if !path.exists() {
            return Ok(Vault { path, keyring: None, wallets: Vec::new() });
        }
        let bytes = fs::read(&path)?;
        let file: VaultFile = serde_json::from_slice(&bytes).map_err(|e| VaultError::Format(e.to_string()))?;
        if file.format != FILE_FORMAT {
            return Err(VaultError::Format(format!("not a keyvault file (format '{}')", file.format)));
        }
        if file.version > FILE_VERSION {
            return Err(VaultError::Format(format!(
                "file version {} is newer than this app supports ({FILE_VERSION})",
                file.version
            )));
        }
        Ok(Vault { path, keyring: file.keyring, wallets: file.wallets })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The vault-key slots, once set up.
    pub fn keyring(&self) -> Option<&Keyring> {
        self.keyring.as_ref()
    }

    /// Install or update the keyring (setup, passphrase change, Touch ID on/off).
    pub fn set_keyring(&mut self, keyring: Keyring) -> Result<()> {
        if let Some(existing) = &self.keyring {
            if existing.vault_id != keyring.vault_id {
                return Err(VaultError::InvalidInput("that keyring belongs to a different vault".into()));
            }
        }
        let old = self.keyring.replace(keyring);
        self.persist_or_rollback(move |v| v.keyring = old)
    }

    /// Replace several entries with one write (bulk migration). All-or-nothing.
    pub fn replace_many(&mut self, entries: Vec<WalletEntry>) -> Result<usize> {
        let before = self.wallets.clone();
        let mut n = 0;
        for e in entries {
            let idx = self.index_of(e.id)?;
            self.wallets[idx] = e;
            n += 1;
        }
        self.persist_or_rollback(move |v| v.wallets = before)?;
        Ok(n)
    }

    pub fn wallets(&self) -> &[WalletEntry] {
        &self.wallets
    }

    pub fn get(&self, id: Uuid) -> Option<&WalletEntry> {
        self.wallets.iter().find(|w| w.id == id)
    }

    /// Add an entry produced by [`WalletEntry::create`].
    pub fn insert(&mut self, entry: WalletEntry) -> Result<()> {
        if let Some(addr) = &entry.address {
            if self.wallets.iter().any(|w| w.chain == entry.chain && w.address.as_ref() == Some(addr)) {
                return Err(VaultError::Duplicate(addr.clone()));
            }
        }
        self.wallets.push(entry);
        self.persist_or_rollback(|v| {
            v.wallets.pop();
        })
    }

    /// Add many entries with a single write (bulk generation). All-or-nothing.
    pub fn insert_many(&mut self, entries: Vec<WalletEntry>) -> Result<usize> {
        let before = self.wallets.len();
        for e in &entries {
            if let Some(addr) = &e.address {
                let dup = self.wallets.iter().chain(entries.iter().filter(|o| o.id != e.id)).any(|w| {
                    w.id != e.id && w.chain == e.chain && w.address.as_ref() == Some(addr)
                });
                if dup {
                    return Err(VaultError::Duplicate(addr.clone()));
                }
            }
        }
        let n = entries.len();
        self.wallets.extend(entries);
        self.persist_or_rollback(move |v| v.wallets.truncate(before))?;
        Ok(n)
    }

    /// Replace an entry (e.g. after [`WalletEntry::reseal`]).
    pub fn replace(&mut self, entry: WalletEntry) -> Result<()> {
        let idx = self.index_of(entry.id)?;
        let old = std::mem::replace(&mut self.wallets[idx], entry);
        self.persist_or_rollback(move |v| v.wallets[idx] = old)
    }

    /// Renaming doesn't need a password: the label isn't part of the
    /// authenticated data.
    pub fn rename(&mut self, id: Uuid, label: &str) -> Result<()> {
        let mut meta = self.get(id).ok_or(VaultError::NotFound)?.meta();
        meta.label = label.to_string();
        self.update_meta(id, meta)
    }

    /// Update name, folder, tags, favorite flag and note. No password needed.
    pub fn update_meta(&mut self, id: Uuid, meta: WalletMeta) -> Result<()> {
        let meta = meta.normalized()?;
        let idx = self.index_of(id)?;
        let old = self.wallets[idx].clone();
        let w = &mut self.wallets[idx];
        w.label = meta.label;
        w.folder = meta.folder;
        w.tags = meta.tags;
        w.favorite = meta.favorite;
        w.note = meta.note;
        w.updated_at = OffsetDateTime::now_utc();
        self.persist_or_rollback(move |v| v.wallets[idx] = old)
    }

    pub fn set_favorite(&mut self, id: Uuid, favorite: bool) -> Result<()> {
        let mut meta = self.get(id).ok_or(VaultError::NotFound)?.meta();
        meta.favorite = favorite;
        self.update_meta(id, meta)
    }

    /// Folder names with wallet counts, sorted case-insensitively.
    pub fn folders(&self) -> Vec<(String, usize)> {
        let mut map: std::collections::BTreeMap<String, (String, usize)> = Default::default();
        for f in self.wallets.iter().filter_map(|w| w.folder.as_ref()) {
            map.entry(f.to_lowercase()).or_insert_with(|| (f.clone(), 0)).1 += 1;
        }
        map.into_values().collect()
    }

    /// Tags with wallet counts, most used first.
    pub fn tags(&self) -> Vec<(String, usize)> {
        let mut map: std::collections::BTreeMap<&str, usize> = Default::default();
        for t in self.wallets.iter().flat_map(|w| w.tags.iter()) {
            *map.entry(t.as_str()).or_default() += 1;
        }
        let mut v: Vec<(String, usize)> = map.into_iter().map(|(k, n)| (k.to_string(), n)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }

    /// Rename (or with `None`, dissolve) a folder for every wallet in it.
    pub fn rename_folder(&mut self, from: &str, to: Option<&str>) -> Result<usize> {
        let to = normalize_folder(to)?;
        let before = self.wallets.clone();
        let mut n = 0;
        for w in self.wallets.iter_mut() {
            if w.folder.as_deref().is_some_and(|f| f.eq_ignore_ascii_case(from)) {
                w.folder = to.clone();
                w.updated_at = OffsetDateTime::now_utc();
                n += 1;
            }
        }
        if n == 0 {
            return Ok(0);
        }
        self.persist_or_rollback(move |v| v.wallets = before)?;
        Ok(n)
    }

    /// Remove an entry. Callers should verify the password with
    /// [`WalletEntry::unseal`] first — deletion is irreversible.
    pub fn remove(&mut self, id: Uuid) -> Result<WalletEntry> {
        let idx = self.index_of(id)?;
        let removed = self.wallets.remove(idx);
        let restore = removed.clone();
        self.persist_or_rollback(move |v| v.wallets.insert(idx, restore))?;
        Ok(removed)
    }

    /// Re-read the file from disk (e.g. after another instance changed it).
    pub fn reload(&mut self) -> Result<()> {
        *self = Vault::open(self.path.clone())?;
        Ok(())
    }

    /// Copy the encrypted vault to `dest` (backups). Keys stay encrypted.
    pub fn export_to(&self, dest: &Path) -> Result<()> {
        write_atomic(dest, &self.serialize()?)
    }

    fn index_of(&self, id: Uuid) -> Result<usize> {
        self.wallets.iter().position(|w| w.id == id).ok_or(VaultError::NotFound)
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let file = VaultFile {
            format: FILE_FORMAT.into(),
            version: FILE_VERSION,
            keyring: self.keyring.clone(),
            wallets: self.wallets.clone(),
        };
        serde_json::to_vec_pretty(&file).map_err(|e| VaultError::Format(e.to_string()))
    }

    fn persist_or_rollback(&mut self, rollback: impl FnOnce(&mut Self)) -> Result<()> {
        let result = self.serialize().and_then(|bytes| {
            if self.path.exists() {
                // Keep the previous version around as a one-step undo.
                let _ = fs::copy(&self.path, self.path.with_extension("json.bak"));
            }
            write_atomic(&self.path, &bytes)
        });
        if result.is_err() {
            rollback(self);
        }
        result
    }
}

/// Write via temp file + fsync + rename so a crash never leaves a half-written
/// vault. Files are created owner-only (0600) on Unix.
/// Atomic, owner-only (0600 on Unix) file write — used for exports too.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    create_private_dir(dir)?;

    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("vault"),
        Uuid::new_v4().simple()
    ));
    let write = || -> Result<()> {
        let mut f = private_file(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        #[cfg(unix)]
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    };
    let res = write();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

fn private_file(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    if dir.exists() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVM_KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

    fn new_wallet(label: &str, chain: Chain, secret: &str, pw: &str) -> NewWallet {
        NewWallet {
            label: label.into(),
            folder: None,
            tags: vec![],
            note: String::new(),
            chain,
            secret: Zeroizing::new(secret.into()),
            address: None,
            password: Some(Zeroizing::new(pw.into())),
        }
    }

    fn entry(label: &str, secret: &str, pw: &str) -> WalletEntry {
        WalletEntry::create_with_params(new_wallet(label, Chain::Evm, secret, pw), None, KdfParams::TEST).unwrap()
    }

    #[test]
    fn add_persist_reopen_unseal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/vault.json");

        let mut vault = Vault::open(&path).unwrap();
        vault.insert(entry("Main", EVM_KEY, "password-one")).unwrap();
        vault.insert(entry("Burner", &format!("{:064x}", 1), "password-two")).unwrap();

        let reopened = Vault::open(&path).unwrap();
        assert_eq!(reopened.wallets().len(), 2);
        let main = &reopened.wallets()[0];
        assert_eq!(main.address.as_deref(), Some("0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"));
        assert_eq!(main.unseal("password-one").unwrap().as_str(), EVM_KEY);
        assert!(matches!(main.unseal("password-two"), Err(VaultError::WrongPassword)));

        // The key never appears in plaintext on disk.
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"));
    }

    #[cfg(unix)]
    #[test]
    fn file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let mut vault = Vault::open(&path).unwrap();
        vault.insert(entry("A", EVM_KEY, "password-one")).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn duplicates_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(dir.path().join("v.json")).unwrap();
        vault.insert(entry("A", EVM_KEY, "password-one")).unwrap();
        assert!(matches!(vault.insert(entry("B", EVM_KEY, "password-xyz")), Err(VaultError::Duplicate(_))));
        assert_eq!(vault.wallets().len(), 1);
    }

    #[test]
    fn change_password() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(dir.path().join("v.json")).unwrap();
        let e = entry("A", EVM_KEY, "old-password");
        let id = e.id;
        vault.insert(e).unwrap();

        let resealed = vault
            .get(id)
            .unwrap()
            .reseal_with_params("old-password", "new-password", KdfParams::TEST)
            .unwrap();
        vault.replace(resealed).unwrap();

        let w = Vault::open(vault.path()).unwrap().get(id).unwrap().clone();
        assert!(matches!(w.unseal("old-password"), Err(VaultError::WrongPassword)));
        assert_eq!(w.unseal("new-password").unwrap().as_str(), EVM_KEY);
    }

    #[test]
    fn tampered_address_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.json");
        let mut vault = Vault::open(&path).unwrap();
        vault.insert(entry("A", EVM_KEY, "password-one")).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        let evil = raw.replace("0x2c7536E3605D9C16a7a3D7b1898e529396a65c23", "0x000000000000000000000000000000000000dEaD");
        fs::write(&path, evil).unwrap();

        let w = Vault::open(&path).unwrap().wallets()[0].clone();
        assert!(matches!(w.unseal("password-one"), Err(VaultError::WrongPassword)));
    }

    #[test]
    fn rename_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.json");
        let mut vault = Vault::open(&path).unwrap();
        let e = entry("A", EVM_KEY, "password-one");
        let id = e.id;
        vault.insert(e).unwrap();

        vault.rename(id, "  Treasury  ").unwrap();
        assert_eq!(Vault::open(&path).unwrap().get(id).unwrap().label, "Treasury");
        // Renaming doesn't break decryption.
        assert!(Vault::open(&path).unwrap().get(id).unwrap().unseal("password-one").is_ok());

        vault.remove(id).unwrap();
        assert!(Vault::open(&path).unwrap().wallets().is_empty());
        assert!(path.with_extension("json.bak").exists());
    }

    #[test]
    fn other_chain_keeps_user_address_and_secret() {
        let mut n = new_wallet("Seed", Chain::Other, "  abandon ability able about  ", "password-one");
        n.address = Some(" bc1qexample ".into());
        let e = WalletEntry::create_with_params(n, None, KdfParams::TEST).unwrap();
        assert_eq!(e.address.as_deref(), Some("bc1qexample"));
        assert_eq!(e.unseal("password-one").unwrap().as_str(), "abandon ability able about");
    }

    #[test]
    fn validation() {
        assert!(check_new_password("short", "short").is_err());
        assert!(check_new_password("long-enough", "long-enougX").is_err());
        assert!(check_new_password("long-enough", "long-enough").is_ok());
        assert!(WalletEntry::create_with_params(new_wallet("", Chain::Evm, EVM_KEY, "password-one"), None, KdfParams::TEST).is_err());
        assert!(matches!(
            WalletEntry::create_with_params(new_wallet("A", Chain::Evm, "nope", "password-one"), None, KdfParams::TEST),
            Err(VaultError::InvalidKey(_))
        ));
    }

    #[test]
    fn rejects_foreign_and_future_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.json");
        fs::write(&p, r#"{"format":"keyvault","version":99,"wallets":[]}"#).unwrap();
        assert!(matches!(Vault::open(&p), Err(VaultError::Format(_))));
        fs::write(&p, "not json").unwrap();
        assert!(matches!(Vault::open(&p), Err(VaultError::Format(_))));
    }

    #[test]
    fn insert_many_is_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.json");
        let mut vault = Vault::open(&path).unwrap();
        let batch: Vec<WalletEntry> = (2..5).map(|k| entry(&format!("W{k}"), &format!("{k:064x}"), "password-one")).collect();
        assert_eq!(vault.insert_many(batch).unwrap(), 3);
        assert_eq!(Vault::open(&path).unwrap().wallets().len(), 3);
        // A batch containing a duplicate is rejected entirely.
        let dup = vec![entry("X", &format!("{:064x}", 9), "password-one"), entry("Y", &format!("{:064x}", 2), "password-one")];
        assert!(matches!(vault.insert_many(dup), Err(VaultError::Duplicate(_))));
        assert_eq!(Vault::open(&path).unwrap().wallets().len(), 3);
    }

    #[test]
    fn vault_key_wallets() {
        use crate::master::Keyring;
        let fast = KdfParams::TEST;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.json");
        let mut vault = Vault::open(&path).unwrap();
        let (kr, mk, code) = Keyring::create_with_params("my vault passphrase", fast, fast).unwrap();
        vault.set_keyring(kr).unwrap();

        // Vault wallet: no password, instant.
        let mut n = new_wallet("Hot", Chain::Evm, EVM_KEY, "unused");
        n.password = None;
        let hot = WalletEntry::create(n, Some(&mk)).unwrap();
        assert!(!hot.needs_password() && hot.sealed.is_none());
        let hot_id = hot.id;
        vault.insert(hot).unwrap();
        // Can't create a vault wallet while locked.
        let mut n = new_wallet("X", Chain::Evm, &format!("{:064x}", 7), "unused");
        n.password = None;
        assert!(matches!(WalletEntry::create(n, None), Err(VaultError::Locked)));

        // Legacy password wallet → migrate.
        let legacy = entry("Legacy", &format!("{:064x}", 1), "old-password");
        let legacy_id = legacy.id;
        vault.insert(legacy).unwrap();

        // Reopen from disk, unlock via recovery code.
        let re = Vault::open(&path).unwrap();
        let mk2 = re.keyring().unwrap().open_recovery(&code).unwrap();
        assert_eq!(re.get(hot_id).unwrap().unseal_vault(&mk2).unwrap().as_str(), EVM_KEY);
        assert!(re.get(hot_id).unwrap().unseal("anything").is_err());
        assert!(re.get(legacy_id).unwrap().unseal_vault(&mk2).is_err());

        let migrated = re.get(legacy_id).unwrap().to_vault("old-password", &mk2).unwrap();
        assert!(re.get(legacy_id).unwrap().to_vault("wrong-password", &mk2).is_err());
        vault.replace_many(vec![migrated]).unwrap();
        let re = Vault::open(&path).unwrap();
        let w = re.get(legacy_id).unwrap();
        assert!(!w.needs_password());
        assert_eq!(w.unseal_vault(&mk2).unwrap().as_str(), format!("{:064x}", 1));

        // Extra lock: vault → own password.
        let locked = re.get(hot_id).unwrap().with_extra_lock_params(&mk2, "extra-secret", fast).unwrap();
        assert!(locked.needs_password() && locked.vault_sealed.is_none());
        assert_eq!(locked.unseal("extra-secret").unwrap().as_str(), EVM_KEY);
        assert!(locked.unseal_vault(&mk2).is_err());

        // A different vault's key can't open these wallets.
        let (_, other_mk, _) = Keyring::create_with_params("another vault", fast, fast).unwrap();
        assert!(re.get(legacy_id).unwrap().unseal_vault(&other_mk).is_err());

        // Tampering with the address breaks vault-key decryption too.
        let mut evil = re.get(hot_id).unwrap().clone();
        evil.address = Some("0x000000000000000000000000000000000000dEaD".into());
        assert!(evil.unseal_vault(&mk2).is_err());
    }

    #[test]
    fn reads_v1_files_written_by_the_previous_version() {
        // Exact shape the first release wrote (aad string "keyvault/v1|…").
        let e = entry("Old", EVM_KEY, "password-one");
        let mut json = serde_json::to_value(&e).unwrap();
        json.as_object_mut().unwrap().remove("vault_sealed");
        let file = serde_json::json!({"format": "keyvault", "version": 1, "wallets": [json]});
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.json");
        fs::write(&p, file.to_string()).unwrap();
        let mut v = Vault::open(&p).unwrap();
        assert!(v.keyring().is_none());
        assert_eq!(v.wallets()[0].unseal("password-one").unwrap().as_str(), EVM_KEY);
        // Saving upgrades the file to v2 and keeps the wallet readable.
        let id = v.wallets()[0].id;
        v.rename(id, "Renamed").unwrap();
        let raw = fs::read_to_string(&p).unwrap();
        assert!(raw.contains("\"version\": 2"));
        assert_eq!(Vault::open(&p).unwrap().wallets()[0].unseal("password-one").unwrap().as_str(), EVM_KEY);
    }

    #[test]
    fn tag_parsing() {
        assert_eq!(parse_tags("DeFi, main  ,#bsc defi,,"), vec!["defi", "main", "bsc"]);
        assert_eq!(parse_tags("we!rd*chars ok"), vec!["werdchars", "ok"]);
        assert!(parse_tags(" , ").is_empty());
    }

    #[test]
    fn folders_tags_favorites_and_meta() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.json");
        let mut vault = Vault::open(&path).unwrap();
        let mut n = new_wallet("A", Chain::Evm, EVM_KEY, "password-one");
        n.folder = Some(" Trading ".into());
        n.tags = vec!["BSC".into(), "hot".into()];
        let a = WalletEntry::create_with_params(n, None, KdfParams::TEST).unwrap();
        let a_id = a.id;
        vault.insert(a).unwrap();
        let mut n = new_wallet("B", Chain::Evm, &format!("{:064x}", 1), "password-two");
        n.folder = Some("trading".into());
        n.tags = vec!["bsc".into()];
        vault.insert(WalletEntry::create_with_params(n, None, KdfParams::TEST).unwrap()).unwrap();

        assert_eq!(vault.folders(), vec![("Trading".to_string(), 2)]);
        assert_eq!(vault.tags(), vec![("bsc".to_string(), 2), ("hot".to_string(), 1)]);

        vault.set_favorite(a_id, true).unwrap();
        let mut meta = vault.get(a_id).unwrap().meta();
        meta.note = "deployer for CLAW".into();
        meta.tags = vec!["cold".into()];
        vault.update_meta(a_id, meta).unwrap();

        let re = Vault::open(&path).unwrap();
        let a = re.get(a_id).unwrap();
        assert!(a.favorite);
        assert_eq!(a.tags, vec!["cold"]);
        assert!(a.matches("claw"));
        assert!(a.matches("#cold trading"));
        assert!(!a.matches("cold nope"));
        // Metadata edits never break decryption.
        assert!(a.unseal("password-one").is_ok());

        assert_eq!(vault.rename_folder("TRADING", Some("Bots")).unwrap(), 2);
        assert_eq!(vault.folders(), vec![("Bots".to_string(), 2)]);
        vault.rename_folder("bots", None).unwrap();
        assert!(vault.folders().is_empty());
    }

    #[test]
    fn reads_files_without_new_fields() {
        // A v1 file written before folders/tags existed still loads.
        let e = entry("Old", EVM_KEY, "password-one");
        let mut json = serde_json::to_value(&e).unwrap();
        let obj = json.as_object_mut().unwrap();
        for k in ["folder", "tags", "favorite", "note"] {
            obj.remove(k);
        }
        let file = serde_json::json!({"format": "keyvault", "version": 1, "wallets": [json]});
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.json");
        fs::write(&p, file.to_string()).unwrap();
        let v = Vault::open(&p).unwrap();
        assert!(v.wallets()[0].tags.is_empty() && !v.wallets()[0].favorite);
    }

    #[test]
    fn default_params_unlock_in_reasonable_time() {
        let e = WalletEntry::create(new_wallet("A", Chain::Evm, EVM_KEY, "password-one"), None).unwrap();
        let t = std::time::Instant::now();
        e.unseal("password-one").unwrap();
        eprintln!("argon2id default unlock: {:?}", t.elapsed());
    }
}
