//! The KeyVault window: navigation · wallet list · details.
//!
//! Every password-based operation (encrypt, decrypt, re-encrypt) runs Argon2id
//! on a background thread so the UI never freezes; results are applied back on
//! the UI thread.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gpui_kit::component::button::*;
use gpui_kit::component::input::{InputEvent, InputState};
use gpui_kit::component::notification::Notification;
use gpui_kit::component::*;
use gpui_kit::prelude::*;
use gpui_kit::*;
use vault_core::{
    check_new_password, derive_address, generate_secret, parse_tags, Chain, NewWallet, Uuid, Vault,
    VaultError, WalletEntry, WalletMeta, Zeroizing,
};
use wallet_tx::{network, AmountSpec, Asset, Family, Network, Quote, Sent};

mod export;
mod security;

use export::ExportState;
use security::SetupStep;
use vault_core::MasterKey;

use crate::ui::{
    self, chain_badge, chain_dot, enter, section_label, segmented, shimmer, tag_chip, Lucide,
    Palette, Segment,
};

/// How long a revealed key stays on screen.
const REVEAL_SECS: u64 = 30;
/// How long a copied key stays in the clipboard.
const CLIPBOARD_CLEAR_SECS: u64 = 30;
/// Rows that get a staggered entrance animation (the rest appear at once).
const STAGGER_ROWS: usize = 14;
/// Bulk generation limit per batch.
const MAX_GENERATE: usize = 500;
/// A reviewed transfer must be re-quoted after this long.
const QUOTE_TTL_SECS: u64 = 180;

gpui_kit::actions!(
    keyvault,
    [
        NewWalletAction,
        GenerateAction,
        FocusSearch,
        LockAll,
        ToggleTheme,
        Quit
    ]
);

#[derive(Clone, PartialEq, Eq)]
enum Filter {
    All,
    Favorites,
    Chain(Chain),
    Folder(String),
    Tag(String),
    Unfiled,
}

impl Filter {
    fn title(&self) -> SharedString {
        match self {
            Filter::All => "All wallets".into(),
            Filter::Favorites => "Favorites".into(),
            Filter::Chain(c) => format!("{} wallets", c.label()).into(),
            Filter::Folder(f) => f.clone().into(),
            Filter::Tag(t) => format!("#{t}").into(),
            Filter::Unfiled => "Not in a folder".into(),
        }
    }

    fn accepts(&self, w: &WalletEntry) -> bool {
        match self {
            Filter::All => true,
            Filter::Favorites => w.favorite,
            Filter::Chain(c) => w.chain == *c,
            Filter::Folder(f) => w
                .folder
                .as_deref()
                .is_some_and(|wf| wf.eq_ignore_ascii_case(f)),
            Filter::Tag(t) => w.tags.iter().any(|wt| wt == t),
            Filter::Unfiled => w.folder.is_none(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortBy {
    Recent,
    Name,
    Chain,
}

impl SortBy {
    fn next(self) -> Self {
        match self {
            SortBy::Recent => SortBy::Name,
            SortBy::Name => SortBy::Chain,
            SortBy::Chain => SortBy::Recent,
        }
    }
    fn label(self) -> &'static str {
        match self {
            SortBy::Recent => "Recent",
            SortBy::Name => "A–Z",
            SortBy::Chain => "Chain",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum Panel {
    Welcome,
    Details(Uuid),
    Add,
    Edit(Uuid),
    ChangePassword(Uuid),
    Delete(Uuid),
    RenameFolder(String),
    Generate,
    Send(Uuid),
    Settings,
    Export,
}

impl Panel {
    fn wallet(&self) -> Option<Uuid> {
        match self {
            Panel::Details(id)
            | Panel::Edit(id)
            | Panel::ChangePassword(id)
            | Panel::Delete(id)
            | Panel::Send(id) => Some(*id),
            _ => None,
        }
    }
}

/// Irreversible actions confirmed by pressing and holding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HoldKind {
    Send,
    Delete,
    Export,
}

const HOLD_MS: u64 = 900;

#[derive(Clone, Copy, PartialEq, Eq)]
enum AfterUnlock {
    Show,
    Copy,
}

struct Revealed {
    id: Uuid,
    secret: Zeroizing<String>,
    until: Instant,
    seq: usize,
}

struct Inputs {
    search: Entity<InputState>,
    add_label: Entity<InputState>,
    add_folder: Entity<InputState>,
    add_tags: Entity<InputState>,
    add_note: Entity<InputState>,
    add_secret: Entity<InputState>,
    add_address: Entity<InputState>,
    add_pw: Entity<InputState>,
    add_pw2: Entity<InputState>,
    unlock_pw: Entity<InputState>,
    cur_pw: Entity<InputState>,
    new_pw: Entity<InputState>,
    new_pw2: Entity<InputState>,
    edit_label: Entity<InputState>,
    edit_folder: Entity<InputState>,
    edit_tags: Entity<InputState>,
    edit_note: Entity<InputState>,
    delete_pw: Entity<InputState>,
    folder_name: Entity<InputState>,
    gen_count: Entity<InputState>,
    gen_prefix: Entity<InputState>,
    gen_folder: Entity<InputState>,
    gen_tags: Entity<InputState>,
    gen_pw: Entity<InputState>,
    gen_pw2: Entity<InputState>,
    send_rpc: Entity<InputState>,
    send_symbol: Entity<InputState>,
    send_token: Entity<InputState>,
    send_to: Entity<InputState>,
    send_amount: Entity<InputState>,
    send_pw: Entity<InputState>,
    lock_pw: Entity<InputState>,
    recovery_in: Entity<InputState>,
    setup_pw: Entity<InputState>,
    setup_pw2: Entity<InputState>,
    pass_cur: Entity<InputState>,
    pass_new: Entity<InputState>,
    pass_new2: Entity<InputState>,
    recovery_auth: Entity<InputState>,
    migrate_pw: Entity<InputState>,
    export_pw: Entity<InputState>,
}

/// State of the Send panel.
struct SendState {
    nets: Vec<Network>,
    /// Index into `nets`; `nets.len()` means "custom RPC".
    net: usize,
    token_mode: bool,
    max: bool,
    quote: Option<(Quote, Instant)>,
    sent: Option<Sent>,
}

impl SendState {
    fn empty() -> Self {
        SendState {
            nets: vec![],
            net: 0,
            token_mode: false,
            max: false,
            quote: None,
            sent: None,
        }
    }
    fn custom(&self) -> bool {
        self.net >= self.nets.len()
    }
}

pub struct KeyVaultApp {
    vault: Result<Vault, String>,
    path: PathBuf,
    panel: Panel,
    filter: Filter,
    sort: SortBy,
    busy: bool,
    error: Option<SharedString>,
    revealed: Option<Revealed>,
    copied_at: Option<Instant>,
    hold: Option<(HoldKind, Instant)>,
    hold_task: Option<Task<()>>,
    /// Segmented controls: (previous index, animation sequence).
    seg_anim: std::collections::HashMap<&'static str, (usize, usize)>,
    add_chain: Chain,
    edit_favorite: bool,
    gen_chain: Chain,
    gen_progress: Option<(Arc<AtomicUsize>, usize)>,
    send: SendState,
    /// Last network used per chain family, so Send remembers your choice.
    last_net: std::collections::HashMap<&'static str, usize>,
    /// Bumped on every navigation / filter change so entrance animations replay.
    nav_seq: usize,
    list_seq: usize,
    reveal_seq: usize,
    inputs: Inputs,
    focus: FocusHandle,
    ticker: Option<Task<()>>,
    clipboard_task: Option<Task<()>>,
    _subscriptions: Vec<Subscription>,
    // ── vault unlock ──
    /// The unlocked vault key; `None` while locked.
    master: Option<MasterKey>,
    setup: Option<SetupStep>,
    use_recovery: bool,
    must_reset_passphrase: bool,
    recovery_shown: Option<Zeroizing<String>>,
    last_activity: Instant,
    auto_lock_mins: u32,
    confirm_secrets: bool,
    _auto_lock: Option<Task<()>>,
    /// New wallets get their own password ("extra lock") when set.
    add_extra_lock: bool,
    gen_extra_lock: bool,
    /// Wallet security panel: 0 = use vault key, 1 = change password.
    sec_tab: usize,
    // ── export ──
    select_mode: bool,
    selected: std::collections::HashSet<Uuid>,
    export: ExportState,
}

pub fn bind_keys(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("secondary-n", NewWalletAction, None),
        KeyBinding::new("secondary-g", GenerateAction, None),
        KeyBinding::new("secondary-f", FocusSearch, None),
        KeyBinding::new("secondary-l", LockAll, None),
        KeyBinding::new("secondary-shift-t", ToggleTheme, None),
        KeyBinding::new("secondary-q", Quit, None),
    ]);
    cx.on_action(|_: &Quit, cx| {
        cx.quit();
        // On Linux the event loop only notices `quit` on the next input event;
        // make sure the process ends promptly. Nothing is pending: the vault is
        // saved on every change.
        #[cfg(target_os = "linux")]
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(300));
            std::process::exit(0);
        });
    });
    // macOS menu bar (ignored elsewhere).
    cx.set_menus([Menu::new("KeyVault").items([
        MenuItem::action("Lock Vault", LockAll),
        MenuItem::action("Toggle Light / Dark", ToggleTheme),
        MenuItem::separator(),
        MenuItem::action("Quit KeyVault", Quit),
    ])]);
    // Closing the window quits, so the decrypted vault key never lingers in a
    // background process (macOS would otherwise keep the app running).
    cx.on_window_closed(|cx, _| {
        if cx.windows().is_empty() {
            cx.quit();
        }
    })
    .detach();
}

fn text_input(placeholder: &str, window: &mut Window, cx: &mut App) -> Entity<InputState> {
    let placeholder = placeholder.to_string();
    cx.new(|cx| InputState::new(window, cx).placeholder(placeholder))
}

fn secret_input(placeholder: &str, window: &mut Window, cx: &mut App) -> Entity<InputState> {
    let placeholder = placeholder.to_string();
    cx.new(|cx| {
        InputState::new(window, cx)
            .placeholder(placeholder)
            .masked(true)
    })
}

/// Read an input into a buffer that is wiped on drop.
fn read_secret(input: &Entity<InputState>, cx: &App) -> Zeroizing<String> {
    Zeroizing::new(input.read(cx).value().to_string())
}

fn read(input: &Entity<InputState>, cx: &App) -> String {
    input.read(cx).value().trim().to_string()
}

fn set(
    input: &Entity<InputState>,
    value: impl Into<SharedString>,
    window: &mut Window,
    cx: &mut App,
) {
    let value: SharedString = value.into();
    input.update(cx, |state, cx| state.set_value(value, window, cx));
}

fn clear(input: &Entity<InputState>, window: &mut Window, cx: &mut App) {
    set(input, "", window, cx);
}

fn focus(input: &Entity<InputState>, window: &mut Window, cx: &mut App) {
    input.update(cx, |state, cx| state.focus(window, cx));
}

impl KeyVaultApp {
    pub fn new(path: PathBuf, window: &mut Window, cx: &mut Context<Self>) -> Self {
        // If the file exists but can't be read we show an error and never
        // write — overwriting a corrupt vault would destroy the user's keys.
        let vault = Vault::open(&path).map_err(|e| e.to_string());

        let inputs = Inputs {
            search: text_input("Search name, address, #tag…", window, cx),
            add_label: text_input("e.g. Main BSC deployer", window, cx),
            add_folder: text_input("e.g. Trading bots", window, cx),
            add_tags: text_input("e.g. bsc, hot, deployer", window, cx),
            add_note: text_input("Anything non-secret to remember", window, cx),
            add_secret: secret_input("Paste private key", window, cx),
            add_address: text_input("Optional public address", window, cx),
            add_pw: secret_input("Password for this wallet", window, cx),
            add_pw2: secret_input("Repeat password", window, cx),
            unlock_pw: secret_input("Wallet password", window, cx),
            cur_pw: secret_input("Current password", window, cx),
            new_pw: secret_input("New password", window, cx),
            new_pw2: secret_input("Repeat new password", window, cx),
            edit_label: text_input("Wallet name", window, cx),
            edit_folder: text_input("No folder", window, cx),
            edit_tags: text_input("Comma separated", window, cx),
            edit_note: text_input("Non-secret note", window, cx),
            delete_pw: secret_input("Wallet password", window, cx),
            folder_name: text_input("Folder name", window, cx),
            gen_count: text_input("10", window, cx),
            gen_prefix: text_input("Wallet", window, cx),
            gen_folder: text_input("e.g. Airdrops", window, cx),
            gen_tags: text_input("e.g. farm, fresh", window, cx),
            gen_pw: secret_input("Password for these wallets", window, cx),
            gen_pw2: secret_input("Repeat password", window, cx),
            send_rpc: text_input("https://…", window, cx),
            send_symbol: text_input("ETH", window, cx),
            send_token: text_input("Token address", window, cx),
            send_to: text_input("Recipient address", window, cx),
            send_amount: text_input("0.0", window, cx),
            send_pw: secret_input("Wallet password", window, cx),
            lock_pw: secret_input("Passphrase", window, cx),
            recovery_in: secret_input("XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX", window, cx),
            setup_pw: secret_input("Choose a passphrase", window, cx),
            setup_pw2: secret_input("Type it again", window, cx),
            pass_cur: secret_input("Current passphrase", window, cx),
            pass_new: secret_input("New passphrase", window, cx),
            pass_new2: secret_input("Repeat new passphrase", window, cx),
            recovery_auth: secret_input("Your passphrase", window, cx),
            migrate_pw: secret_input("A wallet password you used", window, cx),
            export_pw: secret_input("Password for extra-locked wallets (optional)", window, cx),
        };

        let mut subs = Vec::new();
        // Re-render while typing in fields that drive live UI.
        for input in [
            &inputs.search,
            &inputs.add_secret,
            &inputs.add_tags,
            &inputs.edit_tags,
            &inputs.gen_tags,
            &inputs.gen_count,
            &inputs.gen_prefix,
        ] {
            subs.push(
                cx.subscribe_in(input, window, |_, _, ev: &InputEvent, _, cx| {
                    if matches!(ev, InputEvent::Change) {
                        cx.notify();
                    }
                }),
            );
        }
        // Enter submits each form.
        let enter_actions: [(
            &Entity<InputState>,
            fn(&mut Self, &mut Window, &mut Context<Self>),
        ); 16] = [
            (&inputs.lock_pw, Self::unlock_passphrase),
            (&inputs.recovery_in, Self::unlock_recovery),
            (&inputs.setup_pw2, Self::setup_create),
            (&inputs.pass_new2, Self::change_master_passphrase),
            (&inputs.recovery_auth, Self::regenerate_recovery),
            (&inputs.migrate_pw, Self::migrate_wallets),
            (&inputs.gen_pw2, Self::bulk_generate),
            (&inputs.send_amount, Self::review_send),
            (&inputs.send_pw, Self::confirm_send),
            (&inputs.unlock_pw, |this, w, cx| {
                this.submit_unlock(AfterUnlock::Show, w, cx)
            }),
            (&inputs.add_pw2, Self::save_new_wallet),
            (&inputs.new_pw2, Self::change_password),
            (&inputs.edit_label, Self::save_edit),
            (&inputs.edit_note, Self::save_edit),
            (&inputs.delete_pw, Self::delete),
            (&inputs.folder_name, Self::save_folder_rename),
        ];
        for (input, action) in enter_actions {
            subs.push(cx.subscribe_in(
                input,
                window,
                move |this, _, ev: &InputEvent, window, cx| {
                    if matches!(ev, InputEvent::PressEnter { .. }) {
                        action(this, window, cx);
                    }
                },
            ));
        }
        // Hide any revealed key as soon as the window loses focus.
        subs.push(cx.observe_window_activation(window, |this, window, cx| {
            if !window.is_window_active() && this.revealed.is_some() {
                this.hide_secret(cx);
            }
        }));

        let panel = match &vault {
            Ok(v) => v
                .wallets()
                .first()
                .map(|w| Panel::Details(w.id))
                .unwrap_or(Panel::Welcome),
            Err(_) => Panel::Welcome,
        };

        let focus = cx.focus_handle();
        window.focus(&focus, cx);

        let has_keyring = vault.as_ref().is_ok_and(|v| v.keyring().is_some());
        let setup = (vault.is_ok() && !has_keyring).then_some(SetupStep::Passphrase);
        let auto_lock_mins = crate::theme::pref(&path, "auto_lock_mins")
            .and_then(|v| v.as_u64())
            .unwrap_or(15) as u32;
        let confirm_secrets = crate::theme::pref(&path, "confirm_secrets")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if setup.is_some() {
            crate::app::focus(&inputs.setup_pw, window, cx);
        } else if has_keyring {
            crate::app::focus(&inputs.lock_pw, window, cx);
        }
        cx.defer_in(window, move |this: &mut Self, window, cx| {
            this.start_auto_lock(window, cx);
            // Offer the fingerprint prompt straight away on launch.
            if this.is_locked() && this.biometric_label().is_some() {
                this.unlock_biometric(window, cx);
            }
        });

        KeyVaultApp {
            vault,
            path,
            panel,
            filter: Filter::All,
            sort: SortBy::Recent,
            busy: false,
            error: None,
            revealed: None,
            copied_at: None,
            hold: None,
            hold_task: None,
            seg_anim: Default::default(),
            add_chain: Chain::Evm,
            edit_favorite: false,
            gen_chain: Chain::Evm,
            gen_progress: None,
            send: SendState::empty(),
            last_net: Default::default(),
            nav_seq: 0,
            list_seq: 0,
            reveal_seq: 0,
            inputs,
            focus,
            ticker: None,
            clipboard_task: None,
            _subscriptions: subs,
            master: None,
            setup,
            use_recovery: false,
            must_reset_passphrase: false,
            recovery_shown: None,
            last_activity: Instant::now(),
            auto_lock_mins,
            confirm_secrets,
            _auto_lock: None,
            add_extra_lock: false,
            gen_extra_lock: false,
            sec_tab: 0,
            select_mode: false,
            selected: Default::default(),
            export: ExportState::default(),
        }
    }

    // ── data helpers ──────────────────────────────────────────────────────

    fn entry(&self, id: Uuid) -> Option<&WalletEntry> {
        self.vault.as_ref().ok().and_then(|v| v.get(id))
    }

    fn all(&self) -> &[WalletEntry] {
        self.vault.as_ref().map(|v| v.wallets()).unwrap_or(&[])
    }

    fn visible(&self, cx: &App) -> Vec<WalletEntry> {
        let query = self.inputs.search.read(cx).value().to_string();
        let mut list: Vec<WalletEntry> = self
            .all()
            .iter()
            .filter(|w| self.filter.accepts(w) && w.matches(&query))
            .cloned()
            .collect();
        self.sort_like_list(&mut list, &query);
        list
    }

    /// Order wallets the way the list shows them (favourites first, then the
    /// chosen sort). With a search query, name matches come first.
    pub(super) fn sort_like_list(&self, list: &mut [WalletEntry], query: &str) {
        let q = query.trim().to_lowercase();
        let rank = |w: &WalletEntry| !(q.is_empty() || w.label.to_lowercase().contains(&q));
        list.sort_by(|a, b| {
            rank(a)
                .cmp(&rank(b))
                .then(b.favorite.cmp(&a.favorite))
                .then_with(|| match self.sort {
                    // Second precision so a generated batch stays in name order.
                    SortBy::Recent => b
                        .created_at
                        .unix_timestamp()
                        .cmp(&a.created_at.unix_timestamp())
                        .then_with(|| a.label.to_lowercase().cmp(&b.label.to_lowercase())),
                    SortBy::Name => a.label.to_lowercase().cmp(&b.label.to_lowercase()),
                    SortBy::Chain => a
                        .chain
                        .as_str()
                        .cmp(b.chain.as_str())
                        .then(a.label.cmp(&b.label)),
                })
        });
    }

    fn vault_mut(&mut self) -> Result<&mut Vault, VaultError> {
        self.vault
            .as_mut()
            .map_err(|e| VaultError::InvalidInput(e.clone()))
    }

    fn first_panel(&self) -> Panel {
        self.all()
            .first()
            .map(|w| Panel::Details(w.id))
            .unwrap_or(Panel::Welcome)
    }

    /// Where a segmented control's highlight glides from, and its animation key.
    fn seg(&self, id: &'static str, selected: usize) -> (usize, usize) {
        self.seg_anim.get(id).copied().unwrap_or((selected, 0))
    }

    fn seg_moved(&mut self, id: &'static str, previous: usize) {
        let entry = self.seg_anim.entry(id).or_insert((previous, 0));
        entry.0 = previous;
        entry.1 += 1;
    }

    // ── navigation ────────────────────────────────────────────────────────

    fn go(&mut self, panel: Panel, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        // Leaving a wallet always re-locks it and wipes every password field.
        if self
            .revealed
            .as_ref()
            .is_some_and(|r| panel.wallet() != Some(r.id))
        {
            self.hide_secret(cx);
        }
        for input in [
            &self.inputs.unlock_pw,
            &self.inputs.cur_pw,
            &self.inputs.new_pw,
            &self.inputs.new_pw2,
            &self.inputs.delete_pw,
            &self.inputs.send_pw,
            &self.inputs.gen_pw,
            &self.inputs.gen_pw2,
        ] {
            clear(input, window, cx);
        }
        self.error = None;
        if panel != self.panel {
            self.nav_seq += 1;
        }

        match &panel {
            Panel::Settings => {
                if self.must_reset_passphrase {
                    focus(&self.inputs.pass_new, window, cx);
                }
            }
            Panel::Export => window.focus(&self.focus, cx),
            Panel::Details(_) => focus(&self.inputs.unlock_pw, window, cx),
            Panel::Add => {
                // Pre-fill the folder / tag from the active filter: adding a
                // wallet while looking at "Trading" puts it in "Trading".
                match &self.filter {
                    Filter::Folder(f) => set(&self.inputs.add_folder, f.clone(), window, cx),
                    Filter::Tag(t) => set(&self.inputs.add_tags, t.clone(), window, cx),
                    Filter::Chain(c) => self.add_chain = *c,
                    _ => {}
                }
                focus(&self.inputs.add_label, window, cx)
            }
            Panel::ChangePassword(_) => focus(&self.inputs.cur_pw, window, cx),
            Panel::Delete(_) => focus(&self.inputs.delete_pw, window, cx),
            Panel::Edit(id) => {
                if let Some(w) = self.entry(*id).cloned() {
                    set(&self.inputs.edit_label, w.label, window, cx);
                    set(
                        &self.inputs.edit_folder,
                        w.folder.unwrap_or_default(),
                        window,
                        cx,
                    );
                    set(&self.inputs.edit_tags, w.tags.join(", "), window, cx);
                    set(&self.inputs.edit_note, w.note, window, cx);
                    self.edit_favorite = w.favorite;
                }
                focus(&self.inputs.edit_label, window, cx)
            }
            Panel::RenameFolder(name) => {
                set(&self.inputs.folder_name, name.clone(), window, cx);
                focus(&self.inputs.folder_name, window, cx)
            }
            Panel::Welcome => window.focus(&self.focus, cx),
            Panel::Generate => {
                if let Filter::Folder(f) = &self.filter {
                    set(&self.inputs.gen_folder, f.clone(), window, cx);
                }
                if let Filter::Chain(c) = self.filter {
                    if c != Chain::Other {
                        self.gen_chain = c;
                    }
                }
                if read(&self.inputs.gen_count, cx).is_empty() {
                    set(&self.inputs.gen_count, "10", window, cx);
                }
                focus(&self.inputs.gen_count, window, cx)
            }
            Panel::Send(id) => {
                let chain = self.entry(*id).map(|w| w.chain).unwrap_or(Chain::Other);
                self.send = SendState::empty();
                self.send.nets = network::for_chain(chain);
                self.send.net = *self.last_net.get(chain.as_str()).unwrap_or(&0);
                self.sync_rpc_input(window, cx);
                for input in [
                    &self.inputs.send_to,
                    &self.inputs.send_amount,
                    &self.inputs.send_token,
                ] {
                    clear(input, window, cx);
                }
                focus(&self.inputs.send_to, window, cx)
            }
        }
        self.panel = panel;
        cx.notify();
    }

    fn set_filter(&mut self, filter: Filter, window: &mut Window, cx: &mut Context<Self>) {
        if self.filter != filter {
            self.filter = filter;
            self.list_seq += 1;
            // Jump to the first wallet in the new view if the current one isn't in it.
            let visible = self.visible(cx);
            let keep = self
                .panel
                .wallet()
                .is_some_and(|id| visible.iter().any(|w| w.id == id));
            if !keep && !matches!(self.panel, Panel::Add) {
                let next = visible
                    .first()
                    .map(|w| Panel::Details(w.id))
                    .unwrap_or(Panel::Welcome);
                self.go(next, window, cx);
            }
        }
        cx.notify();
    }

    fn fail(&mut self, msg: impl Into<SharedString>, cx: &mut Context<Self>) {
        self.error = Some(msg.into());
        cx.notify();
    }

    /// Run `work` on a background thread (Argon2 is slow on purpose), then
    /// apply `done` to the view.
    fn run_slow<R: Send + 'static>(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
        work: impl FnOnce() -> R + Send + 'static,
        done: impl FnOnce(&mut Self, R, &mut Window, &mut Context<Self>) + 'static,
    ) {
        self.busy = true;
        self.error = None;
        cx.notify();
        cx.spawn_in(window, async move |this, cx| {
            let result = cx.background_spawn(async move { work() }).await;
            this.update_in(cx, |this, window, cx| {
                this.busy = false;
                done(this, result, window, cx);
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    // ── decrypting a wallet key ───────────────────────────────────────────

    /// A job (to run off the UI thread) that returns this wallet's private key:
    /// vault-key wallets → optional Touch ID re-check, then instant decrypt;
    /// extra-lock wallets → the password typed in `pw_input`.
    fn secret_job(
        &self,
        entry: &WalletEntry,
        pw_input: &Entity<InputState>,
        reason: String,
        cx: &App,
    ) -> Result<Box<dyn FnOnce() -> Result<Zeroizing<String>, String> + Send>, String> {
        let entry = entry.clone();
        if entry.needs_password() {
            let password = read_secret(pw_input, cx);
            if password.is_empty() {
                return Err("Enter this wallet's password (it has an extra lock).".into());
            }
            return Ok(Box::new(move || {
                entry.unseal(&password).map_err(|e| e.to_string())
            }));
        }
        let mk = self
            .master
            .clone()
            .ok_or_else(|| "Unlock the vault first.".to_string())?;
        let confirm = self.reconfirm().is_some();
        Ok(Box::new(move || {
            if confirm {
                crate::os_unlock::authenticate(&reason)?;
            }
            entry.unseal_vault(&mk).map_err(|e| e.to_string())
        }))
    }

    // ── reveal / copy ─────────────────────────────────────────────────────

    fn submit_unlock(&mut self, then: AfterUnlock, window: &mut Window, cx: &mut Context<Self>) {
        if let Panel::Details(id) = self.panel {
            self.unlock(id, then, window, cx);
        }
    }

    fn unlock(&mut self, id: Uuid, then: AfterUnlock, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        let Some(entry) = self.entry(id).cloned() else {
            return;
        };
        let job = match self.secret_job(
            &entry,
            &self.inputs.unlock_pw,
            format!("show the private key of \"{}\"", entry.label),
            cx,
        ) {
            Ok(job) => job,
            Err(e) => return self.fail(e, cx),
        };

        self.run_slow(
            window,
            cx,
            move || job(),
            move |this, result, window, cx| match result {
                Ok(secret) => {
                    clear(&this.inputs.unlock_pw, window, cx);
                    // The password field disappears; keep shortcuts working.
                    window.focus(&this.focus, cx);
                    this.reveal_seq += 1;
                    this.revealed = Some(Revealed {
                        id,
                        secret,
                        until: Instant::now() + Duration::from_secs(REVEAL_SECS),
                        seq: this.reveal_seq,
                    });
                    this.start_ticker(cx);
                    if then == AfterUnlock::Copy {
                        this.copy_secret(window, cx);
                        this.hide_secret(cx);
                        window.push_notification(
                            Notification::success(format!(
                                "Private key copied — clipboard clears in {CLIPBOARD_CLEAR_SECS}s."
                            )),
                            cx,
                        );
                    }
                }
                Err(e) => this.error = Some(e.into()),
            },
        );
    }

    /// Re-render for the countdown and hide the key when it expires.
    fn start_ticker(&mut self, cx: &mut Context<Self>) {
        self.ticker = Some(cx.spawn(async move |this, cx| loop {
            cx.background_executor()
                .timer(Duration::from_millis(250))
                .await;
            let keep_going = this
                .update(cx, |this, cx| {
                    if this
                        .revealed
                        .as_ref()
                        .is_some_and(|r| Instant::now() >= r.until)
                    {
                        this.revealed = None;
                    }
                    cx.notify();
                    this.revealed.is_some()
                })
                .unwrap_or(false);
            if !keep_going {
                break;
            }
        }));
    }

    fn hide_secret(&mut self, cx: &mut Context<Self>) {
        self.revealed = None;
        self.ticker = None;
        cx.notify();
    }

    fn copy_secret(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(revealed) = &self.revealed else {
            return;
        };
        let copied = Zeroizing::new(revealed.secret.to_string());
        cx.write_to_clipboard(ClipboardItem::new_string(copied.to_string()));

        // Wipe the clipboard later — but only if it still holds our key, so we
        // never clobber something the user copied afterwards.
        self.clipboard_task = Some(cx.spawn(async move |_, cx| {
            cx.background_executor()
                .timer(Duration::from_secs(CLIPBOARD_CLEAR_SECS))
                .await;
            cx.update(|cx| {
                let current = cx.read_from_clipboard().and_then(|item| item.text());
                if current.as_deref() == Some(copied.as_str()) {
                    cx.write_to_clipboard(ClipboardItem::new_string(String::new()));
                }
            });
        }));
        self.copied_at = Some(Instant::now());
        if self
            .revealed
            .as_ref()
            .is_some_and(|r| r.until > Instant::now() + Duration::from_secs(1))
        {
            // Visible key: the button itself says "Copied".
            let _ = window;
        } else {
            window.push_notification(
                Notification::success(format!(
                    "Private key copied — clipboard clears in {CLIPBOARD_CLEAR_SECS}s."
                )),
                cx,
            );
        }
    }

    fn copy_address(&mut self, id: Uuid, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(addr) = self.entry(id).and_then(|w| w.address.clone()) {
            cx.write_to_clipboard(ClipboardItem::new_string(addr));
            window.push_notification(Notification::info("Address copied."), cx);
        }
    }

    // ── add ───────────────────────────────────────────────────────────────

    fn save_new_wallet(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy || self.panel != Panel::Add {
            return;
        }
        let label = read(&self.inputs.add_label, cx);
        let secret = read_secret(&self.inputs.add_secret, cx);
        let address = read(&self.inputs.add_address, cx);
        let password = read_secret(&self.inputs.add_pw, cx);
        let confirm = read_secret(&self.inputs.add_pw2, cx);
        let extra_lock = self.add_extra_lock;
        let mk = self.master.clone();
        let chain = self.add_chain;

        if label.is_empty() {
            return self.fail("Give the wallet a name.", cx);
        }
        // Validate everything cheap *before* the slow key derivation.
        let derived = match derive_address(chain, &secret) {
            Ok(a) => a,
            Err(e) => return self.fail(format!("Invalid key: {e}"), cx),
        };
        if extra_lock {
            if let Err(e) = check_new_password(&password, &confirm) {
                return self.fail(e.to_string(), cx);
            }
        }
        if let Some(addr) = &derived {
            if let Some(existing) = self
                .all()
                .iter()
                .find(|w| w.chain == chain && w.address.as_ref() == Some(addr))
            {
                return self.fail(
                    format!("This key is already stored as \"{}\".", existing.label),
                    cx,
                );
            }
        }
        drop(confirm);

        let new = NewWallet {
            label,
            folder: Some(read(&self.inputs.add_folder, cx)).filter(|f| !f.is_empty()),
            tags: parse_tags(&read(&self.inputs.add_tags, cx)),
            note: read(&self.inputs.add_note, cx),
            chain,
            secret,
            address: (!address.is_empty()).then_some(address),
            password: extra_lock.then_some(password),
        };

        self.run_slow(
            window,
            cx,
            move || WalletEntry::create(new, mk.as_ref()),
            |this, result, window, cx| {
                let inserted = result.and_then(|entry| {
                    let id = entry.id;
                    this.vault_mut()?.insert(entry).map(|_| id)
                });
                match inserted {
                    Ok(id) => {
                        let inputs = &this.inputs;
                        for input in [
                            &inputs.add_label,
                            &inputs.add_folder,
                            &inputs.add_tags,
                            &inputs.add_note,
                            &inputs.add_secret,
                            &inputs.add_address,
                            &inputs.add_pw,
                            &inputs.add_pw2,
                        ] {
                            clear(input, window, cx);
                        }
                        // Make sure the new wallet is visible in the list.
                        let visible = this.entry(id).is_some_and(|w| this.filter.accepts(w));
                        if !visible {
                            this.filter = Filter::All;
                            this.list_seq += 1;
                        }
                        this.go(Panel::Details(id), window, cx);
                        window.push_notification(
                            Notification::success("Wallet encrypted and saved."),
                            cx,
                        );
                    }
                    Err(e) => this.error = Some(e.to_string().into()),
                }
            },
        );
    }

    // ── edit / favorites / folders ────────────────────────────────────────

    fn save_edit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Panel::Edit(id) = self.panel else { return };
        let meta = WalletMeta {
            label: read(&self.inputs.edit_label, cx),
            folder: Some(read(&self.inputs.edit_folder, cx)),
            tags: parse_tags(&read(&self.inputs.edit_tags, cx)),
            favorite: self.edit_favorite,
            note: read(&self.inputs.edit_note, cx),
        };
        match self.vault_mut().and_then(|v| v.update_meta(id, meta)) {
            Ok(()) => {
                self.go(Panel::Details(id), window, cx);
                window.push_notification(Notification::success("Details saved."), cx);
            }
            Err(e) => self.fail(e.to_string(), cx),
        }
    }

    fn toggle_favorite(&mut self, id: Uuid, cx: &mut Context<Self>) {
        let Some(fav) = self.entry(id).map(|w| !w.favorite) else {
            return;
        };
        if let Err(e) = self.vault_mut().and_then(|v| v.set_favorite(id, fav)) {
            self.fail(e.to_string(), cx);
        }
        cx.notify();
    }

    fn save_folder_rename(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Panel::RenameFolder(from) = self.panel.clone() else {
            return;
        };
        let to = read(&self.inputs.folder_name, cx);
        let to_opt = (!to.is_empty()).then_some(to.as_str());
        match self
            .vault_mut()
            .and_then(|v| v.rename_folder(&from, to_opt))
        {
            Ok(n) => {
                self.filter = match to_opt {
                    Some(t) => Filter::Folder(t.to_string()),
                    None => Filter::All,
                };
                self.list_seq += 1;
                let next = self.first_panel();
                self.go(next, window, cx);
                let msg = match to_opt {
                    Some(t) => format!("Moved {n} wallet(s) to \"{t}\"."),
                    None => format!("Folder removed; {n} wallet(s) are now unfiled."),
                };
                window.push_notification(Notification::success(msg), cx);
            }
            Err(e) => self.fail(e.to_string(), cx),
        }
    }

    // ── change password / delete ─────────────────────────────────────────

    /// Wallet security panel: add an extra lock, remove it, or change it.
    fn change_password(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Panel::ChangePassword(id) = self.panel else {
            return;
        };
        if self.busy {
            return;
        }
        let Some(entry) = self.entry(id).cloned() else {
            return;
        };
        let current = read_secret(&self.inputs.cur_pw, cx);
        let new = read_secret(&self.inputs.new_pw, cx);
        let confirm = read_secret(&self.inputs.new_pw2, cx);
        let mk = self.master.clone();
        let mode = if !entry.needs_password() {
            2
        } else {
            self.sec_tab
        };
        if mode != 0 {
            if let Err(e) = check_new_password(&new, &confirm) {
                return self.fail(e.to_string(), cx);
            }
        }
        if mode != 2 && current.is_empty() {
            return self.fail("Enter the wallet's current password.", cx);
        }
        let Some(mk) = mk else { return };

        self.run_slow(
            window,
            cx,
            move || match mode {
                0 => entry.to_vault(&current, &mk),
                1 => entry.reseal(&current, &new),
                _ => entry.with_extra_lock(&mk, &new),
            },
            move |this, result, window, cx| match result
                .and_then(|entry| this.vault_mut()?.replace(entry))
            {
                Ok(()) => {
                    this.go(Panel::Details(id), window, cx);
                    let msg = match mode {
                        0 => "Extra lock removed — opens with your vault unlock now.",
                        1 => "Wallet password changed.",
                        _ => "Extra lock added.",
                    };
                    window.push_notification(Notification::success(msg), cx);
                }
                Err(VaultError::WrongPassword) => {
                    this.error = Some("Wrong wallet password.".into())
                }
                Err(e) => this.error = Some(e.to_string().into()),
            },
        );
    }

    fn delete(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Panel::Delete(id) = self.panel else {
            return;
        };
        if self.busy {
            return;
        }
        let Some(entry) = self.entry(id).cloned() else {
            return;
        };
        // Proving access before deleting prevents accidental (or malicious, by
        // someone at your unlocked PC) irreversible deletion.
        let job = match self.secret_job(
            &entry,
            &self.inputs.delete_pw,
            format!("delete \"{}\"", entry.label),
            cx,
        ) {
            Ok(job) => job,
            Err(e) => return self.fail(e, cx),
        };
        self.run_slow(
            window,
            cx,
            move || job().map(|_| ()),
            move |this, result, window, cx| match result.and_then(|()| {
                this.vault_mut()
                    .and_then(|v| v.remove(id))
                    .map_err(|e| e.to_string())
            }) {
                Ok(entry) => {
                    let next = this
                        .visible(cx)
                        .first()
                        .map(|w| Panel::Details(w.id))
                        .unwrap_or(Panel::Welcome);
                    this.go(next, window, cx);
                    window.push_notification(
                        Notification::warning(format!("Deleted \"{}\".", entry.label)),
                        cx,
                    );
                }
                Err(e) => this.error = Some(e.into()),
            },
        );
    }

    // ── generate ──────────────────────────────────────────────────────────

    /// Fill the Add form's key field with a freshly generated key.
    fn generate_into_add_form(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(secret) = generate_secret(self.add_chain) {
            set(&self.inputs.add_secret, secret.to_string(), window, cx);
            self.error = None;
            window.push_notification(
                Notification::info(
                    "New key generated. It only exists in this vault — keep backups.",
                ),
                cx,
            );
            focus(&self.inputs.add_label, window, cx);
            cx.notify();
        }
    }

    /// Next free number for "<prefix> N" names, so batches continue
    /// ("Farm 21" after "Farm 20").
    fn next_index(&self, prefix: &str) -> usize {
        let p = format!("{} ", prefix.to_lowercase());
        self.all()
            .iter()
            .filter_map(|w| {
                w.label
                    .to_lowercase()
                    .strip_prefix(&p)
                    .and_then(|n| n.trim().parse::<usize>().ok())
            })
            .max()
            .map(|n| n + 1)
            .unwrap_or(1)
    }

    fn bulk_generate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy || self.panel != Panel::Generate {
            return;
        }
        let count: usize = match read(&self.inputs.gen_count, cx).parse() {
            Ok(n) if (1..=MAX_GENERATE).contains(&n) => n,
            _ => {
                return self.fail(
                    format!("Enter how many wallets to generate (1–{MAX_GENERATE})."),
                    cx,
                )
            }
        };
        let prefix = Some(read(&self.inputs.gen_prefix, cx))
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| "Wallet".into());
        let extra_lock = self.gen_extra_lock;
        let password = read_secret(&self.inputs.gen_pw, cx);
        let confirm = read_secret(&self.inputs.gen_pw2, cx);
        if extra_lock {
            if let Err(e) = check_new_password(&password, &confirm) {
                return self.fail(e.to_string(), cx);
            }
        }
        drop(confirm);
        let mk = self.master.clone();
        let folder = Some(read(&self.inputs.gen_folder, cx)).filter(|f| !f.is_empty());
        let tags = parse_tags(&read(&self.inputs.gen_tags, cx));
        let chain = self.gen_chain;
        let start = self.next_index(&prefix);
        let width = (start + count - 1).to_string().len().max(2);

        let progress = Arc::new(AtomicUsize::new(0));
        self.gen_progress = Some((progress.clone(), count));
        // Poll progress for the progress bar while the batch runs.
        self.ticker = Some(cx.spawn(async move |this, cx| loop {
            cx.background_executor()
                .timer(Duration::from_millis(120))
                .await;
            let running = this.update(cx, |this, cx| {
                cx.notify();
                this.gen_progress.is_some()
            });
            if !running.unwrap_or(false) {
                break;
            }
        }));

        self.run_slow(
            window,
            cx,
            move || {
                // Argon2 is CPU + memory bound; spread the batch over cores.
                let threads = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(2)
                    .clamp(1, 6);
                let indices: Vec<usize> = (0..count).collect();
                let mut results: Vec<(usize, Result<WalletEntry, VaultError>)> =
                    std::thread::scope(|s| {
                        let handles: Vec<_> = indices
                            .chunks(count.div_ceil(threads))
                            .map(|chunk| {
                                let (prefix, folder, tags, password, progress, mk) =
                                    (&prefix, &folder, &tags, &password, &progress, &mk);
                                s.spawn(move || {
                                    chunk
                                        .iter()
                                        .map(|&i| {
                                            let secret =
                                                generate_secret(chain).expect("generatable chain");
                                            let entry = WalletEntry::create(
                                                NewWallet {
                                                    label: format!(
                                                        "{prefix} {:0width$}",
                                                        start + i
                                                    ),
                                                    folder: folder.clone(),
                                                    tags: tags.clone(),
                                                    note: String::new(),
                                                    chain,
                                                    secret,
                                                    address: None,
                                                    password: extra_lock.then(|| {
                                                        Zeroizing::new(password.to_string())
                                                    }),
                                                },
                                                mk.as_ref(),
                                            );
                                            progress.fetch_add(1, Ordering::Relaxed);
                                            (i, entry)
                                        })
                                        .collect::<Vec<_>>()
                                })
                            })
                            .collect();
                        handles
                            .into_iter()
                            .flat_map(|h| h.join().expect("generator thread"))
                            .collect()
                    });
                results.sort_by_key(|(i, _)| *i);
                let mut entries = results
                    .into_iter()
                    .map(|(_, r)| r)
                    .collect::<Result<Vec<_>, _>>()?;
                // One timestamp for the whole batch keeps it together, in name order.
                if let Some(t) = entries.first().map(|e| e.created_at) {
                    for e in &mut entries {
                        e.created_at = t;
                        e.updated_at = t;
                    }
                }
                Ok(entries)
            },
            move |this, result, window, cx| {
                this.gen_progress = None;
                match result.and_then(|entries| {
                    let first = entries.first().map(|e| e.id);
                    let folder = entries.first().and_then(|e| e.folder.clone());
                    this.vault_mut()?
                        .insert_many(entries)
                        .map(|n| (n, first, folder))
                }) {
                    Ok((n, first, folder)) => {
                        for input in [&this.inputs.gen_pw, &this.inputs.gen_pw2] {
                            clear(input, window, cx);
                        }
                        this.filter = folder.map(Filter::Folder).unwrap_or(Filter::All);
                        this.list_seq += 1;
                        if let Some(id) = first {
                            this.go(Panel::Details(id), window, cx);
                        }
                        window.push_notification(
                            Notification::success(format!(
                                "Generated {n} {} wallets.",
                                chain.label()
                            )),
                            cx,
                        );
                    }
                    Err(e) => this.error = Some(e.to_string().into()),
                }
            },
        );
    }

    // ── send ──────────────────────────────────────────────────────────────

    fn sync_rpc_input(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let url = self
            .send
            .nets
            .get(self.send.net)
            .map(|n| n.rpc_url.clone())
            .unwrap_or_default();
        set(&self.inputs.send_rpc, url, window, cx);
    }

    fn select_network(&mut self, idx: usize, window: &mut Window, cx: &mut Context<Self>) {
        self.send.net = idx;
        self.send.quote = None;
        self.error = None;
        if let Some(chain) = self
            .panel
            .wallet()
            .and_then(|id| self.entry(id))
            .map(|w| w.chain)
        {
            self.last_net.insert(chain.as_str(), idx);
        }
        self.sync_rpc_input(window, cx);
        if self.send.custom() {
            focus(&self.inputs.send_rpc, window, cx);
        }
        cx.notify();
    }

    fn current_network(&self, cx: &App) -> Option<Network> {
        let rpc = read(&self.inputs.send_rpc, cx);
        if self.send.custom() {
            return Some(network::custom_evm(
                &rpc,
                &read(&self.inputs.send_symbol, cx),
            ));
        }
        let mut n = self.send.nets.get(self.send.net)?.clone();
        n.rpc_url = rpc;
        Some(n)
    }

    fn review_send(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Panel::Send(id) = self.panel else { return };
        if self.busy {
            return;
        }
        let Some(from) = self.entry(id).and_then(|w| w.address.clone()) else {
            return;
        };
        let Some(net) = self.current_network(cx) else {
            return;
        };
        if net.rpc_url.is_empty() {
            return self.fail("Enter an RPC URL.", cx);
        }
        let asset = if self.send.token_mode {
            let token = read(&self.inputs.send_token, cx);
            if token.is_empty() {
                return self.fail("Paste the token's contract / mint address.", cx);
            }
            Asset::Token(token)
        } else {
            Asset::Native
        };
        let to = read(&self.inputs.send_to, cx);
        if to.is_empty() {
            return self.fail("Enter the recipient's address.", cx);
        }
        let amount = if self.send.max {
            AmountSpec::Max
        } else {
            let a = read(&self.inputs.send_amount, cx);
            if a.is_empty() {
                return self.fail("Enter an amount (or use Max).", cx);
            }
            AmountSpec::Exact(a)
        };

        self.run_slow(
            window,
            cx,
            move || wallet_tx::quote(&net, &from, &asset, &to, &amount),
            |this, result, window, cx| match result {
                Ok(q) => {
                    this.send.quote = Some((q, Instant::now()));
                    this.nav_seq += 1;
                    focus(&this.inputs.send_pw, window, cx);
                }
                Err(e) => this.error = Some(e.to_string().into()),
            },
        );
    }

    fn confirm_send(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Panel::Send(id) = self.panel else { return };
        if self.busy {
            return;
        }
        let Some((quote, at)) = self.send.quote.clone() else {
            return;
        };
        if at.elapsed() > Duration::from_secs(QUOTE_TTL_SECS) {
            // Fees and balances move; never sign a stale review.
            self.send.quote = None;
            return self.review_send(window, cx);
        }
        let Some(entry) = self.entry(id).cloned() else {
            return;
        };
        let reason = format!(
            "send {} {} from \"{}\"",
            quote.amount_display, quote.symbol, entry.label
        );
        let job = match self.secret_job(&entry, &self.inputs.send_pw, reason, cx) {
            Ok(job) => job,
            Err(e) => return self.fail(e, cx),
        };

        self.run_slow(
            window,
            cx,
            move || -> Result<Sent, String> {
                let secret = job()?;
                wallet_tx::send(&quote, &secret).map_err(|e| e.to_string())
            },
            |this, result, window, cx| match result {
                Ok(sent) => {
                    clear(&this.inputs.send_pw, window, cx);
                    this.send.sent = Some(sent);
                    this.nav_seq += 1;
                    window.push_notification(Notification::success("Transaction submitted."), cx);
                }
                Err(e) => this.error = Some(e.into()),
            },
        );
    }

    // ── hold to confirm ───────────────────────────────────────────────────

    fn start_hold(&mut self, kind: HoldKind, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        // Check the cheap stuff up front so a hold never ends in "enter a password".
        let (pw, needs) = match kind {
            HoldKind::Send => (
                &self.inputs.send_pw,
                self.panel
                    .wallet()
                    .and_then(|id| self.entry(id))
                    .is_some_and(|w| w.needs_password()),
            ),
            HoldKind::Delete => (
                &self.inputs.delete_pw,
                self.panel
                    .wallet()
                    .and_then(|id| self.entry(id))
                    .is_some_and(|w| w.needs_password()),
            ),
            HoldKind::Export => (&self.inputs.export_pw, false),
        };
        if needs && pw.read(cx).value().is_empty() {
            return self.fail(
                "Enter this wallet's password first (it has an extra lock).",
                cx,
            );
        }
        self.error = None;
        self.hold = Some((kind, Instant::now()));
        self.hold_task = Some(cx.spawn_in(window, async move |this, cx| loop {
            cx.background_executor()
                .timer(Duration::from_millis(16))
                .await;
            let keep = this
                .update_in(cx, |this, window, cx| {
                    let Some((kind, started)) = this.hold else {
                        return false;
                    };
                    if started.elapsed() >= Duration::from_millis(HOLD_MS) {
                        this.hold = None;
                        match kind {
                            HoldKind::Send => this.confirm_send(window, cx),
                            HoldKind::Delete => this.delete(window, cx),
                            HoldKind::Export => this.run_export(window, cx),
                        }
                        cx.notify();
                        return false;
                    }
                    cx.notify();
                    true
                })
                .unwrap_or(false);
            if !keep {
                break;
            }
        }));
        cx.notify();
    }

    fn cancel_hold(&mut self, cx: &mut Context<Self>) {
        if self.hold.take().is_some() {
            self.hold_task = None;
            cx.notify();
        }
    }

    /// Press-and-hold button: an accent fill sweeps across while held; letting
    /// go early cancels. Used for sending funds and deleting wallets.
    fn hold_button(
        &self,
        kind: HoldKind,
        label: &'static str,
        busy_label: &'static str,
        p: &Palette,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let progress = self
            .hold
            .filter(|(k, _)| *k == kind)
            .map(|(_, t)| (t.elapsed().as_secs_f32() * 1000.0 / HOLD_MS as f32).min(1.0))
            .unwrap_or(0.0);
        let holding = self.hold.is_some_and(|(k, _)| k == kind);
        let danger = kind == HoldKind::Delete;
        let (base, fill, ink) = if danger {
            (p.danger, hsla(0., 0., 0., 0.22), p.primary_fg)
        } else {
            (p.primary, p.accent, p.primary_fg)
        };
        let fill_bg: Background = if danger {
            fill.into()
        } else {
            hsla(0., 0., 0., 0.22).into()
        };
        h_flex()
            .id(SharedString::from(format!("hold-{kind:?}")))
            .relative()
            .overflow_hidden()
            .flex_shrink_0()
            .h(px(ui::CTA_H))
            .px_5()
            .rounded(px(12.))
            .bg(base)
            .cursor_pointer()
            .when(self.busy, |d| d.opacity(0.7))
            .when(!self.busy && !holding, |d| d.hover(|s| s.opacity(0.92)))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _, window, cx| this.start_hold(kind, window, cx)),
            )
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|this, _, _, cx| this.cancel_hold(cx)),
            )
            .on_mouse_up_out(
                MouseButton::Left,
                cx.listener(|this, _, _, cx| this.cancel_hold(cx)),
            )
            .child(
                div()
                    .absolute()
                    .left_0()
                    .top_0()
                    .bottom_0()
                    .w(relative(ui::ease_smooth(progress)))
                    .bg(fill_bg),
            )
            .child(
                h_flex()
                    .relative()
                    .gap_2()
                    .text_sm()
                    .font_medium()
                    .text_color(ink)
                    .child(
                        Icon::new(match kind {
                            HoldKind::Delete => Lucide::Trash,
                            HoldKind::Send => Lucide::Send,
                            HoldKind::Export => Lucide::Download,
                        })
                        .small(),
                    )
                    .child(if self.busy {
                        busy_label
                    } else if holding {
                        "Keep holding…"
                    } else {
                        label
                    }),
            )
    }

    // ── backup / theme ────────────────────────────────────────────────────

    fn backup(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let dir = dirs_home();
        let name = format!("keyvault-backup-{}.json", time_stamp());
        let fallback = dir.join(&name);
        let rx = cx.prompt_for_new_path(&dir, Some(&name));
        cx.spawn_in(window, async move |this, cx| {
            let dest = match rx.await {
                Ok(Ok(Some(path))) => path,
                Ok(Ok(None)) => return,
                _ => fallback,
            };
            this.update_in(cx, |this, window, cx| {
                let result = this
                    .vault
                    .as_ref()
                    .map_err(|e| e.clone())
                    .and_then(|v| v.export_to(&dest).map_err(|e| e.to_string()));
                match result {
                    Ok(()) => window.push_notification(
                        Notification::success(format!(
                            "Encrypted backup saved to {}",
                            dest.display()
                        )),
                        cx,
                    ),
                    Err(e) => window
                        .push_notification(Notification::error(format!("Backup failed: {e}")), cx),
                }
            })
            .ok();
        })
        .detach();
    }

    fn toggle_theme(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let next = if crate::theme::current().is_dark() {
            crate::theme::Flavor::Latte
        } else {
            crate::theme::saved_dark_flavor(&self.path)
        };
        self.set_flavor(next, window, cx);
    }

    pub(super) fn set_flavor(
        &mut self,
        flavor: crate::theme::Flavor,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        crate::theme::apply(flavor, Some(window), cx);
        crate::theme::save_flavor(&self.path, flavor);
        cx.notify();
    }

    // ── rendering: navigation ─────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn nav_item(
        &self,
        id: impl Into<SharedString>,
        leading: AnyElement,
        label: impl Into<SharedString>,
        count: usize,
        filter: Filter,
        p: &Palette,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let active = self.filter == filter;
        let (active_bg, hover_bg, muted, fg) = (p.accent_subtle, p.list_hover, p.muted, p.fg);
        h_flex()
            .id(id.into())
            .mx_2()
            .px_2()
            .py_1p5()
            .gap_2()
            .rounded_md()
            .cursor_pointer()
            .text_sm()
            .when(active, |d| d.bg(active_bg).font_medium())
            .when(!active, |d| {
                d.text_color(fg.opacity(0.85))
                    .hover(move |s| s.bg(hover_bg))
            })
            .on_click(
                cx.listener(move |this, _, window, cx| this.set_filter(filter.clone(), window, cx)),
            )
            .child(div().w_4().flex().justify_center().child(leading))
            .child(div().flex_1().truncate().child(label.into()))
            .child(div().text_xs().text_color(muted).child(count.to_string()))
    }

    fn render_nav(&self, p: &Palette, cx: &mut Context<Self>) -> impl IntoElement {
        let all = self.all();
        let favorites = all.iter().filter(|w| w.favorite).count();
        let unfiled = all.iter().filter(|w| w.folder.is_none()).count();
        let (folders, tags) = match &self.vault {
            Ok(v) => (v.folders(), v.tags()),
            Err(_) => (vec![], vec![]),
        };
        let icon = |name: IconName| Icon::new(name).small().into_any_element();

        let mut col = v_flex()
            .child(self.nav_item(
                "nav-all",
                icon(IconName::Inbox),
                "All wallets",
                all.len(),
                Filter::All,
                p,
                cx,
            ))
            .child(self.nav_item(
                "nav-fav",
                icon(IconName::Star),
                "Favorites",
                favorites,
                Filter::Favorites,
                p,
                cx,
            ));

        let chains: Vec<(Chain, usize)> = Chain::ALL
            .into_iter()
            .map(|c| (c, all.iter().filter(|w| w.chain == c).count()))
            .filter(|(_, n)| *n > 0)
            .collect();
        if !chains.is_empty() {
            col = col.child(section_label("Chains", p));
            for (c, n) in chains {
                col = col.child(self.nav_item(
                    format!("nav-chain-{}", c.as_str()),
                    chain_dot(c).into_any_element(),
                    c.label(),
                    n,
                    Filter::Chain(c),
                    p,
                    cx,
                ));
            }
        }

        col = col.child(section_label("Folders", p));
        if folders.is_empty() {
            col = col.child(
                div()
                    .px_4()
                    .py_1()
                    .text_xs()
                    .text_color(p.muted)
                    .child("Set a folder when adding or editing a wallet."),
            );
        }
        for (name, n) in folders {
            let open = self.filter == Filter::Folder(name.clone());
            col = col.child(self.nav_item(
                format!("nav-folder-{name}"),
                icon(if open {
                    IconName::FolderOpen
                } else {
                    IconName::Folder
                }),
                name.clone(),
                n,
                Filter::Folder(name),
                p,
                cx,
            ));
        }
        if unfiled > 0 && unfiled < all.len() {
            col = col.child(self.nav_item(
                "nav-unfiled",
                icon(IconName::FolderClosed),
                "Not in a folder",
                unfiled,
                Filter::Unfiled,
                p,
                cx,
            ));
        }

        if !tags.is_empty() {
            col = col.child(section_label("Tags", p));
            let chips = tags.into_iter().map(|(tag, n)| {
                let active = self.filter == Filter::Tag(tag.clone());
                let color = ui::tag_color(&tag);
                let filter = Filter::Tag(tag.clone());
                div()
                    .id(SharedString::from(format!("nav-tag-{tag}")))
                    .px_2()
                    .py_0p5()
                    .rounded_full()
                    .text_xs()
                    .cursor_pointer()
                    .border_1()
                    .border_color(if active { color } else { color.opacity(0.0) })
                    .bg(color.opacity(if active { 0.22 } else { 0.12 }))
                    .text_color(color)
                    .hover(move |s| s.bg(color.opacity(0.22)))
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.set_filter(filter.clone(), window, cx)
                    }))
                    .child(format!("#{tag} {n}"))
            });
            col = col.child(h_flex().flex_wrap().gap_1p5().px_4().py_1().children(chips));
        }

        let dark = p.dark;
        v_flex()
            .w(px(240.))
            .h_full()
            .flex_shrink_0()
            .child(
                h_flex()
                    .gap_2p5()
                    .px_4()
                    .pt(px(28.))
                    .pb_4()
                    .child(
                        div()
                            .size_8()
                            .rounded(px(10.))
                            .flex()
                            .items_center()
                            .justify_center()
                            .bg(p.primary)
                            .text_color(p.primary_fg)
                            .child(Icon::new(Lucide::KeyRound).small()),
                    )
                    .child(
                        v_flex()
                            .child(
                                div()
                                    .font_family(crate::theme::DISPLAY_FONT)
                                    .text_base()
                                    .font_medium()
                                    .child("KeyVault"),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(p.muted)
                                    .child("Local · encrypted"),
                            ),
                    ),
            )
            .child(
                div()
                    .id("nav-scroll")
                    .flex_1()
                    .overflow_y_scroll()
                    .pb_3()
                    .child(col),
            )
            .child(
                h_flex()
                    .gap_1()
                    .px(px(11.))
                    .py_2()
                    .border_t_1()
                    .border_color(p.border)
                    .child(
                        ui::button("backup")
                            .ghost()
                            .small()
                            .icon(Lucide::DatabaseBackup)
                            .tooltip("Save an encrypted backup of the vault")
                            .disabled(self.vault.is_err())
                            .on_click(cx.listener(|this, _, window, cx| this.backup(window, cx))),
                    )
                    .child(
                        ui::button("reveal-file")
                            .ghost()
                            .small()
                            .icon(IconName::FolderOpen)
                            .tooltip("Show vault file")
                            .on_click(cx.listener(|this, _, _, cx| cx.reveal_path(&this.path))),
                    )
                    .child(
                        ui::button("settings")
                            .ghost()
                            .small()
                            .icon(Lucide::Settings)
                            .tooltip("Settings")
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.go(Panel::Settings, window, cx)
                            })),
                    )
                    .child(div().flex_1())
                    .when(self.keyring().is_some(), |d| {
                        d.child(
                            ui::button("lock")
                                .ghost()
                                .small()
                                .icon(Lucide::Lock)
                                .label("Lock")
                                .tooltip(format!("Lock the vault ({})", ui::shortcut("L")))
                                .on_click(
                                    cx.listener(|this, _, window, cx| this.lock_vault(window, cx)),
                                ),
                        )
                    })
                    .child(
                        ui::button("theme")
                            .ghost()
                            .small()
                            .icon(if dark { IconName::Sun } else { IconName::Moon })
                            .tooltip(format!("Toggle theme ({})", ui::shortcut("Shift+T")))
                            .on_click(
                                cx.listener(|this, _, window, cx| this.toggle_theme(window, cx)),
                            ),
                    ),
            )
    }

    // ── rendering: wallet list ────────────────────────────────────────────

    fn render_list(&self, p: &Palette, cx: &mut Context<Self>) -> impl IntoElement {
        let wallets = self.visible(cx);
        let selected = self.panel.wallet();
        let searching = !self.inputs.search.read(cx).value().is_empty();
        let list_seq = self.list_seq;

        let rows = wallets.iter().enumerate().map(|(i, w)| {
            let id = w.id;
            let is_selected = selected == Some(id);
            let (active_bg, hover_bg, muted, border) =
                (p.accent_subtle, p.list_hover, p.muted, p.border);
            let seed = w.address.clone().unwrap_or_else(|| w.id.to_string());
            let row = h_flex()
                .id(SharedString::from(format!("row-{id}")))
                .mx_2()
                .px_3()
                .py_2p5()
                .gap_3()
                .rounded(px(14.))
                .border_1()
                .cursor_pointer()
                .when(is_selected, |d| d.bg(active_bg).border_color(border))
                .when(!is_selected, |d| {
                    d.border_color(transparent_black())
                        .hover(move |s| s.bg(hover_bg))
                })
                .on_click(cx.listener(move |this, _, window, cx| {
                    if this.select_mode {
                        this.toggle_selected(id, cx);
                    } else {
                        this.go(Panel::Details(id), window, cx);
                    }
                }))
                .child(if self.select_mode {
                    let on = self.selected.contains(&id);
                    div()
                        .size(px(34.))
                        .flex_shrink_0()
                        .flex()
                        .items_center()
                        .justify_center()
                        .child(
                            div()
                                .size(px(22.))
                                .rounded_full()
                                .border_1()
                                .flex()
                                .items_center()
                                .justify_center()
                                .when(on, |d| {
                                    d.bg(p.fg)
                                        .border_color(p.fg)
                                        .text_color(p.bg)
                                        .child(Icon::new(IconName::Check).xsmall())
                                })
                                .when(!on, |d| d.border_color(p.muted)),
                        )
                        .into_any_element()
                } else {
                    ui::orb(&seed, 34.).into_any_element()
                })
                .child(
                    v_flex()
                        .flex_1()
                        .min_w_0()
                        .gap_0p5()
                        .child(
                            h_flex()
                                .gap_1p5()
                                .child(
                                    div()
                                        .text_sm()
                                        .font_medium()
                                        .truncate()
                                        .child(w.label.clone()),
                                )
                                .when(w.favorite, |d| {
                                    d.child(Icon::new(IconName::StarFill).xsmall().text_color(p.fg))
                                }),
                        )
                        .child(
                            div()
                                .text_xs()
                                .font_family(p.mono.clone())
                                .text_color(muted)
                                .child(w.short_address()),
                        ),
                )
                .child(
                    h_flex()
                        .flex_shrink_0()
                        .gap_1p5()
                        .text_xs()
                        .text_color(muted)
                        .child(chain_dot(w.chain))
                        .child(w.chain.label()),
                );
            if i < STAGGER_ROWS {
                enter(
                    row_wrap(row),
                    SharedString::from(format!("row-anim-{list_seq}-{id}")),
                    260,
                    i as u64 * 28,
                )
                .into_any_element()
            } else {
                row.into_any_element()
            }
        });

        let empty = if wallets.is_empty() {
            let (title, body) = if self.all().is_empty() {
                (
                    "No wallets yet",
                    format!(
                        "Press Add or {} to store your first key.",
                        ui::shortcut("N")
                    ),
                )
            } else if searching {
                (
                    "No matches",
                    "Try another name, address, folder or #tag.".to_string(),
                )
            } else {
                ("Nothing here", "No wallets match this filter.".to_string())
            };
            Some(
                v_flex()
                    .items_center()
                    .gap_2()
                    .px_6()
                    .py_12()
                    .child(Icon::new(IconName::Inbox).large().text_color(p.muted))
                    .child(div().text_sm().font_medium().child(title))
                    .child(
                        div()
                            .text_xs()
                            .text_color(p.muted)
                            .text_center()
                            .child(body),
                    ),
            )
        } else {
            None
        };

        let sort = self.sort;
        v_flex()
            .w(px(360.))
            .h_full()
            .flex_shrink_0()
            .border_r_1()
            .border_color(p.border)
            .child(
                v_flex()
                    .gap_3()
                    .px_4()
                    .pt_5()
                    .pb_3()
                    .child(
                        h_flex()
                            .gap_2()
                            .child(
                                v_flex()
                                    .flex_1()
                                    .min_w_0()
                                    .child(
                                        div()
                                            .font_family(crate::theme::DISPLAY_FONT)
                                            .text_xl()
                                            .font_medium()
                                            .truncate()
                                            .child(self.filter.title()),
                                    )
                                    .child(div().text_xs().text_color(p.muted).child(format!(
                                        "{} wallet{}",
                                        wallets.len(),
                                        if wallets.len() == 1 { "" } else { "s" }
                                    ))),
                            )
                            .when_some(
                                match &self.filter {
                                    Filter::Folder(f) => Some(f.clone()),
                                    _ => None,
                                },
                                |d, f| {
                                    d.child(
                                        ui::button("rename-folder")
                                            .ghost()
                                            .small()
                                            .icon(Lucide::Pencil)
                                            .tooltip("Rename or remove folder")
                                            .on_click(cx.listener(move |this, _, window, cx| {
                                                this.go(Panel::RenameFolder(f.clone()), window, cx)
                                            })),
                                    )
                                },
                            )
                            .child(
                                ui::button("sort")
                                    .ghost()
                                    .small()
                                    .label(sort.label())
                                    .tooltip("Change sort order")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.sort = this.sort.next();
                                        this.list_seq += 1;
                                        cx.notify();
                                    })),
                            )
                            .child(
                                ui::button("select-mode")
                                    .ghost()
                                    .small()
                                    .label(if self.select_mode { "Done" } else { "Select" })
                                    .tooltip("Select wallets to export")
                                    .on_click(
                                        cx.listener(|this, _, _, cx| this.toggle_select_mode(cx)),
                                    ),
                            )
                            .child(
                                ui::button("generate-wallets")
                                    .outline()
                                    .small()
                                    .icon(Lucide::Sparkles)
                                    .tooltip(format!("Generate wallets ({})", ui::shortcut("G")))
                                    .disabled(self.vault.is_err())
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.go(Panel::Generate, window, cx)
                                    })),
                            )
                            .child(
                                ui::button("add-wallet")
                                    .primary()
                                    .small()
                                    .icon(IconName::Plus)
                                    .label("Add")
                                    .tooltip(format!("Import a key ({})", ui::shortcut("N")))
                                    .disabled(self.vault.is_err())
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.go(Panel::Add, window, cx)
                                    })),
                            ),
                    )
                    .child(
                        ui::input(&self.inputs.search)
                            .prefix(Icon::new(IconName::Search).small())
                            .cleanable(true),
                    )
                    .when(self.select_mode, |d| {
                        let n = self.selected.len();
                        d.child(
                            h_flex()
                                .gap_2()
                                .px_3()
                                .py_2()
                                .rounded(px(14.))
                                .bg(p.muted_bg)
                                .child(div().flex_1().text_sm().child(format!("{n} selected")))
                                .child(
                                    ui::button("select-all")
                                        .ghost()
                                        .small()
                                        .label("All in view")
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.select_all_visible(cx)
                                        })),
                                )
                                .child(
                                    ui::button("export-selected")
                                        .primary()
                                        .small()
                                        .label("Export")
                                        .disabled(n == 0)
                                        .on_click(cx.listener(|this, _, window, cx| {
                                            this.open_export(window, cx)
                                        })),
                                ),
                        )
                    }),
            )
            .child(
                div()
                    .id("wallet-list")
                    .flex_1()
                    .overflow_y_scroll()
                    .pb_3()
                    .child(v_flex().gap_0p5().children(rows))
                    .children(empty),
            )
    }

    // ── rendering: right-hand panels ──────────────────────────────────────

    fn render_error(&self, p: &Palette) -> Option<impl IntoElement> {
        let danger = p.danger;
        self.error.clone().map(|msg| {
            enter(
                ui::callout(IconName::CircleAlert, msg.clone(), danger),
                SharedString::from(format!("err-{msg}")),
                200,
                0,
            )
        })
    }

    fn field(
        label: &'static str,
        hint: Option<SharedString>,
        input: impl IntoElement,
        p: &Palette,
    ) -> Div {
        let muted = p.muted;
        v_flex()
            .gap_1p5()
            .child(div().text_sm().font_medium().child(label))
            .child(input)
            .when_some(hint, |d, hint| {
                d.child(div().text_xs().text_color(muted).child(hint))
            })
    }

    fn header(
        title: impl Into<SharedString>,
        subtitle: impl Into<SharedString>,
        p: &Palette,
    ) -> Div {
        v_flex().gap_2().child(ui::display(title)).child(
            div()
                .text_sm()
                .text_color(p.secondary)
                .child(subtitle.into()),
        )
    }

    /// Clickable suggestions under the folder / tag inputs.
    fn folder_suggestions(
        &self,
        target: Entity<InputState>,
        cx: &mut Context<Self>,
    ) -> Option<Div> {
        let folders = self.vault.as_ref().ok()?.folders();
        if folders.is_empty() {
            return None;
        }
        let current = target.read(cx).value().to_lowercase();
        let chips = folders.into_iter().map(|(name, _)| {
            let selected = current == name.to_lowercase();
            let target = target.clone();
            let value = name.clone();
            ui::button(SharedString::from(format!("sugg-folder-{name}")))
                .xsmall()
                .icon(IconName::Folder)
                .label(name)
                .when(selected, |b| b.primary())
                .when(!selected, |b| b.outline())
                .on_click(cx.listener(move |_, _, window, cx| {
                    set(&target, value.clone(), window, cx);
                    cx.notify();
                }))
        });
        Some(h_flex().mt_0p5().flex_wrap().gap_1p5().children(chips))
    }

    fn tag_suggestions(&self, target: Entity<InputState>, cx: &mut Context<Self>) -> Option<Div> {
        let tags = self.vault.as_ref().ok()?.tags();
        let current = parse_tags(&target.read(cx).value());
        let missing: Vec<String> = tags
            .into_iter()
            .map(|(t, _)| t)
            .filter(|t| !current.contains(t))
            .take(12)
            .collect();
        let preview = current.clone();
        if missing.is_empty() && preview.is_empty() {
            return None;
        }
        let chips = missing.into_iter().map(|tag| {
            let target = target.clone();
            let color = ui::tag_color(&tag);
            let current = current.clone();
            let t = tag.clone();
            div()
                .id(SharedString::from(format!("sugg-tag-{tag}")))
                .px_2()
                .py_0p5()
                .rounded_full()
                .text_xs()
                .cursor_pointer()
                .border_1()
                .border_dashed()
                .border_color(color.opacity(0.5))
                .text_color(color)
                .hover(move |s| s.bg(color.opacity(0.12)))
                .on_click(cx.listener(move |_, _, window, cx| {
                    let mut tags = current.clone();
                    tags.push(t.clone());
                    set(&target, tags.join(", "), window, cx);
                    cx.notify();
                }))
                .child(format!("+ {tag}"))
        });
        Some(
            h_flex()
                .mt_0p5()
                .flex_wrap()
                .gap_1p5()
                .children(preview.iter().map(|t| tag_chip(t).py_0p5()))
                .children(chips),
        )
    }

    fn render_welcome(&self, p: &Palette, cx: &mut Context<Self>) -> Div {
        if let Err(err) = &self.vault {
            return v_flex()
                .gap_4()
                .max_w(px(ui::FORM_W))
                .child(Self::header("Can't open the vault", "Nothing has been changed on disk.", p))
                .child(div().p_3().rounded_md().bg(p.danger.opacity(0.12)).text_color(p.danger).text_sm().child(err.clone()))
                .child(div().text_sm().text_color(p.muted).child(format!(
                    "File: {}. Restore it from vault.json.bak in the same folder, or start KeyVault with \
                     KEYVAULT_PATH pointing at another file.",
                    self.path.display()
                )));
        }
        let feature = |icon: Lucide, title: &'static str, body: String| {
            h_flex()
                .gap_3()
                .items_start()
                .p_3()
                .rounded(px(14.))
                .border_1()
                .border_color(p.border)
                .child(
                    div()
                        .mt_0p5()
                        .text_color(p.secondary)
                        .child(Icon::new(icon).small()),
                )
                .child(
                    v_flex()
                        .flex_1()
                        .min_w_0()
                        .gap_0p5()
                        .child(div().text_sm().font_medium().child(title))
                        .child(div().text_xs().text_color(p.muted).child(body)),
                )
        };
        v_flex()
            .gap_5()
            .max_w(px(ui::FORM_W))
            .child(Self::header(
                "Your keys, encrypted on this PC",
                "One unlock — your fingerprint or passphrase — opens every wallet. Each key is still encrypted separately.",
                p,
            ))
            .child(
                v_flex()
                    .gap_2()
                    .child(feature(Lucide::ShieldCheck, "Strong encryption", "A random vault key (XChaCha20-Poly1305) protected by Argon2id, your recovery key, and optionally Touch ID / Windows Hello. Addresses are tamper-checked.".into()))
                    .child(feature(Lucide::EyeOff, "Short-lived exposure", format!("Revealed keys hide after {REVEAL_SECS}s or when the window loses focus; copied keys leave the clipboard after {CLIPBOARD_CLEAR_SECS}s.")))
                    .child(feature(Lucide::Folder, "Organised", "Folders, #tags, favorites, notes, chain filters and search.".into()))
                    .child(feature(Lucide::Send, "Send & generate", "Generate wallets in bulk; send native coins and tokens on EVM chains and Solana — signed locally.".into()))
                    .child(feature(Lucide::HardDrive, "Your files", "One encrypted JSON file you can back up anywhere. Network is only used when you send.".into())),
            )
            .child(
                h_flex()
                    .gap_2()
                    .child(ui::glow_button(
                        p,
                        "welcome-add",
                        Some(IconName::Plus),
                        "Import a key",
                        false,
                        false,
                        cx.listener(|this, _, window, cx| this.go(Panel::Add, window, cx)),
                    ))
                    .child(
                        ui::action("welcome-gen")
                            .outline()
                            .icon(Lucide::Sparkles)
                            .label("Generate wallets")
                            .on_click(cx.listener(|this, _, window, cx| this.go(Panel::Generate, window, cx))),
                    ),
            )
    }

    fn render_details(&self, id: Uuid, p: &Palette, cx: &mut Context<Self>) -> Div {
        let Some(w) = self.entry(id).cloned() else {
            return div();
        };
        let created = w.created_at.date().to_string();

        let revealed = self.revealed.as_ref().filter(|r| r.id == id);
        let copied = self
            .copied_at
            .is_some_and(|t| t.elapsed() < Duration::from_millis(1600));
        let key_card: AnyElement = match revealed {
            Some(r) => {
                let left = r.until.saturating_duration_since(Instant::now()).as_secs() + 1;
                let warning = p.warning;
                let card = ui::glass(p)
                    .flex()
                    .flex_col()
                    .gap_4()
                    .p_5()
                    .rounded(px(ui::R_CARD))
                    .border_color(warning.opacity(0.35))

                    .child(
                        h_flex()
                            .justify_between()
                            .child(ui::label("Private key", p))
                            .child(
                                h_flex()
                                    .gap_1p5()
                                    .px_2()
                                    .py_0p5()
                                    .rounded_full()
                                    .bg(warning.opacity(0.12))
                                    .text_xs()
                                    .text_color(warning)
                                    .child(Icon::new(IconName::Eye).xsmall())
                                    .child(format!("Visible · hides in {left}s")),
                            ),
                    )
                    .child(
                        div()
                            .px_4()
                            .py_3()
                            .rounded(px(14.))
                            .border_1()
                            .border_color(p.border)
                            .bg(p.surface)
                            .text_sm()
                            .line_height(px(22.))
                            .font_family(p.mono.clone())
                            .child(SharedString::from(r.secret.to_string())),
                    )
                    // Countdown: one continuous movement over the reveal window.
                    .child(
                        div().h(px(2.)).w_full().rounded_full().bg(p.border).child(
                            div().h_full().rounded_full().bg(warning).with_animation(
                                SharedString::from(format!("countdown-{}", r.seq)),
                                Animation::new(Duration::from_secs(REVEAL_SECS)),
                                |bar, t| bar.w(relative(1.0 - t)),
                            ),
                        ),
                    )
                    .child(
                        h_flex()
                            .gap_2()
                            .child(ui::glow_button(
                                p,
                                "copy-key",
                                Some(if copied { IconName::Check } else { IconName::Copy }),
                                if copied { "Copied" } else { "Copy key" },
                                false,
                                false,
                                cx.listener(|this, _, window, cx| this.copy_secret(window, cx)),
                            ))
                            .child(
                                ui::action("hide-key")
                                    .ghost()
                                    .icon(Lucide::EyeOff)
                                    .label("Hide")
                                    .on_click(cx.listener(|this, _, _, cx| this.hide_secret(cx))),
                            )
                            .child(div().flex_1())
                            .child(div().text_xs().text_color(p.muted).child(format!("Clipboard clears {CLIPBOARD_CLEAR_SECS}s after copying"))),
                    );
                enter(card, SharedString::from(format!("reveal-{}", r.seq)), 280, 0).into_any_element()
            }
            None => ui::glass(p)
                .flex()
                .flex_col()
                .gap_4()
                .p_5()
                .rounded(px(ui::R_CARD))
                .child(
                    h_flex()
                        .justify_between()
                        .child(ui::label("Private key", p))
                        .child(
                            h_flex()
                                .gap_1p5()
                                .px_2()
                                .py_0p5()
                                .rounded_full()
                                .bg(p.muted_bg)
                                .text_xs()
                                .text_color(p.secondary)
                                .child(div().size(px(6.)).rounded_full().bg(p.success))
                                .child(if w.needs_password() { "Extra lock" } else { "Encrypted" }),
                        ),
                )
                .child(div().text_sm().text_color(p.secondary).child(if w.needs_password() {
                    "This wallet has its own password on top of the vault.".to_string()
                } else if let Some(label) = self.reconfirm() {
                    format!("Protected by your vault key. {label} confirms it's you before the key is shown.")
                } else {
                    "Protected by your vault key — no extra password needed.".to_string()
                }))
                .when(w.needs_password(), |d| d.child(ui::input(&self.inputs.unlock_pw).mask_toggle().disabled(self.busy)))
                .child(
                    h_flex()
                        .gap_2()
                        .child(ui::glow_button(p,
                            "reveal",
                            Some(IconName::Eye),
                            "Reveal",
                            self.busy,
                            false,
                            cx.listener(move |this, _, window, cx| this.unlock(id, AfterUnlock::Show, window, cx)),
                        ))
                        .child(
                            ui::action("unlock-copy")
                                .ghost()
                                .icon(IconName::Copy)
                                .label("Copy without showing")
                                .disabled(self.busy)
                                .on_click(cx.listener(move |this, _, window, cx| this.unlock(id, AfterUnlock::Copy, window, cx))),
                        )
                        .child(div().flex_1())
                        .when(self.busy, |d| d.child(shimmer("Deriving key · Argon2id", p.muted))),
                )
                .into_any_element(),
        };

        let fav = w.favorite;

        let meta_row = h_flex()
            .flex_wrap()
            .gap_2()
            .text_xs()
            .text_color(p.muted)
            .child(chain_badge(w.chain))
            .when_some(w.folder.clone(), |d, f| {
                let filter = Filter::Folder(f.clone());
                d.child(
                    h_flex()
                        .id("detail-folder")
                        .gap_1()
                        .px_1p5()
                        .py_0p5()
                        .rounded_md()
                        .cursor_pointer()
                        .hover(|s| s.underline())
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.set_filter(filter.clone(), window, cx)
                        }))
                        .child(Icon::new(IconName::Folder).xsmall())
                        .child(f),
                )
            })
            .children(w.tags.iter().map(|t| {
                let filter = Filter::Tag(t.clone());
                tag_chip(t)
                    .py_0p5()
                    .id(SharedString::from(format!("detail-tag-{t}")))
                    .cursor_pointer()
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.set_filter(filter.clone(), window, cx)
                    }))
            }))
            .child(div().child(format!("Added {created}")));

        let seed = w.address.clone().unwrap_or_else(|| w.id.to_string());
        let sendable = !network::for_chain(w.chain).is_empty();
        let hero = div()
            .relative()
            .overflow_hidden()
            .rounded(px(ui::R_CARD))
            .border_1()
            .border_color(p.border)
            .bg(ui::orb_colors(&seed)
                .0
                .opacity(if p.dark { 0.07 } else { 0.045 }))
            .p_5()
            .child(
                v_flex()
                    .gap_5()
                    .child(
                        h_flex()
                            .gap_4()
                            .child(ui::living_orb(&seed, 64.))
                            .child(
                                v_flex()
                                    .flex_1()
                                    .min_w_0()
                                    .gap_2()
                                    .child(ui::display(w.label.clone()).truncate())
                                    .child(meta_row),
                            )
                            .child(
                                ui::button("fav")
                                    .ghost()
                                    .icon(
                                        Icon::new(if fav {
                                            IconName::StarFill
                                        } else {
                                            IconName::Star
                                        })
                                        .when(fav, |i| i.text_color(p.fg)),
                                    )
                                    .tooltip(if fav {
                                        "Remove from favorites"
                                    } else {
                                        "Add to favorites"
                                    })
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.toggle_favorite(id, cx)
                                    })),
                            ),
                    )
                    .child(
                        h_flex()
                            .gap_2()
                            .pl_4()
                            .pr_1()
                            .py_1()
                            .rounded(px(14.))
                            .bg(if p.dark {
                                hsla(0., 0., 0., 0.28)
                            } else {
                                hsla(0., 0., 1., 0.7)
                            })
                            .border_1()
                            .border_color(p.border)
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .py_1p5()
                                    .text_sm()
                                    .font_family(p.mono.clone())
                                    .truncate()
                                    .child(
                                        w.address
                                            .clone()
                                            .unwrap_or_else(|| "No address saved".into()),
                                    ),
                            )
                            .when(w.address.is_some(), |d| {
                                d.child(
                                    ui::button("copy-address")
                                        .ghost()
                                        .small()
                                        .icon(IconName::Copy)
                                        .tooltip("Copy address")
                                        .on_click(cx.listener(move |this, _, window, cx| {
                                            this.copy_address(id, window, cx)
                                        })),
                                )
                            }),
                    )
                    .child(
                        h_flex()
                            .gap_1()
                            .when(sendable, |d| {
                                d.child(ui::glow_button(
                                    p,
                                    "send",
                                    Some(Lucide::Send),
                                    "Send",
                                    false,
                                    false,
                                    cx.listener(move |this, _, window, cx| {
                                        this.go(Panel::Send(id), window, cx)
                                    }),
                                ))
                                .child(div().w_2())
                            })
                            .child(
                                ui::action("edit")
                                    .ghost()
                                    .icon(Lucide::Pencil)
                                    .label("Edit")
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.go(Panel::Edit(id), window, cx)
                                    })),
                            )
                            .child(
                                ui::action("change-pw")
                                    .ghost()
                                    .icon(Lucide::ShieldCheck)
                                    .label("Security")
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.go(Panel::ChangePassword(id), window, cx)
                                    })),
                            )
                            .child(div().flex_1())
                            .child(
                                ui::button("delete")
                                    .ghost()
                                    .size(px(ui::CTA_H))
                                    .text_color(p.danger)
                                    .icon(Lucide::Trash)
                                    .tooltip("Delete wallet")
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.go(Panel::Delete(id), window, cx)
                                    })),
                            ),
                    ),
            );

        v_flex()
            .gap_5()
            .max_w(px(ui::WIDE_W))
            .child(hero)
            .when(!w.note.is_empty(), |d| {
                d.child(
                    ui::glass(p).rounded(px(ui::R_CARD)).px_5().py_4().child(
                        v_flex()
                            .gap_1()
                            .child(div().text_xs().text_color(p.muted).child("Note"))
                            .child(div().text_sm().child(w.note.clone())),
                    ),
                )
            })
            .child(key_card)
            .children(self.render_error(p))
    }

    fn render_add(&self, p: &Palette, cx: &mut Context<Self>) -> Div {
        let secret = read_secret(&self.inputs.add_secret, cx);
        let preview: Option<(bool, SharedString)> =
            if secret.trim().is_empty() || !self.add_chain.derives_address() {
                None
            } else {
                Some(match derive_address(self.add_chain, &secret) {
                    Ok(addr) => (true, addr.unwrap_or_default().into()),
                    Err(e) => (false, e.to_string().into()),
                })
            };
        drop(secret);

        let chain_tabs = {
            let this = cx.entity().downgrade();
            let selected = Chain::ALL
                .iter()
                .position(|c| *c == self.add_chain)
                .unwrap_or(0);
            let (from, seq) = self.seg("add-chain", selected);
            segmented(
                "add-chain",
                Chain::ALL
                    .iter()
                    .map(|c| Segment {
                        label: c.label().into(),
                        leading: Some(chain_dot(*c).into_any_element()),
                    })
                    .collect(),
                selected,
                from,
                seq,
                p,
                move |i, _, cx| {
                    this.update(cx, |this, cx| {
                        this.seg_moved("add-chain", selected);
                        this.add_chain = Chain::ALL[i];
                        this.error = None;
                        cx.notify();
                    })
                    .ok();
                },
            )
        };

        let (success, danger, mono) = (p.success, p.danger, p.mono.clone());
        v_flex()
            .gap_5()
            .max_w(px(ui::FORM_W))
            .child(Self::header(
                "Add wallet",
                "Paste a key or generate a new one. It's encrypted with your vault key the moment you save.",
                p,
            ))
            .child(
                v_flex()
                    .gap_1p5()
                    .child(div().text_sm().font_medium().child("Chain"))
                    .child(chain_tabs)
                    .child(div().text_xs().text_color(p.muted).child(self.add_chain.description())),
            )
            .child(
                v_flex()
                    .gap_1p5()
                    .child(
                        h_flex()
                            .justify_between()
                            .child(div().text_sm().font_medium().child(if self.add_chain == Chain::Other { "Secret" } else { "Private key" }))
                            .when(self.add_chain != Chain::Other, |d| {
                                                                d.child(
                                    h_flex()
                                        .id("gen-key")
                                        .gap_1()
                                        .text_xs()
                                        .text_color(p.secondary)
                                        .cursor_pointer()
                                        .hover({
                                            let fg = p.fg;
                                            move |s| s.text_color(fg)
                                        })
                                        .child(Icon::new(Lucide::Sparkles).xsmall())
                                        .child("Generate new key")
                                        .on_click(cx.listener(|this, _, window, cx| this.generate_into_add_form(window, cx))),
                                )
                            }),
                    )
                    .child(ui::input(&self.inputs.add_secret).mask_toggle())
                    .when_some(preview, |d, (ok, text)| {
                        d.child(
                            h_flex()
                                .gap_1p5()
                                .text_xs()
                                .when(ok, |d| d.text_color(success))
                                .when(!ok, |d| d.text_color(danger))
                                .child(Icon::new(if ok { IconName::CircleCheck } else { IconName::CircleAlert }).xsmall())
                                .child(div().when(ok, |d| d.font_family(mono.clone())).child(text)),
                        )
                    }),
            )
            .when(self.add_chain == Chain::Other, |d| d.child(Self::field("Address", None, ui::input(&self.inputs.add_address), p)))
            .child(Self::field("Name", None, ui::input(&self.inputs.add_label), p))
            .child(
                h_flex()
                    .gap_3()
                    .items_start()
                    .child(
                        div().flex_1().child(
                            Self::field("Folder", None, ui::input(&self.inputs.add_folder).cleanable(true), p)
                                .children(self.folder_suggestions(self.inputs.add_folder.clone(), cx)),
                        ),
                    )
                    .child(
                        div().flex_1().child(
                            Self::field("Tags", None, ui::input(&self.inputs.add_tags).cleanable(true), p)
                                .children(self.tag_suggestions(self.inputs.add_tags.clone(), cx)),
                        ),
                    ),
            )
            .child(Self::field("Note", Some("Not encrypted — never put secrets here.".into()), ui::input(&self.inputs.add_note), p))
            .child(Self::extra_lock_toggle(
                "add-extra-lock",
                self.add_extra_lock,
                p,
                cx.listener(|this, _, _, cx| {
                    this.add_extra_lock = !this.add_extra_lock;
                    cx.notify();
                }),
            ))
            .when(self.add_extra_lock, |d| {
                d.child(
                    h_flex()
                        .gap_3()
                        .items_start()
                        .child(div().w(relative(0.5)).child(Self::field(
                            "Wallet password",
                            Some("At least 8 characters.".into()),
                            ui::input(&self.inputs.add_pw).mask_toggle(),
                            p,
                        )))
                        .child(div().w(relative(0.5)).child(Self::field(
                            "Confirm password",
                            None,
                            ui::input(&self.inputs.add_pw2).mask_toggle(),
                            p,
                        ))),
                )
            })
            .children(self.render_error(p))
            .child(
                h_flex()
                    .gap_2()
                    .child(
                        ui::glow_button(p,
                            "save-wallet",
                            Some(IconName::Check),
                            if self.busy { "Encrypting…" } else { "Encrypt & save" },
                            self.busy,
                            false,
                            cx.listener(|this, _, window, cx| this.save_new_wallet(window, cx)),
                        ),
                    )
                    .child(
                        ui::action("cancel-add")
                            .ghost()
                            .label("Cancel")
                            .disabled(self.busy)
                            .on_click(cx.listener(|this, _, window, cx| {
                                let next = this.first_panel();
                                this.go(next, window, cx)
                            })),
                    ),
            )
    }

    fn back_button(id: Uuid, busy: bool, cx: &mut Context<Self>) -> impl IntoElement {
        ui::action("back")
            .ghost()
            .label("Cancel")
            .disabled(busy)
            .on_click(
                cx.listener(move |this, _, window, cx| this.go(Panel::Details(id), window, cx)),
            )
    }

    fn render_edit(&self, id: Uuid, p: &Palette, cx: &mut Context<Self>) -> Div {
        let fav = self.edit_favorite;
        v_flex()
            .gap_5()
            .max_w(px(ui::FORM_W))
            .child(Self::header(
                "Edit details",
                "Names, folders, tags and notes aren't secret, so no password is needed.",
                p,
            ))
            .child(Self::field(
                "Name",
                None,
                ui::input(&self.inputs.edit_label),
                p,
            ))
            .child(
                Self::field(
                    "Folder",
                    Some("Leave empty to remove from its folder.".into()),
                    ui::input(&self.inputs.edit_folder).cleanable(true),
                    p,
                )
                .children(self.folder_suggestions(self.inputs.edit_folder.clone(), cx)),
            )
            .child(
                Self::field(
                    "Tags",
                    None,
                    ui::input(&self.inputs.edit_tags).cleanable(true),
                    p,
                )
                .children(self.tag_suggestions(self.inputs.edit_tags.clone(), cx)),
            )
            .child(Self::field(
                "Note",
                Some("Not encrypted.".into()),
                ui::input(&self.inputs.edit_note),
                p,
            ))
            .child(
                h_flex().child(
                    ui::button("edit-fav")
                        .outline()
                        .small()
                        .icon(if fav {
                            IconName::StarFill
                        } else {
                            IconName::Star
                        })
                        .label(if fav {
                            "In favorites"
                        } else {
                            "Add to favorites"
                        })
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.edit_favorite = !this.edit_favorite;
                            cx.notify();
                        })),
                ),
            )
            .children(self.render_error(p))
            .child(
                h_flex()
                    .gap_2()
                    .child(ui::glow_button(
                        p,
                        "save-edit",
                        Some(IconName::Check),
                        "Save",
                        false,
                        false,
                        cx.listener(|this, _, window, cx| this.save_edit(window, cx)),
                    ))
                    .child(Self::back_button(id, self.busy, cx)),
            )
    }

    fn extra_lock_toggle(
        id: &'static str,
        on: bool,
        p: &Palette,
        on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    ) -> impl IntoElement {
        h_flex()
            .id(id)
            .gap_3()
            .items_start()
            .p_3()
            .rounded(px(14.))
            .border_1()
            .border_color(p.border)
            .cursor_pointer()
            .hover({
                let h = p.list_hover;
                move |s| s.bg(h)
            })
            .on_click(on_click)
                        .child(ui::check_box(on, p).mt_0p5())
            .child(
                v_flex()
                    .gap_0p5()
                    .child(div().text_sm().font_medium().child("Extra lock"))
                    .child(div().text_xs().text_color(p.secondary).child(
                        "Also require a separate password for this wallet. Off: your vault unlock is enough.",
                    )),
            )
    }

    fn render_change_password(&self, id: Uuid, p: &Palette, cx: &mut Context<Self>) -> Div {
        let Some(w) = self.entry(id).cloned() else {
            return div();
        };
        let base = v_flex().gap_5().max_w(px(ui::FORM_W));
        if !w.needs_password() {
            return base
                .child(Self::header(
                    "Security",
                    format!("\"{}\" is protected by your vault key. Add an extra lock to also require its own password.", w.label),
                    p,
                ))
                .child(Self::field("Wallet password", Some("At least 8 characters.".into()), ui::input(&self.inputs.new_pw).mask_toggle(), p))
                .child(Self::field("Confirm password", None, ui::input(&self.inputs.new_pw2).mask_toggle(), p))
                .children(self.render_error(p))
                .child(
                    h_flex()
                        .gap_2()
                        .child(ui::glow_button(
                            p,
                            "add-lock",
                            Some(Lucide::LockKeyhole),
                            if self.busy { "Locking…" } else { "Add extra lock" },
                            self.busy,
                            false,
                            cx.listener(|this, _, window, cx| this.change_password(window, cx)),
                        ))
                        .child(Self::back_button(id, self.busy, cx)),
                );
        }

        let this = cx.entity().downgrade();
        let idx = self.sec_tab;
        let (from, seq) = self.seg("sec-tab", idx);
        let tabs = segmented(
            "sec-tab",
            vec![
                Segment {
                    label: "Use vault unlock".into(),
                    leading: None,
                },
                Segment {
                    label: "Change password".into(),
                    leading: None,
                },
            ],
            idx,
            from,
            seq,
            p,
            move |i, _, cx| {
                this.update(cx, |this, cx| {
                    this.seg_moved("sec-tab", idx);
                    this.sec_tab = i;
                    this.error = None;
                    cx.notify();
                })
                .ok();
            },
        );
        base.child(Self::header(
            "Security",
            format!("\"{}\" has its own password on top of the vault.", w.label),
            p,
        ))
        .child(tabs)
        .child(Self::field("Current wallet password", None, ui::input(&self.inputs.cur_pw).mask_toggle(), p))
        .when(idx == 1, |d| {
            d.child(Self::field("New password", Some("At least 8 characters.".into()), ui::input(&self.inputs.new_pw).mask_toggle(), p))
                .child(Self::field("Confirm new password", None, ui::input(&self.inputs.new_pw2).mask_toggle(), p))
        })
        .when(idx == 0, |d| {
            d.child(div().text_sm().text_color(p.secondary).child(
                "Removes this wallet's own password — it opens with your vault unlock (passphrase or fingerprint) from now on.",
            ))
        })
        .children(self.render_error(p))
        .child(
            h_flex()
                .gap_2()
                .child(ui::glow_button(
                    p,
                    "save-pw",
                    Some(IconName::Check),
                    match (self.busy, idx) {
                        (true, _) => "Working…",
                        (false, 0) => "Remove extra lock",
                        _ => "Change password",
                    },
                    self.busy,
                    false,
                    cx.listener(|this, _, window, cx| this.change_password(window, cx)),
                ))
                .child(Self::back_button(id, self.busy, cx)),
        )
    }

    fn render_delete(&self, id: Uuid, p: &Palette, cx: &mut Context<Self>) -> Div {
        let Some(w) = self.entry(id).cloned() else {
            return div();
        };
        v_flex()
            .gap_5()
            .max_w(px(ui::FORM_W))
            .child(Self::header(
                format!("Delete \"{}\"?", w.label),
                "The encrypted key is removed from the vault.",
                p,
            ))
            .child(ui::callout(
                IconName::TriangleAlert,
                format!(
                    "Funds at {} become unreachable unless you have another copy of this key. \
                     (The previous vault version is kept as vault.json.bak.)",
                    w.short_address()
                ),
                p.danger,
            ))
            .when(w.needs_password(), |d| {
                d.child(Self::field(
                    "Confirm with the wallet password",
                    None,
                    ui::input(&self.inputs.delete_pw).mask_toggle(),
                    p,
                ))
            })
            .children(self.render_error(p))
            .child(
                h_flex()
                    .gap_2()
                    .child(self.hold_button(HoldKind::Delete, "Hold to delete", "Deleting…", p, cx))
                    .child(Self::back_button(id, self.busy, cx)),
            )
    }

    fn render_rename_folder(&self, name: &str, p: &Palette, cx: &mut Context<Self>) -> Div {
        let count = self
            .all()
            .iter()
            .filter(|w| {
                w.folder
                    .as_deref()
                    .is_some_and(|f| f.eq_ignore_ascii_case(name))
            })
            .count();
        v_flex()
            .gap_5()
            .max_w(px(ui::FORM_W))
            .child(Self::header(
                format!("Folder \"{name}\""),
                format!("{count} wallet(s). Rename it, or clear the name to remove the folder."),
                p,
            ))
            .child(Self::field(
                "Folder name",
                None,
                ui::input(&self.inputs.folder_name).cleanable(true),
                p,
            ))
            .children(self.render_error(p))
            .child(
                h_flex()
                    .gap_2()
                    .child(ui::glow_button(
                        p,
                        "save-folder",
                        Some(IconName::Check),
                        "Save",
                        false,
                        false,
                        cx.listener(|this, _, window, cx| this.save_folder_rename(window, cx)),
                    ))
                    .child(
                        ui::action("cancel-folder")
                            .ghost()
                            .label("Cancel")
                            .on_click(cx.listener(|this, _, window, cx| {
                                let next = this.first_panel();
                                this.go(next, window, cx)
                            })),
                    ),
            )
    }
}

impl KeyVaultApp {
    fn render_generate(&self, p: &Palette, cx: &mut Context<Self>) -> Div {
        let count = read(&self.inputs.gen_count, cx)
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=MAX_GENERATE).contains(n));
        let prefix = Some(read(&self.inputs.gen_prefix, cx))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Wallet".into());
        let start = self.next_index(&prefix);
        let preview = count.map(|n| {
            let width = (start + n - 1).to_string().len().max(2);
            if n == 1 {
                format!("{prefix} {:0width$}", start)
            } else {
                format!(
                    "{prefix} {:0width$} … {prefix} {:0width$}",
                    start,
                    start + n - 1
                )
            }
        });

        const GEN_CHAINS: [Chain; 3] = [Chain::Evm, Chain::Solana, Chain::Tron];
        let chain_tabs = {
            let this = cx.entity().downgrade();
            let selected = GEN_CHAINS
                .iter()
                .position(|c| *c == self.gen_chain)
                .unwrap_or(0);
            let (from, seq) = self.seg("gen-chain", selected);
            segmented(
                "gen-chain",
                GEN_CHAINS
                    .iter()
                    .map(|c| Segment {
                        label: c.label().into(),
                        leading: Some(chain_dot(*c).into_any_element()),
                    })
                    .collect(),
                selected,
                from,
                seq,
                p,
                move |i, _, cx| {
                    this.update(cx, |this, cx| {
                        this.seg_moved("gen-chain", selected);
                        this.gen_chain = GEN_CHAINS[i];
                        cx.notify();
                    })
                    .ok();
                },
            )
        };

        let quick = [5usize, 10, 25, 50, 100].into_iter().map(|n| {
            ui::button(SharedString::from(format!("gen-n-{n}")))
                .xsmall()
                .outline()
                .label(n.to_string())
                .on_click(cx.listener(move |this, _, window, cx| {
                    set(&this.inputs.gen_count, n.to_string(), window, cx);
                    cx.notify();
                }))
        });

        let progress = self.gen_progress.as_ref().map(|(done, total)| {
            let done = done.load(Ordering::Relaxed).min(*total);
            let frac = done as f32 / (*total).max(1) as f32;
            v_flex()
                .gap_1p5()
                .child(
                    h_flex()
                        .justify_between()
                        .text_xs()
                        .text_color(p.muted)
                        .child("Generating & encrypting…")
                        .child(format!("{done} / {total}")),
                )
                .child(
                    div()
                        .h(px(6.))
                        .w_full()
                        .rounded_full()
                        .bg(p.muted_bg)
                        .child(div().h_full().rounded_full().bg(p.accent).w(relative(frac))),
                )
        });

        v_flex()
            .gap_5()
            .max_w(px(ui::FORM_W))
            .child(Self::header(
                "Generate wallets",
                "Fresh keys from your OS's secure random generator, encrypted the moment they're created.",
                p,
            ))
            .child(v_flex().gap_1p5().child(div().text_sm().font_medium().child("Chain")).child(chain_tabs))
            .child(
                h_flex()
                    .gap_3()
                    .items_start()
                    .child(
                        div().w(relative(0.5)).child(
                            Self::field("How many", Some(format!("1 – {MAX_GENERATE}").into()), ui::input(&self.inputs.gen_count), p)
                                .child(h_flex().gap_1p5().children(quick)),
                        ),
                    )
                    .child(
                        div().w(relative(0.5)).child(Self::field(
                            "Name prefix",
                            preview.map(SharedString::from),
                            ui::input(&self.inputs.gen_prefix),
                            p,
                        )),
                    ),
            )
            .child(
                h_flex()
                    .gap_3()
                    .items_start()
                    .child(
                        div().w(relative(0.5)).child(
                            Self::field("Folder", None, ui::input(&self.inputs.gen_folder).cleanable(true), p)
                                .children(self.folder_suggestions(self.inputs.gen_folder.clone(), cx)),
                        ),
                    )
                    .child(
                        div().w(relative(0.5)).child(
                            Self::field("Tags", None, ui::input(&self.inputs.gen_tags).cleanable(true), p)
                                .children(self.tag_suggestions(self.inputs.gen_tags.clone(), cx)),
                        ),
                    ),
            )
            .child(Self::extra_lock_toggle(
                "gen-extra-lock",
                self.gen_extra_lock,
                p,
                cx.listener(|this, _, _, cx| {
                    this.gen_extra_lock = !this.gen_extra_lock;
                    cx.notify();
                }),
            ))
            .when(self.gen_extra_lock, |d| {
                d.child(
                    h_flex()
                        .gap_3()
                        .items_start()
                        .child(div().w(relative(0.5)).child(Self::field(
                            "Batch password",
                            Some("Each wallet still gets its own salt.".into()),
                            ui::input(&self.inputs.gen_pw).mask_toggle(),
                            p,
                        )))
                        .child(div().w(relative(0.5)).child(Self::field(
                            "Confirm password",
                            None,
                            ui::input(&self.inputs.gen_pw2).mask_toggle(),
                            p,
                        ))),
                )
            })
            .children(progress)
            .children(self.render_error(p))
            .child(
                h_flex()
                    .gap_2()
                    .child(
                        ui::glow_button(p,
                            "do-generate",
                            Some(Lucide::Sparkles),
                            match count {
                                Some(n) if !self.busy => format!("Generate {n} wallet{}", if n == 1 { "" } else { "s" }),
                                _ if self.busy => "Generating…".into(),
                                _ => "Generate".into(),
                            },
                            self.busy,
                            count.is_none(),
                            cx.listener(|this, _, window, cx| this.bulk_generate(window, cx)),
                        ),
                    )
                    .child(ui::action("cancel-gen").ghost().label("Cancel").disabled(self.busy).on_click(cx.listener(
                        |this, _, window, cx| {
                            let next = this.first_panel();
                            this.go(next, window, cx)
                        },
                    ))),
            )
    }

    fn render_send(&self, id: Uuid, p: &Palette, cx: &mut Context<Self>) -> Div {
        let Some(w) = self.entry(id).cloned() else {
            return div();
        };
        let header = h_flex()
            .gap_3()
            .items_start()
            .child(
                Self::header(format!("Send from {}", w.label), w.short_address(), p)
                    .flex_1()
                    .min_w_0(),
            )
            .child(div().pt(px(6.)).child(chain_badge(w.chain)));

        if let Some(sent) = &self.send.sent {
            return v_flex()
                .gap_5()
                .max_w(px(ui::FORM_W))
                .child(header)
                .child(self.render_sent(id, sent, p, cx));
        }
        if let Some((q, at)) = &self.send.quote {
            return v_flex()
                .gap_5()
                .max_w(px(ui::FORM_W))
                .child(header)
                .child(self.render_review(q, *at, p, cx));
        }

        let family = self
            .send
            .nets
            .first()
            .map(|n| n.family)
            .unwrap_or(Family::Evm);
        let native_symbol = if self.send.custom() {
            Some(read(&self.inputs.send_symbol, cx))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "ETH".into())
                .to_uppercase()
        } else {
            self.send
                .nets
                .get(self.send.net)
                .map(|n| n.symbol.clone())
                .unwrap_or_default()
        };

        let mut net_chips: Vec<AnyElement> = self
            .send
            .nets
            .iter()
            .enumerate()
            .map(|(i, n)| {
                let selected = i == self.send.net;
                ui::button(SharedString::from(format!("net-{}", n.id)))
                    .small()
                    .label(n.name.clone())
                    .when(selected, |b| b.primary())
                    .when(!selected, |b| b.outline())
                    .on_click(
                        cx.listener(move |this, _, window, cx| this.select_network(i, window, cx)),
                    )
                    .into_any_element()
            })
            .collect();
        if family == Family::Evm {
            let idx = self.send.nets.len();
            let selected = self.send.custom();
            net_chips.push(
                ui::button("net-custom")
                    .small()
                    .icon(Lucide::Pencil)
                    .label("Custom RPC")
                    .when(selected, |b| b.primary())
                    .when(!selected, |b| b.outline())
                    .on_click(
                        cx.listener(move |this, _, window, cx| {
                            this.select_network(idx, window, cx)
                        }),
                    )
                    .into_any_element(),
            );
        }

        let token_mode = self.send.token_mode;
        let asset_toggle = {
            let this = cx.entity().downgrade();
            let selected = token_mode as usize;
            let (from, seq) = self.seg("asset", selected);
            segmented(
                "asset",
                vec![
                    Segment {
                        label: format!("Native {native_symbol}").into(),
                        leading: None,
                    },
                    Segment {
                        label: if family == Family::Evm {
                            "Token · ERC-20".into()
                        } else {
                            "Token · SPL".into()
                        },
                        leading: None,
                    },
                ],
                selected,
                from,
                seq,
                p,
                move |i, window, cx| {
                    this.update(cx, |this, cx| {
                        this.seg_moved("asset", selected);
                        this.send.token_mode = i == 1;
                        this.send.max = false;
                        this.error = None;
                        if i == 1 {
                            focus(&this.inputs.send_token, window, cx);
                        }
                        cx.notify();
                    })
                    .ok();
                },
            )
        };

        let max = self.send.max;
        v_flex()
            .gap_5()
            .max_w(px(ui::FORM_W))
            .child(header)
            .child(
                v_flex()
                    .gap_2()
                    .child(div().text_sm().font_medium().child("Network"))
                    .child(h_flex().flex_wrap().gap_1p5().children(net_chips)),
            )
            .child(Self::field(
                "RPC URL",
                Some("Public endpoints are rate-limited — paste your own (Alchemy, QuickNode, Helius…) for reliability.".into()),
                ui::input(&self.inputs.send_rpc),
                p,
            ))
            .when(self.send.custom(), |d| {
                d.child(Self::field("Native symbol", None, ui::input(&self.inputs.send_symbol), p))
            })
            .child(
                v_flex()
                    .gap_1p5()
                    .child(div().text_sm().font_medium().child("Asset"))
                    .child(asset_toggle)
                    .when(token_mode, |d| {
                        d.child(Self::field(
                            if family == Family::Evm { "Token contract address" } else { "Token mint address" },
                            None,
                            ui::input(&self.inputs.send_token).cleanable(true),
                            p,
                        ))
                    }),
            )
            .child(Self::field("Recipient", None, ui::input(&self.inputs.send_to).cleanable(true), p))
            .child(
                v_flex()
                    .gap_1p5()
                    .child(div().text_sm().font_medium().child("Amount"))
                    .child(
                        h_flex()
                            .gap_2()
                            .child(div().flex_1().min_w_0().child(ui::input(&self.inputs.send_amount).disabled(max)))
                            .child(
                                ui::button("max")
                                    .label("Max")
                                    .when(max, |b| b.primary())
                                    .when(!max, |b| b.outline())
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.send.max = !this.send.max;
                                        cx.notify();
                                    })),
                            ),
                    )
                    .when(max, |d| {
                        d.child(div().text_xs().text_color(p.muted).child(if token_mode {
                            "Sends the whole token balance."
                        } else {
                            "Sends the whole balance minus the network fee."
                        }))
                    }),
            )
            .children(self.render_error(p))
            .child(
                h_flex()
                    .gap_2()
                    .child(
                        ui::glow_button(p,
                            "review",
                            Some(IconName::ArrowRight),
                            if self.busy { "Checking balances…" } else { "Review transfer" },
                            self.busy,
                            false,
                            cx.listener(|this, _, window, cx| this.review_send(window, cx)),
                        ),
                    )
                    .child(Self::back_button(id, self.busy, cx)),
            )
    }

    fn render_review(
        &self,
        q: &Quote,
        at: Instant,
        p: &Palette,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let stale = at.elapsed() > Duration::from_secs(QUOTE_TTL_SECS);
        let row = |label: &'static str, value: SharedString, mono: bool| {
            h_flex()
                .gap_4()
                .py_2()
                .items_start()
                .border_t_1()
                .border_color(p.border)
                .child(
                    div()
                        .w(px(110.))
                        .flex_shrink_0()
                        .text_sm()
                        .text_color(p.muted)
                        .child(label),
                )
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .text_sm()
                        .when(mono, |d| d.font_family(p.mono.clone()))
                        .child(value),
                )
        };
        let card = v_flex()
            .gap_4()
            .p_5()
            .rounded(px(ui::R_CARD))
            .border_1()
            .border_color(p.border)
            .child(
                v_flex()
                    .items_center()
                    .gap_1()
                    .py_2()
                    .child(div().text_xs().text_color(p.muted).child("You're sending"))
                    .child(
                        ui::display(format!("{} {}", q.amount_display, q.symbol))
                            .text_size(px(38.))
                            .line_height(px(44.)),
                    )
                    .child(div().text_xs().text_color(p.muted).child(format!(
                        "on {}{}",
                        q.network.name,
                        if q.network.testnet { " · testnet" } else { "" }
                    ))),
            )
            .child(
                v_flex()
                    .child(row("To", q.to.clone().into(), true))
                    .child(row("From", q.from.clone().into(), true))
                    .when_some(q.token.clone(), |d, t| {
                        d.child(row("Token", t.into(), true))
                    })
                    .child(row("Network fee", q.fee_display.clone().into(), false))
                    .child(row(
                        "Balance",
                        format!("{} {}", q.balance_display, q.symbol).into(),
                        false,
                    ))
                    .when(q.token.is_some(), |d| {
                        d.child(row(
                            "Gas balance",
                            format!("{} {}", q.native_balance_display, q.network.symbol).into(),
                            false,
                        ))
                    }),
            )
            .children(
                q.warnings
                    .iter()
                    .map(|w| ui::callout(IconName::TriangleAlert, w.clone(), p.warning)),
            );

        let needs_pw = self
            .panel
            .wallet()
            .and_then(|id| self.entry(id))
            .is_some_and(|w| w.needs_password());
        v_flex()
            .gap_4()
            .child(card)
            .when(needs_pw, |d| {
                d.child(Self::field(
                    "Wallet password",
                    Some("This wallet has an extra lock. Transactions can't be reversed.".into()),
                    ui::input(&self.inputs.send_pw).mask_toggle().disabled(self.busy),
                    p,
                ))
            })
            .when(!needs_pw, |d| {
                d.child(div().text_sm().text_color(p.secondary).child(match self.reconfirm() {
                    Some(label) => format!("Hold the button, then confirm with {label}. The key is decrypted only to sign. Transactions can't be reversed."),
                    None => "Hold the button to sign and send. The key is decrypted only to sign. Transactions can't be reversed.".to_string(),
                }))
            })
            .children(self.render_error(p))
            .child(
                h_flex()
                    .gap_2()
                    .child(if stale {
                        ui::glow_button(
                            p,
                            "refresh-quote",
                            Some(IconName::RefreshCw),
                            "Quote expired — refresh",
                            self.busy,
                            false,
                            cx.listener(|this, _, window, cx| this.confirm_send(window, cx)),
                        )
                        .into_any_element()
                    } else {
                        self.hold_button(HoldKind::Send, "Hold to send", "Signing & sending…", p, cx).into_any_element()
                    })
                    .child(ui::action("edit-send").ghost().label("Edit").disabled(self.busy).on_click(cx.listener(
                        |this, _, _, cx| {
                            this.send.quote = None;
                            this.error = None;
                            this.nav_seq += 1;
                            cx.notify();
                        },
                    ))),
            )
            .into_any_element()
    }

    fn render_sent(
        &self,
        id: Uuid,
        sent: &Sent,
        p: &Palette,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let tx = sent.tx.clone();
        let url = sent.explorer_url.clone();
        let summary = self
            .send
            .quote
            .as_ref()
            .map(|(q, _)| format!("{} {} → {}", q.amount_display, q.symbol, q.to))
            .unwrap_or_default();
        let success = p.success;
        v_flex()
            .gap_4()
            .p_6()
            .items_center()
            .rounded(px(ui::R_CARD))
            .border_1()
            .border_color(success.opacity(0.4))
            .bg(success.opacity(0.06))
            .child(
                div()
                    .size_12()
                    .rounded_full()
                    .flex()
                    .items_center()
                    .justify_center()
                    .bg(success.opacity(0.15))
                    .text_color(success)
                    .child(Icon::new(IconName::Check).large())
                    .with_animation(
                        "sent-pop",
                        Animation::new(Duration::from_millis(480)).with_easing(ease_out_quint()),
                        |el, t| el.size(px(28. + 20. * t)).opacity(0.3 + 0.7 * t),
                    ),
            )
            .child(
                div()
                    .font_family(crate::theme::DISPLAY_FONT)
                    .text_xl()
                    .font_medium()
                    .child("Transaction submitted"),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(p.muted)
                    .text_center()
                    .child(summary),
            )
            .child(
                h_flex()
                    .gap_2()
                    .w_full()
                    .pl_3()
                    .pr_1()
                    .py_1()
                    .rounded(px(14.))
                    .bg(p.bg)
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .truncate()
                            .text_xs()
                            .font_family(p.mono.clone())
                            .child(tx.clone()),
                    )
                    .child(
                        ui::button("copy-tx")
                            .ghost()
                            .small()
                            .icon(IconName::Copy)
                            .tooltip("Copy transaction hash")
                            .on_click(cx.listener(move |_, _, window, cx| {
                                cx.write_to_clipboard(ClipboardItem::new_string(tx.clone()));
                                window.push_notification(
                                    Notification::info("Transaction hash copied."),
                                    cx,
                                );
                            })),
                    ),
            )
            .child(
                h_flex()
                    .gap_2()
                    .when_some(url, |d, url| {
                        d.child(ui::glow_button(
                            p,
                            "explorer",
                            Some(IconName::ExternalLink),
                            "View on explorer",
                            false,
                            false,
                            cx.listener(move |_, _, _, cx| cx.open_url(&url)),
                        ))
                    })
                    .child(
                        ui::action("send-again")
                            .outline()
                            .label("Send another")
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.go(Panel::Send(id), window, cx)
                            })),
                    )
                    .child(
                        ui::action("send-done")
                            .ghost()
                            .label("Done")
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.go(Panel::Details(id), window, cx)
                            })),
                    ),
            )
            .into_any_element()
    }
}

/// Wrap a stateful row in a plain div so the animation wrapper owns layout.
fn row_wrap(row: Stateful<Div>) -> Div {
    div().child(row)
}

fn dirs_home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| ".".into())
}

fn time_stamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // YYYYMMDD from days since epoch (civil-from-days, Howard Hinnant).
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}{m:02}{d:02}")
}

impl Render for KeyVaultApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // If the selected wallet disappeared (e.g. deleted), fall back.
        if self
            .panel
            .wallet()
            .is_some_and(|id| self.entry(id).is_none())
        {
            self.panel = Panel::Welcome;
        }
        let p = Palette::of(cx);

        let root = div()
            .id("keyvault-root")
            .key_context("KeyVault")
            .track_focus(&self.focus)
            .relative()
            .size_full()
            .bg(p.bg)
            .text_color(p.fg)
            // Any interaction counts as activity for auto-lock.
            .on_any_mouse_down(cx.listener(|this, _, _, _| this.touch()))
            .on_mouse_move(cx.listener(|this, _, _, _| this.touch()))
            .capture_key_down(cx.listener(|this, _, _, _| this.touch()))
            .on_action(
                cx.listener(|this, _: &ToggleTheme, window, cx| this.toggle_theme(window, cx)),
            )
            .child(ui::backdrop(&p));

        // First run (or a vault from before vault keys): set up the passphrase.
        if self.setup.is_some() {
            return root.child(self.render_setup(&p, cx));
        }
        if self.is_locked() {
            return root.child(self.render_lock(&p, cx));
        }

        let content = match self.panel.clone() {
            Panel::Welcome => self.render_welcome(&p, cx),
            Panel::Details(id) => self.render_details(id, &p, cx),
            Panel::Add => self.render_add(&p, cx),
            Panel::Edit(id) => self.render_edit(id, &p, cx),
            Panel::ChangePassword(id) => self.render_change_password(id, &p, cx),
            Panel::Delete(id) => self.render_delete(id, &p, cx),
            Panel::RenameFolder(name) => self.render_rename_folder(&name, &p, cx),
            Panel::Generate => self.render_generate(&p, cx),
            Panel::Send(id) => self.render_send(id, &p, cx),
            Panel::Settings => self.render_settings(&p, cx),
            Panel::Export => self.render_export(&p, cx),
        };

        // Shortcuts live on the root (the element that holds focus when no
        // input does) so they also fire when nothing inside is focused.
        root.on_action(cx.listener(|this, _: &NewWalletAction, window, cx| {
            if this.vault.is_ok() {
                this.go(Panel::Add, window, cx)
            }
        }))
        .on_action(cx.listener(|this, _: &GenerateAction, window, cx| {
            if this.vault.is_ok() {
                this.go(Panel::Generate, window, cx)
            }
        }))
        .on_action(
            cx.listener(|this, _: &FocusSearch, window, cx| focus(&this.inputs.search, window, cx)),
        )
        .on_action(cx.listener(|this, _: &LockAll, window, cx| this.lock_vault(window, cx)))
        .child(
            h_flex().size_full().child(self.render_nav(&p, cx)).child(
                div()
                    .relative()
                    .flex_1()
                    .h_full()
                    .min_w_0()
                    .py_2()
                    .pr_2()
                    .child(
                        ui::glass(&p)
                            .flex()
                            .size_full()
                            .rounded(px(ui::R_SURFACE))
                            .overflow_hidden()
                            .child(self.render_list(&p, cx))
                            .child(
                                div()
                                    .id("content")
                                    .flex_1()
                                    .min_w_0()
                                    .h_full()
                                    .overflow_y_scroll()
                                    .px_10()
                                    .py_10()
                                    .child(enter(
                                        content,
                                        SharedString::from(format!("panel-{}", self.nav_seq)),
                                        240,
                                        0,
                                    )),
                            ),
                    ),
            ),
        )
    }
}
