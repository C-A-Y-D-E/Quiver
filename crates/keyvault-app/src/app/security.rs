//! Vault unlock: first-run setup, lock screen, auto-lock, Touch ID /
//! Windows Hello, recovery key and the Settings panel.

use super::*;
use crate::os_unlock;
use crate::ui::Lucide;
use vault_core::{generate_device_key, Keyring, MasterKey};

/// Auto-lock choices in minutes (0 = never).
pub(super) const AUTO_LOCK_CHOICES: [u32; 4] = [5, 15, 60, 0];

pub(super) enum SetupStep {
    Passphrase,
    Recovery(Zeroizing<String>),
    Biometric,
}

impl KeyVaultApp {
    // ── state ─────────────────────────────────────────────────────────────

    pub(super) fn keyring(&self) -> Option<Keyring> {
        self.vault.as_ref().ok().and_then(|v| v.keyring().cloned())
    }

    pub(super) fn is_locked(&self) -> bool {
        self.keyring().is_some() && self.master.is_none()
    }

    /// Touch ID / Windows Hello is set up for this vault on this machine.
    pub(super) fn biometric_label(&self) -> Option<&'static str> {
        let b = os_unlock::backend()?;
        self.keyring()?.device.as_ref().map(|_| b.label)
    }

    /// Ask for the fingerprint again before showing, copying or sending a key.
    pub(super) fn reconfirm(&self) -> Option<&'static str> {
        self.biometric_label().filter(|_| self.confirm_secrets)
    }

    pub(super) fn legacy_count(&self) -> usize {
        self.all().iter().filter(|w| w.needs_password()).count()
    }

    pub(super) fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    pub(super) fn lock_vault(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.master.is_none() || self.busy {
            return;
        }
        self.master = None;
        self.hide_secret(cx);
        self.send = SendState::empty();
        self.hold = None;
        self.selected.clear();
        self.select_mode = false;
        for input in [
            &self.inputs.unlock_pw,
            &self.inputs.send_pw,
            &self.inputs.delete_pw,
            &self.inputs.cur_pw,
            &self.inputs.new_pw,
            &self.inputs.new_pw2,
            &self.inputs.add_secret,
            &self.inputs.add_pw,
            &self.inputs.add_pw2,
            &self.inputs.gen_pw,
            &self.inputs.gen_pw2,
            &self.inputs.pass_cur,
            &self.inputs.pass_new,
            &self.inputs.pass_new2,
            &self.inputs.migrate_pw,
            &self.inputs.recovery_auth,
            &self.inputs.export_pw,
        ] {
            clear(input, window, cx);
        }
        self.recovery_shown = None;
        self.use_recovery = false;
        self.error = None;
        focus(&self.inputs.lock_pw, window, cx);
        cx.notify();
    }

    /// Checks idle time every few seconds and locks when it's up.
    pub(super) fn start_auto_lock(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self._auto_lock = Some(cx.spawn_in(window, async move |this, cx| loop {
            cx.background_executor().timer(Duration::from_secs(5)).await;
            let alive = this
                .update_in(cx, |this, window, cx| {
                    let mins = this.auto_lock_mins;
                    #[cfg_attr(not(debug_assertions), allow(unused_mut))]
                    let mut limit = Duration::from_secs(mins as u64 * 60);
                    // Debug builds: KEYVAULT_AUTOLOCK_TEST_SECS overrides the delay for testing.
                    #[cfg(debug_assertions)]
                    if let Some(secs) = std::env::var("KEYVAULT_AUTOLOCK_TEST_SECS")
                        .ok()
                        .and_then(|v| v.parse().ok())
                    {
                        limit = Duration::from_secs(secs);
                    }
                    if this.master.is_some()
                        && mins > 0
                        && !this.busy
                        && this.last_activity.elapsed() > limit
                    {
                        this.lock_vault(window, cx);
                    }
                })
                .is_ok();
            if !alive {
                break;
            }
        }));
    }

    fn after_unlock(&mut self, mk: MasterKey, window: &mut Window, cx: &mut Context<Self>) {
        self.master = Some(mk);
        self.touch();
        self.error = None;
        clear(&self.inputs.lock_pw, window, cx);
        clear(&self.inputs.recovery_in, window, cx);
        self.use_recovery = false;
        let next = self.first_panel();
        self.nav_seq += 1;
        self.panel = Panel::Welcome;
        self.go(next, window, cx);
        window.focus(&self.focus, cx);
    }

    // ── unlocking ─────────────────────────────────────────────────────────

    pub(super) fn unlock_biometric(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (Some(kr), Some(_)) = (self.keyring(), self.biometric_label()) else {
            return;
        };
        if self.busy {
            return;
        }
        let vault_id = kr.vault_id.to_string();
        self.run_slow(
            window,
            cx,
            move || -> Result<MasterKey, String> {
                os_unlock::authenticate("unlock your wallet vault")?;
                let dk = os_unlock::load_device_key(&vault_id)?;
                kr.open_device(&dk).map_err(|e| e.to_string())
            },
            |this, result, window, cx| match result {
                Ok(mk) => this.after_unlock(mk, window, cx),
                Err(e) => this.error = Some(e.into()),
            },
        );
    }

    pub(super) fn unlock_passphrase(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(kr) = self.keyring() else { return };
        if self.busy {
            return;
        }
        let pw = read_secret(&self.inputs.lock_pw, cx);
        if pw.is_empty() {
            return self.fail("Enter your passphrase.", cx);
        }
        self.run_slow(
            window,
            cx,
            move || kr.open_passphrase(&pw),
            |this, result, window, cx| match result {
                Ok(mk) => this.after_unlock(mk, window, cx),
                Err(VaultError::WrongPassword) => {
                    this.error = Some("Wrong passphrase.".into());
                    focus(&this.inputs.lock_pw, window, cx);
                }
                Err(e) => this.error = Some(e.to_string().into()),
            },
        );
    }

    pub(super) fn unlock_recovery(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(kr) = self.keyring() else { return };
        if self.busy {
            return;
        }
        let code = read_secret(&self.inputs.recovery_in, cx);
        self.run_slow(
            window,
            cx,
            move || kr.open_recovery(&code),
            |this, result, window, cx| match result {
                Ok(mk) => {
                    this.after_unlock(mk, window, cx);
                    this.must_reset_passphrase = true;
                    this.go(Panel::Settings, window, cx);
                    window.push_notification(
                        Notification::warning(
                            "Unlocked with your recovery key. Set a new passphrase now.",
                        ),
                        cx,
                    );
                }
                Err(e) => this.error = Some(e.to_string().into()),
            },
        );
    }

    // ── first-run setup ───────────────────────────────────────────────────

    pub(super) fn setup_create(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy || !matches!(self.setup, Some(SetupStep::Passphrase)) {
            return;
        }
        let pw = read_secret(&self.inputs.setup_pw, cx);
        let confirm = read_secret(&self.inputs.setup_pw2, cx);
        if let Err(e) = check_new_password(&pw, &confirm) {
            return self.fail(e.to_string().replace("password", "passphrase"), cx);
        }
        drop(confirm);
        self.run_slow(
            window,
            cx,
            move || Keyring::create(&pw),
            |this, result, window, cx| match result
                .and_then(|(kr, mk, code)| this.vault_mut()?.set_keyring(kr).map(|_| (mk, code)))
            {
                Ok((mk, code)) => {
                    clear(&this.inputs.setup_pw, window, cx);
                    clear(&this.inputs.setup_pw2, window, cx);
                    this.master = Some(mk);
                    this.touch();
                    this.setup = Some(SetupStep::Recovery(code));
                    this.nav_seq += 1;
                }
                Err(e) => this.error = Some(e.to_string().into()),
            },
        );
    }

    pub(super) fn setup_recovery_saved(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.nav_seq += 1;
        if os_unlock::backend().is_some() {
            self.setup = Some(SetupStep::Biometric);
            cx.notify();
        } else {
            self.setup_finish(window, cx);
        }
    }

    pub(super) fn setup_finish(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.setup = None;
        self.error = None;
        let next = self.first_panel();
        self.nav_seq += 1;
        self.go(next, window, cx);
        let legacy = self.legacy_count();
        if legacy > 0 {
            window.push_notification(
                Notification::info(format!(
                    "{legacy} wallet(s) still use their own password. Move them to vault unlock in Settings."
                )),
                cx,
            );
        }
    }

    // ── Touch ID / Windows Hello ──────────────────────────────────────────

    pub(super) fn enable_biometric(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (Some(backend), Some(kr), Some(mk)) =
            (os_unlock::backend(), self.keyring(), self.master.clone())
        else {
            return;
        };
        if self.busy {
            return;
        }
        let vault_id = kr.vault_id.to_string();
        self.run_slow(
            window,
            cx,
            move || -> Result<Keyring, String> {
                os_unlock::authenticate(&format!("turn on {} unlock", backend.label))?;
                let dk = generate_device_key();
                os_unlock::store_device_key(&vault_id, &dk)?;
                // Read it back before relying on it.
                let check = os_unlock::load_device_key(&vault_id)?;
                if *check != *dk {
                    return Err("the system keychain didn't keep the key".into());
                }
                kr.with_device(&mk, &dk, backend.platform, backend.label)
                    .map_err(|e| e.to_string())
            },
            move |this, result, window, cx| match result.and_then(|kr| {
                this.vault_mut()
                    .and_then(|v| v.set_keyring(kr))
                    .map_err(|e| e.to_string())
            }) {
                Ok(()) => {
                    window.push_notification(
                        Notification::success(format!("{} unlock is on.", backend.label)),
                        cx,
                    );
                    if this.setup.is_some() {
                        this.setup_finish(window, cx);
                    }
                }
                Err(e) => this.error = Some(e.into()),
            },
        );
    }

    pub(super) fn disable_biometric(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(kr) = self.keyring() else { return };
        os_unlock::delete_device_key(&kr.vault_id.to_string());
        match self
            .vault_mut()
            .and_then(|v| v.set_keyring(kr.without_device()))
        {
            Ok(()) => window.push_notification(
                Notification::info("Biometric unlock is off. Use your passphrase."),
                cx,
            ),
            Err(e) => self.error = Some(e.to_string().into()),
        }
        cx.notify();
    }

    // ── settings actions ──────────────────────────────────────────────────

    pub(super) fn set_auto_lock(&mut self, mins: u32, cx: &mut Context<Self>) {
        self.auto_lock_mins = mins;
        crate::theme::set_pref(&self.path, "auto_lock_mins", serde_json::json!(mins));
        cx.notify();
    }

    pub(super) fn set_confirm_secrets(&mut self, on: bool, cx: &mut Context<Self>) {
        self.confirm_secrets = on;
        crate::theme::set_pref(&self.path, "confirm_secrets", serde_json::json!(on));
        cx.notify();
    }

    pub(super) fn change_master_passphrase(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (Some(kr), Some(mk)) = (self.keyring(), self.master.clone()) else {
            return;
        };
        if self.busy {
            return;
        }
        let skip_current = self.must_reset_passphrase;
        let current = read_secret(&self.inputs.pass_cur, cx);
        let new = read_secret(&self.inputs.pass_new, cx);
        let confirm = read_secret(&self.inputs.pass_new2, cx);
        if !skip_current && current.is_empty() {
            return self.fail("Enter your current passphrase.", cx);
        }
        if let Err(e) = check_new_password(&new, &confirm) {
            return self.fail(e.to_string().replace("password", "passphrase"), cx);
        }
        self.run_slow(
            window,
            cx,
            move || {
                if !skip_current {
                    kr.open_passphrase(&current)?;
                }
                kr.with_passphrase(&mk, &new)
            },
            |this, result, window, cx| match result.and_then(|kr| this.vault_mut()?.set_keyring(kr))
            {
                Ok(()) => {
                    this.must_reset_passphrase = false;
                    for i in [
                        &this.inputs.pass_cur,
                        &this.inputs.pass_new,
                        &this.inputs.pass_new2,
                    ] {
                        clear(i, window, cx);
                    }
                    window.push_notification(Notification::success("Passphrase changed."), cx);
                }
                Err(VaultError::WrongPassword) => {
                    this.error = Some("Current passphrase is wrong.".into())
                }
                Err(e) => this.error = Some(e.to_string().into()),
            },
        );
    }

    pub(super) fn regenerate_recovery(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (Some(kr), Some(mk)) = (self.keyring(), self.master.clone()) else {
            return;
        };
        if self.busy {
            return;
        }
        let current = read_secret(&self.inputs.recovery_auth, cx);
        if current.is_empty() {
            return self.fail("Enter your passphrase to create a new recovery key.", cx);
        }
        self.run_slow(
            window,
            cx,
            move || {
                kr.open_passphrase(&current)?;
                kr.with_new_recovery(&mk)
            },
            |this, result, window, cx| match result
                .and_then(|(kr, code)| this.vault_mut()?.set_keyring(kr).map(|_| code))
            {
                Ok(code) => {
                    clear(&this.inputs.recovery_auth, window, cx);
                    this.recovery_shown = Some(code);
                }
                Err(VaultError::WrongPassword) => this.error = Some("Passphrase is wrong.".into()),
                Err(e) => this.error = Some(e.to_string().into()),
            },
        );
    }

    /// Try one password on every password-locked wallet; move the ones it
    /// opens to vault unlock. (Generated batches share a password, so one
    /// entry usually moves a whole batch.)
    pub(super) fn migrate_wallets(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(mk) = self.master.clone() else {
            return;
        };
        if self.busy {
            return;
        }
        let pw = read_secret(&self.inputs.migrate_pw, cx);
        if pw.is_empty() {
            return self.fail("Enter a password one of those wallets uses.", cx);
        }
        let legacy: Vec<WalletEntry> = self
            .all()
            .iter()
            .filter(|w| w.needs_password())
            .cloned()
            .collect();
        let total = legacy.len();
        self.run_slow(
            window,
            cx,
            move || {
                let threads = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(2)
                    .clamp(1, 6);
                let chunk = legacy.len().div_ceil(threads).max(1);
                std::thread::scope(|s| {
                    let handles: Vec<_> = legacy
                        .chunks(chunk)
                        .map(|c| {
                            let (pw, mk) = (&pw, &mk);
                            s.spawn(move || {
                                c.iter()
                                    .filter_map(|w| w.to_vault(pw, mk).ok())
                                    .collect::<Vec<_>>()
                            })
                        })
                        .collect();
                    handles
                        .into_iter()
                        .flat_map(|h| h.join().unwrap_or_default())
                        .collect::<Vec<_>>()
                })
            },
            move |this, moved, window, cx| {
                let n = moved.len();
                if n == 0 {
                    this.error = Some("That password didn't open any of them.".into());
                    return;
                }
                match this.vault_mut().and_then(|v| v.replace_many(moved)) {
                    Ok(_) => {
                        clear(&this.inputs.migrate_pw, window, cx);
                        window.push_notification(
                            Notification::success(format!(
                                "Moved {n} of {total} wallet(s) to vault unlock."
                            )),
                            cx,
                        );
                    }
                    Err(e) => this.error = Some(e.to_string().into()),
                }
            },
        );
    }

    // ── screens ───────────────────────────────────────────────────────────

    fn centered_card(&self, p: &Palette, content: Div) -> Div {
        div()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .child(
                ui::glass(p)
                    .w(px(440.))
                    .rounded(px(28.))
                    .p_8()
                    .flex()
                    .flex_col()
                    .gap_5()
                    .child(content),
            )
    }

    fn brand(p: &Palette) -> Div {
        h_flex()
            .gap_2p5()
            .child(
                div()
                    .size_9()
                    .rounded(px(11.))
                    .flex()
                    .items_center()
                    .justify_center()
                    .bg(p.primary)
                    .text_color(p.primary_fg)
                    .child(Icon::new(Lucide::KeyRound).small()),
            )
            .child(
                div()
                    .font_family(crate::theme::DISPLAY_FONT)
                    .text_lg()
                    .font_medium()
                    .child("KeyVault"),
            )
    }

    pub(super) fn render_lock(&self, p: &Palette, cx: &mut Context<Self>) -> Div {
        let bio = self.biometric_label();
        let mut col = v_flex().gap_5().child(Self::brand(p)).child(
            v_flex().gap_1().child(ui::display("Locked")).child(
                div().text_sm().text_color(p.secondary).child(match bio {
                    Some(label) => format!("Unlock with {label} or your passphrase."),
                    None => "Enter your passphrase to open your wallets.".into(),
                }),
            ),
        );

        if let (Some(label), false) = (bio, self.use_recovery) {
            col = col
                .child(
                    ui::glow_button(
                        p,
                        "unlock-bio",
                        Some(Lucide::ScanFace),
                        if self.busy {
                            "Waiting for you…".to_string()
                        } else {
                            format!("Unlock with {label}")
                        },
                        self.busy,
                        false,
                        cx.listener(|this, _, window, cx| this.unlock_biometric(window, cx)),
                    )
                    .w_full(),
                )
                .child(
                    h_flex()
                        .gap_3()
                        .text_xs()
                        .text_color(p.muted)
                        .child(div().flex_1().h_px().bg(p.border))
                        .child("or")
                        .child(div().flex_1().h_px().bg(p.border)),
                );
        }

        if self.use_recovery {
            col = col
                .child(Self::field(
                    "Recovery key",
                    Some(
                        "The 32-character key you saved at setup. Dashes and case don't matter."
                            .into(),
                    ),
                    ui::input(&self.inputs.recovery_in).mask_toggle(),
                    p,
                ))
                .child(
                    ui::glow_button(
                        p,
                        "unlock-recovery",
                        Some(Lucide::KeyRound),
                        "Unlock with recovery key",
                        self.busy,
                        false,
                        cx.listener(|this, _, window, cx| this.unlock_recovery(window, cx)),
                    )
                    .w_full(),
                );
        } else {
            col = col.child(
                h_flex()
                    .gap_2()
                    .child(
                        div().flex_1().min_w_0().child(
                            ui::input(&self.inputs.lock_pw)
                                .mask_toggle()
                                .disabled(self.busy),
                        ),
                    )
                    .child(
                        ui::button("unlock-pass")
                            .when(bio.is_some(), |b| b.outline())
                            .when(bio.is_none(), |b| b.primary())
                            .label("Unlock")
                            .loading(self.busy && bio.is_none())
                            .disabled(self.busy)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.unlock_passphrase(window, cx)
                            })),
                    ),
            );
        }

        col = col.children(self.render_error(p)).child(
            h_flex()
                .justify_between()
                .child(
                    ui::text_link(
                        "toggle-recovery",
                        if self.use_recovery {
                            "Use passphrase instead"
                        } else {
                            "Forgot passphrase?"
                        },
                        p,
                    )
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.use_recovery = !this.use_recovery;
                        this.error = None;
                        if this.use_recovery {
                            focus(&this.inputs.recovery_in, window, cx);
                        } else {
                            focus(&this.inputs.lock_pw, window, cx);
                        }
                        cx.notify();
                    })),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(p.muted)
                        .child(format!("{} wallets", self.all().len())),
                ),
        );
        self.centered_card(p, col)
    }

    pub(super) fn render_setup(&self, p: &Palette, cx: &mut Context<Self>) -> Div {
        let bio = os_unlock::backend();
        let (step, total) = (
            match self.setup {
                Some(SetupStep::Passphrase) | None => 1,
                Some(SetupStep::Recovery(_)) => 2,
                Some(SetupStep::Biometric) => 3,
            },
            if bio.is_some() { 3 } else { 2 },
        );
        let steps = h_flex().gap_1p5().children((1..=total).map(|i| {
            div()
                .h(px(4.))
                .flex_1()
                .rounded_full()
                .bg(if i <= step { p.primary } else { p.border })
        }));

        let body = match &self.setup {
            Some(SetupStep::Passphrase) | None => {
                let legacy = self.legacy_count();
                v_flex()
                    .gap_5()
                    .child(
                        v_flex().gap_2().child(ui::display("Secure your vault")).child(div().text_sm().text_color(p.secondary).child(
                            match bio {
                                Some(b) => format!(
                                    "One passphrase protects every wallet — no more password per wallet. Day to day you'll unlock with {}.",
                                    b.label
                                ),
                                None => "One passphrase protects every wallet — no more password per wallet.".into(),
                            },
                        )),
                    )
                    .child(Self::field(
                        "Passphrase",
                        Some("At least 8 characters. A few random words is ideal.".into()),
                        ui::input(&self.inputs.setup_pw).mask_toggle(),
                        p,
                    ))
                    .child(Self::field("Confirm passphrase", None, ui::input(&self.inputs.setup_pw2).mask_toggle(), p))
                    .when(legacy > 0, |d| {
                        d.child(div().text_xs().text_color(p.muted).child(format!(
                            "Your {legacy} existing wallet(s) keep their own passwords until you move them (Settings)."
                        )))
                    })
                    .children(self.render_error(p))
                    .child(
                        ui::glow_button(
                            p,
                            "setup-continue",
                            Some(IconName::ArrowRight),
                            if self.busy { "Creating vault key…" } else { "Continue" },
                            self.busy,
                            false,
                            cx.listener(|this, _, window, cx| this.setup_create(window, cx)),
                        )
                        .w_full(),
                    )
            }
            Some(SetupStep::Recovery(code)) => {
                let copy = code.to_string();
                v_flex()
                    .gap_5()
                    .child(
                        v_flex().gap_2().child(ui::display("Save your recovery key")).child(
                            div()
                                .text_sm()
                                .text_color(p.secondary)
                                .child("If you forget your passphrase, this is the only way back in. Write it down or keep it in a password manager — offline is best."),
                        ),
                    )
                    .child(
                        div()
                            .px_5()
                            .py_4()
                            .rounded(px(16.))
                            .border_1()
                            .border_color(p.border)
                            .bg(if p.dark { hsla(0., 0., 0., 0.3) } else { hsla(0., 0., 1., 0.8) })
                            .font_family(p.mono.clone())
                            .text_lg()
                            .line_height(px(30.))
                            .text_center()
                            .child(code.get(..19).unwrap_or(code.as_str()).to_string())
                            .child(code.get(20..).unwrap_or("").to_string()),
                    )
                    .child(
                        h_flex()
                            .gap_2()
                            .child(
                                ui::action("copy-recovery")
                                    .outline()
                                    .icon(IconName::Copy)
                                    .label("Copy")
                                    .on_click(cx.listener(move |_, _, window, cx| {
                                        cx.write_to_clipboard(ClipboardItem::new_string(copy.clone()));
                                        window.push_notification(Notification::info("Recovery key copied — clear your clipboard after saving it."), cx);
                                    })),
                            )
                            .child(div().flex_1())
                            .child(ui::glow_button(
                                p,
                                "recovery-saved",
                                Some(IconName::Check),
                                "I've saved it",
                                false,
                                false,
                                cx.listener(|this, _, window, cx| this.setup_recovery_saved(window, cx)),
                            )),
                    )
            }
            Some(SetupStep::Biometric) => {
                let label = bio.map(|b| b.label).unwrap_or("biometrics");
                v_flex()
                    .gap_5()
                    .child(
                        v_flex().gap_2().child(ui::display(format!("Turn on {label}?"))).child(
                            div().text_sm().text_color(p.secondary).child(format!(
                                "Open KeyVault with a touch instead of typing. Your passphrase and recovery key keep working, and you can turn this off in Settings."
                            )),
                        ),
                    )
                    .children(self.render_error(p))
                    .child(
                        ui::glow_button(
                            p,
                            "setup-bio",
                            Some(Lucide::ScanFace),
                            if self.busy { "Waiting for you…".to_string() } else { format!("Turn on {label}") },
                            self.busy,
                            false,
                            cx.listener(|this, _, window, cx| this.enable_biometric(window, cx)),
                        )
                        .w_full(),
                    )
                    .child(
                        ui::action("setup-skip")
                            .ghost()
                            .label("Not now")
                            .disabled(self.busy)
                            .on_click(cx.listener(|this, _, window, cx| this.setup_finish(window, cx))),
                    )
            }
        };

        self.centered_card(
            p,
            v_flex()
                .gap_6()
                .child(
                    h_flex().justify_between().child(Self::brand(p)).child(
                        div()
                            .text_xs()
                            .text_color(p.muted)
                            .child(format!("Step {step} of {total}")),
                    ),
                )
                .child(steps)
                .child(enter(
                    body,
                    SharedString::from(format!("setup-{}", self.nav_seq)),
                    240,
                    0,
                )),
        )
    }

    fn settings_card(title: &'static str, desc: impl Into<SharedString>, p: &Palette) -> Div {
        ui::glass(p)
            .rounded(px(ui::R_CARD))
            .p_5()
            .flex()
            .flex_col()
            .gap_4()
            .min_w_0()
            .child(
                v_flex()
                    .gap_1()
                    .child(div().text_base().font_medium().child(title))
                    .child(div().text_sm().text_color(p.secondary).child(desc.into())),
            )
    }

    pub(super) fn render_settings(&self, p: &Palette, cx: &mut Context<Self>) -> Div {
        let backend = os_unlock::backend();
        let bio_on = self.biometric_label().is_some();

        // Biometric
        let bio_card = match backend {
            None => Self::settings_card(
                "Fingerprint unlock",
                "Not available on this system — KeyVault unlocks with your passphrase here. (Touch ID on macOS, Windows Hello on Windows.)",
                p,
            ),
            Some(b) => {
                let this = cx.entity().downgrade();
                let confirm_idx = if self.confirm_secrets { 0 } else { 1 };
                let (from, seq) = self.seg("confirm", confirm_idx);
                Self::settings_card(
                    b.label,
                    if bio_on {
                        format!("On. KeyVault opens with {} — your passphrase still works.", b.label)
                    } else {
                        format!("Open KeyVault with {} instead of typing your passphrase.", b.label)
                    },
                    p,
                )
                                .child(h_flex().child(if bio_on {
                    ui::action("bio-off")
                        .outline()
                        .label(format!("Turn off {}", b.label))
                        .disabled(self.busy)
                        .on_click(cx.listener(|this, _, window, cx| this.disable_biometric(window, cx)))
                        .into_any_element()
                } else {
                    ui::glow_button(
                        p,
                        "bio-on",
                        Some(Lucide::ScanFace),
                        format!("Turn on {}", b.label),
                        self.busy,
                        false,
                        cx.listener(|this, _, window, cx| this.enable_biometric(window, cx)),
                    )
                    .into_any_element()
                }))
                .when(bio_on, |d| {
                    d.child(
                        v_flex()
                            .gap_2()
                            .child(div().text_sm().child(format!("Ask for {} again before showing, copying, sending or exporting keys", b.label)))
                            .child(segmented(
                                "confirm",
                                vec![
                                    Segment { label: "Ask every time".into(), leading: None },
                                    Segment { label: "Only to unlock".into(), leading: None },
                                ],
                                confirm_idx,
                                from,
                                seq,
                                p,
                                move |i, _, cx| {
                                    this.update(cx, |this, cx| {
                                        this.seg_moved("confirm", confirm_idx);
                                        this.set_confirm_secrets(i == 0, cx);
                                    })
                                    .ok();
                                },
                            )),
                    )
                })
            }
        };

        // Auto-lock
        let lock_card = {
            let this = cx.entity().downgrade();
            let idx = AUTO_LOCK_CHOICES
                .iter()
                .position(|m| *m == self.auto_lock_mins)
                .unwrap_or(1);
            let (from, seq) = self.seg("autolock", idx);
            Self::settings_card(
                "Auto-lock",
                "Lock the vault after a period without activity.",
                p,
            )
            .child(segmented(
                "autolock",
                ["5 min", "15 min", "1 hour", "Never"]
                    .iter()
                    .map(|l| Segment {
                        label: (*l).into(),
                        leading: None,
                    })
                    .collect(),
                idx,
                from,
                seq,
                p,
                move |i, _, cx| {
                    this.update(cx, |this, cx| {
                        this.seg_moved("autolock", idx);
                        this.set_auto_lock(AUTO_LOCK_CHOICES[i], cx);
                    })
                    .ok();
                },
            ))
            .child(
                h_flex().child(
                    ui::action("lock-now")
                        .outline()
                        .icon(Lucide::Lock)
                        .label("Lock now")
                        .on_click(cx.listener(|this, _, window, cx| this.lock_vault(window, cx))),
                ),
            )
        };

        // Passphrase
        let reset = self.must_reset_passphrase;
        let pass_card = Self::settings_card(
            "Passphrase",
            if reset {
                "You unlocked with your recovery key. Choose a new passphrase now."
            } else {
                "Change the passphrase that protects the vault key. Wallets don't need re-encrypting."
            },
            p,
        )
        .when(!reset, |d| d.child(Self::field("Current passphrase", None, ui::input(&self.inputs.pass_cur).mask_toggle(), p)))
        .child(
            h_flex()
                .gap_3()
                .items_start()
                .child(div().w(relative(0.5)).child(Self::field("New passphrase", None, ui::input(&self.inputs.pass_new).mask_toggle(), p)))
                .child(div().w(relative(0.5)).child(Self::field("Confirm", None, ui::input(&self.inputs.pass_new2).mask_toggle(), p))),
        )
        .child(
                        h_flex().child(ui::glow_button(
                p,
                "change-pass",
                Some(IconName::Check),
                if self.busy { "Changing…" } else { "Change passphrase" },
                self.busy,
                false,
                cx.listener(|this, _, window, cx| this.change_master_passphrase(window, cx)),
            )),
        );

        // Recovery key
        let recovery_card = match &self.recovery_shown {
            Some(code) => {
                let copy = code.to_string();
                Self::settings_card(
                    "New recovery key",
                    "Save it now — it won't be shown again. The old key no longer works.",
                    p,
                )
                .child(
                    div()
                        .px_4()
                        .py_3()
                        .rounded(px(14.))
                        .border_1()
                        .border_color(p.border)
                        .font_family(p.mono.clone())
                        .text_base()
                        .child(code.to_string()),
                )
                .child(
                    h_flex()
                        .gap_2()
                        .child(
                            ui::action("copy-new-recovery")
                                .outline()
                                .icon(IconName::Copy)
                                .label("Copy")
                                .on_click(cx.listener(move |_, _, window, cx| {
                                    cx.write_to_clipboard(ClipboardItem::new_string(copy.clone()));
                                    window.push_notification(
                                        Notification::info("Recovery key copied."),
                                        cx,
                                    );
                                })),
                        )
                        .child(ui::glow_button(
                            p,
                            "recovery-done",
                            Some(IconName::Check),
                            "I've saved it",
                            false,
                            false,
                            cx.listener(|this, _, _, cx| {
                                this.recovery_shown = None;
                                cx.notify();
                            }),
                        )),
                )
            }
            None => Self::settings_card(
                "Recovery key",
                "Lost it, or think someone saw it? Create a new one; the old one stops working.",
                p,
            )
            .child(
                h_flex()
                    .gap_2()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(ui::input(&self.inputs.recovery_auth).mask_toggle()),
                    )
                    .child(
                        ui::button("new-recovery")
                            .outline()
                            .icon(IconName::RefreshCw)
                            .label("Create new key")
                            .disabled(self.busy)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.regenerate_recovery(window, cx)
                            })),
                    ),
            ),
        };

        let legacy = self.legacy_count();
        let migrate_card = (legacy > 0).then(|| {
            Self::settings_card(
                "Wallets with their own password",
                format!(
                    "{legacy} wallet(s) still ask for their own password. Enter a password you used — every wallet it opens moves to vault unlock. Generated batches share one password, so one entry usually moves the whole batch."
                ),
                p,
            )
            .child(
                h_flex()
                    .gap_2()
                    .child(div().flex_1().min_w_0().child(ui::input(&self.inputs.migrate_pw).mask_toggle()))
                    .child(
                        ui::button("migrate")
                            .primary()
                            .label(if self.busy { "Moving…" } else { "Move wallets" })
                            .loading(self.busy)
                            .disabled(self.busy)
                            .on_click(cx.listener(|this, _, window, cx| this.migrate_wallets(window, cx))),
                    ),
            )
        });

        let theme_card = {
            let this = cx.entity().downgrade();
            let current = crate::theme::current();
            let idx = crate::theme::Flavor::ALL
                .iter()
                .position(|f| *f == current)
                .unwrap_or(3);
            let (from, seq) = self.seg("flavor", idx);
            Self::settings_card(
                "Theme",
                "Catppuccin — Latte is light; Frappé, Macchiato and Mocha are dark.",
                p,
            )
            .child(segmented(
                "flavor",
                crate::theme::Flavor::ALL
                    .iter()
                    .map(|f| Segment {
                        label: f.label().into(),
                        leading: None,
                    })
                    .collect(),
                idx,
                from,
                seq,
                p,
                move |i, window, cx| {
                    this.update(cx, |this, cx| {
                        this.seg_moved("flavor", idx);
                        this.set_flavor(crate::theme::Flavor::ALL[i], window, cx);
                    })
                    .ok();
                },
            ))
        };

        let (first, pass_card) = if reset {
            (Some(pass_card), None)
        } else {
            (None, Some(pass_card))
        };
        v_flex()
            .gap_5()
            .w_full()
            .max_w(px(ui::FORM_W))
            .child(Self::header(
                "Settings",
                "How your vault unlocks and stays locked.",
                p,
            ))
            .children(self.render_error(p))
            .children(first)
            .child(theme_card)
            .child(bio_card)
            .child(lock_card)
            .children(migrate_card)
            .children(pass_card)
            .child(recovery_card)
    }
}
