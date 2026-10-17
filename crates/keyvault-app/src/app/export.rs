//! Export wallets to CSV or TXT for importing into other wallets / tools.

use super::*;
use vault_core::export::{self as fmt, Field, Format, Options, Row};

const SEPARATORS: [(&str, &str); 4] = [
    (":", "Colon  :"),
    (",", "Comma  ,"),
    ("\t", "Tab"),
    (" ", "Space"),
];

#[derive(Clone)]
pub(super) struct ExportState {
    pub csv: bool,
    pub header: bool,
    pub sep: usize,
    pub fields: Vec<Field>,
    pub strip_0x: bool,
    /// 0 = selected wallets, 1 = current view, 2 = everything.
    pub scope: usize,
}

impl Default for ExportState {
    fn default() -> Self {
        ExportState {
            csv: true,
            header: true,
            sep: 0,
            fields: vec![Field::Address, Field::PrivateKey],
            strip_0x: false,
            scope: 2,
        }
    }
}

impl ExportState {
    fn options(&self) -> Options {
        Options {
            format: if self.csv {
                Format::Csv {
                    header: self.header,
                }
            } else {
                Format::Txt {
                    sep: SEPARATORS[self.sep].0,
                }
            },
            strip_0x: self.strip_0x,
        }
    }

    fn includes_keys(&self) -> bool {
        self.fields.contains(&Field::PrivateKey)
    }
}

impl KeyVaultApp {
    // ── selection mode in the list ────────────────────────────────────────

    pub(super) fn toggle_select_mode(&mut self, cx: &mut Context<Self>) {
        self.select_mode = !self.select_mode;
        if !self.select_mode {
            self.selected.clear();
        }
        self.list_seq += 1;
        cx.notify();
    }

    pub(super) fn toggle_selected(&mut self, id: Uuid, cx: &mut Context<Self>) {
        if !self.selected.remove(&id) {
            self.selected.insert(id);
        }
        cx.notify();
    }

    pub(super) fn select_all_visible(&mut self, cx: &mut Context<Self>) {
        let ids: Vec<Uuid> = self.visible(cx).iter().map(|w| w.id).collect();
        let all_on = ids.iter().all(|id| self.selected.contains(id));
        for id in ids {
            if all_on {
                self.selected.remove(&id);
            } else {
                self.selected.insert(id);
            }
        }
        cx.notify();
    }

    pub(super) fn open_export(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.export.scope = if self.selected.is_empty() { 1 } else { 0 };
        self.go(Panel::Export, window, cx);
    }

    /// Wallets in scope, in the same order as the list on screen.
    fn export_wallets(&self, cx: &App) -> Vec<WalletEntry> {
        let mut list: Vec<WalletEntry> = match self.export.scope {
            0 => self
                .all()
                .iter()
                .filter(|w| self.selected.contains(&w.id))
                .cloned()
                .collect(),
            1 => return self.visible(cx),
            _ => self.all().to_vec(),
        };
        self.sort_like_list(&mut list, "");
        list
    }

    // ── run ───────────────────────────────────────────────────────────────

    pub(super) fn run_export(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        let wallets = self.export_wallets(cx);
        if wallets.is_empty() {
            return self.fail("No wallets to export — pick some first.", cx);
        }
        if self.export.fields.is_empty() {
            return self.fail("Choose at least one field.", cx);
        }
        let Some(mk) = self.master.clone() else {
            return;
        };
        let ext = if self.export.csv { "csv" } else { "txt" };
        let name = format!("keyvault-export-{}.{ext}", time_stamp());
        let dir = dirs_home().join("Downloads");
        let dir = if dir.is_dir() { dir } else { dirs_home() };
        let fallback = dir.join(&name);
        let rx = cx.prompt_for_new_path(&dir, Some(&name));
        cx.spawn_in(window, async move |this, cx| {
            let path = match rx.await {
                Ok(Ok(Some(path))) => path,
                Ok(Ok(None)) => return, // cancelled
                // No file dialog available (e.g. minimal Linux desktop): save to Downloads.
                _ => fallback,
            };
            this.update_in(cx, |this, window, cx| {
                this.write_export(path, wallets, mk, window, cx)
            })
            .ok();
        })
        .detach();
    }

    fn write_export(
        &mut self,
        path: PathBuf,
        wallets: Vec<WalletEntry>,
        mk: MasterKey,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let state = self.export.clone();
        let fields = state.fields.clone();
        let opts = state.options();
        let with_keys = state.includes_keys();
        let confirm = with_keys && self.reconfirm().is_some();
        let extra_pw = read_secret(&self.inputs.export_pw, cx);
        let n = wallets.len();
        let shown_path = path.display().to_string();

        self.run_slow(
            window,
            cx,
            move || -> Result<Vec<String>, String> {
                if confirm {
                    crate::os_unlock::authenticate(&format!("export {n} private keys"))?;
                }
                let mut skipped = Vec::new();
                let secrets: Vec<Option<Zeroizing<String>>> = wallets
                    .iter()
                    .map(|w| {
                        if !with_keys {
                            return None;
                        }
                        let s = if w.needs_password() {
                            (!extra_pw.is_empty()).then(|| w.unseal(&extra_pw).ok()).flatten()
                        } else {
                            w.unseal_vault(&mk).ok()
                        };
                        if s.is_none() {
                            skipped.push(w.label.clone());
                        }
                        s
                    })
                    .collect();
                let rows: Vec<Row> = wallets.iter().zip(secrets).map(|(wallet, secret)| Row { wallet, secret }).collect();
                let out = fmt::render(&rows, &fields, &opts);
                vault_core::store::write_atomic(&path, out.as_bytes()).map_err(|e| e.to_string())?;
                Ok(skipped)
            },
            move |this, result, window, cx| match result {
                Ok(skipped) => {
                    clear(&this.inputs.export_pw, window, cx);
                    window.push_notification(Notification::success(format!("Exported {n} wallet(s) to {shown_path}")), cx);
                    if !skipped.is_empty() {
                        let names = skipped.iter().take(4).cloned().collect::<Vec<_>>().join(", ");
                        let more = if skipped.len() > 4 { format!(" and {} more", skipped.len() - 4) } else { String::new() };
                        window.push_notification(
                            Notification::warning(format!(
                                "{} wallet(s) have an extra lock and were exported without their key: {names}{more}.",
                                skipped.len()
                            )),
                            cx,
                        );
                    }
                }
                Err(e) => this.error = Some(e.into()),
            },
        );
    }

    // ── panel ─────────────────────────────────────────────────────────────

    pub(super) fn render_export(&self, p: &Palette, cx: &mut Context<Self>) -> Div {
        let wallets = self.export_wallets(cx);
        let (n_sel, n_view, n_all) = (
            self.selected.len(),
            self.visible(cx).len(),
            self.all().len(),
        );
        let st = &self.export;
        let locked_in_scope = wallets.iter().filter(|w| w.needs_password()).count();

        // Scope. The "current view" option only appears when the view is
        // actually narrower than the whole vault; otherwise it would just
        // repeat "All".
        let scope = {
            let this = cx.entity().downgrade();
            let mut options: Vec<(usize, String)> = vec![(0, format!("Selected · {n_sel}"))];
            if n_view != n_all {
                options.push((1, format!("{} · {n_view}", self.filter.title())));
            }
            options.push((2, format!("All wallets · {n_all}")));
            let current = if st.scope == 1 && n_view == n_all { 2 } else { st.scope };
            let idx = options.iter().position(|(s, _)| *s == current).unwrap_or(0);
            let map: Vec<usize> = options.iter().map(|(s, _)| *s).collect();
            let (from, seq) = self.seg("export-scope", idx);
            segmented(
                "export-scope",
                options
                    .into_iter()
                    .map(|(_, label)| Segment { label: label.into(), leading: None })
                    .collect(),
                idx,
                from,
                seq,
                p,
                move |i, _, cx| {
                    let scope = map[i];
                    this.update(cx, |this, cx| {
                        this.seg_moved("export-scope", idx);
                        this.export.scope = scope;
                        cx.notify();
                    })
                    .ok();
                },
            )
        };

        // Fields (toggle chips, output order is fixed)
        let chips = Field::ALL
            .into_iter()
            .map(|f| {
                let on = st.fields.contains(&f);
                let (fg, bg, border, secondary) = (p.fg, p.bg, p.border, p.secondary);
                h_flex()
                    .id(SharedString::from(format!("field-{}", f.column())))
                    .gap_1p5()
                    .h(px(32.))
                    .px_3()
                    .rounded_full()
                    .border_1()
                    .cursor_pointer()
                    .text_sm()
                    .when(on, |d| d.bg(fg).text_color(bg).border_color(fg))
                    .when(!on, |d| {
                        d.border_color(border)
                            .text_color(secondary)
                            .hover(move |s| s.text_color(fg))
                    })
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if let Some(i) = this.export.fields.iter().position(|x| *x == f) {
                            this.export.fields.remove(i);
                        } else {
                            this.export.fields.push(f);
                        }
                        this.error = None;
                        cx.notify();
                    }))
                    .when(on, |d| d.child(Icon::new(IconName::Check).xsmall()))
                    .child(f.label())
            })
            .collect::<Vec<_>>();

        // Format
        let format = {
            let this = cx.entity().downgrade();
            let idx = if st.csv { 0 } else { 1 };
            let (from, seq) = self.seg("export-format", idx);
            segmented(
                "export-format",
                vec![
                    Segment {
                        label: "CSV".into(),
                        leading: None,
                    },
                    Segment {
                        label: "TXT".into(),
                        leading: None,
                    },
                ],
                idx,
                from,
                seq,
                p,
                move |i, _, cx| {
                    this.update(cx, |this, cx| {
                        this.seg_moved("export-format", idx);
                        this.export.csv = i == 0;
                        cx.notify();
                    })
                    .ok();
                },
            )
        };
        let format_option = if st.csv {
            let this = cx.entity().downgrade();
            let idx = if st.header { 0 } else { 1 };
            let (from, seq) = self.seg("export-header", idx);
            segmented(
                "export-header",
                vec![
                    Segment {
                        label: "With header row".into(),
                        leading: None,
                    },
                    Segment {
                        label: "No header".into(),
                        leading: None,
                    },
                ],
                idx,
                from,
                seq,
                p,
                move |i, _, cx| {
                    this.update(cx, |this, cx| {
                        this.seg_moved("export-header", idx);
                        this.export.header = i == 0;
                        cx.notify();
                    })
                    .ok();
                },
            )
            .into_any_element()
        } else {
            let this = cx.entity().downgrade();
            let idx = st.sep;
            let (from, seq) = self.seg("export-sep", idx);
            segmented(
                "export-sep",
                SEPARATORS
                    .iter()
                    .map(|(_, l)| Segment {
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
                        this.seg_moved("export-sep", idx);
                        this.export.sep = i;
                        cx.notify();
                    })
                    .ok();
                },
            )
            .into_any_element()
        };

        // Preview (keys masked — nothing is decrypted until you export)
        let masked: Vec<Row> = wallets
            .iter()
            .take(4)
            .map(|w| Row {
                wallet: w,
                secret: Some(Zeroizing::new(match w.chain {
                    Chain::Evm | Chain::Tron => "0x••••••••••••".into(),
                    _ => "••••••••••••".into(),
                })),
            })
            .collect();
        let preview = fmt::render(&masked, &st.fields, &st.options());
        let preview_text: String = preview
            .replace('\t', "  →  ")
            .replace("\r\n", "\n")
            .trim_end()
            .to_string();
        let more = wallets.len().saturating_sub(4);

        let with_keys = st.includes_keys();
        let action: AnyElement = if with_keys {
            self.hold_button(HoldKind::Export, "Hold to export", "Exporting…", p, cx)
                .into_any_element()
        } else {
            ui::glow_button(
                p,
                "export-go",
                Some(ui::Lucide::Download),
                format!("Export {} wallet(s)", wallets.len()),
                self.busy,
                wallets.is_empty() || st.fields.is_empty(),
                cx.listener(|this, _, window, cx| this.run_export(window, cx)),
            )
            .into_any_element()
        };

        v_flex()
            .gap_5()
            .w_full()
            .max_w(px(ui::WIDE_W))
            .child(Self::header(
                "Export wallets",
                "Save a CSV or TXT file in the shape another wallet or tool expects.",
                p,
            ))
            .child(v_flex().gap_2().child(ui::label("Wallets", p)).child(scope))
            .child(
                v_flex()
                    .gap_2()
                    .child(ui::label("Fields", p))
                    .child(h_flex().flex_wrap().gap_2().children(chips))
                    .when(with_keys, |d| {
                        let strip = st.strip_0x;
                                                d.child(
                            h_flex().pt_1().child(
                                h_flex()
                                    .id("strip0x")
                                    .gap_2()
                                    .text_sm()
                                    .cursor_pointer()
                                    .child(ui::check_box(strip, p))
                                    .child("Write EVM / Tron keys without the 0x prefix")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.export.strip_0x = !this.export.strip_0x;
                                        cx.notify();
                                    })),
                            ),
                        )
                    }),
            )
            .child(
                h_flex()
                    .gap_3()
                    .items_start()
                    .child(v_flex().w(relative(0.34)).gap_2().child(ui::label("Format", p)).child(format))
                    .child(
                        v_flex()
                            .w(relative(0.66))
                            .gap_2()
                            .child(ui::label(if st.csv { "Header" } else { "Separator" }, p))
                            .child(format_option),
                    ),
            )
            .child(
                v_flex()
                    .gap_2()
                    .child(
                        h_flex()
                            .justify_between()
                            .child(ui::label("Preview", p))
                            .child(div().text_xs().text_color(p.muted).child("keys masked")),
                    )
                    .child(
                        ui::glass(p)
                            .rounded(px(14.))
                            .px_4()
                            .py_3()
                            .min_w_0()
                            .overflow_hidden()
                            .min_h(px(64.))
                            .font_family(p.mono.clone())
                            .text_xs()
                            .line_height(px(20.))
                            .text_color(p.secondary)
                            .child(if preview_text.is_empty() { "Nothing to export yet.".to_string() } else { preview_text })
                            .when(more > 0, |d| d.child(div().text_color(p.muted).child(format!("… and {more} more")))),
                    ),
            )
            .when(with_keys && locked_in_scope > 0, |d| {
                d.child(Self::field(
                    "Extra-locked wallets",
                    Some(
                        if locked_in_scope == 1 {
                            "1 of these has its own password. Enter it to include its key; otherwise it's exported without a key.".to_string()
                        } else {
                            format!("{locked_in_scope} of these have their own password. Enter it to include their keys; otherwise they're exported without a key.")
                        }
                        .into(),
                    ),
                    ui::input(&self.inputs.export_pw).mask_toggle(),
                    p,
                ))
            })
            .when(with_keys, |d| {
                d.child(ui::callout(
                    IconName::TriangleAlert,
                    "The file will contain private keys in plain text. Anyone who gets it gets the funds — import it, then delete it.",
                    p.warning,
                ))
            })
            .children(self.render_error(p))
            .child(
                                h_flex()
                    .gap_4()
                    .child(action)
                    .child(div().text_sm().text_color(p.muted).child(format!(
                        "{} wallet(s) · {}",
                        wallets.len(),
                        if st.csv { "CSV" } else { "TXT" }
                    ))),
            )
    }
}
