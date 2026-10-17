//! Design primitives: palette, type, badges and motion.
//!
//! Visual language: paper / graphite neutrals with a single accent used
//! sparingly (selection, progress, focus), Inter for UI text and Geist for
//! display headings, weights 400–500 only, hairline borders instead of
//! shadows, and large concentric radii. Motion is spring-shaped and quick:
//! things glide to their new state instead of popping.

use std::time::Duration;

use gpui_kit::component::*;
use gpui_kit::prelude::*;
use gpui_kit::*;
use vault_core::Chain;

use crate::theme::DISPLAY_FONT;

/// Radii (concentric): controls 12, panels 18, cards 22, window surface 24.
pub const R_PANEL: f32 = 18.;
pub const R_CARD: f32 = 22.;
pub const R_SURFACE: f32 = 24.;

/// Height of every call-to-action row button (primary, hold, and the ghost /
/// outline buttons that sit next to them) so action rows line up.
pub const CTA_H: f32 = 38.;
/// Max width of form panels (add, edit, send, settings…).
pub const FORM_W: f32 = 600.;
/// Max width of wider read-only panels (wallet details, export).
pub const WIDE_W: f32 = 680.;

/// The full Lucide icon set (the component set lacks e.g. Pencil, Lock).
pub use gpui_kit::assets::IconName as Lucide;

/// Theme colours copied out of the global theme so we can keep using `cx`
/// mutably (for listeners) while building elements.
#[derive(Clone)]
pub struct Palette {
    pub bg: Hsla,
    pub surface: Hsla,
    #[allow(dead_code)]
    pub raised: Hsla,
    pub fg: Hsla,
    pub secondary: Hsla,
    pub muted: Hsla,
    pub muted_bg: Hsla,
    pub border: Hsla,
    pub accent: Hsla,
    pub accent_subtle: Hsla,
    pub list_hover: Hsla,
    pub danger: Hsla,
    pub success: Hsla,
    pub warning: Hsla,
    pub mono: SharedString,
    pub dark: bool,
    /// Catppuccin accent for primary actions (mauve) and the text on it.
    pub primary: Hsla,
    pub primary_fg: Hsla,
    /// Selected pill in segmented controls.
    pub highlight: Hsla,
}

impl Palette {
    pub fn of(cx: &App) -> Self {
        let t = cx.theme();
        Palette {
            bg: t.background,
            surface: t.secondary,
            raised: t.popover,
            fg: t.foreground,
            secondary: t.foreground.opacity(0.66),
            muted: t.muted_foreground,
            muted_bg: t.muted,
            border: t.border,
            accent: t.primary,
            accent_subtle: t.list_active,
            list_hover: t.list_hover,
            danger: t.danger,
            success: t.success,
            warning: t.warning,
            mono: t.mono_font_family.clone(),
            dark: t.is_dark(),
            primary: t.primary,
            primary_fg: t.primary_foreground,
            highlight: {
                let c = crate::theme::current().palette();
                rgb(if t.is_dark() { c.surface1 } else { c.base }).into()
            },
        }
    }
}

// ── motion ────────────────────────────────────────────────────────────────

/// Critically damped feel (no overshoot) — panels, progress, state changes.
pub fn ease_smooth(t: f32) -> f32 {
    1.0 - (1.0 - t).powi(4)
}

/// Small overshoot (~3%) — selection highlights that glide and settle.
pub fn ease_morph(t: f32) -> f32 {
    let c1 = 1.10;
    let c3 = c1 + 1.0;
    1.0 + c3 * (t - 1.0).powi(3) + c1 * (t - 1.0).powi(2)
}

/// Fade + short rise. Used once per navigation (and staggered for list rows).
pub fn enter(
    el: Div,
    id: impl Into<ElementId>,
    duration_ms: u64,
    delay_ms: u64,
) -> AnimationElement<Div> {
    let total = duration_ms + delay_ms;
    let delay = delay_ms as f32 / total as f32;
    el.with_animation(
        id,
        Animation::new(Duration::from_millis(total)).with_easing(move |t| {
            if t <= delay {
                0.0
            } else {
                ease_smooth(((t - delay) / (1.0 - delay)).clamp(0.0, 1.0))
            }
        }),
        |el, t| el.opacity(t).mt(px(6.0 * (1.0 - t))),
    )
}

/// Text that gently pulses while work is in progress.
pub fn shimmer(text: impl Into<SharedString>, color: Hsla) -> AnimationElement<Div> {
    div()
        .text_sm()
        .text_color(color)
        .child(text.into())
        .with_animation(
            "shimmer",
            Animation::new(Duration::from_millis(1400))
                .repeat()
                .with_easing(pulsating_between(0.35, 1.0)),
            |el, t| el.opacity(t),
        )
}

// ── type ──────────────────────────────────────────────────────────────────

pub fn display(text: impl Into<SharedString>) -> Div {
    div()
        .font_family(DISPLAY_FONT)
        .text_size(px(30.))
        .line_height(px(34.))
        .font_medium()
        .child(text.into())
}

pub fn label(text: impl Into<SharedString>, p: &Palette) -> Div {
    div()
        .text_sm()
        .font_medium()
        .text_color(p.fg)
        .child(text.into())
}

pub fn section_label(text: &'static str, p: &Palette) -> Div {
    // px_4 = the sidebar's 8px margin + 8px item padding, so labels line up
    // with item icons, the brand mark and the tag chips.
    div()
        .px_4()
        .pt_5()
        .pb_1p5()
        .text_xs()
        .font_medium()
        .text_color(p.muted)
        .child(text)
}

// ── badges ────────────────────────────────────────────────────────────────

/// Brand colours for chains (third-party marks keep their real colours).
pub fn chain_color(chain: Chain) -> Hsla {
    let c = crate::theme::current().palette();
    rgb(match chain {
        Chain::Evm => c.blue,
        Chain::Solana => c.mauve,
        Chain::Tron => c.red,
        Chain::Other => c.overlay1,
    })
    .into()
}

/// Deterministic, calm colour for a tag name.
/// Each tag gets a stable Catppuccin accent.
pub fn tag_color(tag: &str) -> Hsla {
    let h = tag
        .bytes()
        .fold(2166136261u32, |h, b| (h ^ b as u32).wrapping_mul(16777619));
    let accents = crate::theme::current().palette().accents();
    rgb(accents[(h % accents.len() as u32) as usize]).into()
}

pub fn chain_dot(chain: Chain) -> Div {
    div()
        .size(px(7.))
        .rounded_full()
        .flex_shrink_0()
        .bg(chain_color(chain))
}

/// Dot + chain name: informative without a loud pill.
pub fn chain_badge(chain: Chain) -> Div {
    h_flex()
        .flex_shrink_0()
        .gap_1p5()
        .px_2()
        .py_0p5()
        .rounded_full()
        .border_1()
        .border_color(hsla(0., 0., 0.5, 0.25))
        .text_xs()
        .font_medium()
        .child(chain_dot(chain))
        .child(chain.label())
}

pub fn tag_chip(tag: &str) -> Div {
    let color = tag_color(tag);
    div()
        .flex_shrink_0()
        .px_2()
        .rounded_full()
        .text_xs()
        .text_color(color)
        .bg(color.opacity(0.14))
        .child(format!("#{tag}"))
}

// ── segmented control with a gliding highlight ────────────────────────────

/// One option of a [`segmented`] control.
pub struct Segment {
    pub label: SharedString,
    pub leading: Option<AnyElement>,
}

/// Equal-width segmented control. The selected pill glides from `from` to
/// `selected` (spring-shaped) whenever `seq` changes.
pub fn segmented(
    id: &'static str,
    segments: Vec<Segment>,
    selected: usize,
    from: usize,
    seq: usize,
    p: &Palette,
    on_select: impl Fn(usize, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let n = segments.len().max(1) as f32;
    let on_select = std::rc::Rc::new(on_select);
    let (fg, secondary, surface, border) = (p.fg, p.secondary, p.highlight, p.border);
    let pad = 4.0;
    let highlight = div()
        .absolute()
        .top(px(pad))
        .bottom(px(pad))
        .w(relative(1.0 / n))
        .px(px(pad))
        .child(
            div()
                .size_full()
                .rounded(px(R_PANEL - pad * 2.0))
                .bg(surface)
                .border_1()
                .border_color(border),
        )
        .with_animation(
            SharedString::from(format!("{id}-glide-{seq}")),
            Animation::new(Duration::from_millis(if from == selected {
                1
            } else {
                420
            }))
            .with_easing(ease_morph),
            move |el, t| {
                let pos = from as f32 + (selected as f32 - from as f32) * t;
                el.left(relative(pos / n))
            },
        );

    let items = segments.into_iter().enumerate().map(|(i, s)| {
        let active = i == selected;
        let on_select = on_select.clone();
        h_flex()
            .id(SharedString::from(format!("{id}-{i}")))
            .flex_1()
            .min_w_0()
            .h_full()
            .px_1()
            .justify_center()
            .gap_2()
            .text_sm()
            .cursor_pointer()
            .when(active, |d| d.text_color(fg).font_medium())
            .when(!active, |d| {
                d.text_color(secondary).hover(move |s| s.text_color(fg))
            })
            .on_click(move |_, window, cx| on_select(i, window, cx))
            .children(s.leading)
            .child(div().min_w_0().truncate().child(s.label))
    });

    div()
        .id(id)
        .relative()
        .h(px(40.))
        .p(px(pad))
        .rounded(px(R_PANEL))
        .bg(p.muted_bg)
        .child(highlight)
        .child(h_flex().relative().size_full().children(items))
}

// ── "midnight glass" ──────────────────────────────────────────────────────

/// One Catppuccin accent per wallet (stable per address), lightly shaded so
/// it reads as a sphere — a single hue, no multi-colour gradients.
pub fn orb_colors(seed: &str) -> (Hsla, Hsla) {
    let h = seed.bytes().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ b as u64).wrapping_mul(0x100000001b3)
    });
    let accents = crate::theme::current().palette().accents();
    let base: Hsla = rgb(accents[(h % accents.len() as u64) as usize]).into();
    let light = hsla(base.h, base.s, (base.l + 0.10).min(0.92), 1.0);
    let deep = hsla(base.h, base.s, (base.l - 0.12).max(0.18), 1.0);
    (light, deep)
}

fn gradient(angle: f32, a: Hsla, b: Hsla) -> Background {
    linear_gradient(angle, linear_color_stop(a, 0.0), linear_color_stop(b, 1.0))
}

#[allow(dead_code)]
pub fn glow(color: Hsla, blur: f32, y: f32) -> BoxShadow {
    BoxShadow {
        color,
        offset: point(px(0.), px(y)),
        blur_radius: px(blur),
        spread_radius: px(0.),
        inset: false,
    }
}

fn highlight(alpha: f32) -> BoxShadow {
    BoxShadow {
        color: hsla(0., 0., 1., alpha),
        offset: point(px(0.), px(1.)),
        blur_radius: px(0.),
        spread_radius: px(0.),
        inset: true,
    }
}

/// Gradient identity orb for a wallet.
pub fn orb(seed: &str, size: f32) -> Div {
    let (a, b) = orb_colors(seed);
    div()
        .size(px(size))
        .flex_shrink_0()
        .rounded_full()
        .bg(gradient(135., a, b))
        .shadow(vec![highlight(0.25)])
}

/// Same orb with its gradient slowly turning — used once, in the hero.
pub fn living_orb(seed: &str, size: f32) -> AnimationElement<Div> {
    let (a, b) = orb_colors(seed);
    orb(seed, size).with_animation(
        SharedString::from(format!("orb-{seed}")),
        Animation::new(Duration::from_secs(9)).repeat(),
        move |el, t| el.bg(gradient(135. + 360. * t, a, b)),
    )
}

/// A card / panel on the Catppuccin base surface.
pub fn glass(p: &Palette) -> Div {
    div().border_1().border_color(p.border).bg(p.surface)
}

/// Primary call-to-action in the flavour's mauve.
pub fn glow_button(
    p: &Palette,
    id: impl Into<ElementId>,
    icon: Option<impl Into<Icon>>,
    label: impl Into<SharedString>,
    busy: bool,
    disabled: bool,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> Stateful<Div> {
    let label: SharedString = label.into();
    let (bg, ink) = (p.primary, p.primary_fg);
    h_flex()
        .id(id.into())
        .flex_shrink_0()
        .h(px(CTA_H))
        .px_5()
        .gap_2()
        .justify_center()
        .rounded(px(12.))
        .bg(bg)
        .text_color(ink)
        .text_sm()
        .font_medium()
        .when(disabled || busy, |d| d.opacity(0.5))
        .when(!disabled && !busy, |d| {
            d.cursor_pointer()
                .hover(|s| s.opacity(0.9))
                .active(|s| s.opacity(0.78))
                .on_click(on_click)
        })
        .children(icon.map(|i| i.into().small()))
        .child(label)
}

/// Inline notice (warning / error / info). Text wraps inside the box.
pub fn callout(icon: impl Into<Icon>, text: impl Into<SharedString>, color: Hsla) -> Div {
    h_flex()
        .w_full()
        .gap_2p5()
        .items_start()
        .px_3p5()
        .py_3()
        .rounded(px(12.))
        .bg(color.opacity(0.10))
        .text_color(color)
        .text_sm()
        .child(div().flex_shrink_0().pt(px(2.)).child(icon.into().small()))
        .child(div().flex_1().min_w_0().child(text.into()))
}

/// Square checkbox mark (used by toggle rows).
pub fn check_box(on: bool, p: &Palette) -> Div {
    div()
        .size(px(18.))
        .flex_shrink_0()
        .rounded(px(6.))
        .border_1()
        .flex()
        .items_center()
        .justify_center()
        .when(on, |d| {
            d.bg(p.primary)
                .border_color(p.primary)
                .text_color(p.primary_fg)
                .child(Icon::new(IconName::Check).xsmall())
        })
        .when(!on, |d| d.border_color(p.muted))
}

/// Keyboard shortcut label for this platform: `⌘N` / `⇧⌘T` on macOS,
/// `Ctrl+N` / `Ctrl+Shift+T` elsewhere.
pub fn shortcut(keys: &str) -> String {
    if cfg!(target_os = "macos") {
        match keys.strip_prefix("Shift+") {
            Some(k) => format!("⇧⌘{k}"),
            None => format!("⌘{keys}"),
        }
    } else {
        format!("Ctrl+{keys}")
    }
}

/// Text-only link (no padding, so it lines up with the content edge).
pub fn text_link(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    p: &Palette,
) -> Stateful<Div> {
    let fg = p.fg;
    div()
        .id(id.into())
        .text_sm()
        .text_color(p.secondary)
        .cursor_pointer()
        .hover(move |s| s.text_color(fg))
        .child(label.into())
}

/// Background layer (kept as a hook; Catppuccin is flat).
pub fn backdrop(_p: &Palette) -> Div {
    div().absolute().size_full()
}

// ── controls without focus rings ──────────────────────────────────────────

/// A button that doesn't draw a focus ring/outline when clicked or focused.
pub fn button(id: impl Into<ElementId>) -> component::button::Button {
    component::button::Button::new(id).focus_ring(false)
}

/// A secondary button sized to sit in a call-to-action row next to a
/// [`glow_button`] (same height and radius).
pub fn action(id: impl Into<ElementId>) -> component::button::Button {
    button(id).h(px(CTA_H)).px_4()
}

/// A text input whose border doesn't change colour or grow a ring on focus.
pub fn input(state: &Entity<component::input::InputState>) -> component::input::Input {
    component::input::Input::new(state).focus_ring(false)
}
