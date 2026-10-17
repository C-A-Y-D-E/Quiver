//! Look & feel: Catppuccin (Latte, Frappé, Macchiato, Mocha), bundled fonts
//! (Inter, Geist, Geist Mono — SIL OFL) and small UI preferences.

use std::borrow::Cow;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU8, Ordering};

use gpui_kit::component::{Theme, ThemeConfig, ThemeMode};
use gpui_kit::*;

/// Base theme (every token the component library knows); colours are
/// replaced with the selected Catppuccin flavour at runtime.
const BASE_THEME_JSON: &str = include_str!("../assets/arc-theme.json");

pub const DISPLAY_FONT: &str = "Geist";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Latte,
    Frappe,
    Macchiato,
    Mocha,
}

impl Flavor {
    pub const ALL: [Flavor; 4] = [
        Flavor::Latte,
        Flavor::Frappe,
        Flavor::Macchiato,
        Flavor::Mocha,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Flavor::Latte => "Latte",
            Flavor::Frappe => "Frappé",
            Flavor::Macchiato => "Macchiato",
            Flavor::Mocha => "Mocha",
        }
    }

    fn key(self) -> &'static str {
        match self {
            Flavor::Latte => "latte",
            Flavor::Frappe => "frappe",
            Flavor::Macchiato => "macchiato",
            Flavor::Mocha => "mocha",
        }
    }

    fn from_key(k: &str) -> Option<Flavor> {
        Flavor::ALL.into_iter().find(|f| f.key() == k)
    }

    pub fn is_dark(self) -> bool {
        self != Flavor::Latte
    }

    pub fn palette(self) -> &'static Ctp {
        match self {
            Flavor::Latte => &LATTE,
            Flavor::Frappe => &FRAPPE,
            Flavor::Macchiato => &MACCHIATO,
            Flavor::Mocha => &MOCHA,
        }
    }
}

/// The official Catppuccin palette for one flavour.
#[allow(dead_code)]
pub struct Ctp {
    pub rosewater: u32,
    pub flamingo: u32,
    pub pink: u32,
    pub mauve: u32,
    pub red: u32,
    pub maroon: u32,
    pub peach: u32,
    pub yellow: u32,
    pub green: u32,
    pub teal: u32,
    pub sky: u32,
    pub sapphire: u32,
    pub blue: u32,
    pub lavender: u32,
    pub text: u32,
    pub subtext1: u32,
    pub subtext0: u32,
    pub overlay2: u32,
    pub overlay1: u32,
    pub overlay0: u32,
    pub surface2: u32,
    pub surface1: u32,
    pub surface0: u32,
    pub base: u32,
    pub mantle: u32,
    pub crust: u32,
}

impl Ctp {
    /// The 14 accent colours, used for wallet orbs and tags.
    pub fn accents(&self) -> [u32; 14] {
        [
            self.rosewater,
            self.flamingo,
            self.pink,
            self.mauve,
            self.red,
            self.maroon,
            self.peach,
            self.yellow,
            self.green,
            self.teal,
            self.sky,
            self.sapphire,
            self.blue,
            self.lavender,
        ]
    }
}

pub const LATTE: Ctp = Ctp {
    rosewater: 0xdc8a78,
    flamingo: 0xdd7878,
    pink: 0xea76cb,
    mauve: 0x8839ef,
    red: 0xd20f39,
    maroon: 0xe64553,
    peach: 0xfe640b,
    yellow: 0xdf8e1d,
    green: 0x40a02b,
    teal: 0x179299,
    sky: 0x04a5e5,
    sapphire: 0x209fb5,
    blue: 0x1e66f5,
    lavender: 0x7287fd,
    text: 0x4c4f69,
    subtext1: 0x5c5f77,
    subtext0: 0x6c6f85,
    overlay2: 0x7c7f93,
    overlay1: 0x8c8fa1,
    overlay0: 0x9ca0b0,
    surface2: 0xacb0be,
    surface1: 0xbcc0cc,
    surface0: 0xccd0da,
    base: 0xeff1f5,
    mantle: 0xe6e9ef,
    crust: 0xdce0e8,
};

pub const FRAPPE: Ctp = Ctp {
    rosewater: 0xf2d5cf,
    flamingo: 0xeebebe,
    pink: 0xf4b8e4,
    mauve: 0xca9ee6,
    red: 0xe78284,
    maroon: 0xea999c,
    peach: 0xef9f76,
    yellow: 0xe5c890,
    green: 0xa6d189,
    teal: 0x81c8be,
    sky: 0x99d1db,
    sapphire: 0x85c1dc,
    blue: 0x8caaee,
    lavender: 0xbabbf1,
    text: 0xc6d0f5,
    subtext1: 0xb5bfe2,
    subtext0: 0xa5adce,
    overlay2: 0x949cbb,
    overlay1: 0x838ba7,
    overlay0: 0x737994,
    surface2: 0x626880,
    surface1: 0x51576d,
    surface0: 0x414559,
    base: 0x303446,
    mantle: 0x292c3c,
    crust: 0x232634,
};

pub const MACCHIATO: Ctp = Ctp {
    rosewater: 0xf4dbd6,
    flamingo: 0xf0c6c6,
    pink: 0xf5bde6,
    mauve: 0xc6a0f6,
    red: 0xed8796,
    maroon: 0xee99a0,
    peach: 0xf5a97f,
    yellow: 0xeed49f,
    green: 0xa6da95,
    teal: 0x8bd5ca,
    sky: 0x91d7e3,
    sapphire: 0x7dc4e4,
    blue: 0x8aadf4,
    lavender: 0xb7bdf8,
    text: 0xcad3f5,
    subtext1: 0xb8c0e0,
    subtext0: 0xa5adcb,
    overlay2: 0x939ab7,
    overlay1: 0x8087a2,
    overlay0: 0x6e738d,
    surface2: 0x5b6078,
    surface1: 0x494d64,
    surface0: 0x363a4f,
    base: 0x24273a,
    mantle: 0x1e2030,
    crust: 0x181926,
};

pub const MOCHA: Ctp = Ctp {
    rosewater: 0xf5e0dc,
    flamingo: 0xf2cdcd,
    pink: 0xf5c2e7,
    mauve: 0xcba6f7,
    red: 0xf38ba8,
    maroon: 0xeba0ac,
    peach: 0xfab387,
    yellow: 0xf9e2af,
    green: 0xa6e3a1,
    teal: 0x94e2d5,
    sky: 0x89dceb,
    sapphire: 0x74c7ec,
    blue: 0x89b4fa,
    lavender: 0xb4befe,
    text: 0xcdd6f4,
    subtext1: 0xbac2de,
    subtext0: 0xa6adc8,
    overlay2: 0x9399b2,
    overlay1: 0x7f849c,
    overlay0: 0x6c7086,
    surface2: 0x585b70,
    surface1: 0x45475a,
    surface0: 0x313244,
    base: 0x1e1e2e,
    mantle: 0x181825,
    crust: 0x11111b,
};

static CURRENT: AtomicU8 = AtomicU8::new(3);

pub fn current() -> Flavor {
    Flavor::ALL[CURRENT.load(Ordering::Relaxed) as usize % 4]
}

pub fn load_fonts(cx: &mut App) {
    let fonts: Vec<Cow<'static, [u8]>> = vec![
        Cow::Borrowed(include_bytes!("../assets/fonts/Inter-Regular.ttf")),
        Cow::Borrowed(include_bytes!("../assets/fonts/Inter-Medium.ttf")),
        Cow::Borrowed(include_bytes!("../assets/fonts/Geist-Regular.ttf")),
        Cow::Borrowed(include_bytes!("../assets/fonts/Geist-Medium.ttf")),
        Cow::Borrowed(include_bytes!("../assets/fonts/GeistMono-Regular.ttf")),
        Cow::Borrowed(include_bytes!("../assets/fonts/GeistMono-Medium.ttf")),
    ];
    if let Err(e) = cx.text_system().add_fonts(fonts) {
        eprintln!("keyvault: couldn't load bundled fonts: {e}");
    }
}

fn hex(c: u32) -> String {
    format!("#{c:06x}")
}

fn hexa(c: u32, alpha: f32) -> String {
    format!(
        "#{c:06x}{:02x}",
        (alpha.clamp(0.0, 1.0) * 255.0).round() as u8
    )
}

/// Build a component-library theme config for a flavour.
fn config(flavor: Flavor) -> ThemeConfig {
    let base: serde_json::Value =
        serde_json::from_str(BASE_THEME_JSON).expect("bundled theme is valid");
    let template_idx = if flavor.is_dark() { 1 } else { 0 };
    let mut t = base["themes"][template_idx].clone();
    let c = flavor.palette();
    let on_accent = if flavor.is_dark() { c.crust } else { c.base };
    let colors: Vec<(&str, String)> = vec![
        ("background", hex(c.mantle)),
        ("foreground", hex(c.text)),
        ("caret", hex(c.rosewater)),
        ("accent.background", hex(c.surface0)),
        ("accent.foreground", hex(c.text)),
        ("accordion.background", hex(c.base)),
        ("border", hex(c.surface0)),
        ("input.border", hex(c.surface1)),
        ("ring", hex(c.surface1)),
        ("muted.background", hex(c.surface0)),
        ("muted.foreground", hex(c.overlay1)),
        ("popover.background", hex(c.base)),
        ("popover.foreground", hex(c.text)),
        ("primary.background", hex(c.mauve)),
        ("primary.foreground", hex(on_accent)),
        ("primary.hover.background", hex(c.lavender)),
        ("primary.active.background", hexa(c.mauve, 0.85)),
        ("secondary.background", hex(c.base)),
        ("secondary.foreground", hex(c.text)),
        ("secondary.hover.background", hex(c.surface0)),
        ("secondary.active.background", hex(c.surface1)),
        ("list.background", hex(c.base)),
        ("list.active.background", hexa(c.mauve, 0.14)),
        ("list.active.border", hex(c.mauve)),
        ("list.hover.background", hexa(c.surface0, 0.7)),
        ("list.even.background", hex(c.mantle)),
        ("list.head.background", hex(c.mantle)),
        ("selection.background", hexa(c.overlay2, 0.35)),
        ("sidebar.background", hex(c.mantle)),
        ("sidebar.foreground", hex(c.text)),
        ("sidebar.border", hex(c.surface0)),
        ("sidebar.accent.background", hex(c.surface0)),
        ("sidebar.accent.foreground", hex(c.text)),
        ("sidebar.primary.background", hex(c.mauve)),
        ("sidebar.primary.foreground", hex(on_accent)),
        ("success.background", hex(c.green)),
        ("success.foreground", hex(c.green)),
        ("warning.background", hex(c.yellow)),
        ("warning.foreground", hex(c.yellow)),
        ("danger.background", hex(c.red)),
        ("danger.foreground", hex(c.red)),
        ("info.background", hex(c.sapphire)),
        ("info.foreground", hex(c.sapphire)),
        ("link.foreground", hex(c.blue)),
        ("link.hover.foreground", hex(c.sapphire)),
        ("link.active.foreground", hex(c.blue)),
        ("progress_bar.background", hex(c.mauve)),
        ("switch.background", hex(c.surface1)),
        ("skeleton.background", hex(c.surface0)),
        ("tab_bar.background", hex(c.mantle)),
        ("tab_bar.segmented.background", hex(c.surface0)),
        ("tab.active.background", hex(c.base)),
        ("tab.active.foreground", hex(c.text)),
        ("tab.foreground", hex(c.subtext0)),
        ("title_bar.background", hex(c.mantle)),
        ("title_bar.border", hex(c.surface0)),
        ("window.border", hex(c.surface0)),
        ("scrollbar.thumb.background", hexa(c.surface2, 0.8)),
        ("scrollbar.thumb.hover.background", hex(c.surface2)),
        ("group_box.background", hex(c.base)),
        ("table.background", hex(c.base)),
        ("overlay", hexa(c.crust, 0.55)),
    ];
    if let Some(dst) = t["colors"].as_object_mut() {
        for (k, v) in colors {
            dst.insert(k.to_string(), serde_json::Value::String(v));
        }
    }
    t["name"] = serde_json::json!(format!("Catppuccin {}", flavor.label()));
    t["mode"] = serde_json::json!(if flavor.is_dark() { "dark" } else { "light" });
    serde_json::from_value(t).expect("catppuccin theme config")
}

/// Switch the whole app to a flavour.
pub fn apply(flavor: Flavor, window: Option<&mut Window>, cx: &mut App) {
    CURRENT.store(
        Flavor::ALL.iter().position(|f| *f == flavor).unwrap_or(3) as u8,
        Ordering::Relaxed,
    );
    let cfg = Rc::new(config(flavor));
    {
        let theme = Theme::global_mut(cx);
        // No focus rings anywhere — focus is shown by the caret only.
        theme.focus_ring = false;
        if flavor.is_dark() {
            theme.dark_theme = cfg;
        } else {
            theme.light_theme = cfg;
        }
    }
    Theme::change(
        if flavor.is_dark() {
            ThemeMode::Dark
        } else {
            ThemeMode::Light
        },
        window,
        cx,
    );
    Theme::global_mut(cx).focus_ring = false;
}

// ── preferences ───────────────────────────────────────────────────────────

fn prefs_path(vault: &std::path::Path) -> PathBuf {
    vault.with_file_name("keyvault-ui.json")
}

fn load(vault: &std::path::Path) -> serde_json::Value {
    std::fs::read_to_string(prefs_path(vault))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .filter(|v: &serde_json::Value| v.is_object())
        .unwrap_or_else(|| serde_json::json!({}))
}

/// Non-secret UI preferences, stored next to the vault in `keyvault-ui.json`.
pub fn pref(vault: &std::path::Path, key: &str) -> Option<serde_json::Value> {
    load(vault).get(key).cloned()
}

pub fn set_pref(vault: &std::path::Path, key: &str, value: serde_json::Value) {
    let mut v = load(vault);
    v[key] = value;
    if let Some(dir) = vault.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(prefs_path(vault), v.to_string());
}

/// Saved flavour; Mocha by default.
pub fn saved_flavor(vault: &std::path::Path) -> Flavor {
    pref(vault, "flavor")
        .and_then(|f| f.as_str().and_then(Flavor::from_key))
        .unwrap_or(Flavor::Mocha)
}

pub fn save_flavor(vault: &std::path::Path, flavor: Flavor) {
    set_pref(vault, "flavor", serde_json::json!(flavor.key()));
    if flavor.is_dark() {
        set_pref(vault, "dark_flavor", serde_json::json!(flavor.key()));
    }
}

/// The dark flavour to return to from Latte.
pub fn saved_dark_flavor(vault: &std::path::Path) -> Flavor {
    pref(vault, "dark_flavor")
        .and_then(|f| f.as_str().and_then(Flavor::from_key))
        .unwrap_or(Flavor::Mocha)
}
