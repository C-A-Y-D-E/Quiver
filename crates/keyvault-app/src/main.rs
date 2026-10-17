//! KeyVault — keep many wallet private keys on your PC, encrypted under one
//! vault key you unlock with your fingerprint, face or passphrase.

// Release builds on Windows are a GUI app: no console window behind it.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

extern crate gpui_kit as gpui;

mod app;
mod os_unlock;
mod theme;
mod ui;

use std::borrow::Cow;

use gpui_kit::*;

// Lucide icons beyond the component set's defaults (see `ui::Lucide`).
gpui_kit::assets::icon_assets!(
    ExtraIcons,
    [
        DatabaseBackup,
        Download,
        Eye,
        EyeOff,
        Folder,
        HardDrive,
        KeyRound,
        Lock,
        LockKeyhole,
        Pencil,
        ScanFace,
        Send,
        Settings,
        ShieldCheck,
        Sparkles,
        Trash
    ]
);

/// Default component assets plus [`ExtraIcons`].
struct AppAssets;

impl AssetSource for AppAssets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        if let Some(bytes) = ExtraIcons.load(path)? {
            return Ok(Some(bytes));
        }
        gpui_kit::assets::Assets.load(path)
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        let mut paths = gpui_kit::assets::Assets.list(path)?;
        paths.extend(ExtraIcons.list(path)?);
        paths.sort();
        paths.dedup();
        Ok(paths)
    }
}

fn main() {
    let path = std::env::var_os("KEYVAULT_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(vault_core::Vault::default_path);

    gpui_kit::application()
        .with_assets(AppAssets)
        .run(move |cx| {
            gpui_kit::init(cx);
            theme::load_fonts(cx);
            theme::apply(theme::saved_flavor(&path), None, cx);
            app::bind_keys(cx);

            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                    None,
                    size(px(1280.), px(800.)),
                    cx,
                ))),
                window_min_size: Some(size(px(1040.), px(600.))),
                // Linux: matches keyvault.desktop so the dock / taskbar shows our icon.
                app_id: Some("keyvault".into()),
                titlebar: Some(TitlebarOptions {
                    title: Some("KeyVault".into()),
                    ..Default::default()
                }),
                ..Default::default()
            };

            gpui_kit::open_window(options, cx, move |window, cx| {
                cx.new(|cx| app::KeyVaultApp::new(path, window, cx))
            })
            .expect("failed to open window");
            cx.activate(true);
        });
}
