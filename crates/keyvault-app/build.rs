//! Windows: embed the app icon and version info into keyvault.exe.
//! Other platforms: nothing to do (macOS / Linux packaging lives in `packaging/`).

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../packaging/windows/keyvault.rc");
    println!("cargo:rerun-if-changed=../../packaging/windows/keyvault.ico");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let windows_dir = manifest_dir.join("../../packaging/windows");
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let mut parts = version.split(['.', '-']).map(|p| p.parse::<u16>().unwrap_or(0));
    let mut next = || parts.next().unwrap_or(0).to_string();
    let (major, minor, patch) = (next(), next(), next());

    // rc.exe / windres want forward slashes or escaped backslashes in paths.
    let icon = windows_dir
        .join("keyvault.ico")
        .canonicalize()
        .expect("packaging/windows/keyvault.ico is missing");
    let icon = icon.to_string_lossy().replace('\\', "/");
    let icon = icon.strip_prefix("//?/").unwrap_or(&icon).to_string();

    let template = std::fs::read_to_string(windows_dir.join("keyvault.rc")).unwrap();
    let rc = template
        .replace("@ICON@", &icon)
        .replace("@MAJOR@", &major)
        .replace("@MINOR@", &minor)
        .replace("@PATCH@", &patch)
        .replace("@VERSION@", &version);
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("keyvault.rc");
    std::fs::write(&out, rc).unwrap();
    embed_resource::compile(&out, embed_resource::NONE)
        .manifest_optional()
        .expect("failed to compile the Windows resource file (icon/version)");
}
