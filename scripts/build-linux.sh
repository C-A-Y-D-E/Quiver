#!/usr/bin/env bash
# Build KeyVault for Linux on this machine's architecture (x86_64 or arm64).
#
#   ./scripts/build-linux.sh
#
# Output in dist/:
#   KeyVault-<version>-linux-<arch>.tar.gz   portable: unpack and run ./keyvault/keyvault
#                                            (or ./keyvault/install.sh for a menu entry)
#   keyvault_<version>_<debarch>.deb         Debian / Ubuntu / Mint / Pop!_OS package
#
# Build an arm64 version on an arm64 machine (Raspberry Pi 5, Ampere, Graviton,
# Asahi, …) or let GitHub build both: .github/workflows/release.yml.
#
# Needs Rust (https://rustup.rs) and, on Debian/Ubuntu:
#   sudo apt install build-essential pkg-config libxkbcommon-dev libxkbcommon-x11-dev \
#     libwayland-dev libvulkan-dev libx11-xcb-dev libxcb1-dev libfontconfig-dev libfreetype-dev libssl-dev
set -euo pipefail

say() { printf '\033[1;35m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Linux" ]] || die "run this on Linux."
command -v cargo >/dev/null || die "Rust isn't installed. Get it from https://rustup.rs, then open a new terminal."

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -1)"
VERSION="${VERSION:-0.1.0}"
case "$(uname -m)" in
  x86_64|amd64) ARCH=x86_64; DEB_ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64; DEB_ARCH=arm64 ;;
  *) ARCH="$(uname -m)"; DEB_ARCH="$ARCH" ;;
esac
DIST="$ROOT/dist"
mkdir -p "$DIST"

say "Building KeyVault $VERSION for linux-$ARCH (release)…"
cargo build --release --locked -p keyvault-app
BIN="target/release/keyvault"
strip "$BIN" 2>/dev/null || true

DESKTOP='[Desktop Entry]
Type=Application
Name=KeyVault
GenericName=Wallet key vault
Comment=Keep your wallet private keys encrypted on this computer
Exec=keyvault
Icon=keyvault
Terminal=false
Categories=Office;Finance;Utility;
Keywords=wallet;crypto;private key;vault;ethereum;solana;
StartupWMClass=keyvault'

# ── portable tarball ───────────────────────────────────────────────────────
say "Packing the portable .tar.gz…"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
PKG="$STAGE/keyvault"
mkdir -p "$PKG"
cp "$BIN" "$PKG/keyvault"
cp packaging/linux/keyvault.png packaging/linux/keyvault.svg "$PKG/"
printf '%s\n' "$DESKTOP" > "$PKG/keyvault.desktop"
cat > "$PKG/install.sh" <<'EOS'
#!/usr/bin/env bash
# Install KeyVault for the current user (no sudo): ~/.local/bin + app menu entry.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p ~/.local/bin ~/.local/share/applications ~/.local/share/icons/hicolor/512x512/apps ~/.local/share/icons/hicolor/scalable/apps
install -m 0755 "$HERE/keyvault" ~/.local/bin/keyvault
install -m 0644 "$HERE/keyvault.png" ~/.local/share/icons/hicolor/512x512/apps/keyvault.png
install -m 0644 "$HERE/keyvault.svg" ~/.local/share/icons/hicolor/scalable/apps/keyvault.svg
sed "s|^Exec=keyvault|Exec=$HOME/.local/bin/keyvault|" "$HERE/keyvault.desktop" > ~/.local/share/applications/keyvault.desktop
update-desktop-database ~/.local/share/applications >/dev/null 2>&1 || true
echo "KeyVault installed. Find it in your app menu, or run: ~/.local/bin/keyvault"
EOS
chmod +x "$PKG/install.sh"
cat > "$PKG/README.txt" <<EOS
KeyVault $VERSION for Linux ($ARCH)

Run it:      ./keyvault
Install it:  ./install.sh     (adds it to your app menu; no sudo)

Needs an X11 or Wayland desktop. If it doesn't start, install:
  sudo apt install libxkbcommon0 libxkbcommon-x11-0 libxcb1 libegl1 libvulkan1 mesa-vulkan-drivers
Your vault is stored in ~/.local/share/keyvault/vault.json.
EOS
TARBALL="$DIST/KeyVault-$VERSION-linux-$ARCH.tar.gz"
tar -C "$STAGE" -czf "$TARBALL" keyvault

# ── .deb ───────────────────────────────────────────────────────────────────
if command -v dpkg-deb >/dev/null; then
  say "Building the .deb…"
  DEB_ROOT="$STAGE/deb"
  install -Dm0755 "$BIN" "$DEB_ROOT/usr/bin/keyvault"
  install -Dm0644 packaging/linux/keyvault.png "$DEB_ROOT/usr/share/icons/hicolor/512x512/apps/keyvault.png"
  install -Dm0644 packaging/linux/keyvault.svg "$DEB_ROOT/usr/share/icons/hicolor/scalable/apps/keyvault.svg"
  mkdir -p "$DEB_ROOT/usr/share/applications" "$DEB_ROOT/DEBIAN"
  printf '%s\n' "$DESKTOP" > "$DEB_ROOT/usr/share/applications/keyvault.desktop"

  # Work out the minimum library versions from the binary when the tools are here.
  DEPENDS=""
  if command -v dpkg-shlibdeps >/dev/null; then
    SHL="$STAGE/shlibs"
    mkdir -p "$SHL/debian"
    echo "Source: keyvault" > "$SHL/debian/control"
    DEPENDS="$(cd "$SHL" && dpkg-shlibdeps -O "$DEB_ROOT/usr/bin/keyvault" 2>/dev/null | sed -n 's/^shlibs:Depends=//p')" || DEPENDS=""
  fi
  [[ -n "$DEPENDS" ]] || DEPENDS="libc6, libxcb1, libxkbcommon0, libxkbcommon-x11-0"
  SIZE_KB="$(du -sk "$DEB_ROOT/usr" | cut -f1)"
  cat > "$DEB_ROOT/DEBIAN/control" <<EOS
Package: keyvault
Version: $VERSION
Architecture: $DEB_ARCH
Maintainer: KeyVault Developers <keyvault@localhost>
Installed-Size: $SIZE_KB
Depends: $DEPENDS, libegl1 | libvulkan1
Recommends: libvulkan1, mesa-vulkan-drivers, libwayland-client0, libwayland-egl1
Section: utils
Priority: optional
Description: Encrypted vault for many crypto wallet private keys
 KeyVault keeps the private keys of all your wallets encrypted on this
 computer under one vault key (passphrase or recovery key). Organise wallets
 with folders and tags, generate new ones, send native coins and tokens, and
 export selected wallets to CSV or TXT.
EOS
  DEB="$DIST/keyvault_${VERSION}_${DEB_ARCH}.deb"
  dpkg-deb --root-owner-group --build "$DEB_ROOT" "$DEB" >/dev/null
fi

say "Done."
echo "   $TARBALL"
[[ -n "${DEB:-}" ]] && echo "   $DEB   (install: sudo apt install ./$(basename "$DEB"))"
exit 0
