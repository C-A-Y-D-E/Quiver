#!/usr/bin/env bash
# Build KeyVault.app (and a .dmg) on a Mac.
#
#   ./scripts/build-macos.sh                 # this Mac's chip (Apple silicon or Intel)
#   ./scripts/build-macos.sh --arch arm64    # Apple silicon build (works from any Mac)
#   ./scripts/build-macos.sh --arch x86_64   # Intel build (works from any Mac)
#   ./scripts/build-macos.sh --universal     # one app for both Apple silicon and Intel
#   ./scripts/build-macos.sh --no-dmg        # just the .app
#
# Output goes to dist/. Needs: Rust (rustup) and Xcode Command Line Tools
# (`xcode-select --install`). Full Xcode is not needed.
#
# Signing (optional):
#   MACOS_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
#       sign with your Developer ID instead of an ad-hoc signature.
#   MACOS_NOTARY_PROFILE=<profile>
#       also notarize + staple the .dmg, using credentials saved earlier with
#       `xcrun notarytool store-credentials <profile>`.
set -euo pipefail

UNIVERSAL=0
MAKE_DMG=1
ARCH=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --universal) UNIVERSAL=1 ;;
    --no-dmg) MAKE_DMG=0 ;;
    --arch) ARCH="${2:-}"; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
case "$ARCH" in
  ""|arm64|x86_64) ;;
  aarch64) ARCH=arm64 ;;
  intel|x64) ARCH=x86_64 ;;
  *) echo "--arch must be arm64 or x86_64" >&2; exit 2 ;;
esac

say() { printf '\033[1;35m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Darwin" ]] || die "run this on a Mac (the macOS build can't be cross-compiled)."
command -v cargo >/dev/null || die "Rust isn't installed. Get it from https://rustup.rs, then open a new terminal."
xcode-select -p >/dev/null 2>&1 || die "Xcode Command Line Tools are missing. Run: xcode-select --install"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -1)"
VERSION="${VERSION:-0.1.0}"
APP_NAME="KeyVault"
BIN="keyvault"
DIST="$ROOT/dist"
APP="$DIST/$APP_NAME.app"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"

# ── compile ────────────────────────────────────────────────────────────────
if [[ $UNIVERSAL == 1 ]]; then
  ARCH_LABEL="universal"
  TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
  command -v rustup >/dev/null || die "--universal needs rustup (to add the second target)."
  rustup target add "${TARGETS[@]}"
  for t in "${TARGETS[@]}"; do
    say "Building $t (release)…"
    cargo build --release --locked -p keyvault-app --target "$t"
  done
  mkdir -p target/universal-apple-darwin/release
  lipo -create -output "target/universal-apple-darwin/release/$BIN" \
    "target/aarch64-apple-darwin/release/$BIN" "target/x86_64-apple-darwin/release/$BIN"
  BUILT="target/universal-apple-darwin/release/$BIN"
else
  [[ -n "$ARCH" ]] || ARCH="$(uname -m)"
  case "$ARCH" in
    arm64) ARCH_LABEL="apple-silicon"; TARGET=aarch64-apple-darwin ;;
    *) ARCH_LABEL="intel"; TARGET=x86_64-apple-darwin ;;
  esac
  if command -v rustup >/dev/null; then rustup target add "$TARGET" >/dev/null; fi
  say "Building for $ARCH_LABEL ($TARGET, release)…"
  cargo build --release --locked -p keyvault-app --target "$TARGET"
  BUILT="target/$TARGET/release/$BIN"
fi

# ── bundle ─────────────────────────────────────────────────────────────────
say "Assembling $APP_NAME.app…"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BUILT" "$APP/Contents/MacOS/$BIN"
strip -x "$APP/Contents/MacOS/$BIN" 2>/dev/null || true
cp packaging/macos/KeyVault.icns "$APP/Contents/Resources/KeyVault.icns"
sed "s/__VERSION__/$VERSION/g" packaging/macos/Info.plist > "$APP/Contents/Info.plist"
printf 'APPL????' > "$APP/Contents/PkgInfo"
plutil -lint "$APP/Contents/Info.plist" >/dev/null

# ── sign ───────────────────────────────────────────────────────────────────
if [[ -n "${MACOS_SIGN_IDENTITY:-}" ]]; then
  say "Signing with \"$MACOS_SIGN_IDENTITY\" (hardened runtime)…"
  codesign --force --timestamp --options runtime --sign "$MACOS_SIGN_IDENTITY" "$APP"
else
  say "Signing ad-hoc (fine for your own Mac)…"
  codesign --force --sign - "$APP"
fi
codesign --verify --strict "$APP"

# ── dmg ────────────────────────────────────────────────────────────────────
if [[ $MAKE_DMG == 1 ]]; then
  DMG="$DIST/$APP_NAME-$VERSION-$ARCH_LABEL.dmg"
  say "Creating $(basename "$DMG")…"
  STAGE="$(mktemp -d)"
  trap 'rm -rf "$STAGE"' EXIT
  cp -R "$APP" "$STAGE/"
  ln -s /Applications "$STAGE/Applications"
  rm -f "$DMG"
  hdiutil create -quiet -volname "$APP_NAME" -srcfolder "$STAGE" -fs HFS+ -format UDZO -ov "$DMG"
  if [[ -n "${MACOS_SIGN_IDENTITY:-}" ]]; then
    codesign --force --timestamp --sign "$MACOS_SIGN_IDENTITY" "$DMG"
  fi
  if [[ -n "${MACOS_NOTARY_PROFILE:-}" ]]; then
    [[ -n "${MACOS_SIGN_IDENTITY:-}" ]] || die "notarizing needs MACOS_SIGN_IDENTITY too."
    say "Notarizing (takes a few minutes)…"
    xcrun notarytool submit "$DMG" --keychain-profile "$MACOS_NOTARY_PROFILE" --wait
    xcrun stapler staple "$DMG"
  fi
fi

say "Done."
echo "   App: $APP"
[[ $MAKE_DMG == 1 ]] && echo "   DMG: $DMG"
echo "   Run it:  open \"$APP\"    (or drag it into Applications)"
