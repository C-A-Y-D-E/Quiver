//! Biometric unlock: Touch ID on macOS, Windows Hello on Windows.
//!
//! How it fits together:
//! * A random 32-byte **device key** lives in the OS keychain (macOS Keychain
//!   / Windows Credential Manager) under "KeyVault".
//! * The vault file holds the vault key wrapped by that device key.
//! * Unlocking = system biometric prompt → read device key → unwrap vault key.
//!
//! Neither half is useful alone: the keychain entry can't open a vault file
//! without its wrapped slot, and the file can't be opened without the
//! keychain entry. The passphrase and recovery key always work as fallbacks.
//!
//! Debug builds support `KEYVAULT_FAKE_BIOMETRIC=1` (or `=deny`) to exercise
//! the flow on machines without biometrics. Release builds ignore it.

use std::sync::mpsc;
use std::time::Duration;

use robius_authentication::{
    AndroidText, BiometricStrength, Context, Error as AuthError, PolicyBuilder, Text, WindowsText,
};
use vault_core::Zeroizing;

const SERVICE: &str = "KeyVault";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backend {
    /// "Touch ID" / "Windows Hello".
    pub label: &'static str,
    pub platform: &'static str,
}

#[cfg(debug_assertions)]
fn fake_mode() -> Option<String> {
    std::env::var("KEYVAULT_FAKE_BIOMETRIC").ok()
}

#[cfg(not(debug_assertions))]
fn fake_mode() -> Option<String> {
    None
}

/// What this machine offers, if anything.
pub fn backend() -> Option<Backend> {
    if fake_mode().is_some() {
        return Some(Backend {
            label: "Test biometric",
            platform: "fake",
        });
    }
    if cfg!(target_os = "macos") {
        Some(Backend {
            label: "Touch ID",
            platform: "macos",
        })
    } else if cfg!(target_os = "windows") {
        Some(Backend {
            label: "Windows Hello",
            platform: "windows",
        })
    } else {
        None
    }
}

/// Show the system prompt and wait for the answer. Blocking — call it from a
/// background thread. `reason` completes "KeyVault is trying to …" on macOS.
pub fn authenticate(reason: &str) -> Result<(), String> {
    if let Some(mode) = fake_mode() {
        std::thread::sleep(Duration::from_millis(500));
        return if mode == "deny" {
            Err("Cancelled.".into())
        } else {
            Ok(())
        };
    }
    // Biometrics first; the OS offers the device password as its own fallback.
    let policy = PolicyBuilder::new()
        .biometrics(Some(BiometricStrength::Strong))
        .password(true)
        .companion(true)
        .build()
        .ok_or_else(|| "this system can't show an authentication prompt".to_string())?;
    let text = Text {
        android: AndroidText {
            title: "KeyVault",
            subtitle: None,
            description: None,
        },
        apple: reason,
        windows: WindowsText::new_truncated("KeyVault", reason),
    };
    let (tx, rx) = mpsc::channel();
    Context::new(())
        .authenticate(text, &policy, move |result| {
            let _ = tx.send(result);
        })
        .map_err(describe)?;
    match rx.recv_timeout(Duration::from_secs(180)) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(describe(e)),
        Err(_) => Err("the authentication prompt timed out".into()),
    }
}

fn describe(e: AuthError) -> String {
    match e {
        AuthError::UserCanceled | AuthError::AppCanceled | AuthError::SystemCanceled => {
            "Cancelled.".into()
        }
        AuthError::Authentication => "Not recognised — try again or use your passphrase.".into(),
        AuthError::Exhausted => "Too many attempts. Use your passphrase.".into(),
        AuthError::NotEnrolled => "No fingerprint or face is enrolled on this device.".into(),
        AuthError::Unavailable => "Biometric unlock isn't available right now.".into(),
        other => format!("Authentication failed ({other:?})."),
    }
}

fn account(vault_id: &str) -> String {
    format!("vault-{vault_id}")
}

pub fn store_device_key(vault_id: &str, key: &[u8; 32]) -> Result<(), String> {
    if fake_mode().is_some() {
        return std::fs::write(fake_path(vault_id), hex_encode(key)).map_err(|e| e.to_string());
    }
    keyring::Entry::new(SERVICE, &account(vault_id))
        .and_then(|e| e.set_secret(key))
        .map_err(|e| format!("couldn't save to the system keychain: {e}"))
}

pub fn load_device_key(vault_id: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let bytes = Zeroizing::new(if fake_mode().is_some() {
        hex_decode(
            &std::fs::read_to_string(fake_path(vault_id))
                .map_err(|_| "no device key".to_string())?,
        )
    } else {
        keyring::Entry::new(SERVICE, &account(vault_id))
            .and_then(|e| e.get_secret())
            .map_err(|e| format!("couldn't read the system keychain: {e}"))?
    });
    let mut out = Zeroizing::new([0u8; 32]);
    if bytes.len() != 32 {
        return Err("the keychain entry is damaged — use your passphrase".into());
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn delete_device_key(vault_id: &str) {
    if fake_mode().is_some() {
        let _ = std::fs::remove_file(fake_path(vault_id));
        return;
    }
    if let Ok(e) = keyring::Entry::new(SERVICE, &account(vault_id)) {
        let _ = e.delete_credential();
    }
}

fn fake_path(vault_id: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("keyvault-fake-keychain-{vault_id}"))
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.trim().len() / 2)
        .filter_map(|i| u8::from_str_radix(&s.trim()[2 * i..2 * i + 2], 16).ok())
        .collect()
}
