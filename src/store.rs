// .senv — YAML with symmetric-encrypted values.
//
// keys:
//   API_KEY: "salt:nonce:ciphertext"        # base64-encoded
//   STRIPE_KEY:
//     value: "salt:nonce:ciphertext"
//     history:
//       - blob: "salt:nonce:ciphertext"
//         ts: "2026-04-11T14:30Z"
//
// Each value is independently encrypted with ChaCha20-Poly1305.
// Key = HKDF-SHA256(password, per-value random salt).
// No recipient field — whoever has the password can decrypt.

use anyhow::{bail, Context, Result};
use argon2::Argon2;
use base64::prelude::*;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::path::Path;
use zeroize::Zeroizing;

const MAX_HISTORY: usize = 2;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SenvFile {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub keys: BTreeMap<String, KeyEntry>,
}

/// Bare string for simple keys, struct when history exists.
#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum KeyEntry {
    Simple(String),
    WithHistory {
        value: String,
        history: Vec<HistoryEntry>,
    },
}

impl KeyEntry {
    pub fn value(&self) -> &str {
        match self {
            KeyEntry::Simple(v) => v,
            KeyEntry::WithHistory { value, .. } => value,
        }
    }

    pub fn history(&self) -> &[HistoryEntry] {
        match self {
            KeyEntry::Simple(_) => &[],
            KeyEntry::WithHistory { history, .. } => history,
        }
    }

    pub fn update(&mut self, new_blob: String) {
        let old = self.value().to_string();
        let mut hist: Vec<HistoryEntry> = self.history().to_vec();
        hist.insert(0, HistoryEntry { blob: old, ts: now_iso() });
        hist.truncate(MAX_HISTORY);
        *self = KeyEntry::WithHistory { value: new_blob, history: hist };
    }

    pub fn rollback(&mut self, n: usize) -> Result<()> {
        let hist = self.history().to_vec();
        if n == 0 || n > hist.len() {
            bail!("version {n} not found ({} in history)", hist.len());
        }
        let old_current = self.value().to_string();
        let mut hist = hist;
        let restored = hist.remove(n - 1);
        hist.insert(0, HistoryEntry { blob: old_current, ts: now_iso() });
        hist.truncate(MAX_HISTORY);
        *self = KeyEntry::WithHistory { value: restored.blob, history: hist };
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HistoryEntry {
    pub blob: String,
    pub ts: String,
}

impl SenvFile {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        serde_yaml::from_str(&raw)
            .with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let yaml = serde_yaml::to_string(self).context("serializing YAML")?;
        // Sibling temp file (`<path>.tmp`) written atomically with 0600 perms,
        // then renamed into place.
        let mut tmp_os = path.as_os_str().to_owned();
        tmp_os.push(".tmp");
        let tmp = std::path::PathBuf::from(tmp_os);
        write_private(&tmp, yaml.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path).context("rename .senv into place")?;
        Ok(())
    }

    pub fn set_key(&mut self, key: &str, blob: String) {
        if let Some(entry) = self.keys.get_mut(key) {
            entry.update(blob);
        } else {
            self.keys.insert(key.to_string(), KeyEntry::Simple(blob));
        }
    }
}

// --- Symmetric encryption -------------------------------------------------
//
// Format: base64( salt[16] || nonce[12] || ciphertext )
// Key derivation (current): Argon2id(password, salt) — memory-hard, so a
// committed `.senv` resists offline brute-force of the password.
// Legacy blobs used HKDF-SHA256; `decrypt_value` still reads those so existing
// stores keep working. Anything re-encrypted (`s set`, rollback) upgrades to
// Argon2id.

pub fn encrypt_value(plaintext: &str, password: &str) -> Result<String> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;

    let dk = derive_key_argon2(password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&dk[..]));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;

    let mut packed = Vec::with_capacity(SALT_LEN + NONCE_LEN + ct.len());
    packed.extend_from_slice(&salt);
    packed.extend_from_slice(&nonce_bytes);
    packed.extend_from_slice(&ct);
    Ok(BASE64_STANDARD.encode(&packed))
}

pub fn decrypt_value(blob_b64: &str, password: &str) -> Result<String> {
    let packed = BASE64_STANDARD.decode(blob_b64.trim().as_bytes())
        .context("base64 decode")?;
    if packed.len() < SALT_LEN + NONCE_LEN + 16 {
        bail!("blob too short");
    }
    let salt = &packed[..SALT_LEN];
    let nonce = &packed[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ct = &packed[SALT_LEN + NONCE_LEN..];

    // Try the current scheme (Argon2id) first, then fall back to the legacy
    // HKDF scheme so pre-0.7 stores still decrypt. The AEAD tag tells us which
    // key was correct, so a wrong password fails both and errors cleanly.
    let pt = derive_key_argon2(password, salt)
        .ok()
        .and_then(|dk| try_decrypt(&dk, nonce, ct))
        .or_else(|| {
            derive_key_hkdf(password, salt)
                .ok()
                .and_then(|dk| try_decrypt(&dk, nonce, ct))
        })
        .ok_or_else(|| anyhow::anyhow!("decryption failed (wrong password?)"))?;
    String::from_utf8(pt).context("plaintext is not UTF-8")
}

fn try_decrypt(key: &[u8; 32], nonce: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(Nonce::from_slice(nonce), ct).ok()
}

/// Current KDF: Argon2id with the crate's default cost params.
fn derive_key_argon2(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut okm = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, okm.as_mut())
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?;
    Ok(okm)
}

/// Legacy KDF (pre-0.7), kept only so old blobs still decrypt.
fn derive_key_hkdf(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), password.as_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(b"s-v1", okm.as_mut()).map_err(|e| anyhow::anyhow!("HKDF: {e}"))?;
    Ok(okm)
}

/// Write `data` to `path` with 0600 permissions (owner read/write only).
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    #[cfg(unix)]
    {
        // Enforce 0600 even if the file already existed (mode() only applies on
        // creation).
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod {}", path.display()))?;
    }
    f.write_all(data).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

// --- Validation -----------------------------------------------------------

pub fn valid_key_name(k: &str) -> bool {
    let mut cs = k.chars();
    let Some(first) = cs.next() else { return false };
    (first.is_ascii_alphabetic() || first == '_')
        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn now_iso() -> String {
    use std::process::Command;
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_roundtrip() {
        let blob = encrypt_value("s3cr3t-value", "correct horse").unwrap();
        assert_eq!(decrypt_value(&blob, "correct horse").unwrap(), "s3cr3t-value");
        assert!(decrypt_value(&blob, "wrong password").is_err());
    }

    /// A blob produced by the pre-0.7 HKDF scheme must still decrypt.
    #[test]
    fn legacy_hkdf_blob_still_decrypts() {
        let password = "old-password";
        let plaintext = "legacy-secret";
        let salt = [7u8; SALT_LEN];
        let nonce = [9u8; NONCE_LEN];

        // Reconstruct exactly what the old code wrote: HKDF-SHA256 key.
        let dk = derive_key_hkdf(password, &salt).unwrap();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&dk[..]));
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
            .unwrap();
        let mut packed = Vec::new();
        packed.extend_from_slice(&salt);
        packed.extend_from_slice(&nonce);
        packed.extend_from_slice(&ct);
        let blob = BASE64_STANDARD.encode(&packed);

        assert_eq!(decrypt_value(&blob, password).unwrap(), plaintext);
    }
}
