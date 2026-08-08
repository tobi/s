// .senv — YAML with symmetric-encrypted values.
//
// keys:
//   API_KEY: "s2:<base64>"
//   STRIPE_KEY:
//     value: "s2:<base64>"
//     history:
//       - blob: "s2:<base64>"
//         ts: "2026-04-11T14:30:00Z"
//
// Each value is independently encrypted with ChaCha20-Poly1305 under a key
// derived from the store password. No recipient field — whoever has the
// password can decrypt.

use anyhow::{bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::prelude::*;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
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
const TAG_LEN: usize = 16;

/// Marks the current blob scheme. Legacy (pre-0.9) blobs are bare base64 with
/// no marker, which is what makes the two forms unambiguous: base64 never
/// contains `:`.
const V2_PREFIX: &str = "s2:";

/// Argon2id cost, pinned deliberately rather than taken from `Argon2::default()`.
/// The crate is free to change its defaults in any release; because the cost
/// parameters are not recorded in the blob, a changed default would silently
/// make every existing store undecryptable — and the failure would surface as
/// "wrong password", sending users to look for a lost password instead of a
/// version mismatch. Pinning means the scheme prefix, not the crate version,
/// decides how a key is derived.
const ARGON2_V2: Argon2Cost = Argon2Cost { m_cost: 19 * 1024, t_cost: 2, p_cost: 1 };

/// The cost `Argon2::default()` had when v1 blobs were written. Frozen so v1
/// stays readable no matter what happens to the crate default or to `ARGON2_V2`.
const ARGON2_V1: Argon2Cost = Argon2Cost { m_cost: 19 * 1024, t_cost: 2, p_cost: 1 };

struct Argon2Cost {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

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

    /// Install `new_blob`, pushing the current value onto the history stack.
    pub fn update(&mut self, new_blob: String, password: &str, key_name: &str) -> Result<()> {
        let old = self.value().to_string();
        let mut hist: Vec<HistoryEntry> = self.history().to_vec();
        hist.insert(0, HistoryEntry { blob: old, ts: now_iso() });
        hist.truncate(MAX_HISTORY);
        upgrade_history(&mut hist, password, key_name);
        *self = KeyEntry::WithHistory { value: new_blob, history: hist };
        Ok(())
    }

    /// Restore history version `n` (1-based) as the live value.
    ///
    /// The restored blob is re-encrypted under the current scheme, which is also
    /// what makes this an authenticated operation: without the store password
    /// the re-encryption cannot happen, so a rollback cannot silently reinstate
    /// a revoked credential.
    pub fn rollback(&mut self, n: usize, password: &str, key_name: &str) -> Result<()> {
        let mut hist = self.history().to_vec();
        if n == 0 || n > hist.len() {
            bail!("version {n} not found ({} in history)", hist.len());
        }
        let restored = hist.remove(n - 1);
        let restored_blob = reencrypt_value(&restored.blob, password, key_name)
            .context("restoring history entry")?;

        hist.insert(0, HistoryEntry { blob: self.value().to_string(), ts: now_iso() });
        hist.truncate(MAX_HISTORY);
        upgrade_history(&mut hist, password, key_name);
        *self = KeyEntry::WithHistory { value: restored_blob, history: hist };
        Ok(())
    }
}

/// Re-encrypt legacy history blobs, dropping any that will not decrypt.
///
/// A committed `.senv` is only as strong as its weakest blob. Leaving a pre-0.9
/// HKDF entry in history hands an attacker a cheap (two HMACs, not memory-hard)
/// offline oracle for the single password that unlocks every other value — so
/// whenever we already hold the password, the weak blobs go. An entry that does
/// not decrypt is unusable by definition; keeping it would preserve only the
/// liability, so it is dropped rather than failing the write.
fn upgrade_history(hist: &mut Vec<HistoryEntry>, password: &str, key_name: &str) {
    hist.retain_mut(|h| {
        if !is_legacy_blob(&h.blob) {
            return true;
        }
        match reencrypt_value(&h.blob, password, key_name) {
            Ok(upgraded) => {
                h.blob = upgraded;
                true
            }
            Err(_) => false,
        }
    });
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
        serde_yaml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let yaml = serde_yaml::to_string(self).context("serializing YAML")?;

        // Randomized temp name. A predictable sibling (`<path>.tmp`) in a
        // group-writable checkout can be pre-planted by another user; with
        // O_NOFOLLOW that turns a silent overwrite of the link target into a
        // failed save, and a random name avoids the collision entirely.
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
        let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "senv".to_string());
        let tmp = path.with_file_name(format!(".{name}.{suffix}.tmp"));

        write_private(&tmp, yaml.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).context("rename .senv into place");
        }
        // The rename is only durable once the directory entry is on disk. Best
        // effort: some filesystems reject fsync on a directory, and refusing to
        // save at all would be a worse outcome than a weaker crash guarantee.
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if let Ok(d) = std::fs::File::open(parent) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }

    pub fn set_key(&mut self, key: &str, blob: String, password: &str) -> Result<()> {
        if let Some(entry) = self.keys.get_mut(key) {
            entry.update(blob, password, key)?;
        } else {
            self.keys.insert(key.to_string(), KeyEntry::Simple(blob));
        }
        Ok(())
    }
}

// --- Symmetric encryption -------------------------------------------------
//
// v2 (current): "s2:" || base64( salt[16] || nonce[12] || ciphertext+tag )
//   key  = Argon2id(password, salt) with ARGON2_V2 — memory-hard, so a
//          committed `.senv` resists offline brute-force of the password.
//   aad  = the key name, so a blob cannot be relocated to another key.
//
// v1 (legacy, read-only): base64( salt[16] || nonce[12] || ciphertext+tag )
//   key  = Argon2id(ARGON2_V1) or, older still, HKDF-SHA256. No aad.
//   Never written any more; upgraded in place on the next write to that key.

pub fn encrypt_value(plaintext: &str, password: &str, key_name: &str) -> Result<String> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;

    let dk = derive_key_argon2(password, &salt, &ARGON2_V2)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&dk[..]));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload { msg: plaintext.as_bytes(), aad: key_name.as_bytes() },
        )
        .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;

    let mut packed = Vec::with_capacity(SALT_LEN + NONCE_LEN + ct.len());
    packed.extend_from_slice(&salt);
    packed.extend_from_slice(&nonce_bytes);
    packed.extend_from_slice(&ct);
    Ok(format!("{V2_PREFIX}{}", BASE64_STANDARD.encode(&packed)))
}

pub fn decrypt_value(blob: &str, password: &str, key_name: &str) -> Result<String> {
    let blob = blob.trim();
    let legacy = !blob.starts_with(V2_PREFIX);
    let b64 = blob.strip_prefix(V2_PREFIX).unwrap_or(blob);

    let packed = BASE64_STANDARD.decode(b64.as_bytes()).context("base64 decode")?;
    if packed.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
        bail!("blob too short");
    }
    let salt = &packed[..SALT_LEN];
    let nonce = &packed[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ct = &packed[SALT_LEN + NONCE_LEN..];

    let pt = if legacy {
        // Pre-0.9: no associated data, and two possible KDFs. Trying both is
        // safe rather than a downgrade oracle — both are AEAD-authenticated
        // under the same password, so a blob cannot be forged without it.
        derive_key_argon2(password, salt, &ARGON2_V1)
            .ok()
            .and_then(|dk| try_decrypt(&dk, nonce, ct, b""))
            .or_else(|| {
                derive_key_hkdf(password, salt)
                    .ok()
                    .and_then(|dk| try_decrypt(&dk, nonce, ct, b""))
            })
            .ok_or_else(|| anyhow::anyhow!("decryption failed (wrong password?)"))?
    } else {
        let dk = derive_key_argon2(password, salt, &ARGON2_V2)?;
        try_decrypt(&dk, nonce, ct, key_name.as_bytes()).ok_or_else(|| {
            anyhow::anyhow!("decryption failed (wrong password, or the entry was tampered with)")
        })?
    };
    String::from_utf8(pt).context("plaintext is not UTF-8")
}

/// Rewrite `blob` under the current scheme, preserving the plaintext.
pub fn reencrypt_value(blob: &str, password: &str, key_name: &str) -> Result<String> {
    let pt = Zeroizing::new(decrypt_value(blob, password, key_name)?);
    encrypt_value(&pt, password, key_name)
}

/// True for a blob written before the versioned format, i.e. one that should be
/// upgraded the next time we hold the password.
pub fn is_legacy_blob(blob: &str) -> bool {
    !blob.trim().starts_with(V2_PREFIX)
}

fn try_decrypt(key: &[u8; 32], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad }).ok()
}

fn derive_key_argon2(
    password: &str,
    salt: &[u8],
    cost: &Argon2Cost,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(cost.m_cost, cost.t_cost, cost.p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let mut okm = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, okm.as_mut())
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?;
    Ok(okm)
}

/// Oldest KDF, kept only so pre-0.7 blobs still decrypt.
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
        // Never write *through* a symlink. Without this, a planted link at the
        // target turns "create the store" into "truncate and chmod whatever
        // that link points at" — and on the `export --file` path, into writing
        // plaintext secrets somewhere the attacker chose.
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = opts
        .open(path)
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
    // A rename over unsynced data is not atomic across a crash: the directory
    // entry can land while the contents are still zeroes. For a secrets store
    // that is total loss, so pay the fsync.
    f.sync_all().with_context(|| format!("syncing {}", path.display()))?;
    Ok(())
}

// --- Validation -----------------------------------------------------------

pub fn valid_key_name(k: &str) -> bool {
    let mut cs = k.chars();
    let Some(first) = cs.next() else { return false };
    (first.is_ascii_alphabetic() || first == '_')
        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// --- Time -----------------------------------------------------------------

/// UTC timestamp, `YYYY-MM-DDTHH:MM:SSZ`.
fn now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format_iso(secs)
}

fn format_iso(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let tod = unix_secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "correct horse";

    fn legacy_blob(password: &str, plaintext: &str, hkdf: bool) -> String {
        let salt = [7u8; SALT_LEN];
        let nonce = [9u8; NONCE_LEN];
        let dk = if hkdf {
            derive_key_hkdf(password, &salt).unwrap()
        } else {
            derive_key_argon2(password, &salt, &ARGON2_V1).unwrap()
        };
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&dk[..]));
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext.as_bytes(), aad: b"" })
            .unwrap();
        let mut packed = Vec::new();
        packed.extend_from_slice(&salt);
        packed.extend_from_slice(&nonce);
        packed.extend_from_slice(&ct);
        BASE64_STANDARD.encode(&packed)
    }

    #[test]
    fn v2_roundtrip() {
        let blob = encrypt_value("s3cr3t-value", PW, "API_KEY").unwrap();
        assert!(blob.starts_with(V2_PREFIX));
        assert_eq!(decrypt_value(&blob, PW, "API_KEY").unwrap(), "s3cr3t-value");
        assert!(decrypt_value(&blob, "wrong password", "API_KEY").is_err());
    }

    #[test]
    fn v2_is_bound_to_its_key_name() {
        // The AAD binding is what stops a blob being relocated between keys, so
        // an attacker with write access to .senv cannot move PROD_DB_URL's
        // ciphertext into a key whose value gets echoed.
        let blob = encrypt_value("prod-url", PW, "PROD_DB_URL").unwrap();
        assert!(decrypt_value(&blob, PW, "LOG_LEVEL").is_err());
        assert_eq!(decrypt_value(&blob, PW, "PROD_DB_URL").unwrap(), "prod-url");
    }

    #[test]
    fn v2_tamper_is_reported_as_tamper() {
        let blob = encrypt_value("v", PW, "K").unwrap();
        let mut packed = BASE64_STANDARD.decode(blob.strip_prefix(V2_PREFIX).unwrap()).unwrap();
        let last = packed.len() - 1;
        packed[last] ^= 0xff;
        let tampered = format!("{V2_PREFIX}{}", BASE64_STANDARD.encode(&packed));
        let err = decrypt_value(&tampered, PW, "K").unwrap_err().to_string();
        assert!(err.contains("tampered"), "unexpected error: {err}");
    }

    #[test]
    fn legacy_argon2_blob_still_decrypts() {
        let blob = legacy_blob("old-password", "legacy-secret", false);
        assert!(is_legacy_blob(&blob));
        assert_eq!(decrypt_value(&blob, "old-password", "ANY").unwrap(), "legacy-secret");
    }

    #[test]
    fn legacy_hkdf_blob_still_decrypts() {
        let blob = legacy_blob("old-password", "legacy-secret", true);
        assert_eq!(decrypt_value(&blob, "old-password", "ANY").unwrap(), "legacy-secret");
    }

    /// Legacy blobs carry no AAD, so the key name must be ignored for them —
    /// otherwise every pre-0.9 store would become undecryptable.
    #[test]
    fn legacy_blob_ignores_key_name() {
        let blob = legacy_blob("pw", "v", true);
        assert_eq!(decrypt_value(&blob, "pw", "WHATEVER").unwrap(), "v");
    }

    #[test]
    fn reencrypt_upgrades_legacy_to_v2() {
        let old = legacy_blob("pw", "the-value", true);
        let new = reencrypt_value(&old, "pw", "TOKEN").unwrap();
        assert!(!is_legacy_blob(&new));
        assert_eq!(decrypt_value(&new, "pw", "TOKEN").unwrap(), "the-value");
    }

    /// The advertised "re-encrypting upgrades it" must cover history too: a
    /// weak-KDF blob left in history is a cheap offline oracle for the one
    /// password that unlocks every other value.
    #[test]
    fn update_upgrades_legacy_history_blobs() {
        let mut entry = KeyEntry::Simple(legacy_blob("pw", "gen1", true));
        let new = encrypt_value("gen2", "pw", "TOKEN").unwrap();
        entry.update(new, "pw", "TOKEN").unwrap();

        assert_eq!(entry.history().len(), 1);
        let h = &entry.history()[0];
        assert!(!is_legacy_blob(&h.blob), "history blob was left in the legacy scheme");
        assert_eq!(decrypt_value(&h.blob, "pw", "TOKEN").unwrap(), "gen1");
    }

    /// A history entry that cannot be decrypted is unusable, and keeping it
    /// would preserve only the weak-KDF liability — so it is dropped instead of
    /// failing the write.
    #[test]
    fn update_drops_undecryptable_legacy_history() {
        let mut entry = KeyEntry::Simple(legacy_blob("some-other-pw", "gen1", true));
        let new = encrypt_value("gen2", "pw", "TOKEN").unwrap();
        entry.update(new, "pw", "TOKEN").unwrap();
        assert!(entry.history().is_empty());
        assert_eq!(decrypt_value(entry.value(), "pw", "TOKEN").unwrap(), "gen2");
    }

    #[test]
    fn rollback_restores_and_reencrypts() {
        let mut entry = KeyEntry::Simple(encrypt_value("v1", "pw", "K").unwrap());
        entry.update(encrypt_value("v2", "pw", "K").unwrap(), "pw", "K").unwrap();
        entry.rollback(1, "pw", "K").unwrap();

        assert_eq!(decrypt_value(entry.value(), "pw", "K").unwrap(), "v1");
        assert!(!is_legacy_blob(entry.value()));
        // The value we rolled away from is still reachable.
        assert_eq!(decrypt_value(&entry.history()[0].blob, "pw", "K").unwrap(), "v2");
    }

    /// Rollback reinstates a credential, so it must not be possible without the
    /// store password.
    #[test]
    fn rollback_requires_the_password() {
        let mut entry = KeyEntry::Simple(encrypt_value("old", "pw", "K").unwrap());
        entry.update(encrypt_value("new", "pw", "K").unwrap(), "pw", "K").unwrap();

        let mut wrong = entry.clone();
        assert!(wrong.rollback(1, "not-the-password", "K").is_err());
        // ... and the entry is untouched after a failed attempt.
        assert_eq!(decrypt_value(wrong.value(), "pw", "K").unwrap(), "new");
    }

    #[test]
    fn rollback_rejects_out_of_range() {
        let mut entry = KeyEntry::Simple(encrypt_value("v", "pw", "K").unwrap());
        assert!(entry.rollback(1, "pw", "K").is_err());
        assert!(entry.rollback(0, "pw", "K").is_err());
    }

    #[test]
    fn history_is_capped() {
        let mut entry = KeyEntry::Simple(encrypt_value("v0", "pw", "K").unwrap());
        for i in 1..6 {
            let blob = encrypt_value(&format!("v{i}"), "pw", "K").unwrap();
            entry.update(blob, "pw", "K").unwrap();
        }
        assert_eq!(entry.history().len(), MAX_HISTORY);
        assert_eq!(decrypt_value(&entry.history()[0].blob, "pw", "K").unwrap(), "v4");
    }

    #[test]
    fn set_key_on_new_and_existing() {
        let mut f = SenvFile::default();
        f.set_key("A", encrypt_value("1", "pw", "A").unwrap(), "pw").unwrap();
        assert!(f.keys["A"].history().is_empty());
        f.set_key("A", encrypt_value("2", "pw", "A").unwrap(), "pw").unwrap();
        assert_eq!(f.keys["A"].history().len(), 1);
        assert_eq!(decrypt_value(f.keys["A"].value(), "pw", "A").unwrap(), "2");
    }

    #[test]
    fn valid_key_names() {
        assert!(valid_key_name("API_KEY"));
        assert!(valid_key_name("lower_key"));
        assert!(valid_key_name("_X1"));
        assert!(!valid_key_name(""));
        assert!(!valid_key_name("1ABC"));
        assert!(!valid_key_name("HAS-DASH"));
        assert!(!valid_key_name("HAS SPACE"));
    }

    #[test]
    fn iso_timestamps() {
        assert_eq!(format_iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_iso(1_000_000_000), "2001-09-09T01:46:40Z");
        // leap day
        assert_eq!(format_iso(1_709_164_800), "2024-02-29T00:00:00Z");
        // last second of a year
        assert_eq!(format_iso(1_767_225_599), "2025-12-31T23:59:59Z");
    }

    #[test]
    fn now_iso_is_well_formed() {
        let ts = now_iso();
        assert_eq!(ts.len(), 20, "{ts}");
        assert!(ts.ends_with('Z'));
        // Must not regress to the old `date`-subprocess fallback.
        assert_ne!(ts, "unknown");
        assert!(ts.starts_with("20"), "{ts}");
    }

    #[test]
    fn write_private_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        write_private(&p, b"data").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(std::fs::read(&p).unwrap(), b"data");
    }

    /// A planted symlink must not redirect the write. Otherwise `s init` or
    /// `s export --file` can be aimed at any file the user can write.
    #[test]
    #[cfg(unix)]
    fn write_private_refuses_to_follow_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"precious").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        assert!(write_private(&link, b"clobbered").is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(".senv");
        let mut f = SenvFile::default();
        f.set_key("A", encrypt_value("1", "pw", "A").unwrap(), "pw").unwrap();
        f.save(&p).unwrap();

        let back = SenvFile::load(&p).unwrap();
        assert_eq!(decrypt_value(back.keys["A"].value(), "pw", "A").unwrap(), "1");
        // No temp file left behind.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left temp files: {leftovers:?}");
    }

    /// Guard, not a requirement: if the crate's default cost ever diverges from
    /// what we pin, nothing breaks (we no longer call `default()`), but we want
    /// to know about it.
    #[test]
    fn pinned_argon2_cost_still_matches_crate_default() {
        let d = Params::DEFAULT;
        assert_eq!(
            (d.m_cost(), d.t_cost(), d.p_cost()),
            (ARGON2_V2.m_cost, ARGON2_V2.t_cost, ARGON2_V2.p_cost),
            "argon2 crate default changed; v2 stays pinned, but review this"
        );
    }
}
