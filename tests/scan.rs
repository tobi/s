mod common;
use common::*;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// A secret value with a meaningful length (>= 8 bytes so it clears the floor).
const SECRET: &str = "hunter2secret";

#[cfg(unix)]
fn is_exec(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn read_text(fx: &Fixture, rel: &str) -> String {
    String::from_utf8(fx.read(rel)).unwrap()
}

fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

/// `s scan --staged` must read the INDEX blob, not the worktree copy. Stage a
/// file holding the secret, then overwrite the worktree with a placeholder:
/// the old code read the worktree and reported clean; the index still leaks.
#[test]
fn staged_scans_index_not_worktree() {
    let fx = Fixture::inited_git();
    fx.set("API_KEY", SECRET);

    fx.write("cfg.txt", format!("key={SECRET}\n"));
    fx.git(&["add", "cfg.txt"]);
    // "oops, cleaned up, forgot to re-add" — worktree no longer has the secret.
    fx.write("cfg.txt", "key=PLACEHOLDER\n");

    let r = fx.s(&["scan", "--staged"]);
    assert_eq!(r.code, 1, "staged scan must fail; stderr:\n{}", r.stderr);
    assert!(r.stderr.contains("cfg.txt"), "must name the file:\n{}", r.stderr);
    assert!(r.stderr.contains("API_KEY"), "must name the key:\n{}", r.stderr);
}

/// A file that is not valid UTF-8 (contains 0xFF) but holds the secret must be
/// detected. The old `read_to_string` path silently skipped it.
#[test]
fn non_utf8_file_is_scanned() {
    let fx = Fixture::inited_git();
    fx.set("API_KEY", SECRET);

    let mut bytes = Vec::from(b"key=".as_slice());
    bytes.extend_from_slice(SECRET.as_bytes());
    bytes.extend_from_slice(b"\xff\x00more garbage\n");
    fx.write("bin.dat", &bytes);
    fx.git(&["add", "bin.dat"]);

    let r = fx.s(&["scan", "--staged"]);
    assert_eq!(r.code, 1, "non-utf8 file must be caught:\n{}", r.stderr);
    assert!(r.stderr.contains("bin.dat"), "must name bin.dat:\n{}", r.stderr);
}

/// A multi-line (PEM-style) secret committed in plaintext must be found, with a
/// sensible line number. The old per-line `contains` made needles with `\n`
/// structurally unfindable — and private keys are the highest-value secret.
#[test]
fn multiline_secret_is_found_with_line_number() {
    let fx = Fixture::inited_git();
    let pem = "-----BEGIN PRIVATE KEY-----\nMIIBVwIBADANBgkqhkiG9w0BAQE\n-----END PRIVATE KEY-----";
    // Store the multi-line value verbatim via stdin.
    let r = fx.s_stdin(&["set", "PRIVATE_KEY", "--stdin"], pem);
    assert_eq!(r.code, 0, "set PRIVATE_KEY failed:\n{}", r.stderr);

    // Put a leading line so the match line is non-trivial.
    fx.write("leaked.key", format!("intro line\n{pem}\n"));
    fx.git(&["add", "leaked.key"]);

    let r = fx.s(&["scan", "--staged"]);
    assert_eq!(r.code, 1, "multiline secret must be caught:\n{}", r.stderr);
    assert!(r.stderr.contains("leaked.key"), "must name leaked.key:\n{}", r.stderr);
    assert!(
        r.stderr.contains("leaked.key:2"),
        "must report the starting line (2):\n{}",
        r.stderr
    );
}

/// A non-ASCII filename (`créds.txt`) staged with a secret must be detected.
/// The old code split git output by lines and never unquoted, so the quoted
/// path `cr\303\251ds.txt` never opened.
#[test]
fn non_ascii_filename_is_scanned() {
    let fx = Fixture::inited_git();
    fx.set("API_KEY", SECRET);

    fx.write("créds.txt", format!("API_KEY={SECRET}\n"));
    fx.git(&["add", "créds.txt"]);

    let r = fx.s(&["scan", "--staged"]);
    assert_eq!(r.code, 1, "non-ascii filename must be caught:\n{}", r.stderr);
    assert!(
        r.stderr.contains("créds.txt"),
        "must name créds.txt:\n{}",
        r.stderr
    );
}

/// An unrelated plaintext `prod.senv` must be scanned; the real store must not.
/// The old `ends_with(".senv")` suffix test skipped `prod.senv` too. Force-add
/// the real store as well so the canonical-path exclusion is exercised: it is
/// excluded, while `prod.senv` is scanned.
#[test]
fn prod_senv_scanned_real_store_excluded() {
    let fx = Fixture::inited_git();
    fx.set("API_KEY", SECRET);

    fx.write("prod.senv", format!("API_KEY={SECRET}\n"));
    fx.git(&["add", "prod.senv"]);
    // Force the real store into the index so exclusion is actually tested.
    fx.git(&["add", "-f", ".senv"]);

    let r = fx.s(&["scan", "--staged"]);
    assert_eq!(r.code, 1, "prod.senv must be caught:\n{}", r.stderr);
    assert!(r.stderr.contains("prod.senv"), "must name prod.senv:\n{}", r.stderr);
    // The real store must never appear as a finding line.
    assert!(
        !r.stderr.contains("  .senv:"),
        "real store must be excluded, but stderr:\n{}",
        r.stderr
    );
}

/// A clean tree exits 0.
#[test]
fn clean_tree_exits_zero() {
    let fx = Fixture::inited_git();
    fx.set("API_KEY", SECRET);

    fx.write("clean.txt", "nothing to see here\n");
    fx.git(&["add", "clean.txt"]);

    let r = fx.s(&["scan", "--staged"]);
    assert_eq!(r.code, 0, "clean tree must exit 0:\n{}", r.stderr);
}

/// Values under 8 bytes are skipped (short values are noise) but the skip must
/// be VISIBLE: a note naming the short keys is printed on stderr.
#[test]
fn short_secret_floor_is_visible() {
    let fx = Fixture::inited_git();
    fx.set("SHORT", "abc"); // 3 bytes — under the 8-byte floor
    fx.set("API_KEY", SECRET);

    // File contains both the short value and a real secret.
    fx.write("f.txt", format!("SHORT=abc\nAPI_KEY={SECRET}\n"));
    fx.git(&["add", "f.txt"]);

    let r = fx.s(&["scan", "--staged"]);
    // The real secret is still caught.
    assert_eq!(r.code, 1, "real secret must be caught:\n{}", r.stderr);
    assert!(
        r.stderr.contains("not scanning for 1 secret(s) under 8 bytes: SHORT"),
        "must note the skipped short key:\n{}",
        r.stderr
    );
    // The short value itself is not reported as a finding.
    assert!(
        !r.stderr.contains("contains: SHORT"),
        "short secret must not be scanned:\n{}",
        r.stderr
    );
}

/// A worktree file that cannot be read produces a warning instead of being
/// silently dropped. Skipped when running as root (chmod 000 won't deny root).
#[test]
fn unreadable_file_warns() {
    if is_root() {
        eprintln!("s: skipping unreadable_file_warns under root");
        return;
    }

    let fx = Fixture::inited_git();
    fx.set("API_KEY", SECRET);

    fx.write("secret.txt", format!("API_KEY={SECRET}\n"));
    fx.git(&["add", "secret.txt"]);

    let path = fx.path("secret.txt");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    let r = fx.s(&["scan"]); // worktree scan reads the file
    // Restore perms so the temp dir can be cleaned up.
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));

    assert!(
        r.stderr.contains("could not read"),
        "must warn about unreadable file:\n{}",
        r.stderr
    );
    assert!(
        r.stderr.contains("secret.txt"),
        "warning must name the file:\n{}",
        r.stderr
    );
}

/// With `core.hooksPath .husky` set, `s init` installs into `.husky/pre-commit`
/// (executable), not the dead `.git/hooks/pre-commit`.
#[test]
fn install_hook_respects_hooks_path() {
    let fx = Fixture::new_git();
    fx.git(&["config", "core.hooksPath", ".husky"]);

    let r = fx.s(&["init"]);
    assert_eq!(r.code, 0, "s init failed:\n{}", r.stderr);

    let hook = fx.path(".husky/pre-commit");
    assert!(hook.exists(), ".husky/pre-commit must exist");
    assert!(is_exec(&hook), "hook must be executable");

    let content = read_text(&fx, ".husky/pre-commit");
    assert!(
        content.contains("s scan --staged"),
        "hook must contain the scan guard:\n{content}"
    );

    // The default location must NOT have been used.
    assert!(!fx.path(".git/hooks/pre-commit").exists());
}

/// Appending to a hook whose body ends in `exit 0` still yields a hook that
/// runs the guard: the guard is inserted right after the shebang, before the
/// `exit 0`.
#[test]
fn append_guard_before_exit_zero() {
    let fx = Fixture::new_git();
    // Pre-existing hook that ends in `exit 0` (common in templates).
    fx.write(".git/hooks/pre-commit", "#!/bin/sh\necho running\nexit 0\n");

    let r = fx.s(&["init"]);
    assert_eq!(r.code, 0, "s init failed:\n{}", r.stderr);

    let content = read_text(&fx, ".git/hooks/pre-commit");
    let guard = content
        .find("s scan --staged")
        .expect("guard must be present");
    let exit = content.find("exit 0").expect("exit 0 must be present");
    assert!(
        guard < exit,
        "guard must appear before `exit 0`:\n{content}"
    );
    assert!(is_exec(&fx.path(".git/hooks/pre-commit")), "must be executable");
}

/// `check_hook` warns when the only `s scan` occurrence is inside a comment —
/// a substring grep used to be satisfied by `# s scan`.
#[test]
fn check_hook_warns_on_commented_guard() {
    let fx = Fixture::inited_git();
    // Overwrite the installed hook with a commented-only guard, kept executable
    // so only the missing-guard warning fires.
    let hook = fx.path(".git/hooks/pre-commit");
    std::fs::write(&hook, "#!/bin/sh\n# s scan --staged\necho hi\n").unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Any `s` invocation runs check_hook first.
    let r = fx.s(&["list"]);
    assert!(
        r.stderr.contains("no `s scan` guard"),
        "must warn about commented-out guard:\n{}",
        r.stderr
    );
}
