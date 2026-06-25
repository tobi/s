// s — encrypted env store
//
// .senv:
//   keys:
//     API_KEY: "<salt:nonce:ct in base64>"
//     STRIPE_KEY:
//       value: "<salt:nonce:ct>"
//       history:
//         - blob: "<previous>"
//           ts: "2026-04-11T14:30Z"

mod scrub;
mod store;

use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use zeroize::Zeroizing;

const STORE_FILE: &str = ".senv";
const REDACTED: &str = "[REDACTED]";

fn main() {
    if let Err(e) = run() {
        eprintln!("s: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    expand_inline_shebang_args(&mut args);
    if args.is_empty() {
        print_usage();
        return Ok(());
    }

    // Verify git hook exists (if in a git repo with .senv)
    check_hook();

    // `s KEY1 KEY2 -- cmd args...`
    if let Some(dash_pos) = args.iter().position(|a| a == "--") {
        let names = &args[..dash_pos];
        let cmd_args = &args[dash_pos + 1..];
        if cmd_args.is_empty() {
            bail!("missing command after --");
        }
        // `s --all -- cmd` injects every secret — opt-in only, never the default.
        if names.len() == 1 && names[0] == "--all" {
            return cmd_exec(cmd_args, None);
        }
        // `s -- cmd` with no names injects nothing (safe default).
        if names.is_empty() {
            return cmd_exec(cmd_args, Some(&[]));
        }
        if names.iter().all(|n| looks_like_key(n)) {
            return cmd_exec(cmd_args, Some(names));
        }
    }

    match args[0].as_str() {
        "init" => cmd_init(),
        "set" => cmd_set(&args[1..]),
        "get" => cmd_get(&args[1..]),
        "rm" => cmd_rm(&args[1..]),
        "list" | "ls" => cmd_list(&args[1..]),
        "import" => cmd_import(&args[1..]),
        "export" => cmd_export(&args[1..]),
        "scan" => cmd_scan(&args[1..]),
        "history" => cmd_history(&args[1..]),
        "rollback" => cmd_rollback(&args[1..]),
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        other => bail!("unknown command: {other} (try `s help`)"),
    }
}

fn print_usage() {
    eprintln!(
        "\
s — encrypted env store. your agent doesn't need to know your secrets.

usage:
  s KEY [KEY...] -- <cmd>       run cmd with specific secrets injected
  s --all -- <cmd>              run cmd with ALL secrets injected

inline / shebang mode:
  #!/usr/bin/env -S s KEY [KEY...] -- python3
  #!/usr/local/bin/s KEY [KEY...] -- python3
                                inject secrets into scripts automatically

secrets:
  s set <NAME>                  set a secret (interactive, masked)
  s set <NAME> --stdin          set from stdin
  s get <NAME>                  show decrypted value (human debugging)
  s rm <NAME>                   delete a secret
  s list                        list secrets (values masked)

import/export:
  s import .env                 import from .env file
  s import --stdin              import KEY=VALUE lines from stdin
  s import --from-env           import all env vars
  s import --from-env NAME      import specific env var
  s export                      export all as KEY=VALUE to stdout
  s export --file .env          export to file

history:
  s history <NAME>              show version history
  s rollback <NAME> --to N      restore version N

scanning:
  s scan                        scan tracked files for leaked secrets
  s scan --staged               scan only staged files

setup:
  s init                        create .senv + install pre-commit hook

store location (precedence):
  S_FILE env var                explicit store path (overrides the rest)
  ./.senv                       project-local store
  ~/.config/senv/senv           global store (merged under local; local wins)

password (one of):
  S_KEY env var                 the password directly
  S_KEY=\"!cmd\"                  execute cmd to get password
  TTY prompt                    fallback if interactive"
    );
}

/// Linux shebangs pass everything after the interpreter path as one argv string.
/// This lets scripts use inline mode directly:
///   #!/usr/local/bin/s API_KEY -- python3
/// as well as the portable env form:
///   #!/usr/bin/env -S s API_KEY -- python3
fn expand_inline_shebang_args(args: &mut Vec<String>) {
    let Some(first) = args.first() else { return; };
    if !first.contains("--") || !first.contains(char::is_whitespace) {
        return;
    }

    let mut expanded: Vec<String> = first
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    expanded.extend(args.iter().skip(1).cloned());
    *args = expanded;
}

/// Returns true if stdout is connected to a TTY (human at terminal).
fn is_tty() -> bool {
    use std::os::fd::AsRawFd;
    unsafe { libc::isatty(io::stdout().as_raw_fd()) == 1 }
}

/// Bail if no TTY — prevents secrets from leaking into agent context.
fn require_tty(action: &str) -> Result<()> {
    if !is_tty() {
        bail!("refusing to {action} without a TTY (secret would leak into agent context)");
    }
    Ok(())
}

/// UPPER_SNAKE_CASE — looks like an env var name.
fn looks_like_key(s: &str) -> bool {
    !s.is_empty()
        && s.chars().next().unwrap().is_ascii_uppercase()
        && s.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Project-local store in the current directory.
fn store_path() -> PathBuf {
    PathBuf::from(STORE_FILE)
}

/// `$S_FILE` if set to a non-empty value — an explicit override of the store
/// location, used for both reads and writes (including `s init`).
fn override_store_path() -> Option<PathBuf> {
    std::env::var_os("S_FILE")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Global fallthrough store: `~/.config/senv/senv` (honours `$XDG_CONFIG_HOME`).
fn global_store_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(xdg).join("senv/senv"));
    }
    std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map(|h| PathBuf::from(h).join(".config/senv/senv"))
}

/// Where `s init` should create the store: `$S_FILE` if set, else local `.senv`.
fn store_path_for_init() -> PathBuf {
    override_store_path().unwrap_or_else(store_path)
}

/// Stores to read from, highest precedence first. With `$S_FILE` set, that
/// file is the *only* store (an explicit override — no global merge).
/// Otherwise reads merge `./.senv` over `~/.config/senv/senv`, local winning.
fn read_store_paths() -> Vec<PathBuf> {
    if let Some(p) = override_store_path() {
        return if p.exists() { vec![p] } else { Vec::new() };
    }
    let mut paths = Vec::new();
    let local = store_path();
    if local.exists() {
        paths.push(local);
    }
    if let Some(g) = global_store_path() {
        if g.exists() {
            paths.push(g);
        }
    }
    paths
}

/// The single store that writes target / the existence guard for reads.
/// Precedence: `$S_FILE` (explicit override), then `./.senv`, then
/// `~/.config/senv/senv`; first existing wins. New keys land here, while
/// existing keys are updated wherever they already live (see `store_containing`).
fn ensure_store() -> Result<PathBuf> {
    if let Some(p) = override_store_path() {
        if p.exists() {
            return Ok(p);
        }
        bail!("S_FILE={} does not exist — run `s init` first", p.display());
    }
    let local = store_path();
    if local.exists() {
        return Ok(local);
    }
    if let Some(g) = global_store_path() {
        if g.exists() {
            return Ok(g);
        }
        bail!(
            "no {STORE_FILE} here and no global store at {} — run `s init` first",
            g.display()
        );
    }
    bail!("no {STORE_FILE} here — run `s init` first");
}

/// Find which store currently holds `key`, searching in read precedence order.
fn store_containing(key: &str) -> Result<Option<PathBuf>> {
    for p in read_store_paths() {
        let f = store::SenvFile::load(&p)?;
        if f.keys.contains_key(key) {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

/// Merge every readable store into one map, local (higher precedence) winning.
/// This is the single source of truth for all read paths, so one password
/// decrypts everything.
fn merged_keys() -> Result<std::collections::BTreeMap<String, store::KeyEntry>> {
    use std::collections::BTreeMap;
    if let Some(p) = override_store_path() {
        if !p.exists() {
            bail!("S_FILE={} does not exist — run `s init` first", p.display());
        }
    }
    let paths = read_store_paths();
    let mut merged: BTreeMap<String, store::KeyEntry> = BTreeMap::new();
    // Apply lowest precedence first so higher-precedence stores overwrite.
    for p in paths.iter().rev() {
        let f = store::SenvFile::load(p)?;
        for (k, v) in f.keys {
            merged.insert(k, v);
        }
    }
    Ok(merged)
}

/// Get the password from S_KEY env (supports !command), or prompt on TTY.
/// Wrapped in `Zeroizing` so the password is wiped from memory on drop.
fn get_password() -> Result<Zeroizing<String>> {
    if let Ok(val) = std::env::var("S_KEY") {
        if !val.is_empty() {
            return Ok(Zeroizing::new(resolve_cli_value(&val)?));
        }
    }
    // Prompt on TTY
    let pw = rpassword::prompt_password("s password: ")
        .context("reading password from TTY")?;
    Ok(Zeroizing::new(pw))
}

/// If `val` starts with `!`, execute the rest as a shell command.
fn resolve_cli_value(val: &str) -> Result<String> {
    if let Some(cmd) = val.strip_prefix('!') {
        let cmd = cmd.trim();
        if cmd.is_empty() { bail!("empty command after '!'") }
        let output = Command::new("sh")
            .args(["-c", cmd])
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("executing: {cmd}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("S_KEY command failed ({}): {}", output.status, stderr.trim());
        }
        let s = String::from_utf8(output.stdout).context("S_KEY command output not UTF-8")?;
        let s = s.trim().to_string();
        if s.is_empty() { bail!("S_KEY command produced no output") }
        Ok(s)
    } else {
        Ok(val.to_string())
    }
}

// --- init -----------------------------------------------------------------

fn cmd_init() -> Result<()> {
    let path = store_path_for_init();
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    let file = store::SenvFile::default();
    file.save(&path)?;
    eprintln!("s: created {}", path.display());

    // Git hook + .gitignore only make sense for a project-local .senv.
    if path == store_path() {
        install_hook()?;
        ensure_gitignore()?;
    }

    Ok(())
}

fn install_hook() -> Result<()> {
    let hooks_dir = PathBuf::from(".git/hooks");
    if !hooks_dir.exists() {
        eprintln!("s: not a git repo, skipping hook install");
        return Ok(());
    }
    let hook_path = hooks_dir.join("pre-commit");
    let scan_line = "s scan --staged";

    if hook_path.exists() {
        let content = std::fs::read_to_string(&hook_path).unwrap_or_default();
        if content.contains(scan_line) {
            eprintln!("s: pre-commit hook already has scan guard");
            return Ok(());
        }
        // Append to existing hook
        let mut f = std::fs::OpenOptions::new().append(true).open(&hook_path)
            .context("appending to pre-commit hook")?;
        writeln!(f, "\n# s: guard against committing secrets")?;
        writeln!(f, "{scan_line}")?;
        eprintln!("s: appended scan guard to existing pre-commit hook");
    } else {
        let content = format!("#!/bin/sh\n# s: guard against committing secrets\n{scan_line}\n");
        std::fs::write(&hook_path, &content).context("writing pre-commit hook")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755))?;
        }
        eprintln!("s: installed pre-commit hook");
    }
    Ok(())
}

fn ensure_gitignore() -> Result<()> {
    let gi = PathBuf::from(".gitignore");
    if gi.exists() {
        let content = std::fs::read_to_string(&gi).unwrap_or_default();
        if content.lines().any(|l| l.trim() == ".senv") {
            return Ok(());
        }
        let mut f = std::fs::OpenOptions::new().append(true).open(&gi)
            .context("appending to .gitignore")?;
        writeln!(f, "\n# s: encrypted secrets\n.senv")?;
    } else {
        std::fs::write(&gi, "# s: encrypted secrets\n.senv\n")
            .context("writing .gitignore")?;
    }
    eprintln!("s: added .senv to .gitignore");
    Ok(())
}

/// Warn once if .senv exists but pre-commit hook is missing.
fn check_hook() {
    if !store_path().exists() { return }
    let hook = PathBuf::from(".git/hooks/pre-commit");
    if !hook.exists() { return }
    let content = std::fs::read_to_string(&hook).unwrap_or_default();
    if !content.contains("s scan") {
        eprintln!("s: ⚠ pre-commit hook exists but has no `s scan` guard. run `s init` to fix.");
    }
}

// --- set / get / rm -------------------------------------------------------

fn cmd_set(args: &[String]) -> Result<()> {
    let mut from_stdin = false;
    let mut force = false;
    let mut positional: Vec<String> = Vec::new();
    for a in args {
        match a.as_str() {
            "--stdin" => from_stdin = true,
            "-f" | "--force" => force = true,
            other => positional.push(other.to_string()),
        }
    }
    if positional.is_empty() {
        bail!("usage: s set <NAME> [--stdin]");
    }
    let key = &positional[0];
    if !store::valid_key_name(key) { bail!("invalid key: {key:?}") }

    let value = if from_stdin {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).context("reading stdin")?;
        buf.trim_end_matches('\n').to_string()
    } else {
        read_secret_interactive(key)?
    };
    set_key_value(key, &value, force)
}

/// Read a secret value interactively, echoing `*` for each character.
fn read_secret_interactive(key: &str) -> Result<String> {
    use std::io::BufReader;

    let tty = std::fs::OpenOptions::new()
        .read(true).write(true).open("/dev/tty")
        .context("no TTY available — use --stdin")?;
    let mut tty_w = tty.try_clone()?;
    write!(tty_w, "{key}: ")?;
    tty_w.flush()?;

    // Raw mode: read char by char
    let fd = {
        use std::os::fd::AsRawFd;
        tty.as_raw_fd()
    };
    let orig = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        libc::tcgetattr(fd, &mut t);
        t
    };
    let mut raw = orig;
    // Disable echo and canonical mode so the password is never displayed.
    raw.c_lflag &= !(libc::ECHO | libc::ICANON);
    raw.c_cc[libc::VMIN] = 1;
    raw.c_cc[libc::VTIME] = 0;
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) };

    let mut value = String::new();
    let mut reader = BufReader::new(&tty);
    let mut byte = [0u8; 1];
    loop {
        use std::io::Read;
        match reader.read(&mut byte) {
            Ok(1) => {
                match byte[0] {
                    b'\n' | b'\r' => break,
                    127 | 8 => { // backspace / delete
                        if !value.is_empty() {
                            value.pop();
                            let _ = write!(tty_w, "\x08 \x08");
                            let _ = tty_w.flush();
                        }
                    }
                    3 => { // Ctrl-C
                        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };
                        let _ = writeln!(tty_w);
                        bail!("aborted");
                    }
                    c if c >= 32 => {
                        value.push(c as char);
                        let _ = write!(tty_w, "*");
                        let _ = tty_w.flush();
                    }
                    _ => {} // ignore other control chars
                }
            }
            _ => break,
        }
    }

    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };
    let _ = writeln!(tty_w);

    if value.is_empty() {
        bail!("empty value");
    }
    Ok(value)
}

fn set_key_value(key: &str, value: &str, force: bool) -> Result<()> {
    // Update the key where it already lives (any store); otherwise create it
    // in the primary writable store.
    let path = match store_containing(key)? {
        Some(p) => p,
        None => ensure_store()?,
    };
    let mut file = store::SenvFile::load(&path)?;
    if file.keys.contains_key(key) && !force && !confirm_overwrite(key)? {
        bail!("aborted");
    }
    let pw = get_password()?;
    let blob = store::encrypt_value(value, &pw)?;
    let verb = if file.keys.contains_key(key) { "updated" } else { "added" };
    file.set_key(key, blob);
    file.save(&path)?;
    eprintln!("s: {verb} {key}");
    Ok(())
}

fn cmd_get(args: &[String]) -> Result<()> {
    require_tty("show secret")?;
    if args.is_empty() { bail!("usage: s get <NAME>") }
    let key = &args[0];
    let merged = merged_keys()?;
    let entry = merged.get(key.as_str())
        .ok_or_else(|| anyhow!("key {key} not found"))?;
    let pw = get_password()?;
    let v = store::decrypt_value(entry.value(), &pw)
        .with_context(|| format!("decrypting {key}"))?;
    println!("{v}");
    Ok(())
}

fn cmd_rm(args: &[String]) -> Result<()> {
    if args.is_empty() { bail!("usage: s rm <NAME>") }
    let key = &args[0];
    let path = store_containing(key)?
        .ok_or_else(|| anyhow!("key {key} not found"))?;
    let mut file = store::SenvFile::load(&path)?;
    file.keys.remove(key);
    file.save(&path)?;
    eprintln!("s: removed {key}");
    Ok(())
}

// --- list -----------------------------------------------------------------

fn cmd_list(args: &[String]) -> Result<()> {
    let mut json = false;
    for a in args {
        if a == "--json" { json = true }
        else { bail!("unknown flag: {a}") }
    }
    // Merged view across local + global (or just $S_FILE), local winning.
    let keys = match merged_keys() {
        Ok(m) => m,
        Err(_) => {
            if json { println!("[]") } else { eprintln!("s: no {STORE_FILE} here") }
            return Ok(());
        }
    };
    if keys.is_empty() {
        if json { println!("[]") } else { eprintln!("s: (no secrets)") }
        return Ok(());
    }
    if json {
        print!("[");
        for (i, k) in keys.keys().enumerate() {
            if i > 0 { print!(",") }
            print!("\"{k}\"");
        }
        println!("]");
    } else {
        for k in keys.keys() {
            println!("  {k:30} {REDACTED}");
        }
    }
    Ok(())
}

// --- exec -----------------------------------------------------------------

fn cmd_exec(cmd_args: &[String], only: Option<&[String]>) -> Result<()> {
    ensure_store()?;
    let entries = decrypt_all()?;

    let entries: Vec<(String, String)> = match only {
        Some(names) => {
            let mut selected = Vec::new();
            for name in names {
                match entries.iter().find(|(k, _)| k == name) {
                    Some((k, v)) => selected.push((k.clone(), v.clone())),
                    None => bail!("secret {name} not found. add it: s set {name}"),
                }
            }
            selected
        }
        None => entries,
    };

    let mut cmd = Command::new(&cmd_args[0]);
    cmd.args(&cmd_args[1..]);
    // Don't leak the master password into the child: a spawned command (or the
    // agent driving it) could otherwise read $S_KEY and exfiltrate it.
    cmd.env_remove("S_KEY");
    for (k, v) in &entries {
        cmd.env(k, v);
    }

    let secrets: Vec<Vec<u8>> = entries.iter()
        .map(|(_, v)| v.as_bytes().to_vec())
        .filter(|v| !v.is_empty())
        .collect();

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.stdin(Stdio::inherit());

    let mut child = cmd.spawn().with_context(|| format!("spawn {}", &cmd_args[0]))?;
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let sa = secrets.clone();
    let sb = secrets;
    let t1 = std::thread::spawn(move || scrub::copy(&mut out, &mut io::stdout(), &sa));
    let t2 = std::thread::spawn(move || scrub::copy(&mut err, &mut io::stderr(), &sb));
    let status = child.wait().context("wait child")?;
    let _ = t1.join();
    let _ = t2.join();
    std::process::exit(status.code().unwrap_or(1));
}

// --- import / export ------------------------------------------------------

fn cmd_import(args: &[String]) -> Result<()> {
    let path = ensure_store()?;
    let mut force = false;
    let mut from_stdin = false;
    let mut from_env = false;
    let mut from_env_name: Option<String> = None;
    let mut file_arg: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-f" | "--force" => force = true,
            "--stdin" => from_stdin = true,
            "--from-env" => {
                from_env = true;
                if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    i += 1;
                    from_env_name = Some(args[i].clone());
                }
            }
            other => file_arg = Some(other.to_string()),
        }
        i += 1;
    }

    let pw = get_password()?;

    if from_env {
        if let Some(name) = from_env_name {
            if !store::valid_key_name(&name) { bail!("invalid variable name: {name:?}") }
            let v = std::env::var(&name).with_context(|| format!("${name} is not set"))?;
            let blob = store::encrypt_value(&v, &pw)?;
            let mut file = store::SenvFile::load(&path)?;
            file.set_key(&name, blob);
            file.save(&path)?;
            eprintln!("s: imported {name}");
            return Ok(());
        }
        let mut file = store::SenvFile::load(&path)?;
        let mut count = 0;
        for (k, v) in std::env::vars() {
            if !store::valid_key_name(&k) || is_boring_env(&k) { continue }
            if file.keys.contains_key(&k) && !force { continue }
            let blob = store::encrypt_value(&v, &pw)?;
            file.set_key(&k, blob);
            count += 1;
        }
        file.save(&path)?;
        eprintln!("s: imported {count} variable(s) from environment");
        return Ok(());
    }

    let lines: Vec<String> = if from_stdin {
        io::stdin().lock().lines().collect::<Result<Vec<_>, _>>().context("reading stdin")?
    } else if let Some(f) = file_arg {
        std::fs::read_to_string(&f)
            .with_context(|| format!("reading {f}"))?
            .lines().map(String::from).collect()
    } else {
        bail!("usage: s import <file> | --stdin | --from-env [NAME]");
    };

    let mut file = store::SenvFile::load(&path)?;
    let mut count = 0;
    for line in &lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') { continue }
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let Some((k, v)) = trimmed.split_once('=') else { continue };
        let k = k.trim();
        if !store::valid_key_name(k) { continue }
        let v = strip_quotes(v.trim());
        if file.keys.contains_key(k) && !force {
            eprintln!("s: skipping {k} (exists, use -f to overwrite)");
            continue;
        }
        let blob = store::encrypt_value(&v, &pw)?;
        file.set_key(k, blob);
        count += 1;
    }
    file.save(&path)?;
    eprintln!("s: imported {count} secret(s)");
    Ok(())
}

fn strip_quotes(s: &str) -> String {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"'))
            || (s.starts_with('\'') && s.ends_with('\'')))
    {
        return s[1..s.len() - 1].to_string();
    }
    s.to_string()
}

fn is_boring_env(k: &str) -> bool {
    matches!(k,
        "HOME" | "USER" | "SHELL" | "PATH" | "PWD" | "OLDPWD" | "TERM"
        | "LANG" | "LC_ALL" | "LC_CTYPE" | "EDITOR" | "VISUAL" | "PAGER"
        | "HOSTNAME" | "LOGNAME" | "SHLVL" | "TMPDIR" | "_"
        | "XDG_CONFIG_HOME" | "XDG_DATA_HOME" | "XDG_CACHE_HOME" | "XDG_RUNTIME_DIR"
        | "S_KEY"
    )
}

fn cmd_export(args: &[String]) -> Result<()> {
    require_tty("export secrets")?;
    ensure_store()?;
    let mut out_file: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--file" | "--env-file" => {
                i += 1;
                if i >= args.len() { bail!("--file requires a path") }
                out_file = Some(args[i].clone());
            }
            other => bail!("unknown flag: {other}"),
        }
        i += 1;
    }
    let entries = decrypt_all()?;
    let mut output = String::new();
    for (k, v) in &entries {
        if v.contains(' ') || v.contains('"') || v.contains('\'') || v.contains('#') {
            let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
            output.push_str(&format!("{k}=\"{escaped}\"\n"));
        } else {
            output.push_str(&format!("{k}={v}\n"));
        }
    }
    if let Some(f) = out_file {
        // Plaintext on disk — restrict to owner read/write.
        store::write_private(Path::new(&f), output.as_bytes())
            .with_context(|| format!("writing {f}"))?;
        eprintln!("s: exported {} secret(s) to {f}", entries.len());
    } else {
        print!("{output}");
    }
    Ok(())
}

// --- history / rollback ---------------------------------------------------

fn cmd_history(args: &[String]) -> Result<()> {
    if args.is_empty() { bail!("usage: s history <NAME>") }
    let key = &args[0];
    let merged = merged_keys()?;
    let entry = merged.get(key.as_str())
        .ok_or_else(|| anyhow!("key {key} not found"))?;
    println!("history for {key}\n");
    println!("  ● current (active)");
    let hist = entry.history();
    if hist.is_empty() {
        println!("\n  no previous versions");
    } else {
        for (i, h) in hist.iter().enumerate() {
            println!("  ● v{}  {}", i + 1, h.ts);
        }
        println!("\n  {} previous version(s)", hist.len());
        println!("  rollback: s rollback {key} --to <version>");
    }
    Ok(())
}

fn cmd_rollback(args: &[String]) -> Result<()> {
    let mut key: Option<String> = None;
    let mut to: Option<usize> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--to" => {
                i += 1;
                if i >= args.len() { bail!("--to requires a version number") }
                to = Some(args[i].parse().context("version must be a number")?);
            }
            other if key.is_none() => key = Some(other.to_string()),
            _ => bail!("usage: s rollback <NAME> --to N"),
        }
        i += 1;
    }
    let key = key.ok_or_else(|| anyhow!("usage: s rollback <NAME> --to N"))?;
    let n = to.ok_or_else(|| anyhow!("usage: s rollback <NAME> --to N"))?;
    let path = store_containing(&key)?
        .ok_or_else(|| anyhow!("key {key} not found"))?;
    let mut file = store::SenvFile::load(&path)?;
    let entry = file.keys.get_mut(key.as_str())
        .ok_or_else(|| anyhow!("key {key} not found"))?;
    entry.rollback(n)?;
    file.save(&path)?;
    eprintln!("s: rolled back {key} to v{n}");
    Ok(())
}

// --- scan -----------------------------------------------------------------

fn cmd_scan(args: &[String]) -> Result<()> {
    ensure_store()?;
    let mut staged = false;
    let mut scan_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--staged" => staged = true,
            "--path" => {
                i += 1;
                if i >= args.len() { bail!("--path requires a directory") }
                scan_path = Some(args[i].clone());
            }
            other => bail!("unknown flag: {other}"),
        }
        i += 1;
    }

    let entries = decrypt_all()?;
    let secrets: Vec<(&str, &str)> = entries.iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    if secrets.is_empty() {
        eprintln!("s: no secrets to scan for");
        return Ok(());
    }

    let files = collect_scan_files(staged, scan_path.as_deref())?;
    if files.is_empty() {
        eprintln!("s: no files to scan");
        return Ok(());
    }

    let mut found: Vec<(String, usize, String)> = Vec::new();
    for file_path in &files {
        if file_path.ends_with(STORE_FILE) { continue }
        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for (line_no, line) in content.lines().enumerate() {
            for (key, val) in &secrets {
                if val.len() >= 8 && line.contains(val) {
                    found.push((file_path.clone(), line_no + 1, key.to_string()));
                }
            }
        }
    }

    if found.is_empty() {
        // exit 0 — clean
        return Ok(());
    }

    eprintln!("✗ secrets found in files:\n");
    for (f, line, key) in &found {
        eprintln!("  {f}:{line}");
        eprintln!("    contains: {key}\n");
    }
    let unique: std::collections::HashSet<&str> =
        found.iter().map(|(f, _, _)| f.as_str()).collect();
    eprintln!("found {} secret(s) in {} file(s)", found.len(), unique.len());
    std::process::exit(1);
}

fn collect_scan_files(staged: bool, scan_path: Option<&str>) -> Result<Vec<String>> {
    if staged {
        let out = Command::new("git")
            .args(["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
            .output().context("running git diff")?;
        let text = String::from_utf8_lossy(&out.stdout);
        return Ok(text.lines().map(String::from).filter(|s| !s.is_empty()).collect());
    }
    let dir = scan_path.unwrap_or(".");
    let out = Command::new("git").args(["ls-files", "--", dir]).output();
    if let Ok(out) = out {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            return Ok(text.lines().map(String::from).filter(|s| !s.is_empty()).collect());
        }
    }
    let mut files = Vec::new();
    walk_dir(Path::new(dir), &mut files)?;
    Ok(files)
}

fn walk_dir(dir: &Path, out: &mut Vec<String>) -> Result<()> {
    let entries = std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let ft = entry.file_type()?;
        let path = entry.path();
        if ft.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || name == "node_modules" || name == "target" { continue }
            walk_dir(&path, out)?;
        } else if ft.is_file() {
            out.push(path.to_string_lossy().to_string());
        }
    }
    Ok(())
}

// --- decrypt all ----------------------------------------------------------

fn decrypt_all() -> Result<Vec<(String, String)>> {
    let merged = merged_keys()?;
    if merged.is_empty() {
        return Ok(Vec::new());
    }
    let pw = get_password()?;
    let mut out = Vec::with_capacity(merged.len());
    for (k, entry) in &merged {
        let v = store::decrypt_value(entry.value(), &pw)
            .with_context(|| format!("decrypting {k}"))?;
        out.push((k.clone(), v));
    }
    Ok(out)
}

// --- helpers --------------------------------------------------------------

fn confirm_overwrite(key: &str) -> Result<bool> {
    use std::io::BufReader;
    let tty = match std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
        Ok(f) => f,
        Err(_) => {
            eprintln!("s: key {key} already exists; pass -f to overwrite");
            return Ok(false);
        }
    };
    let mut tty_w = tty.try_clone().context("cloning /dev/tty")?;
    write!(tty_w, "overwrite existing {key}? [y/N] ")?;
    tty_w.flush()?;
    let mut line = String::new();
    BufReader::new(tty).read_line(&mut line).context("reading from /dev/tty")?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES"))
}
