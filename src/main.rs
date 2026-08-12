// s — encrypted env store
//
// .senv:
//   keys:
//     API_KEY:
//       value: "s2:<base64>"
//       history:
//         - blob: "s2:<base64>"
//           ts: "2026-04-11T14:30:00Z"
//   domains:
//     api.example.com:
//       headers:
//         Authorization: "Bearer $API_KEY"

mod scrub;
mod store;

use std::fmt;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use zeroize::Zeroizing;

const STORE_FILE: &str = ".senv";
const REDACTED: &str = "[REDACTED]";

const AGENT_SKILL: &str = r#"---
name: s
description: Use when you need to use credentials and the project uses an .senv.
---

# Use credentials with `s`

## Execute with credentials

Name only the credentials the command needs:

```sh
s API_KEY -- command arg
s API_KEY DB_URL -- command arg
```

Use `s --all -- command arg` only when the command needs every stored credential.
`s` injects the selected names into the child environment and redacts their
literal values from terminal output.

## Credential-aware scripts

Put the required credential names in the shebang:

```python
#!/usr/bin/env -S s API_KEY -- python3
import os
token = os.environ["API_KEY"]
```

For a fixed `s` installation path:

```sh
#!/usr/local/bin/s API_KEY DB_URL -- bash
curl -H "Authorization: Bearer $API_KEY" "$DB_URL"
```

Make the script executable, then run it directly. `s` injects the named
credentials before starting the interpreter.

## HTTP requests

Attach headers to a domain before using it with `s curl`:

```sh
s configure api.example.com \
  --header 'Authorization: Bearer $API_KEY'
```

Repeat `--header` to add more headers. A key can appear in different templates
for different domains. Keep placeholders single-quoted.

Then call the URL:

```sh
s curl https://api.example.com/v1/items
```

Configured headers are added only when every request URL matches their allowed
domains. Known `$KEY` and `${KEY}` placeholders in curl arguments are also
substituted:

```sh
s curl -H 'Authorization: Bearer $API_KEY' \
  --data '{"token":"${OTHER_KEY}"}' \
  https://api.example.com/v1/items
```

Single-quote placeholders so the shell does not expand them. Credentialed HTTP
is restricted to `localhost`, `*.localhost`, and loopback IPs; use HTTPS
elsewhere.
"#;

fn main() {
    if let Err(e) = run() {
        emit_error(format_args!("{e:#}"));
        std::process::exit(1);
    }
}

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_DIM: &str = "\x1b[2m";

/// Status output is for people, so keep it on stderr and make it readable in
/// both terminals and logs. NO_COLOR follows no-color.org: a non-empty value
/// disables ANSI styling; non-TTY output is unstyled too.
fn colors_enabled() -> bool {
    !std::env::var("NO_COLOR")
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        && is_stderr_tty()
}

fn is_stderr_tty() -> bool {
    use std::os::fd::AsRawFd;
    unsafe { libc::isatty(io::stderr().as_raw_fd()) == 1 }
}

fn emit_status(symbol: &str, color: &str, message: fmt::Arguments<'_>) {
    if colors_enabled() {
        eprintln!("{color}{symbol}{ANSI_RESET} {message}");
    } else {
        eprintln!("{symbol} {message}");
    }
}

fn emit_error(message: fmt::Arguments<'_>) {
    if colors_enabled() {
        eprintln!("{ANSI_RED}error:{ANSI_RESET} {message}");
    } else {
        eprintln!("error: {message}");
    }
}

macro_rules! success {
    ($($arg:tt)*) => { emit_status("✓", ANSI_GREEN, format_args!($($arg)*)) };
}
macro_rules! info {
    ($($arg:tt)*) => { emit_status("·", ANSI_DIM, format_args!($($arg)*)) };
}
macro_rules! warning {
    ($($arg:tt)*) => { emit_status("!", ANSI_YELLOW, format_args!($($arg)*)) };
}
fn run() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    expand_inline_shebang_args(&mut args);
    if args.is_empty() {
        print_usage();
        return Ok(());
    }

    if args.as_slice() == ["--skill"] {
        print!("{AGENT_SKILL}");
        return Ok(());
    }

    // Verify git hook exists (if in a git repo with .senv)
    check_hook();

    // `curl` owns the rest of argv, including its own `--` option terminator.
    // It must therefore dispatch before the generic `KEY -- command` form.
    if args[0] == "curl" {
        return cmd_curl(&args[1..]);
    }

    // A `--` anywhere means exec form. Dispatch on it FIRST so a stored key
    // named `help` or `init` can never shadow a subcommand.
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
        // Every pre-`--` name must be a valid key name (letters, digits,
        // underscore). Report which one and why instead of falling through
        // to "unknown command".
        for n in names {
            if !store::valid_key_name(n) {
                bail!("not a valid key name: {n:?} (letters, digits, underscore only)");
            }
        }
        return cmd_exec(cmd_args, Some(names));
    }

    // No `--`: subcommand matching only.
    match args[0].as_str() {
        "init" => cmd_init(&args[1..]),
        "set" | "add" => cmd_set(&args[1..]),
        "configure" | "config" => cmd_configure(&args[1..]),
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

Agents:
  s KEY [KEY...] -- <cmd>       run a command with only the named credentials
  s configure HOST --header 'Name: $KEY'
                                attach headers using a stored key to a domain
  s curl [options] <URL>        use domain-scoped credentials for HTTP
  #!/usr/bin/env -S s KEY -- python3
                                inject credentials into an executable script
  More agent information: s --skill

Humans:
  s set <NAME>                  set a secret interactively
  s get <NAME>                  reveal a secret for human debugging
  s configure <DOMAIN> --header 'Name: $NAME'
                                attach domain-specific headers using stored keys
  s list                        list names with values redacted

Commands:

secrets:
  s set <NAME>                  set a secret (interactive, masked)
  s set <NAME> --stdin          set from stdin
  s configure <DOMAIN> \\
    --header 'Authorization: Bearer $NAME'
                                add or update headers for a domain
  s configure <DOMAIN> --clear-headers
                                remove the domain's configured headers
  s get <NAME>                  show decrypted value (human debugging)
  s rm <NAME>                   delete a secret
  s list                        list secrets (values masked)

HTTP:
  s curl [curl options] <URL>   run curl with domain-scoped configured headers
                                and substitute known $KEY / ${{KEY}} placeholders

import/export:
  s import .env                 import from .env file
  s import --stdin              import KEY=VALUE lines from stdin
  s import --from-env           import all env vars
  s import --from-env NAME      import specific env var
  s export                      export all as KEY=VALUE to stdout
  s export --file .env          export to file

history:
  s history <NAME>              show version history
  s rollback <NAME> --to N      restore version N (needs password)

scanning:
  s scan                        scan tracked files for leaked secrets
  s scan --staged               scan only staged files

setup:
  s init                        create .senv, ignore it, install pre-commit hook
  s init --git                  create .senv eligible for Git tracking

store location (precedence):
  S_FILE env var                explicit store path (overrides the rest)
  ./.senv                       project-local store
  ~/.config/senv/senv           global store (merged under local; local wins)

password (one of):
  S_KEY env var                 the password directly
  S_KEY_COMMAND env var         execute command to get password
  S_KEY=\"!cmd\"                  execute cmd (legacy shorthand for the above)
  TTY prompt                    fallback if interactive"
    );
}

/// Linux shebangs pass everything after the interpreter path as one argv string.
/// This lets scripts use inline mode directly:
///   #!/usr/local/bin/s API_KEY -- python3
/// as well as the portable env form:
///   #!/usr/bin/env -S s API_KEY -- python3
fn expand_inline_shebang_args(args: &mut Vec<String>) {
    let Some(first) = args.first() else {
        return;
    };
    if !first.contains("--") || !first.contains(char::is_whitespace) {
        return;
    }

    let mut expanded: Vec<String> = first.split_whitespace().map(|s| s.to_string()).collect();
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

/// Project-local store in the current directory.
fn store_path() -> PathBuf {
    // S_FILE overrides the store location so `s` works from any cwd
    // (e.g. services that don't run from the directory holding .senv).
    if let Ok(p) = std::env::var("S_FILE") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
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

/// Merge every readable store, local (higher precedence) winning independently
/// for each key and configured header.
fn merged_store() -> Result<store::SenvFile> {
    if let Some(path) = override_store_path() {
        if !path.exists() {
            bail!(
                "S_FILE={} does not exist — run `s init` first",
                path.display()
            );
        }
    }
    let mut merged = store::SenvFile::default();
    // Apply lowest precedence first so higher-precedence values overwrite.
    for path in read_store_paths().iter().rev() {
        let file = store::SenvFile::load(path)?;
        merged.keys.extend(file.keys);
        for (domain, policy) in file.domains {
            merged
                .domains
                .entry(domain)
                .or_default()
                .headers
                .extend(policy.headers);
        }
    }
    Ok(merged)
}

fn merged_keys() -> Result<std::collections::BTreeMap<String, store::KeyEntry>> {
    Ok(merged_store()?.keys)
}

/// Canonicalized paths of every store, so `scan` can exclude them by identity
/// rather than by filename. A suffix test on `.senv` also skips an unrelated
/// plaintext file that happens to be called `prod.senv`.
fn store_paths_canonical() -> Vec<PathBuf> {
    read_store_paths()
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect()
}

/// Decrypt the requested keys, or every key when `only` is `None`.
///
/// Deriving a key is deliberately expensive (Argon2id, ~18ms each), so
/// decrypting the whole store to inject one secret costs latency proportional to
/// store size on every invocation — and it makes one damaged or foreign-password
/// entry break commands that never needed it. It also puts plaintext the caller
/// never asked for on the heap, which is the opposite of the point.
fn decrypt_selected(only: Option<&[String]>) -> Result<Vec<(String, String)>> {
    let merged = merged_keys()?;
    decrypt_from_keys(&merged, only)
}

fn decrypt_from_keys(
    keys: &std::collections::BTreeMap<String, store::KeyEntry>,
    only: Option<&[String]>,
) -> Result<Vec<(String, String)>> {
    let wanted: Vec<(&String, &store::KeyEntry)> = match only {
        Some(names) => {
            let mut out = Vec::with_capacity(names.len());
            for name in names {
                let (key, entry) = keys
                    .get_key_value(name.as_str())
                    .ok_or_else(|| anyhow!("secret {name} not found. add it: s set {name}"))?;
                out.push((key, entry));
            }
            out
        }
        None => keys.iter().collect(),
    };
    if wanted.is_empty() {
        return Ok(Vec::new());
    }
    let password = get_password()?;
    let mut out = Vec::with_capacity(wanted.len());
    for (key, entry) in wanted {
        let value = store::decrypt_value(entry.value(), &password, key)
            .with_context(|| format!("decrypting {key}"))?;
        out.push((key.clone(), value));
    }
    Ok(out)
}

/// Variables that must never be injected into a child, nor accepted into the
/// store. These do not carry data to a program — they change which code the
/// program runs. A store that can set `LD_PRELOAD` is a store that can execute
/// arbitrary code in every command `s` wraps, so the name is refused at both
/// ends: on the way in (`set`, `import`) and again at injection.
fn is_unsafe_env_name(k: &str) -> bool {
    if k.starts_with("LD_") || k.starts_with("DYLD_") {
        return true;
    }
    matches!(
        k,
        "PATH"
            | "IFS"
            | "ENV"
            | "BASH_ENV"
            | "SHELL"
            | "SHELLOPTS"
            | "BASHOPTS"
            | "PYTHONPATH"
            | "PYTHONSTARTUP"
            | "PYTHONHOME"
            | "NODE_OPTIONS"
            | "PERL5OPT"
            | "PERL5LIB"
            | "RUBYOPT"
            | "RUBYLIB"
            | "GCONV_PATH"
            | "LOCPATH"
            | "NLSPATH"
            | "S_KEY"
            | "S_KEY_COMMAND"
            | "S_FILE"
    )
}

/// A store must be encrypted under a single password. Writing a secret under a
/// different password produces a store that `s --all` can't fully decrypt — it
/// aborts on the mismatched entry, which can crash-loop anything driven by it.
///
/// Before writing, confirm `pw` decrypts at least one *existing* secret (i.e. it
/// is the store's password). `exclude` is the key being written, so re-setting
/// the sole secret in a single-key store — effectively re-keying it — is still
/// allowed. An empty store has no password to match yet, so this passes.
fn ensure_password_matches_store(pw: &str, exclude: &str) -> Result<()> {
    let existing = merged_keys()?;
    let mut others = existing
        .iter()
        .filter(|(k, _)| k.as_str() != exclude)
        .peekable();
    if others.peek().is_none() {
        return Ok(());
    }
    if others.any(|(k, e)| store::decrypt_value(e.value(), pw, k).is_ok()) {
        return Ok(());
    }
    bail!(
        "password does not match the existing store — refusing to write a secret \
         under a different key.\n  \
         Every secret in a store must share one password, or `s --all` will abort \
         on the mismatched entry.\n  \
         Use the store's original S_KEY, or remove the old secrets first (`s rm ...`)."
    );
}

/// Get the password from S_KEY_COMMAND, S_KEY, or a TTY prompt.
/// Wrapped in `Zeroizing` so the password is wiped from memory on drop.
fn get_password() -> Result<Zeroizing<String>> {
    // S_KEY_COMMAND is the explicit command form. When it is set, S_KEY is
    // not interpreted (its `!` prefix is never executed), giving an escape
    // hatch for a literal password that starts with `!`.
    if let Ok(cmd) = std::env::var("S_KEY_COMMAND") {
        if !cmd.is_empty() {
            return Ok(Zeroizing::new(run_password_command(&cmd)?));
        }
    }
    if let Ok(val) = std::env::var("S_KEY") {
        if !val.is_empty() {
            return Ok(Zeroizing::new(resolve_cli_value(&val)?));
        }
    }
    let pw = rpassword::prompt_password("s password: ").context("reading password from TTY")?;
    Ok(Zeroizing::new(pw))
}

/// Run `cmd` via `sh -c` and return its trimmed stdout. Never includes the
/// command text or the command's stderr in any error — the command IS the
/// password, so leaking either would leak the secret.
fn run_password_command(cmd: &str) -> Result<String> {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        bail!("empty S_KEY command")
    }
    let output = Command::new("sh")
        .args(["-c", cmd])
        .stdin(Stdio::null())
        .output()
        .context("running S_KEY command")?;
    if !output.status.success() {
        bail!(
            "S_KEY command failed (exit {})",
            output.status.code().unwrap_or(-1)
        );
    }
    let s = String::from_utf8(output.stdout).context("S_KEY command output not UTF-8")?;
    let s = s.trim().to_string();
    if s.is_empty() {
        bail!("S_KEY command produced no output")
    }
    Ok(s)
}

/// If `val` starts with `!`, execute the rest as a shell command (legacy
/// S_KEY shorthand). Otherwise return `val` as a literal.
fn resolve_cli_value(val: &str) -> Result<String> {
    if let Some(cmd) = val.strip_prefix('!') {
        run_password_command(cmd)
    } else {
        Ok(val.to_string())
    }
}

// --- init -----------------------------------------------------------------

fn cmd_init(args: &[String]) -> Result<()> {
    let mut track_in_git = false;
    for a in args {
        match a.as_str() {
            "--git" => track_in_git = true,
            other => bail!("unknown flag: {other}"),
        }
    }
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
    success!("created {}", path.display());

    // Hook and .gitignore installation apply when the resolved path is the
    // project-local .senv, including an absolute S_FILE pointing at it. A
    // genuinely external S_FILE (for example a global store) must not mutate
    // the current repository.
    let is_local = path == PathBuf::from(STORE_FILE)
        || std::fs::canonicalize(&path).ok() == std::fs::canonicalize(STORE_FILE).ok();
    if is_local {
        install_hook()?;
        if track_in_git {
            allow_git_tracking()?;
        } else {
            ensure_gitignore()?;
        }
    }

    Ok(())
}

/// The hooks directory git actually uses. `git rev-parse --git-path hooks`
/// honours `core.hooksPath` and resolves correctly in worktrees/submodules
/// (where `.git` is a file), so the hook lands where git will run it. None
/// outside a git repo.
fn resolve_hooks_dir() -> Option<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--git-path", "hooks"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let dir = String::from_utf8_lossy(&out.stdout);
    let dir = dir.trim();
    if dir.is_empty() {
        return None;
    }
    Some(PathBuf::from(dir))
}

/// True if the hook runs `s scan` outside of a comment. A commented-out
/// `# s scan` must not count as an installed guard.
fn has_scan_guard(content: &str) -> bool {
    content.lines().any(|line| {
        let t = line.trim();
        !t.starts_with('#') && t.contains("s scan")
    })
}

/// Insert the scan guard right after the shebang line (or at the top if there
/// is none) rather than at the end: many hook templates end in `exit 0`,
/// which would make an appended guard dead code.
fn insert_guard_after_shebang(content: &str, scan_line: &str) -> String {
    let block = format!("# s: guard against committing secrets\n{scan_line}\n\n");
    if let Some(rest) = content.strip_prefix("#!") {
        if let Some(nl) = rest.find('\n') {
            let split = 2 + nl + 1; // end of the shebang line, newline included
            return format!("{}{block}{}", &content[..split], &content[split..]);
        }
        // Shebang is the whole file.
        return format!("{content}\n{block}");
    }
    format!("{block}{content}")
}

#[cfg(unix)]
fn ensure_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod {}", path.display()))?;
    Ok(())
}
#[cfg(not(unix))]
fn ensure_executable(_path: &Path) -> Result<()> {
    Ok(())
}

fn install_hook() -> Result<()> {
    let hooks_dir = match resolve_hooks_dir() {
        Some(d) => d,
        None => {
            info!("not a Git repository; skipped pre-commit hook");
            return Ok(());
        }
    };
    let hook_path = hooks_dir.join("pre-commit");
    let scan_line = "s scan --staged";

    if hook_path.exists() {
        let content = std::fs::read_to_string(&hook_path).unwrap_or_default();
        if has_scan_guard(&content) {
            info!("pre-commit hook already has a secret scan guard");
            return Ok(());
        }
        std::fs::write(&hook_path, insert_guard_after_shebang(&content, scan_line))
            .context("writing pre-commit hook")?;
        ensure_executable(&hook_path)?;
        success!("updated existing pre-commit hook with a secret scan");
    } else {
        std::fs::create_dir_all(&hooks_dir)
            .with_context(|| format!("creating {}", hooks_dir.display()))?;
        let content = format!("#!/bin/sh\n# s: guard against committing secrets\n{scan_line}\n");
        std::fs::write(&hook_path, &content).context("writing pre-commit hook")?;
        ensure_executable(&hook_path)?;
        success!("installed pre-commit hook with a secret scan");
    }
    Ok(())
}

const GITIGNORE_NOTE_1: &str =
    "# .senv is encrypted and can be committed if its encryption key is not shared.";
const GITIGNORE_NOTE_2: &str =
    "# Ignored by default; remove this entry to track it (or create with `s init --git`).";

fn ensure_gitignore() -> Result<()> {
    let gi = PathBuf::from(".gitignore");
    let content = if gi.exists() {
        std::fs::read_to_string(&gi).context("reading .gitignore")?
    } else {
        String::new()
    };
    if !content.lines().any(|l| l.trim() == ".senv") {
        let separator = if content.is_empty() || content.ends_with("\n\n") {
            ""
        } else if content.ends_with('\n') {
            "\n"
        } else {
            "\n\n"
        };
        let block = format!("{separator}{GITIGNORE_NOTE_1}\n{GITIGNORE_NOTE_2}\n.senv\n");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&gi)
            .context("appending to .gitignore")?;
        f.write_all(block.as_bytes())
            .context("writing .gitignore")?;
    }
    success!("ignored .senv by default");
    info!(
        "the encrypted store may be committed if its encryption key stays private; \
          remove the ignore or create it with `s init --git`"
    );
    Ok(())
}

fn allow_git_tracking() -> Result<()> {
    let gi = PathBuf::from(".gitignore");
    if gi.exists() {
        let content = std::fs::read_to_string(&gi).context("reading .gitignore")?;
        let mut filtered = content
            .lines()
            .filter(|line| {
                let line = line.trim();
                line != ".senv" && line != GITIGNORE_NOTE_1 && line != GITIGNORE_NOTE_2
            })
            .collect::<Vec<_>>()
            .join("\n");
        if !filtered.is_empty() {
            filtered.push('\n');
        }
        std::fs::write(&gi, filtered).context("writing .gitignore")?;
    }
    success!(".senv is eligible for Git tracking (--git)");
    warning!("keep its encryption key private; never commit or share the key");
    Ok(())
}

/// Warn if .senv exists but the pre-commit hook lacks a live `s scan` guard or
/// is not executable. A commented-out `# s scan` does not count as a guard.
fn check_hook() {
    if !store_path().exists() {
        return;
    }
    let hooks_dir = match resolve_hooks_dir() {
        Some(d) => d,
        None => return,
    };
    let hook = hooks_dir.join("pre-commit");
    if !hook.exists() {
        return;
    }
    let content = std::fs::read_to_string(&hook).unwrap_or_default();
    if !has_scan_guard(&content) {
        warning!("pre-commit hook has no `s scan` guard; run `s init` to fix");
    }
    if !is_executable(&hook) {
        warning!("pre-commit hook is not executable; run `s init` to fix");
    }
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}
#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    true
}

// --- set / get / rm -------------------------------------------------------

fn cmd_set(args: &[String]) -> Result<()> {
    let mut from_stdin = false;
    let mut force = false;
    let mut key: Option<&str> = None;
    for arg in args {
        match arg.as_str() {
            "--stdin" => from_stdin = true,
            "-f" | "--force" => force = true,
            arg if arg.starts_with('-') => bail!("unknown flag: {arg}"),
            arg if key.is_none() => key = Some(arg),
            arg => bail!("unexpected argument: {arg}"),
        }
    }
    let key = key.context("usage: s set <NAME> [--stdin]")?;
    if !store::valid_key_name(key) {
        bail!("invalid key: {key:?}")
    }
    if is_unsafe_env_name(key) {
        bail!("unsafe env name: {key} — cannot enter the store")
    }

    let value = if from_stdin {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("reading stdin")?;
        buf.trim_end_matches('\n').to_string()
    } else {
        read_secret_interactive(key)?
    };
    set_key_value(key, &value, force)
}

/// Read a secret value interactively, echoing `*` per character (not byte).
fn read_secret_interactive(key: &str) -> Result<String> {
    use std::io::BufReader;

    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("no TTY available — use --stdin")?;
    let mut tty_w = tty.try_clone()?;
    write!(tty_w, "{key}: ")?;
    tty_w.flush()?;

    // Ask the terminal to wrap clipboard input in bracketed-paste markers.
    // Without this, a pasted newline is indistinguishable from the Enter key
    // that submits a one-line value.
    write!(tty_w, "\x1b[?2004h")?;
    tty_w.flush()?;

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

    // Accumulate raw bytes and decode UTF-8 once at the end. The old code
    // pushed each byte as a char (`c as char`), mangling non-ASCII: `päss`
    // became `pÃ¤ss`. Backspace now drops a whole UTF-8 sequence, and we
    // echo one `*` per CHARACTER — from_utf8 succeeds only when the
    // accumulated bytes end on a char boundary, so continuation bytes
    // don't echo until the character completes.
    let mut bytes: Vec<u8> = Vec::new();
    let mut stars: usize = 0;
    let mut in_paste = false;
    let mut marker = Vec::new();
    let read_result: Result<()> = (|| {
        let mut reader = BufReader::new(&tty);
        let mut buf = [0u8; 1];
        loop {
            if reader.read(&mut buf)? == 0 {
                break;
            }
            let c = buf[0];

            // Bracketed-paste markers are terminal control sequences, not
            // part of the value. Newlines are data only between the markers;
            // an ordinary Enter still submits the value.
            if c == 0x1b && marker.is_empty() {
                marker.push(c);
                continue;
            }
            if !marker.is_empty() {
                marker.push(c);
                let expected = if in_paste {
                    b"\x1b[201~".as_slice()
                } else {
                    b"\x1b[200~".as_slice()
                };
                if expected.starts_with(&marker) {
                    if marker == expected {
                        in_paste = !in_paste;
                        marker.clear();
                    }
                    continue;
                }
                marker.clear();
                continue;
            }

            if !in_paste && matches!(c, b'\n' | b'\r') {
                break;
            }
            if !in_paste && matches!(c, 127 | 8) {
                // backspace / delete — drop a whole UTF-8 char
                if !bytes.is_empty() {
                    let mut start = bytes.len() - 1;
                    while start > 0 && (bytes[start] & 0xC0) == 0x80 {
                        start -= 1;
                    }
                    bytes.truncate(start);
                    let _ = write!(tty_w, "\x08 \x08");
                    let _ = tty_w.flush();
                    if stars > 0 {
                        stars -= 1;
                    }
                }
                continue;
            }
            if !in_paste && c == 3 {
                bail!("aborted"); // Ctrl-C
            }
            if in_paste && c < 32 && c != b'\n' && c != b'\r' {
                continue;
            }
            bytes.push(c);
            if let Ok(s) = std::str::from_utf8(&bytes) {
                let chars = s.chars().filter(|&c| c != '\n' && c != '\r').count();
                while stars < chars {
                    let _ = write!(tty_w, "*");
                    stars += 1;
                }
                let _ = tty_w.flush();
            }
        }
        Ok(())
    })();

    // Disable bracketed paste even when reading failed, so the user's shell
    // does not remain in paste mode.
    let _ = write!(tty_w, "\x1b[?2004l");
    let _ = tty_w.flush();
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };
    let _ = writeln!(tty_w);

    read_result?;

    if bytes.is_empty() {
        bail!("empty value");
    }
    String::from_utf8(bytes).map_err(|_| anyhow!("input is not valid UTF-8"))
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

    ensure_password_matches_store(&pw, key)?;
    let blob = store::encrypt_value(value, &pw, key)?;
    let verb = if file.keys.contains_key(key) {
        "updated"
    } else {
        "added"
    };
    file.set_key(key, blob, &pw)?;

    file.save(&path)?;
    success!("{verb} {key}");
    Ok(())
}
fn cmd_configure(args: &[String]) -> Result<()> {
    let raw_domain = args.first().filter(|arg| !arg.starts_with('-')).context(
        "usage: s configure <DOMAIN> --header 'NAME: VALUE' \
             [--header 'NAME: VALUE' ...] [--clear-headers]",
    )?;
    let domain = normalize_domain_pattern(raw_domain)?;
    let mut headers = std::collections::BTreeMap::new();
    let mut clear = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--header" => {
                i += 1;
                let raw = args.get(i).context("--header requires 'NAME: VALUE'")?;
                let (name, template) = raw
                    .split_once(':')
                    .context("--header requires 'NAME: VALUE'")?;
                let name = name.trim();
                if !valid_header_name(name) {
                    bail!("invalid HTTP header name: {name:?}");
                }
                let template = template.trim_start();
                if template.contains(['\r', '\n', '\0']) {
                    bail!("header template contains a forbidden control character");
                }
                headers.insert(name.to_string(), template.to_string());
            }
            "--clear-headers" => clear = true,
            flag => bail!("unknown flag: {flag}"),
        }
        i += 1;
    }
    if headers.is_empty() && !clear {
        bail!("configure requires --header or --clear-headers");
    }

    let path = ensure_store()?;
    let mut file = store::SenvFile::load(&path)?;
    if clear {
        file.domains.remove(&domain);
    }
    if !headers.is_empty() {
        file.domains
            .entry(domain.clone())
            .or_default()
            .headers
            .extend(headers);
    }
    file.save(&path)?;
    success!("configured {domain}");
    Ok(())
}

fn cmd_get(args: &[String]) -> Result<()> {
    require_tty("show secret")?;
    if args.is_empty() {
        bail!("usage: s get <NAME>")
    }
    ensure_store()?;
    let key = &args[0];
    let merged = merged_keys()?;
    let entry = merged
        .get(key.as_str())
        .ok_or_else(|| anyhow!("key {key} not found"))?;
    let pw = get_password()?;
    let v = store::decrypt_value(entry.value(), &pw, key)
        .with_context(|| format!("decrypting {key}"))?;
    println!("{v}");
    Ok(())
}

/// Remove a key. Deliberately passwordless: deletion is equivalent to
/// `rm .senv`, which the same actor can already do, and requiring a password
/// would strand anyone who lost it.
fn cmd_rm(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("usage: s rm <NAME>")
    }
    let key = &args[0];
    let path = store_containing(key)?.ok_or_else(|| anyhow!("key {key} not found"))?;
    let mut file = store::SenvFile::load(&path)?;
    file.keys.remove(key);
    file.save(&path)?;
    success!("removed {key}");
    Ok(())
}

// --- list -----------------------------------------------------------------

fn cmd_list(args: &[String]) -> Result<()> {
    let mut json = false;
    for a in args {
        if a == "--json" {
            json = true
        } else {
            bail!("unknown flag: {a}")
        }
    }
    // Only a genuinely absent store is empty; a load/parse error is real.
    let paths = read_store_paths();
    if paths.is_empty() {
        if json {
            println!("[]")
        } else {
            info!("no {STORE_FILE} here")
        }
        return Ok(());
    }
    let keys = merged_keys()?;
    if keys.is_empty() {
        if json {
            println!("[]")
        } else {
            info!("no secrets")
        }
        return Ok(());
    }
    if json {
        print!("[");
        for (i, k) in keys.keys().enumerate() {
            if i > 0 {
                print!(",")
            }
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

// --- curl -----------------------------------------------------------------

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn normalize_domain_pattern(raw: &str) -> Result<String> {
    let raw = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let wildcard = raw.starts_with("*.");
    let host = raw.strip_prefix("*.").unwrap_or(&raw);
    if host.is_empty()
        || host.contains('*')
        || host.contains('/')
        || wildcard && host.parse::<std::net::IpAddr>().is_ok()
        || host.contains(':') && host.parse::<std::net::Ipv6Addr>().is_err()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
    {
        bail!("invalid domain pattern: {raw:?}");
    }
    Ok(if wildcard {
        format!("*.{host}")
    } else {
        host.to_string()
    })
}

fn domain_matches(pattern: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.len() > suffix.len()
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
    } else {
        host == pattern
    }
}

fn policy_matches_urls(pattern: &str, urls: &[url::Url]) -> bool {
    urls.iter().all(|url| {
        url.host_str()
            .is_some_and(|host| domain_matches(pattern, host))
    })
}

fn policy_matches_any_url(pattern: &str, urls: &[url::Url]) -> bool {
    urls.iter().any(|url| {
        url.host_str()
            .is_some_and(|host| domain_matches(pattern, host))
    })
}

fn parse_curl_url(raw: &str) -> Result<url::Url> {
    if raw.contains(['{', '}']) {
        bail!("s curl does not allow URL globbing when selecting credential domains");
    }
    let candidate = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{raw}")
    };
    let url = url::Url::parse(&candidate).with_context(|| format!("invalid curl URL: {raw}"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("s curl only supports HTTP(S) URLs, got {raw:?}");
    }
    let host_text = &url[url::Position::BeforeHost..url::Position::AfterHost];
    let outside_host = candidate.replacen(host_text, "", 1);
    if outside_host.contains(['[', ']']) {
        bail!("s curl does not allow URL globbing when selecting credential domains");
    }
    Ok(url)
}

fn curl_short_option_name(short: u8) -> Option<&'static str> {
    Some(match short {
        b'A' => "user-agent",
        b'b' => "cookie",
        b'c' => "cookie-jar",
        b'C' => "continue-at",
        b'd' => "data",
        b'D' => "dump-header",
        b'e' => "referer",
        b'E' => "cert",
        b'F' => "form",
        b'H' => "header",
        b'K' => "config",
        b'm' => "max-time",
        b'o' => "output",
        b'P' => "ftp-port",
        b'Q' => "quote",
        b'r' => "range",
        b't' => "telnet-option",
        b'T' => "upload-file",
        b'u' => "user",
        b'U' => "proxy-user",
        b'w' => "write-out",
        b'x' => "proxy",
        b'X' => "request",
        b'Y' => "speed-limit",
        b'y' => "speed-time",
        b'z' => "time-cond",
        _ => return None,
    })
}

fn curl_long_option_takes_value(option: &str) -> bool {
    matches!(
        option,
        "abstract-unix-socket"
            | "alt-svc"
            | "aws-sigv4"
            | "cacert"
            | "capath"
            | "cert"
            | "cert-type"
            | "ciphers"
            | "config"
            | "connect-timeout"
            | "connect-to"
            | "continue-at"
            | "cookie"
            | "cookie-jar"
            | "create-file-mode"
            | "crlfile"
            | "curves"
            | "data"
            | "data-ascii"
            | "data-binary"
            | "data-raw"
            | "data-urlencode"
            | "delegation"
            | "dns-interface"
            | "dns-ipv4-addr"
            | "dns-ipv6-addr"
            | "dns-servers"
            | "doh-url"
            | "dump-header"
            | "ech"
            | "engine"
            | "etag-compare"
            | "etag-save"
            | "expect100-timeout"
            | "form"
            | "form-string"
            | "ftp-account"
            | "ftp-alternative-to-user"
            | "ftp-method"
            | "ftp-port"
            | "happy-eyeballs-timeout-ms"
            | "haproxy-clientip"
            | "header"
            | "hostpubmd5"
            | "hostpubsha256"
            | "hsts"
            | "interface"
            | "ip-tos"
            | "ipfs-gateway"
            | "json"
            | "keepalive-cnt"
            | "keepalive-time"
            | "key"
            | "key-type"
            | "knownhosts"
            | "krb"
            | "libcurl"
            | "limit-rate"
            | "local-port"
            | "login-options"
            | "mail-auth"
            | "mail-from"
            | "mail-rcpt"
            | "max-filesize"
            | "max-redirs"
            | "max-time"
            | "noproxy"
            | "oauth2-bearer"
            | "output"
            | "output-dir"
            | "parallel-max"
            | "parallel-max-host"
            | "pass"
            | "pinnedpubkey"
            | "preproxy"
            | "proto"
            | "proto-default"
            | "proto-redir"
            | "proxy"
            | "proxy-cacert"
            | "proxy-capath"
            | "proxy-cert"
            | "proxy-cert-type"
            | "proxy-ciphers"
            | "proxy-crlfile"
            | "proxy-header"
            | "proxy-key"
            | "proxy-key-type"
            | "proxy-pass"
            | "proxy-pinnedpubkey"
            | "proxy-service-name"
            | "proxy-tls13-ciphers"
            | "proxy-tlspassword"
            | "proxy-tlsuser"
            | "proxy-user"
            | "proxy1.0"
            | "pubkey"
            | "quote"
            | "range"
            | "rate"
            | "referer"
            | "request"
            | "request-target"
            | "resolve"
            | "retry"
            | "retry-delay"
            | "retry-max-time"
            | "sasl-authzid"
            | "service-name"
            | "sigalgs"
            | "socks4"
            | "socks4a"
            | "socks5"
            | "socks5-gssapi-service"
            | "socks5-hostname"
            | "speed-limit"
            | "speed-time"
            | "stderr"
            | "telnet-option"
            | "tftp-blksize"
            | "time-cond"
            | "tls-max"
            | "tls13-ciphers"
            | "tlsauthtype"
            | "tlspassword"
            | "tlsuser"
            | "trace"
            | "trace-ascii"
            | "trace-config"
            | "unix-socket"
            | "upload-file"
            | "url"
            | "url-query"
            | "user"
            | "user-agent"
            | "variable"
            | "vlan-priority"
            | "write-out"
    )
}

fn curl_option_value(arg: &str) -> Option<(&str, Option<&str>)> {
    if let Some(long) = arg.strip_prefix("--") {
        if let Some((name, value)) = long.split_once('=') {
            return Some((name, Some(value)));
        }
        return curl_long_option_takes_value(long).then_some((long, None));
    }
    let short = arg.strip_prefix('-')?;
    if !short.is_ascii() {
        return None;
    }
    for (offset, byte) in short.bytes().enumerate() {
        if let Some(name) = curl_short_option_name(byte) {
            let value = (offset + 1 < short.len()).then(|| &short[offset + 1..]);
            return Some((name, value));
        }
    }
    None
}

fn curl_short_has_flag(arg: &str, wanted: u8) -> bool {
    let Some(short) = arg.strip_prefix('-').filter(|s| !s.starts_with('-')) else {
        return false;
    };
    for byte in short.bytes() {
        if byte == wanted {
            return true;
        }
        if curl_short_option_name(byte).is_some() {
            return false;
        }
    }
    false
}

fn curl_target_urls(args: &[String]) -> Result<Vec<url::Url>> {
    let mut urls = Vec::new();
    let mut options = true;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if options && arg == "--" {
            options = false;
            i += 1;
            continue;
        }
        if options {
            if matches!(arg.as_str(), "-K" | "--config") || arg.starts_with("--config=") {
                bail!("s curl does not accept curl config files (they bypass domain checks)");
            }
            if let Some((name, attached)) = curl_option_value(arg) {
                if name == "config" {
                    bail!("s curl does not accept curl config files (they bypass domain checks)");
                }
                let value = match attached {
                    Some(value) => value,
                    None => {
                        i += 1;
                        args.get(i)
                            .with_context(|| format!("curl option {arg} requires a value"))?
                    }
                };
                if name == "url" {
                    urls.push(parse_curl_url(value)?);
                }
                i += 1;
                continue;
            }
            if arg.starts_with('-') {
                i += 1;
                continue;
            }
        }
        urls.push(parse_curl_url(arg)?);
        i += 1;
    }
    Ok(urls)
}

fn curl_manual_header_names(args: &[String]) -> std::collections::BTreeSet<String> {
    let mut names = std::collections::BTreeSet::new();
    let mut options = true;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if options && arg == "--" {
            options = false;
            i += 1;
            continue;
        }
        if options {
            if let Some((name, attached)) = curl_option_value(arg) {
                let value = attached.or_else(|| args.get(i + 1).map(String::as_str));
                if name == "header" {
                    if let Some((header, _)) = value.and_then(|value| value.split_once(':')) {
                        names.insert(header.trim().to_ascii_lowercase());
                    }
                }
                if attached.is_none() {
                    i += 1;
                }
            }
        }
        i += 1;
    }
    names
}

fn placeholder_names(
    input: &str,
    keys: &std::collections::BTreeMap<String, store::KeyEntry>,
) -> std::collections::BTreeSet<String> {
    let bytes = input.as_bytes();
    let mut names = std::collections::BTreeSet::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            i += 1;
            continue;
        }
        let (start, end, braced) = if bytes.get(i + 1) == Some(&b'{') {
            let start = i + 2;
            let Some(rel_end) = input[start..].find('}') else {
                i += 1;
                continue;
            };
            (start, start + rel_end, true)
        } else {
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            (start, end, false)
        };
        if end > start {
            let name = &input[start..end];
            if keys.contains_key(name) {
                names.insert(name.to_string());
            }
        }
        i = end + usize::from(braced);
    }
    names
}

fn expand_placeholders(input: &str, values: &std::collections::BTreeMap<&str, &str>) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            i += 1;
            continue;
        }
        let (start, end, token_end) = if bytes.get(i + 1) == Some(&b'{') {
            let start = i + 2;
            let Some(rel_end) = input[start..].find('}') else {
                i += 1;
                continue;
            };
            let end = start + rel_end;
            (start, end, end + 1)
        } else {
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            (start, end, end)
        };
        if let Some(value) = values.get(&input[start..end]) {
            out.push_str(&input[copied..i]);
            out.push_str(value);
            copied = token_end;
        }
        i = token_end.max(i + 1);
    }
    out.push_str(&input[copied..]);
    out
}

fn curl_config_quote(value: &str) -> Result<String> {
    if value.contains('\0') {
        bail!("curl value contains NUL");
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for c in value.chars() {
        match c {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            _ => quoted.push(c),
        }
    }
    quoted.push('"');
    Ok(quoted)
}

fn curl_config_line(config: &mut String, option: &str, value: &str) -> Result<()> {
    if option.is_empty()
        || !option
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        bail!("invalid curl option name: {option:?}");
    }
    config.push_str(option);
    config.push_str(" = ");
    config.push_str(&curl_config_quote(value)?);
    config.push('\n');
    Ok(())
}

fn prepare_curl_args(
    args: &[String],
    values: &std::collections::BTreeMap<&str, &str>,
    config: &mut String,
) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(args.len() + 2);
    let mut options = true;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if options && arg == "--" {
            options = false;
            out.push(arg.clone());
            i += 1;
            continue;
        }
        if options {
            if let Some((name, attached)) = curl_option_value(arg) {
                if let Some(value) = attached {
                    let expanded = expand_placeholders(value, values);
                    if expanded != value {
                        curl_config_line(config, name, &expanded)?;
                    } else {
                        out.push(arg.clone());
                    }
                    i += 1;
                    continue;
                }
                if let Some(value) = args.get(i + 1) {
                    let expanded = expand_placeholders(value, values);
                    if expanded != *value {
                        curl_config_line(config, name, &expanded)?;
                        i += 2;
                        continue;
                    }
                }
                out.push(arg.clone());
                i += 1;
                continue;
            }
        }
        let expanded = expand_placeholders(arg, values);
        if expanded != *arg {
            curl_config_line(config, "url", &expanded)?;
        } else {
            out.push(arg.clone());
        }
        i += 1;
    }
    Ok(out)
}

fn curl_uses_redirects(args: &[String]) -> bool {
    args.iter().any(|arg| {
        matches!(
            arg.as_str(),
            "--location" | "--location-trusted" | "--follow"
        ) || curl_short_has_flag(arg, b'L')
    })
}

fn curl_uses_next(args: &[String]) -> bool {
    args.iter()
        .any(|arg| matches!(arg.as_str(), "--next" | "-:"))
}

fn curl_disables_tls_verification(args: &[String]) -> bool {
    args.iter()
        .any(|arg| arg == "--insecure" || curl_short_has_flag(arg, b'k'))
}

fn curl_bypasses_scrubber(args: &[String]) -> bool {
    args.iter().any(|arg| {
        if matches!(arg.as_str(), "--remote-name" | "--remote-name-all")
            || curl_short_has_flag(arg, b'O')
        {
            return true;
        }
        curl_option_value(arg).is_some_and(|(name, _)| {
            matches!(
                name,
                "output"
                    | "output-dir"
                    | "dump-header"
                    | "stderr"
                    | "trace"
                    | "trace-ascii"
                    | "trace-config"
                    | "libcurl"
            )
        })
    })
}

fn safe_secret_transport(url: &url::Url) -> bool {
    if url.scheme() == "https" {
        return true;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host.len() > ".localhost".len()
            && host[host.len() - ".localhost".len()..].eq_ignore_ascii_case(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

#[cfg(unix)]
fn secure_curl_config(contents: &str) -> Result<(std::fs::File, String)> {
    use std::io::{Seek, SeekFrom};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let mut last_error = None;
    for _ in 0..16 {
        let mut random = [0u8; 12];
        getrandom::getrandom(&mut random).map_err(|e| anyhow!("getrandom: {e}"))?;
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!(".s-curl-{suffix}"));
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW);
        let mut file = match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
                continue;
            }
            Err(error) => return Err(error).context("creating curl credential config"),
        };
        file.write_all(contents.as_bytes())
            .context("writing curl credential config")?;
        file.seek(SeekFrom::Start(0))?;
        std::fs::remove_file(&path).context("unlinking curl credential config")?;

        let fd = file.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
            bail!(
                "making curl credential descriptor inheritable: {}",
                io::Error::last_os_error()
            );
        }
        #[cfg(target_os = "linux")]
        let fd_path = format!("/proc/self/fd/{fd}");
        #[cfg(not(target_os = "linux"))]
        let fd_path = format!("/dev/fd/{fd}");
        return Ok((file, fd_path));
    }
    Err(last_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::AlreadyExists, "name collision"))
        .into())
}

fn cmd_curl(args: &[String]) -> Result<()> {
    let urls = curl_target_urls(args)?;
    if urls.is_empty() {
        let mut command = vec!["curl".to_string()];
        command.extend_from_slice(args);
        return run_scrubbed(&command, &[], &[]);
    }

    let merged = merged_store()?;
    let keys = &merged.keys;
    let manual_headers = curl_manual_header_names(args);
    let mut configured = std::collections::BTreeMap::<String, (String, String, String)>::new();
    let mut authorized = std::collections::BTreeSet::new();
    for (domain, policy) in &merged.domains {
        if policy.headers.is_empty() {
            continue;
        }
        let any = policy_matches_any_url(domain, &urls);
        let all = policy_matches_urls(domain, &urls);
        if any && !all {
            bail!(
                "curl invocation mixes URLs matched and unmatched by {domain}; \
                 split it into separate s curl commands"
            );
        }
        if !all {
            continue;
        }
        for (name, template) in &policy.headers {
            if !valid_header_name(name) {
                bail!("invalid configured HTTP header name for {domain}: {name:?}");
            }
            authorized.extend(placeholder_names(template, keys));
            let normalized = name.to_ascii_lowercase();
            if manual_headers.contains(&normalized) {
                continue;
            }
            if let Some((previous_name, previous_template, previous_domain)) =
                configured.get(&normalized)
            {
                if previous_template != template {
                    bail!(
                        "conflicting {previous_name} header configuration for \
                         {previous_domain} and {domain}"
                    );
                }
                continue;
            }
            configured.insert(normalized, (name.clone(), template.clone(), domain.clone()));
        }
    }

    let mut referenced = std::collections::BTreeSet::new();
    for arg in args {
        referenced.extend(placeholder_names(arg, keys));
    }
    for (_, template, _) in configured.values() {
        referenced.extend(placeholder_names(template, keys));
    }
    for name in &referenced {
        if !authorized.contains(name) {
            let hosts = urls
                .iter()
                .filter_map(url::Url::host_str)
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "{name} is not authorized for every target host ({hosts}); \
                 configure matching domain headers before using it with s curl"
            );
        }
    }

    let protected = !configured.is_empty() || !referenced.is_empty();
    if protected && urls.iter().any(|url| !safe_secret_transport(url)) {
        bail!(
            "s curl sends credentials only over HTTPS \
             (HTTP is allowed for loopback and *.localhost)"
        );
    }
    if protected && curl_uses_redirects(args) {
        bail!(
            "s curl refuses redirects with credentials because curl can forward custom \
             headers to another host; request the allowed destination directly"
        );
    }
    if protected && curl_uses_next(args) {
        bail!("s curl refuses --next with credentials; split it into separate commands");
    }
    if protected && curl_disables_tls_verification(args) {
        bail!("s curl refuses --insecure with credentials");
    }
    if protected && curl_bypasses_scrubber(args) {
        bail!("s curl refuses output/trace files with credentials because they bypass redaction");
    }

    let names: Vec<String> = referenced.into_iter().collect();
    let entries = decrypt_from_keys(keys, Some(&names))?;
    let values: std::collections::BTreeMap<&str, &str> = entries
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();

    let mut config = String::new();
    for (_, (name, template, _)) in configured {
        let value = expand_placeholders(&template, &values);
        if value.contains(['\r', '\n', '\0']) {
            bail!("configured {name} header expands to a forbidden control character");
        }
        curl_config_line(&mut config, "header", &format!("{name}: {value}"))?;
    }
    let forwarded = prepare_curl_args(args, &values, &mut config)?;
    let mut command = vec!["curl".to_string()];
    let _config_guard = if config.is_empty() {
        command.extend(forwarded);
        None
    } else {
        let (guard, path) = secure_curl_config(&config)?;
        command.push("--config".to_string());
        command.push(path);
        command.extend(forwarded);
        Some(guard)
    };
    run_scrubbed(&command, &entries, &[])
}

// --- exec -----------------------------------------------------------------

fn cmd_exec(cmd_args: &[String], only: Option<&[String]>) -> Result<()> {
    ensure_store()?;
    // Resolve only the requested secrets. Never derive an unrequested key:
    // Argon2id is ~18ms each, and a corrupt or foreign-password entry must not
    // abort an invocation that never asked for it.
    if let Some(names) = only {
        let merged = merged_keys()?;
        for name in names {
            if !merged.contains_key(name) {
                bail!("secret {name} not found. add it: s set {name}");
            }
        }
    }
    let entries = decrypt_selected(only)?;
    run_scrubbed(cmd_args, &entries, &entries)
}

/// Run a child while redacting `scrub_entries` from every output path.
/// `env_entries` is separate because `s curl` must scrub the secrets it uses
/// without also exposing them as environment variables to curl or its helpers.
fn run_scrubbed(
    cmd_args: &[String],
    scrub_entries: &[(String, String)],
    env_entries: &[(String, String)],
) -> Result<()> {
    let secrets: Vec<Vec<u8>> = scrub_entries
        .iter()
        .map(|(_, value)| value.as_bytes().to_vec())
        .filter(|value| !value.is_empty())
        .collect();
    let scrubber = std::sync::Arc::new(scrub::Scrubber::new(&secrets));

    // A human at a terminal gets a PTY so /dev/tty and fd 0 flow through the
    // scrubber; pipes (agent/CI) keep two streams with locked writes.
    if is_tty() {
        pty::exec_pty(cmd_args, env_entries, scrubber)
    } else {
        exec_pipes(cmd_args, env_entries, scrubber)
    }
}

/// `s`'s own control vars and dangerous loader knobs must never reach the child.
/// `env_remove` runs AFTER the loop so a stored `S_KEY` cannot be re-added.
fn setup_child_env(cmd: &mut Command, entries: &[(String, String)]) {
    for (k, v) in entries {
        if is_unsafe_env_name(k) {
            warning!("refusing to inject {k} (unsafe variable name)");
            continue;
        }
        cmd.env(k, v);
    }
    cmd.env_remove("S_KEY");
    cmd.env_remove("S_FILE");
}

/// Child pid for signal forwarding. 0 while no child is live, so a handler
/// never kills a recycled pid.
static CHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn forward_signal(sig: libc::c_int) {
    let pid = CHILD_PID.load(std::sync::atomic::Ordering::SeqCst);
    if pid > 0 {
        // The only async-signal-safe call we make: deliver to the child.
        unsafe { libc::kill(pid, sig) };
    }
}

fn install_signal_forwarders() {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        unsafe { libc::signal(sig, forward_signal as *const () as libc::sighandler_t) };
    }
}

/// Signal deaths exit 128+signal (matching the shell); otherwise the child code.
fn exit_status(status: std::process::ExitStatus) -> ! {
    use std::os::unix::process::ExitStatusExt;
    if let Some(sig) = status.signal() {
        std::process::exit(128 + sig);
    }
    std::process::exit(status.code().unwrap_or(1));
}

/// Pipe mode (stdout not a tty): two relays, each writing to a locked handle so
/// one write is never split across the two streams. A downstream `head` closing
/// the pipe surfaces as BrokenPipe — normal, not a failure.
fn exec_pipes(
    cmd_args: &[String],
    entries: &[(String, String)],
    scrubber: std::sync::Arc<scrub::Scrubber>,
) -> Result<()> {
    let mut cmd = Command::new(&cmd_args[0]);
    cmd.args(&cmd_args[1..]);
    setup_child_env(&mut cmd, entries);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.stdin(Stdio::inherit());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn {}", &cmd_args[0]))?;
    CHILD_PID.store(child.id() as i32, std::sync::atomic::Ordering::SeqCst);
    install_signal_forwarders();

    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let sa = scrubber.clone();
    let sb = scrubber;
    let t1 = std::thread::spawn(move || {
        let h = io::stdout();
        let mut w = h.lock();
        sa.copy(&mut out, &mut w)
    });
    let t2 = std::thread::spawn(move || {
        let h = io::stderr();
        let mut w = h.lock();
        sb.copy(&mut err, &mut w)
    });

    let status = child.wait().context("wait child")?;
    CHILD_PID.store(0, std::sync::atomic::Ordering::SeqCst);

    // Drain both relays. BrokenPipe = downstream closed the pipe (e.g. `head`);
    // let the child have died of SIGPIPE on its own and exit without complaint.
    for t in [t1, t2] {
        match t.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe => {}
            Ok(Err(e)) => return Err(anyhow!(e)),
            Err(_) => {}
        }
    }
    exit_status(status);
}

// --- pty ------------------------------------------------------------------

/// PTY mode: the child runs on a pseudo-terminal whose slave IS its controlling
/// terminal, so /dev/tty, fd 0, fd 1 and fd 2 all flow through the master and
/// the scrubber. The raw secret can never escape via /dev/tty.
mod pty {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::os::unix::process::CommandExt;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Arc;

    /// Master fd for the SIGWINCH handler (window-size propagation).
    static MASTER: AtomicI32 = AtomicI32::new(-1);

    extern "C" fn on_winch(_sig: libc::c_int) {
        let m = MASTER.load(Ordering::Relaxed);
        if m < 0 {
            return;
        }
        unsafe {
            let mut ws: libc::winsize = std::mem::zeroed();
            if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws as *mut _) == 0 {
                libc::ioctl(m, libc::TIOCSWINSZ, &ws as *const _);
            }
        }
    }

    fn copy_winsz(master: libc::c_int) {
        unsafe {
            let mut ws: libc::winsize = std::mem::zeroed();
            if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws as *mut _) == 0 {
                libc::ioctl(master, libc::TIOCSWINSZ, &ws as *const _);
            }
        }
    }

    /// Restore the parent terminal on drop — every path, including `?` unwinds,
    /// so raw mode never leaks to the shell.
    struct TermRaw {
        fd: Option<libc::c_int>,
        saved: libc::termios,
    }
    impl TermRaw {
        fn new() -> Result<Self> {
            // Raw-mode the terminal the user types on: stdin if it's a tty,
            // else the first of stdout/stderr that is. If none is a tty there's
            // nothing to raw-mode — the PTY relay still scrubs output, and the
            // stdin relay reads EOF right away.
            let fd = [0, 1, 2]
                .into_iter()
                .find(|&fd| unsafe { libc::isatty(fd) } == 1);
            let Some(fd) = fd else {
                return Ok(TermRaw {
                    fd: None,
                    saved: unsafe { std::mem::zeroed() },
                });
            };
            let mut saved: libc::termios = unsafe { std::mem::zeroed() };
            if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
                bail!("tcgetattr: {}", io::Error::last_os_error());
            }
            let mut raw = saved;
            unsafe {
                libc::cfmakeraw(&mut raw);
            }
            if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
                bail!("tcsetattr: {}", io::Error::last_os_error());
            }
            Ok(TermRaw {
                fd: Some(fd),
                saved,
            })
        }
    }
    impl Drop for TermRaw {
        fn drop(&mut self) {
            if let Some(fd) = self.fd {
                unsafe {
                    libc::tcsetattr(fd, libc::TCSANOW, &self.saved);
                }
            }
        }
    }

    /// Reading the master returns EIO on Linux once the child exits; treat that
    /// as clean EOF (the Scrubber only retries EINTR).
    struct MasterRead {
        fd: libc::c_int,
    }
    impl Read for MasterRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n >= 0 {
                return Ok(n as usize);
            }
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EIO) {
                return Ok(0);
            }
            Err(e)
        }
    }

    pub fn exec_pty(
        cmd_args: &[String],
        entries: &[(String, String)],
        scrubber: Arc<scrub::Scrubber>,
    ) -> Result<()> {
        // Open the master (O_NOCTTY: the parent keeps its own controlling tty).
        let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        if master < 0 {
            bail!("posix_openpt: {}", io::Error::last_os_error());
        }
        if unsafe { libc::grantpt(master) } < 0 {
            bail!("grantpt: {}", io::Error::last_os_error());
        }
        if unsafe { libc::unlockpt(master) } < 0 {
            bail!("unlockpt: {}", io::Error::last_os_error());
        }
        let slave_name: CString = unsafe {
            let p = libc::ptsname(master);
            if p.is_null() {
                bail!("ptsname: {}", io::Error::last_os_error());
            }
            CStr::from_ptr(p).to_owned()
        };
        let slave = unsafe { libc::open(slave_name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
        if slave < 0 {
            bail!("open pty slave: {}", io::Error::last_os_error());
        }

        copy_winsz(master);
        MASTER.store(master, Ordering::SeqCst);
        unsafe {
            libc::signal(libc::SIGWINCH, on_winch as *const () as libc::sighandler_t);
        }

        let raw = TermRaw::new()?;

        let mut cmd = Command::new(&cmd_args[0]);
        cmd.args(&cmd_args[1..]);
        setup_child_env(&mut cmd, entries);
        // Inherit fds; pre_exec re-points 0/1/2 at the slave and makes it the
        // controlling terminal so /dev/tty resolves to the pty slave.
        let mfd = master;
        let sfd = slave;
        unsafe {
            cmd.pre_exec(move || {
                // SAFETY: running between fork and exec; we own fds 0/1/2 and
                // the session. All calls are async-signal-safe here.
                {
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    for fd in 0..=2 {
                        if libc::dup2(sfd, fd) < 0 {
                            return Err(io::Error::last_os_error());
                        }
                    }
                    // fd 0 is now the slave — acquire it as controlling terminal.
                    #[cfg(target_os = "macos")]
                    libc::ioctl(0, libc::TIOCSCTTY as libc::c_ulong, 0 as libc::c_int);
                    #[cfg(not(target_os = "macos"))]
                    libc::ioctl(0, libc::TIOCSCTTY, 0 as libc::c_int);
                    if sfd > 2 {
                        libc::close(sfd);
                    }
                    libc::close(mfd); // child must not hold the master open
                    Ok(())
                }
            });
        }

        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawn {}", &cmd_args[0]))?;
        // The parent has no use for the slave; only the child does.
        unsafe {
            libc::close(slave);
        }
        CHILD_PID.store(child.id() as i32, Ordering::SeqCst);
        install_signal_forwarders();

        // Relay parent stdin -> master on a thread.
        let input = std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            loop {
                let n = unsafe { libc::read(0, buf.as_mut_ptr() as *mut _, buf.len()) };
                if n <= 0 {
                    break;
                }
                let mut off = 0usize;
                while off < n as usize {
                    let w = unsafe {
                        libc::write(master, buf[off..].as_ptr() as *const _, (n as usize) - off)
                    };
                    if w <= 0 {
                        break;
                    }
                    off += w as usize;
                }
                if off < n as usize {
                    break;
                }
            }
        });

        // Relay master -> scrubber -> stdout (one stream => no interleave).
        let mut mr = MasterRead { fd: master };
        let stdout = io::stdout();
        let mut out = stdout.lock();
        let copy_res = scrubber.copy(&mut mr, &mut out);

        let status = child.wait().context("wait child")?;
        CHILD_PID.store(0, Ordering::SeqCst);
        MASTER.store(-1, Ordering::SeqCst);
        unsafe {
            libc::signal(libc::SIGWINCH, libc::SIG_DFL);
        }

        // Restore the terminal before exiting (process::exit skips destructors),
        // and drop the input handle — its thread may still be blocked on read(0)
        // and is reaped by process::exit.
        drop(raw);
        drop(input);

        // A closed downstream is not a failure; EIO EOF is the normal stop.
        if let Err(e) = copy_res {
            if e.kind() != io::ErrorKind::BrokenPipe {
                return Err(anyhow!(e));
            }
        }
        exit_status(status);
    }
}

// --- import / export ------------------------------------------------------

fn cmd_import(args: &[String]) -> Result<()> {
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

    // Collect (key, value) pairs before touching any store, so the destination
    // can be resolved per key rather than picking one file upfront.
    let pairs: Vec<(String, String)> = if from_env {
        if let Some(name) = from_env_name {
            if !store::valid_key_name(&name) {
                bail!("invalid variable name: {name:?}")
            }
            if is_unsafe_env_name(&name) {
                bail!("unsafe env name: {name} — cannot enter the store");
            }
            let v = std::env::var(&name).with_context(|| format!("${name} is not set"))?;
            vec![(name, v)]
        } else {
            std::env::vars()
                .filter(|(k, _)| {
                    store::valid_key_name(k) && !is_boring_env(k) && !is_unsafe_env_name(k)
                })
                .collect()
        }
    } else if from_stdin {
        let lines: Vec<String> = io::stdin()
            .lock()
            .lines()
            .collect::<Result<Vec<_>, _>>()
            .context("reading stdin")?;
        join_multiline_lines(lines)
            .iter()
            .filter_map(|l| parse_env_line(l))
            .collect()
    } else if let Some(f) = file_arg {
        let lines: Vec<String> = std::fs::read_to_string(&f)
            .with_context(|| format!("reading {f}"))?
            .lines()
            .map(String::from)
            .collect();
        join_multiline_lines(lines)
            .iter()
            .filter_map(|l| parse_env_line(l))
            .collect()
    } else {
        bail!("usage: s import <file> | --stdin | --from-env [NAME]");
    };

    if pairs.is_empty() {
        info!("nothing to import");
        return Ok(());
    }

    let pw = get_password()?;
    ensure_password_matches_store(&pw, "")?;
    let primary = ensure_store()?;

    // Group pairs by destination store so each file is loaded and saved once.
    // Existing keys go to the store that already holds them; brand-new keys
    // fall back to the primary writable store (ensure_store).
    let mut by_dest: std::collections::BTreeMap<PathBuf, Vec<(String, String)>> =
        std::collections::BTreeMap::new();
    for (k, v) in pairs {
        let dest = match store_containing(&k)? {
            Some(p) => p,
            None => ensure_store()?,
        };
        by_dest.entry(dest).or_default().push((k, v));
    }

    let mut total = 0;
    for (path, items) in by_dest {
        let mut file = store::SenvFile::load(&path)?;
        let mut count = 0;
        for (k, v) in items {
            if file.keys.contains_key(&k) && !force && path == primary {
                warning!("skipping {k} (exists; use -f to overwrite)");
                continue;
            }
            let blob = store::encrypt_value(&v, &pw, &k)?;
            file.set_key(&k, blob, &pw)?;
            count += 1;
        }
        file.save(&path)?;
        total += count;
    }
    success!("imported {total} secret(s)");
    Ok(())
}

/// Inverse of the export quoting: unquote a single-quoted value and unescape
/// `'\''` back to `'`. Also handles double-quoted values from other .env
/// tools, so export->import is lossless for values containing quotes, `$`,
/// and newlines.
fn strip_quotes(s: &str) -> String {
    if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        return s[1..s.len() - 1].replace("'\\''", "'");
    }
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        return s[1..s.len() - 1].to_string();
    }
    s.to_string()
}

/// Parse a `KEY=VALUE` line (stripping `export `, unquoting the value).
/// Returns None for blank/comment lines, invalid key names, or unsafe env
/// names (LD_PRELOAD etc. must never enter the store).
fn parse_env_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);
    let (k, v) = trimmed.split_once('=')?;
    let k = k.trim();
    if !store::valid_key_name(k) {
        return None;
    }
    if is_unsafe_env_name(k) {
        return None;
    }
    Some((k.to_string(), strip_quotes(v.trim())))
}

/// Count the outer single-quote pair, ignoring export's embedded `\\'` token.
/// Even means the closing quote is on this line.
fn is_quote_balanced(line: &str) -> bool {
    let Some((_k, v)) = line.split_once('=') else {
        return true;
    };
    v.replace("'\\''", "").matches('\'').count() % 2 == 0
}

/// Join lines that belong to a multi-line single-quoted value. The export
/// format wraps values in single quotes; a value containing a newline spans
/// multiple lines, with the closing `'` on a later line. Without this, import
/// would see the continuation line as a separate (invalid) entry and drop it.
fn join_multiline_lines(lines: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    for line in lines {
        if let Some(buf) = &mut current {
            buf.push('\n');
            buf.push_str(&line);
            if is_quote_balanced(buf) {
                out.push(std::mem::take(&mut current).unwrap());
            }
        } else {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || is_quote_balanced(&line) {
                out.push(line);
            } else {
                current = Some(line);
            }
        }
    }
    if let Some(buf) = current {
        out.push(buf);
    }
    out
}

fn is_boring_env(k: &str) -> bool {
    matches!(
        k,
        "HOME"
            | "USER"
            | "SHELL"
            | "PATH"
            | "PWD"
            | "OLDPWD"
            | "TERM"
            | "LANG"
            | "LC_ALL"
            | "LC_CTYPE"
            | "EDITOR"
            | "VISUAL"
            | "PAGER"
            | "HOSTNAME"
            | "LOGNAME"
            | "SHLVL"
            | "TMPDIR"
            | "_"
            | "XDG_CONFIG_HOME"
            | "XDG_DATA_HOME"
            | "XDG_CACHE_HOME"
            | "XDG_RUNTIME_DIR"
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
                if i >= args.len() {
                    bail!("--file requires a path")
                }
                out_file = Some(args[i].clone());
            }
            other => bail!("unknown flag: {other}"),
        }
        i += 1;
    }
    let entries = decrypt_selected(None)?;
    let mut output = String::new();
    for (k, v) in &entries {
        // Always single-quote: it's the only shell quoting that stops `$`,
        // backtick, and newline from being interpreted by `source`/`eval`.
        // Escape embedded single quotes the POSIX way: `'` -> `'\''`.
        let escaped = v.replace('\'', "'\\''");
        output.push_str(&format!("{k}='{escaped}'\n"));
    }
    if let Some(f) = out_file {
        // Plaintext on disk — restrict to owner read/write.
        store::write_private(Path::new(&f), output.as_bytes())
            .with_context(|| format!("writing {f}"))?;
        success!("exported {} secret(s) to {f}", entries.len());
    } else {
        print!("{output}");
    }
    Ok(())
}

// --- history / rollback ---------------------------------------------------

fn cmd_history(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("usage: s history <NAME>")
    }
    ensure_store()?;
    let key = &args[0];
    let merged = merged_keys()?;
    let entry = merged
        .get(key.as_str())
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
                if i >= args.len() {
                    bail!("--to requires a version number")
                }
                to = Some(args[i].parse().context("version must be a number")?);
            }
            other if key.is_none() => key = Some(other.to_string()),
            _ => bail!("usage: s rollback <NAME> --to N"),
        }
        i += 1;
    }
    let key = key.ok_or_else(|| anyhow!("usage: s rollback <NAME> --to N"))?;
    let n = to.ok_or_else(|| anyhow!("usage: s rollback <NAME> --to N"))?;
    let path = store_containing(&key)?.ok_or_else(|| anyhow!("key {key} not found"))?;
    // Re-encrypting the restored blob needs the password, which also makes
    // rollback an authenticated action — a revoked credential cannot be
    // silently reinstated without it.
    let pw = get_password()?;
    let mut file = store::SenvFile::load(&path)?;
    let entry = file
        .keys
        .get_mut(key.as_str())
        .ok_or_else(|| anyhow!("key {key} not found"))?;
    entry.rollback(n, &pw, &key)?;
    file.save(&path)?;
    success!("rolled back {key} to v{n}");
    Ok(())
}

// --- scan -----------------------------------------------------------------

/// One file's worth of content to scan: its path and raw bytes. Both the
/// staged (index blob) and worktree paths build these, so the matching loop
/// is shared and only touches bytes.
struct ScanUnit {
    path: String,
    bytes: Vec<u8>,
}

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
                if i >= args.len() {
                    bail!("--path requires a directory")
                }
                scan_path = Some(args[i].clone());
            }
            other => bail!("unknown flag: {other}"),
        }
        i += 1;
    }

    let entries = decrypt_selected(None)?;
    // Keep a floor (short values are noise) but make it visible: report which
    // keys were skipped instead of silently dropping them.
    let mut secrets: Vec<(&str, &[u8])> = Vec::new();
    let mut too_short: Vec<&str> = Vec::new();
    for (k, v) in &entries {
        if v.is_empty() {
            continue;
        }
        if v.len() < 8 {
            too_short.push(k.as_str());
        } else {
            secrets.push((k.as_str(), v.as_bytes()));
        }
    }
    if !too_short.is_empty() {
        info!(
            "not scanning for {} secret(s) under 8 bytes: {}",
            too_short.len(),
            too_short.join(", ")
        );
    }

    if secrets.is_empty() {
        info!("no secrets to scan for");
        return Ok(());
    }

    let paths = collect_scan_paths(staged, scan_path.as_deref())?;
    if paths.is_empty() {
        info!("no files to scan");
        return Ok(());
    }

    // Exclude the encrypted stores by canonical path, not by name suffix: an
    // unrelated `prod.senv` must still be scanned.
    let store_paths = store_paths_canonical();

    let mut units: Vec<ScanUnit> = Vec::new();
    let mut unreadable: Vec<(String, String)> = Vec::new();
    for path in &paths {
        if is_store_path(path, &store_paths) {
            continue;
        }
        let bytes = if staged {
            // Read the staged blob from the index, never the worktree: a file
            // cleaned up in the worktree but still staged must still be caught.
            match staged_blob_bytes(path) {
                Ok(b) => b,
                Err(e) => {
                    unreadable.push((path.clone(), format!("{e}")));
                    continue;
                }
            }
        } else {
            match std::fs::read(path) {
                Ok(b) => b,
                Err(e) => {
                    unreadable.push((path.clone(), e.to_string()));
                    continue;
                }
            }
        };
        units.push(ScanUnit {
            path: path.clone(),
            bytes,
        });
    }

    // Search the whole byte content so multi-line secrets (e.g. PEM keys) can
    // match; derive the line number from the match offset.
    let mut found: Vec<(String, usize, String)> = Vec::new();
    for unit in &units {
        for (key, val) in &secrets {
            if let Some(pos) = find_subsequence(&unit.bytes, val) {
                let line = 1 + unit.bytes[..pos].iter().filter(|&&c| c == b'\n').count();
                found.push((unit.path.clone(), line, key.to_string()));
            }
        }
    }

    // Report unreadable files rather than silently dropping them.
    for (p, e) in &unreadable {
        warning!("could not read {p}: {e}");
    }

    if found.is_empty() {
        // exit 0 — clean
        return Ok(());
    }

    emit_error(format_args!("secrets found in files:"));
    eprintln!();
    for (f, line, key) in &found {
        eprintln!("  {f}:{line}");
        eprintln!("    contains: {key}\n");
    }
    let unique: std::collections::HashSet<&str> =
        found.iter().map(|(f, _, _)| f.as_str()).collect();
    emit_error(format_args!(
        "found {} secret(s) in {} file(s)",
        found.len(),
        unique.len()
    ));
    std::process::exit(1);
}

/// Paths to scan. Both git invocations use `-z` (NUL-separated) so non-ASCII
/// paths are emitted raw (no `core.quotePath` escaping) and paths containing
/// newlines are not mis-split.
fn collect_scan_paths(staged: bool, scan_path: Option<&str>) -> Result<Vec<String>> {
    if staged {
        let out = Command::new("git")
            .args([
                "diff",
                "--cached",
                "-z",
                "--name-only",
                "--diff-filter=ACMR",
            ])
            .output()
            .context("running git diff")?;
        return Ok(split_nul(&out.stdout));
    }
    let dir = scan_path.unwrap_or(".");
    let out = Command::new("git")
        .args(["ls-files", "-z", "--", dir])
        .output();
    if let Ok(out) = out {
        if out.status.success() {
            return Ok(split_nul(&out.stdout));
        }
    }
    let mut files = Vec::new();
    walk_dir(Path::new(dir), &mut files)?;
    Ok(files)
}

fn split_nul(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// Read a path's staged blob from the index via `git show :<path>`. This is
/// the index content, never the worktree copy.
fn staged_blob_bytes(path: &str) -> Result<Vec<u8>> {
    let spec = format!(":{path}");
    let out = Command::new("git")
        .args(["show", spec.as_str()])
        .output()
        .with_context(|| format!("running git show :{path}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        bail!("git show :{path} failed: {err}");
    }
    Ok(out.stdout)
}

fn find_subsequence(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// True if `path` is one of the encrypted stores — compared by canonicalized
/// path so a same-named plaintext file like `prod.senv` is not skipped.
fn is_store_path(path: &str, store_paths: &[PathBuf]) -> bool {
    let cand = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(_) => return false,
    };
    store_paths.iter().any(|s| *s == cand)
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
            if name.starts_with('.') || name == "node_modules" || name == "target" {
                continue;
            }
            walk_dir(&path, out)?;
        } else if ft.is_file() {
            out.push(path.to_string_lossy().to_string());
        }
    }
    Ok(())
}

// --- helpers --------------------------------------------------------------

fn confirm_overwrite(key: &str) -> Result<bool> {
    use std::io::BufReader;
    let tty = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    {
        Ok(f) => f,
        Err(_) => {
            warning!("key {key} already exists; pass -f to overwrite");
            return Ok(false);
        }
    };
    let mut tty_w = tty.try_clone().context("cloning /dev/tty")?;
    write!(tty_w, "overwrite existing {key}? [y/N] ")?;
    tty_w.flush()?;
    let mut line = String::new();
    BufReader::new(tty)
        .read_line(&mut line)
        .context("reading from /dev/tty")?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES"))
}
