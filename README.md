# s — encrypted env store

Your agent doesn't need to see your secrets. `s` encrypts secrets with a password, injects them into subprocesses at runtime, and scrubs them from output. The agent orchestrates; `s` handles the secrets.

```bash
# Agent writes this:
s API_KEY -- curl -H "Authorization: Bearer $API_KEY" https://api.example.com

# Agent sees: response with [REDACTED] where the key was
# What ran: curl with the real key injected
```

## Setup

```bash
s init                          # creates .senv, installs pre-commit hook
s set API_KEY                   # interactive (masked input: ****)
s set DB_URL --stdin            # piped
```

## Managing secrets

```bash
s set <NAME>                    # add/update (interactive, masked)
s set <NAME> --stdin            # add/update (piped)
s get <NAME>                    # show value (refuses without TTY)
s rm <NAME>                     # delete
s list                          # list names ([REDACTED] values)
```

## Running commands

```bash
s API_KEY -- curl https://...                    # specific secrets
s API_KEY DB_URL -- ./deploy.sh                  # multiple secrets
s --all -- ./deploy.sh                           # ALL secrets (explicit)
s -- ./build.sh                                  # no secrets injected
```

Secrets are injected as env vars. Output is scrubbed — any secret value replaced
with `[REDACTED]`. Injecting **all** secrets is never the default: name the keys
you need, or opt in explicitly with `--all`.

Scrubbing is verbatim-only: it catches the secret as written, not transformed
copies (base64, URL-encoding, etc.). It's a strong guardrail, not a guarantee.

## Inline / shebang mode

Scripts can declare their own secret dependencies in the shebang, so callers and agents do not need to remember to wrap them with `s`:

```bash
#!/usr/bin/env -S s TOOL_GATEWAY_TOKEN -- bash
curl -H "Authorization: Bearer $TOOL_GATEWAY_TOKEN" https://example.com
```

Multiple secrets work the same way:

```bash
#!/usr/bin/env -S s SCRAPECREATORS_API_KEY X_BEARER_TOKEN -- bun
console.log(process.env.SCRAPECREATORS_API_KEY ? "ready" : "missing")
```

On systems where `s` has a stable absolute path, direct shebangs work too:

```bash
#!/usr/local/bin/s API_KEY -- python3
import os
print("API_KEY is present" if os.environ.get("API_KEY") else "missing")
```

This is equivalent to running `s KEY [KEY...] -- <interpreter> <script> ...`: the named secrets are injected into the interpreter process and scrubbed from stdout/stderr. The script's arguments are preserved.

Operational notes:

- The process still needs the password via `S_KEY`, `S_KEY="!command"`, or an interactive prompt.
- `s` reads `.senv` from the current working directory. Run tools from the repo/workspace that owns the `.senv`, or have a wrapper `cd` there first.
- Prefer shebang mode for committed tools: the tool declares what it needs, while callers simply run `bin/tool ...`.

## Import / Export

```bash
s import .env                   # import from .env file
s import --stdin                # import KEY=VALUE lines from stdin
s import --from-env             # import all env vars
s import --from-env API_KEY     # import specific env var
s export                        # export as KEY=VALUE (refuses without TTY)
s export --file .env            # export to file (refuses without TTY)
```

## History & Rollback

Last 2 versions kept automatically when you update a secret.

```bash
s history API_KEY               # show versions
s rollback API_KEY --to 1       # restore previous version
```

## Scanning for leaks

```bash
s scan                          # scan all git-tracked files
s scan --staged                 # scan only staged files (used by pre-commit hook)
```

Checks actual secret values — no regex, no false positives.

`s init` installs a pre-commit hook that runs `s scan --staged` automatically.

## Store location

`s` resolves which `.senv` to use in this order:

1. `S_FILE` env var — explicit path override (used for reads and writes)
2. `./.senv` — project-local store in the current directory
3. `~/.config/senv/senv` — global store (honours `$XDG_CONFIG_HOME`)

When both a local and a global store exist, reads **merge** them with the local
store winning on conflicts — so a repo can override or extend your global
secrets. A single password (from `S_KEY` or one prompt) decrypts both. Setting
`S_FILE` bypasses the merge and uses only that file.

Writes update a key wherever it already lives; brand-new keys are created in the
highest-precedence existing store. `s init` creates `./.senv` by default, or the
`S_FILE` path if set (e.g. `S_FILE=~/.config/senv/senv s init` for a global store).

## Password

The encryption password is resolved in order:

1. `S_KEY` env var — the password directly
2. `S_KEY="!command"` — execute command (e.g. `!security find-generic-password -s s-secrets -w`)
3. TTY prompt — fallback if interactive

## Agent safety

- `s get` and `s export` **refuse without a TTY** — prevents secrets leaking into agent context
- `s list` only shows names with `[REDACTED]`
- `s KEY -- cmd` / `s --all -- cmd` inject secrets but scrub all output
- Pre-commit hook blocks committing leaked secret values

## How it works

- Each secret is independently encrypted with ChaCha20-Poly1305
- Key derived with **Argon2id** (memory-hard) from your password + random per-value salt
- `.senv` is safe to commit (only encrypted blobs); written with `0600` perms
- Pre-0.7 stores (HKDF-derived) still decrypt; re-encrypting a value upgrades it
- The master password (`S_KEY`) is stripped from injected subprocess environments
- No daemon, no network, no SSH keys, no keychain dependency

## Install

```bash
# Nix flake
nix profile install github:tobi/s

# Or build from source
cargo install --path .
```

## Nix home-manager

```nix
{
  inputs.s.url = "github:tobi/s";
  # in modules:
  imports = [ inputs.s.homeModules.default ];
  programs.s = {
    enable = true;
    passwordCommand = "security find-generic-password -s s-secrets -w";  # macOS
  };
}
```
