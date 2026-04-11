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
s run ./deploy.sh                                # ALL secrets
```

Secrets are injected as env vars. Output is scrubbed — any secret value replaced with `[REDACTED]`.

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

## Password

The encryption password is resolved in order:

1. `S_KEY` env var — the password directly
2. `S_KEY="!command"` — execute command (e.g. `!security find-generic-password -s s-secrets -w`)
3. TTY prompt — fallback if interactive

## Agent safety

- `s get` and `s export` **refuse without a TTY** — prevents secrets leaking into agent context
- `s list` only shows names with `[REDACTED]`
- `s run` / `s KEY -- cmd` inject secrets but scrub all output
- Pre-commit hook blocks committing leaked secret values

## How it works

- Each secret is independently encrypted with ChaCha20-Poly1305
- Key derived via HKDF-SHA256 from your password + random per-value salt
- `.senv` is safe to commit (only encrypted blobs)
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
