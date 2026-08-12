mod common;
use common::*;

use std::process::Command;

// --- Defect 1: S_FILE=<global> s init in a git repo must not mutate the repo -

#[test]
fn init_with_s_file_does_not_mutate_repo() {
    let f = Fixture::new_git();
    let global = f.path("global/senv");
    let global_str = global.to_str().unwrap();
    // S_FILE points to a global store path outside ./.senv
    f.s_env(&["init"], &[("S_FILE", Some(global_str))], None)
        .ok();
    // The global store is created ...
    assert!(global.exists());
    // ... but the repo is untouched: no .gitignore, no pre-commit hook.
    assert!(!f.path(".gitignore").exists());
    assert!(!f.path(".git/hooks/pre-commit").exists());
    // And no local .senv either.
    assert!(!f.path(".senv").exists());
}

// --- Defect 2: s init ignores by default; --git explicitly opts in ----------

#[test]
fn init_default_gitignores_with_explanation() {
    let f = Fixture::new_git();
    let r = f.s(&["init"]);
    r.ok();
    assert!(f.path(".senv").exists());
    let content = String::from_utf8(f.read(".gitignore")).unwrap();
    assert!(
        content.lines().any(|l| l.trim() == ".senv"),
        ".senv should be gitignored by default"
    );
    assert!(
        content.contains("can be committed if its encryption key is not shared"),
        "the ignore must explain that committing the encrypted store is optional"
    );
    assert!(
        content.contains("s init --git"),
        "the ignore must document the creation-time opt-in"
    );
    assert!(r.stderr.contains("ignored .senv by default"));
    assert!(r.stderr.contains("encryption key stays private"));
}

#[test]
fn init_git_flag_makes_store_trackable() {
    let f = Fixture::new_git();
    f.write(".gitignore", "# keep this unrelated rule\n*.log\n.senv\n");
    let r = f.s(&["init", "--git"]);
    r.ok();
    assert!(f.path(".senv").exists());
    let content = String::from_utf8(f.read(".gitignore")).unwrap();
    assert!(
        content.contains("*.log"),
        "unrelated ignore rules must survive"
    );
    assert!(
        !content.lines().any(|l| l.trim() == ".senv"),
        "--git should remove an existing exact .senv ignore"
    );
    assert!(r.stderr.contains("eligible for Git tracking"));
    assert!(r.stderr.contains("never commit or share the key"));
}

// --- Defect 3: set and exec disagree on key names ---------------------------

#[test]
fn add_is_an_alias_for_set() {
    let f = Fixture::inited();
    let r = f.s_stdin(&["add", "ALIAS", "--stdin"], "hello");
    r.ok();
    assert!(f.s(&["list"]).stdout.contains("ALIAS"));
}

#[cfg(unix)]
#[test]
fn interactive_set_accepts_bracketed_multiline_paste() {
    let f = Fixture::inited();
    let pasted = b"\x1b[200~first line\nsecond line\x1b[201~\n";
    let r = f.s_pty_input(&["set", "PEM_KEY"], pasted);
    assert_eq!(r.code, 0, "interactive set failed: {}", r.output);

    let out = f.path("pasted");
    let out_str = out.to_str().unwrap();
    let r = f.s(&[
        "PEM_KEY",
        "--",
        "sh",
        "-c",
        &format!("printf %s \"$PEM_KEY\" > {out_str}"),
    ]);
    r.ok();
    assert_eq!(f.read_str("pasted"), "first line\nsecond line");

    let r = f.s_pty_input(
        &["add", "PEM_ADD"],
        b"\x1b[200~add first\nadd second\x1b[201~\n",
    );
    assert_eq!(r.code, 0, "interactive add failed: {}", r.output);
    let r = f.s(&[
        "PEM_ADD",
        "--",
        "sh",
        "-c",
        &format!("printf %s \"$PEM_ADD\" >> {out_str}"),
    ]);
    r.ok();
    assert_eq!(
        f.read_str("pasted"),
        "first line\nsecond lineadd first\nadd second"
    );
}

#[test]
fn lower_case_key_exec() {
    let f = Fixture::inited();
    f.s_stdin(&["set", "lower_key", "--stdin"], "hello").ok();
    // Write to a file so the scrubber does not redact the value on stdout.
    let out = f.path("out");
    let out_str = out.to_str().unwrap();
    f.s(&[
        "lower_key",
        "--",
        "sh",
        "-c",
        &format!("printf %s \"$lower_key\" > {out_str}"),
    ])
    .ok();
    assert_eq!(String::from_utf8(f.read("out")).unwrap(), "hello");
}

#[test]
fn help_key_does_not_shadow_subcommand() {
    let f = Fixture::inited();
    f.s_stdin(&["set", "help", "--stdin"], "helper").ok();

    // With `--`, "help" is a key name — exec form runs.
    let out = f.path("out");
    let out_str = out.to_str().unwrap();
    f.s(&[
        "help",
        "--",
        "sh",
        "-c",
        &format!("printf %s \"$help\" > {out_str}"),
    ])
    .ok();
    assert_eq!(String::from_utf8(f.read("out")).unwrap(), "helper");

    // Without `--`, "help" is the subcommand — prints usage.
    let r = f.s(&["help"]);
    assert_eq!(r.code, 0);
    assert!(r.stderr.contains("encrypted env store"));
}

#[test]
fn skill_is_valid_agent_facing_markdown() {
    let f = Fixture::new();
    let run = f.s(&["--skill"]);
    run.ok();
    assert!(run.stderr.is_empty(), "unexpected stderr: {}", run.stderr);

    let document = run
        .stdout
        .strip_prefix("---\n")
        .expect("skill must start with YAML frontmatter");
    let (frontmatter, body) = document
        .split_once("\n---\n")
        .expect("skill must close YAML frontmatter");
    let metadata: serde_yaml::Value =
        serde_yaml::from_str(frontmatter).expect("frontmatter must be valid YAML");
    assert_eq!(metadata["name"], "s");
    assert_eq!(
        metadata["description"],
        "Use when you need to use credentials and the project uses an .senv."
    );

    for heading in [
        "## Execute with credentials",
        "## Credential-aware scripts",
        "## HTTP requests",
    ] {
        assert!(body.contains(heading), "missing section: {heading}");
    }
    assert!(body.contains("s configure api.example.com"));
    assert!(body.contains("--header 'Authorization: Bearer $API_KEY'"));
    for unrelated in ["s set", "s get", "s import", "s export"] {
        assert!(
            !body.contains(unrelated),
            "skill must stay focused, found {unrelated:?}"
        );
    }
}

#[test]
fn empty_and_help_output_prioritize_agents_and_humans() {
    let f = Fixture::new();
    for args in [&[][..], &["--help"][..]] {
        let run = f.s(args);
        run.ok();
        let agents = run.stderr.find("Agents:").expect("missing Agents section");
        let humans = run.stderr.find("Humans:").expect("missing Humans section");
        let commands = run
            .stderr
            .find("Commands:")
            .expect("missing Commands section");
        assert!(agents < humans && humans < commands, "{}", run.stderr);
        assert!(run.stderr.contains("s KEY [KEY...] -- <cmd>"));
        assert!(run.stderr.contains("s configure HOST --header"));
        assert!(run.stderr.contains("More agent information: s --skill"));
        assert!(run.stderr.contains("s set <NAME>"));
        assert!(run.stderr.contains("s get <NAME>"));
    }
}

#[test]
fn version_flag_prints_package_version() {
    let f = Fixture::new();
    for flag in ["-v", "--version"] {
        let r = f.s(&[flag]);
        r.ok();
        assert_eq!(r.stdout.trim(), env!("CARGO_PKG_VERSION"));
    }
}
#[test]
fn set_rejects_unsafe_env_name() {
    let f = Fixture::inited();
    let r = f.s_stdin(&["set", "LD_PRELOAD", "--stdin"], "evil");
    r.fails();
    assert!(r.stderr.contains("unsafe env name"));
    // The key must not have entered the store.
    let r2 = f.s(&["list"]);
    assert!(!r2.stdout.contains("LD_PRELOAD"));
}

// --- Defect 4: rollback requires password -----------------------------------

#[test]
fn rollback_requires_password() {
    let f = Fixture::inited();
    f.set("API_KEY", "v1");
    f.set("API_KEY", "v2"); // pushes v1 into history

    // Without a password (S_KEY unset, no TTY): must fail.
    let r = f.s_env(
        &["rollback", "API_KEY", "--to", "1"],
        &[("S_KEY", None)],
        None,
    );
    r.fails();

    // With the password: succeeds and restores v1.
    f.s(&["rollback", "API_KEY", "--to", "1"]).ok();
    let out = f.path("out");
    let out_str = out.to_str().unwrap();
    f.s(&[
        "API_KEY",
        "--",
        "sh",
        "-c",
        &format!("printf %s \"$API_KEY\" > {out_str}"),
    ])
    .ok();
    assert_eq!(String::from_utf8(f.read("out")).unwrap(), "v1");
}

// --- Defect 5: export must be shell-safe (single-quote) ---------------------

#[test]
fn export_shell_safe_sourcing() {
    let f = Fixture::inited();
    f.set("WEIRD_PW", "p$(id)w");

    // Export to a file (needs a PTY for the TTY check).
    let r = f.s_pty(&["export", "--file", "exported.env"]);
    assert_eq!(r.code, 0);

    // Source the file in sh — `$(id)` must NOT execute.
    let output = Command::new("sh")
        .current_dir(f.dir())
        .args(["-c", ". ./exported.env && printf %s \"$WEIRD_PW\""])
        .output()
        .unwrap();
    assert!(output.status.success(), "sourcing exported file failed");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "p$(id)w",
        "sourced value must be literal, not command-substituted"
    );
}

#[test]
fn export_import_roundtrip_special_chars() {
    let f = Fixture::inited();
    // Contains: single quote, double quote, $, and a newline.
    let value = "it's \"dollar$\" and\nnewline";
    f.s_stdin(&["set", "RT", "--stdin"], value).ok();

    // Export to file (PTY).
    let r = f.s_pty(&["export", "--file", "exported.env"]);
    assert_eq!(r.code, 0);

    // Import into a fresh store.
    let f2 = Fixture::inited();
    f2.write("exported.env", f.read("exported.env"));
    f2.s(&["import", "exported.env"]).ok();

    // Verify the value survived the round-trip (write to file to bypass
    // the scrubber, which would redact the value on stdout).
    let out = f2.path("out");
    let out_str = out.to_str().unwrap();
    f2.s(&[
        "RT",
        "--",
        "sh",
        "-c",
        &format!("printf %s \"$RT\" > {out_str}"),
    ])
    .ok();
    assert_eq!(String::from_utf8(f2.read("out")).unwrap(), value);
}

// --- Defect 6: import updates the store that already holds the key ----------

#[test]
fn import_updates_global_store() {
    let f = Fixture::new();
    let home_str = f.dir().to_str().unwrap();
    let global = f.path(".config/senv/senv");
    let global_str = global.to_str().unwrap();
    let local = f.path(".senv");
    let local_str = local.to_str().unwrap();

    // 1. Create a global store and put a key in it.
    f.s_env(
        &["init"],
        &[("S_FILE", Some(global_str)), ("XDG_CONFIG_HOME", None)],
        None,
    )
    .ok();
    f.s_env(
        &["set", "GKEY", "--stdin"],
        &[("S_FILE", Some(global_str)), ("XDG_CONFIG_HOME", None)],
        Some("old_val"),
    )
    .ok();

    // 2. Create a local .senv (so both stores exist for the merge).
    f.s_env(
        &["init"],
        &[("S_FILE", Some(local_str)), ("XDG_CONFIG_HOME", None)],
        None,
    )
    .ok();

    // 3. Import --from-env GKEY with merge mode (S_FILE unset, HOME set).
    //    The key lives only in the global store, so it must be UPDATED there,
    //    not duplicated into the local store.
    f.s_env(
        &["import", "--from-env", "GKEY"],
        &[
            ("S_FILE", None),
            ("HOME", Some(home_str)),
            ("XDG_CONFIG_HOME", None),
            ("GKEY", Some("new_val")),
        ],
        None,
    )
    .ok();

    // The local store must not contain GKEY.
    let local = String::from_utf8(f.read(".senv")).unwrap();
    assert!(
        !local.contains("GKEY"),
        "GKEY should not be duplicated in the local store"
    );

    // The global store must contain GKEY with the updated value.
    let out = f.path("out");
    let out_str = out.to_str().unwrap();
    f.s_env(
        &[
            "GKEY",
            "--",
            "sh",
            "-c",
            &format!("printf %s \"$GKEY\" > {out_str}"),
        ],
        &[
            ("S_FILE", None),
            ("HOME", Some(home_str)),
            ("XDG_CONFIG_HOME", None),
        ],
        None,
    )
    .ok();
    assert_eq!(
        String::from_utf8(f.read("out")).unwrap(),
        "new_val",
        "global store should have the updated value"
    );
}

// --- Defect 7: import --from-env NAME honours -f ----------------------------

#[test]
fn import_from_env_name_respects_force() {
    let f = Fixture::inited();
    f.set("EXISTING", "old_val");

    // Without -f: must skip and warn.
    let r = f.s_env(
        &["import", "--from-env", "EXISTING"],
        &[("EXISTING", Some("new_val"))],
        None,
    );
    r.ok();
    assert!(r.stderr.contains("skipping"), "should skip without -f");

    // With -f: overwrites.
    f.s_env(
        &["import", "--from-env", "EXISTING", "-f"],
        &[("EXISTING", Some("new_val"))],
        None,
    )
    .ok();

    let out = f.path("out");
    let out_str = out.to_str().unwrap();
    f.s(&[
        "EXISTING",
        "--",
        "sh",
        "-c",
        &format!("printf %s \"$EXISTING\" > {out_str}"),
    ])
    .ok();
    assert_eq!(String::from_utf8(f.read("out")).unwrap(), "new_val");
}

// --- Defect 8: list on a corrupt .senv fails loudly -------------------------

#[test]
fn list_corrupt_store_fails() {
    let f = Fixture::inited();
    // Write non-UTF8 garbage — load will fail at read_to_string.
    f.write(".senv", b"\xff\xfe\xfd not valid utf8");
    let r = f.s(&["list"]);
    r.fails();
    // Must NOT print the authoritative empty [].
    assert!(!r.stdout.contains("[]"));
    // Must have an error message on stderr.
    assert!(!r.stderr.is_empty());
}

// --- Defect 9: history with no store says to run s init ---------------------

#[test]
fn history_no_store_says_init() {
    let f = Fixture::new();
    // No .senv exists — fixture::new does not init.
    let r = f.s(&["history", "API_KEY"]);
    r.fails();
    assert!(
        r.stderr.contains("s init"),
        "should tell the user to run s init"
    );
}

// --- Defect 10: S_KEY='!cmd' must not leak the command or its stderr --------

#[test]
fn s_key_bang_error_safe() {
    let f = Fixture::inited();
    // `false` exits 1 with no stderr — the error must not name the command.
    let r = f.s_env(
        &["set", "KEY", "--stdin"],
        &[("S_KEY", Some("!false"))],
        Some("val"),
    );
    r.fails();
    assert!(
        !r.stderr.contains("false"),
        "error must not contain the command text"
    );
    assert!(
        r.stderr.contains("S_KEY command failed"),
        "should report the safe failure message"
    );
}

#[test]
fn s_key_bang_does_not_leak_stderr() {
    let f = Fixture::inited();
    // A command that writes to stderr — the old code echoed sh's stderr
    // (which is the password) into the error message.
    let r = f.s_env(
        &["set", "KEY", "--stdin"],
        &[("S_KEY", Some("!echo LEAKED >&2; exit 5"))],
        Some("val"),
    );
    r.fails();
    assert!(
        !r.stderr.contains("LEAKED"),
        "error must not contain the command's stderr"
    );
    assert!(r.stderr.contains("S_KEY command failed"));
}

// --- Defect 11: S_KEY_COMMAND takes precedence; S_KEY is then literal -------

#[test]
fn s_key_command_overrides_bang_s_key() {
    let f = Fixture::inited();
    // S_KEY_COMMAND provides a working password; S_KEY='!false' would fail
    // if executed. With S_KEY_COMMAND set, S_KEY's `!` is never interpreted.
    let r = f.s_env(
        &["set", "KEY", "--stdin"],
        &[
            ("S_KEY_COMMAND", Some("printf real_pw")),
            ("S_KEY", Some("!false")),
        ],
        Some("val"),
    );
    r.ok();

    // Verify the key was encrypted with "real_pw" (from S_KEY_COMMAND), not
    // with "SHOULD_NOT_RUN" or anything else.
    let out = f.path("out");
    let out_str = out.to_str().unwrap();
    f.s_env(
        &[
            "KEY",
            "--",
            "sh",
            "-c",
            &format!("printf %s \"$KEY\" > {out_str}"),
        ],
        &[
            ("S_KEY_COMMAND", Some("printf real_pw")),
            ("S_KEY", Some("!false")),
        ],
        None,
    )
    .ok();
    assert_eq!(String::from_utf8(f.read("out")).unwrap(), "val");
}
