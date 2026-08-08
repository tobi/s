mod common;
use common::*;

/// A secret long enough to clear the scrubber floor (>= 8 bytes).
const SECRET: &str = "hunter2exec-secret";

/// Pull a `KEY: "blob"` value out of the serialized .senv YAML.
fn extract_blob(yaml: &str, key: &str) -> String {
    let needle = format!("{key}:");
    for line in yaml.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix(&needle) {
            return rest.trim().trim_matches('"').to_string();
        }
    }
    panic!("key {key} not found in yaml:\n{yaml}");
}

/// Named injection provides ONLY the named secret; an unnamed one is absent
/// from the child env. Uses `${VAR:+present}` so the value never reaches stdout
/// (the scrubber would redact it) — we assert presence, not the value.
#[test]
fn named_only_injects_named_secret() {
    let f = Fixture::inited();
    f.set("API_KEY", "alpha-secret-aaaa");
    f.set("DB_URL", "beta-secret-bbbb");
    let r = f.s(&[
        "API_KEY",
        "--",
        "sh",
        "-c",
        "echo API=${API_KEY:+present}; echo DB=${DB_URL:+present}",
    ]);
    let out = r.out();
    assert_eq!(r.code, 0, "{}", r.all());
    assert!(out.contains("API=present"), "named secret injected: {out}");
    assert!(
        !out.contains("DB=present"),
        "unnamed secret must not be injected: {out}"
    );
}

/// `s -- cmd` (no names) injects nothing — the safe default.
#[test]
fn empty_only_injects_nothing() {
    let f = Fixture::inited();
    f.set("API_KEY", "alpha-secret-aaaa");
    let r = f.s(&["--", "sh", "-c", "echo API=${API_KEY:+present}"]);
    let out = r.out();
    assert_eq!(r.code, 0, "{}", r.all());
    assert!(
        !out.contains("present"),
        "no secrets injected with bare --: {out}"
    );
}

/// A corrupt / foreign-password entry must NOT break `s GOOD_KEY -- cmd`. The
/// old code called decrypt_all() and aborted on the mismatched entry. BAD_KEY is
/// encrypted under a different password in a second store, then its blob is
/// spliced into the first store under the same name (so the v2 AAD matches).
#[test]
fn foreign_password_entry_does_not_break_named_lookup() {
    let f = Fixture::inited();
    f.set("GOOD_KEY", "good-value-xxxx");

    let f2 = Fixture::inited();
    f2.s_env(
        &["set", "BAD_KEY", "--stdin"],
        &[("S_KEY", Some("other-password"))],
        Some("bad-value-yyyy"),
    );
    let bad_blob = extract_blob(&String::from_utf8(f2.read(".senv")).unwrap(), "BAD_KEY");

    let mut f1_yaml = String::from_utf8(f.read(".senv")).unwrap();
    if !f1_yaml.ends_with('\n') {
        f1_yaml.push('\n');
    }
    f1_yaml.push_str(&format!("  BAD_KEY: \"{bad_blob}\"\n"));
    f.write(".senv", f1_yaml);

    let r = f.s(&[
        "GOOD_KEY",
        "--",
        "sh",
        "-c",
        "echo GOOD=${GOOD_KEY:+present}",
    ]);
    assert_eq!(
        r.code,
        0,
        "named lookup survives foreign sibling: {}",
        r.all()
    );
    assert!(
        r.out().contains("GOOD=present"),
        "good key still works: {}",
        r.out()
    );
    assert!(
        !r.stderr.contains("BAD_KEY"),
        "foreign entry never touched: {}",
        r.stderr
    );
}

/// `s --all -- yes | head -n1` must terminate. The old scrubber discarded write
/// errors and spun forever; `timeout` returns 124 when it has to kill the
/// hung pipeline, so any other code means s stopped on its own.
#[test]
fn all_yes_pipe_to_head_terminates() {
    let f = Fixture::inited();
    f.set("SECRET", SECRET);
    let s = env!("CARGO_BIN_EXE_s");
    let script = format!("{s} --all -- yes | head -n1");
    let out = std::process::Command::new("timeout")
        .arg("3")
        .arg("sh")
        .arg("-c")
        .arg(&script)
        .env("S_KEY", PW)
        .env("S_FILE", f.path(".senv"))
        .current_dir(f.dir())
        .output()
        .expect("run pipeline");
    // 124 = `timeout` killed it => it hung. Anything else => it terminated.
    assert_ne!(
        out.status.code(),
        Some(124),
        "s --all -- yes | head -n1 hung (timeout fired)"
    );
}

/// Signal deaths exit 128+signal, matching the shell — not collapsed to 1.
#[test]
fn signal_death_exits_128_plus_signal() {
    let f = Fixture::inited();
    let r = f.s(&["--", "sh", "-c", "kill -TERM $$"]);
    assert_eq!(r.code, 143, "SIGTERM -> 128+15: {}", r.all());
    let r = f.s(&["--", "sh", "-c", "kill -9 $$"]);
    assert_eq!(r.code, 137, "SIGKILL -> 128+9: {}", r.all());
}

/// A plain child exit code propagates unchanged.
#[test]
fn child_exit_code_propagates() {
    let f = Fixture::inited();
    let r = f.s(&["--", "sh", "-c", "exit 7"]);
    assert_eq!(r.code, 7, "exit 7 propagates: {}", r.all());
}

/// Scrubbing redacts the secret on BOTH stdout and stderr.
#[test]
fn scrub_redacts_stdout_and_stderr() {
    let f = Fixture::inited();
    f.set("SECRET", SECRET);
    let r = f.s(&["SECRET", "--", "sh", "-c", "echo $SECRET; echo $SECRET >&2"]);
    let all = r.all();
    assert!(
        !all.contains(SECRET),
        "secret redacted on both streams: {all}"
    );
    assert!(
        all.contains("[REDACTED]"),
        "redaction marker present: {all}"
    );
}

/// A stored `LD_PRELOAD` is refused at injection time (ld.so really honored the
/// old injection) and a warning is printed; the value never reaches the child.
#[test]
fn unsafe_ld_preload_not_injected() {
    let f = Fixture::inited();
    f.inject_legacy("LD_PRELOAD", "/tmp/evil-loader.so");
    let r = f.s(&[
        "LD_PRELOAD",
        "--",
        "sh",
        "-c",
        "echo LD=${LD_PRELOAD:-unset}",
    ]);
    let all = r.all();
    assert!(
        all.contains("LD=unset"),
        "LD_PRELOAD not injected into child: {all}"
    );
    assert!(
        all.contains("refusing to inject LD_PRELOAD"),
        "warning on stderr: {all}"
    );
    assert!(
        !all.contains("/tmp/evil-loader.so"),
        "preload value never reaches output: {all}"
    );
}

/// A stored `S_KEY` is not injected, and the live `S_KEY` is removed after the
/// loop so it cannot be re-added. The old code env_removed S_KEY *before* the
/// injection loop, putting a stored S_KEY straight back.
#[test]
fn stored_s_key_not_injected() {
    let f = Fixture::inited();
    f.inject_legacy("S_KEY", "leaked-master-password");
    let r = f.s(&["S_KEY", "--", "sh", "-c", "echo SK=${S_KEY:-unset}"]);
    let all = r.all();
    assert!(all.contains("SK=unset"), "S_KEY not in child env: {all}");
    assert!(
        !all.contains("leaked-master-password"),
        "stored S_KEY value must not leak: {all}"
    );
    assert!(
        all.contains("refusing to inject S_KEY"),
        "warning emitted: {all}"
    );
}

/// PTY mode: under a real PTY, `echo $SECRET > /dev/tty` must be redacted (the
/// old pipe-only code let the raw secret out via /dev/tty) and the child's fd 1
/// must report a TTY.
#[test]
fn pty_redacts_dev_tty_and_reports_tty() {
    let f = Fixture::inited();
    f.set("SECRET", SECRET);
    let r = f.s_pty(&[
        "SECRET",
        "--",
        "sh",
        "-c",
        "echo $SECRET > /dev/tty; test -t 1 && echo IS_TTY",
    ]);
    assert!(
        r.output.contains("[REDACTED]"),
        "/dev/tty output redacted: {}",
        r.output
    );
    assert!(
        !r.output.contains(SECRET),
        "raw secret must not leak via /dev/tty: {}",
        r.output
    );
    assert!(
        r.output.contains("IS_TTY"),
        "child stdout is a tty: {}",
        r.output
    );
}

/// Signal forwarding: killing the wrapper forwards the signal to the child and
/// reaps it, instead of orphaning it with secrets still in its environ. The old
/// code had no handler, so `kill <s-pid>` orphaned the sleep.
#[test]
fn forwards_signal_and_reaps_child() {
    let f = Fixture::inited();
    let s_bin = env!("CARGO_BIN_EXE_s");
    // `exec sleep` keeps the pid stable so childpid identifies the process s
    // manages; SIGTERM to s must reach it, not leave it running.
    let script = format!(
        "{s_bin} -- sh -c 'echo $$ > childpid; exec sleep 30' & \n\
         SPID=$!\n\
         sleep 0.3\n\
         kill -TERM $SPID\n\
         wait $SPID; echo \"exit=$?\"\n\
         sleep 0.2\n\
         CPID=$(cat childpid 2>/dev/null)\n\
         if [ -n \"$CPID\" ] && kill -0 \"$CPID\" 2>/dev/null; then\n\
           echo ORPHAN; kill \"$CPID\" 2>/dev/null\n\
         else\n\
           echo NOORPHAN\n\
         fi"
    );
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(&script)
        .env("S_KEY", PW)
        .env("S_FILE", f.path(".senv"))
        .current_dir(f.dir())
        .output()
        .expect("run");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("exit=143"),
        "s forwards SIGTERM and exits 143: {s}"
    );
    assert!(
        s.contains("NOORPHAN"),
        "child was forwarded the signal, not orphaned: {s}"
    );
}
