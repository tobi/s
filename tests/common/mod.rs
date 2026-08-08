// Shared harness for the integration tests.
//
// Everything runs the real `s` binary in a throwaway directory. Most of the
// behaviour under test is process-level — exit codes, signals, pipes, PTYs, git
// integration — and none of that is reachable from an in-process unit test.
//
// Isolation matters more than usual here: `s` reads $S_FILE, $S_KEY, $HOME and
// $XDG_CONFIG_HOME, and shells out to git. A developer's own global store or a
// global `core.hooksPath` would otherwise leak into the results.

#![allow(dead_code)] // each test file uses a subset

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::prelude::*;
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, ChaCha20Poly1305, Key, Nonce};
use std::time::{Duration, Instant};

pub const PW: &str = "test-password";
pub const BIN: &str = env!("CARGO_BIN_EXE_s");

pub struct Fixture {
    tmp: tempfile::TempDir,
}

pub struct Run {
    pub code: i32,
    pub signal: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

pub struct PtyRun {
    pub code: i32,
    pub output: String,
}

impl Run {
    /// Assert success. Borrows so the fields stay usable for further assertions.
    pub fn ok(&self) -> &Run {
        assert!(
            self.code == 0 && self.signal.is_none(),
            "expected success, got code={} signal={:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.code,
            self.signal,
            self.stdout,
            self.stderr
        );
        self
    }

    pub fn fails(&self) -> &Run {
        assert!(
            self.code != 0 || self.signal.is_some(),
            "expected failure, got success\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.stdout,
            self.stderr
        );
        self
    }

    pub fn out(&self) -> &str {
        &self.stdout
    }

    pub fn all(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

impl Fixture {
    pub fn new() -> Fixture {
        Fixture { tmp: tempfile::tempdir().expect("tempdir") }
    }

    pub fn new_git() -> Fixture {
        let f = Fixture::new();
        f.git(&["init", "-q", "."]).ok();
        f.git(&["config", "user.email", "test@example.com"]).ok();
        f.git(&["config", "user.name", "Test"]).ok();
        f
    }

    pub fn inited() -> Fixture {
        let f = Fixture::new();
        f.s(&["init"]).ok();
        f
    }

    pub fn inited_git() -> Fixture {
        let f = Fixture::new_git();
        f.s(&["init"]).ok();
        f
    }

    pub fn dir(&self) -> &Path {
        self.tmp.path()
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.tmp.path().join(rel)
    }

    pub fn store(&self) -> PathBuf {
        self.path(".senv")
    }

    pub fn write(&self, rel: &str, bytes: impl AsRef<[u8]>) {
        let p = self.path(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, bytes).unwrap_or_else(|e| panic!("writing {}: {e}", p.display()));
    }

    pub fn read(&self, rel: &str) -> Vec<u8> {
        let p = self.path(rel);
        std::fs::read(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
    }

    pub fn read_str(&self, rel: &str) -> String {
        String::from_utf8_lossy(&self.read(rel)).into_owned()
    }

    pub fn exists(&self, rel: &str) -> bool {
        self.path(rel).exists()
    }

    /// Base environment shared by `s` and `git` invocations.
    fn apply_env(&self, c: &mut Command) {
        c.current_dir(self.dir());
        // Pin HOME inside the fixture so the global store resolves to a path
        // that does not exist unless a test creates it.
        c.env("HOME", self.dir());
        c.env_remove("XDG_CONFIG_HOME");
        c.env_remove("S_KEY_COMMAND");
        // A developer's ~/.gitconfig (notably core.hooksPath) must not decide
        // what these tests observe.
        c.env("GIT_CONFIG_GLOBAL", "/dev/null");
        c.env("GIT_CONFIG_SYSTEM", "/dev/null");
        c.env("GIT_TERMINAL_PROMPT", "0");
        c.env("S_FILE", self.store());
        c.env("S_KEY", PW);
    }

    fn finish(out: std::process::Output) -> Run {
        #[cfg(unix)]
        let signal = {
            use std::os::unix::process::ExitStatusExt;
            out.status.signal()
        };
        #[cfg(not(unix))]
        let signal = None;
        Run {
            code: out.status.code().unwrap_or(-1),
            signal,
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    pub fn s(&self, args: &[&str]) -> Run {
        self.s_env(args, &[], None)
    }

    pub fn s_stdin(&self, args: &[&str], stdin: &str) -> Run {
        self.s_env(args, &[], Some(stdin))
    }

    /// Run `s` with extra or overridden environment. A `None` value unsets.
    pub fn s_env(&self, args: &[&str], env: &[(&str, Option<&str>)], stdin: Option<&str>) -> Run {
        let mut c = Command::new(BIN);
        c.args(args);
        self.apply_env(&mut c);
        for (k, v) in env {
            match v {
                Some(v) => c.env(k, v),
                None => c.env_remove(k),
            };
        }
        c.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
        c.stdout(Stdio::piped());
        c.stderr(Stdio::piped());

        let mut child = c.spawn().expect("spawn s");
        if let Some(data) = stdin {
            child.stdin.take().unwrap().write_all(data.as_bytes()).unwrap();
        }
        Fixture::finish(child.wait_with_output().expect("wait s"))
    }

    pub fn git(&self, args: &[&str]) -> Run {
        let mut c = Command::new("git");
        c.args(args);
        self.apply_env(&mut c);
        c.stdin(Stdio::null());
        Fixture::finish(c.output().expect("spawn git"))
    }

    /// `s set KEY --stdin` with `value` piped in. Chains.
    pub fn set(&self, key: &str, value: &str) -> &Self {
        self.s_stdin(&["set", key, "--stdin", "-f"], value).ok();
        self
    }

    /// Install a legacy blob under an arbitrary key. This exercises the
    /// injection denylist while `set` still rejects dangerous names on input.
    pub fn inject_legacy(&self, key: &str, value: &str) {
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut salt).unwrap();
        getrandom::getrandom(&mut nonce).unwrap();
        let params = Params::new(19 * 1024, 2, 1, Some(32)).unwrap();
        let mut derived = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(PW.as_bytes(), &salt, &mut derived)
            .unwrap();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: value.as_bytes(), aad: b"" })
            .unwrap();
        let mut packed = Vec::with_capacity(16 + 12 + ciphertext.len());
        packed.extend_from_slice(&salt);
        packed.extend_from_slice(&nonce);
        packed.extend_from_slice(&ciphertext);
        self.write(".senv", format!("keys:\n  {key}: \"{}\"\n", BASE64_STANDARD.encode(packed)));
    }

    /// Run a shell script with the fixture environment, giving up after
    /// `secs`. `None` means it never finished — which is how a hang is asserted.
    pub fn sh_timeout(&self, script: &str, secs: u64) -> Option<Run> {
        let mut c = Command::new("sh");
        c.args(["-c", script]);
        self.apply_env(&mut c);
        // Scripts invoke `s` by name.
        let path = std::env::var("PATH").unwrap_or_default();
        let bin_dir = Path::new(BIN).parent().unwrap().to_string_lossy().into_owned();
        c.env("PATH", format!("{bin_dir}:{path}"));
        c.stdin(Stdio::null());
        c.stdout(Stdio::piped());
        c.stderr(Stdio::piped());

        let mut child = c.spawn().expect("spawn sh");
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            match child.try_wait().expect("try_wait") {
                Some(_) => break,
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        Some(Fixture::finish(child.wait_with_output().expect("wait sh")))
    }

    /// Run `s` with stdin/stdout/stderr on a real PTY and return everything the
    /// PTY saw. This is the only way to exercise the terminal paths: a child that
    /// writes to `/dev/tty` bypasses ordinary pipes entirely.
    #[cfg(unix)]
    pub fn s_pty(&self, args: &[&str]) -> PtyRun {
        use std::os::fd::FromRawFd;
        use std::os::unix::process::CommandExt;

        let (master, slave) = open_pty();

        let (stdin_fd, stdout_fd, stderr_fd) = unsafe {
            (dup(slave), dup(slave), dup(slave))
        };
        let mut c = Command::new(BIN);
        c.args(args);
        self.apply_env(&mut c);
        unsafe {
            c.stdin(Stdio::from_raw_fd(stdin_fd));
            c.stdout(Stdio::from_raw_fd(stdout_fd));
            c.stderr(Stdio::from_raw_fd(stderr_fd));
            // New session with the slave as controlling terminal, so the child
            // is a genuine foreground terminal job.
            c.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut child = c.spawn().expect("spawn s on pty");
        // Command retains the Stdio owners until it is dropped; dropping it
        // closes the parent copies without risking a double-close.
        drop(c);
        // The parent must drop its own slave handle or the master never sees EOF.
        unsafe { libc::close(slave) };

        let mut out = Vec::new();
        let mut m = unsafe { std::fs::File::from_raw_fd(master) };
        let mut buf = [0u8; 4096];
        loop {
            match m.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                // Linux reports EIO on the master once every slave is closed.
                Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let status = child.wait().expect("wait s on pty");
        PtyRun {
            code: status.code().unwrap_or(-1),
            output: String::from_utf8_lossy(&out).into_owned(),
        }
    }
}

#[cfg(unix)]
unsafe fn dup(fd: i32) -> i32 {
    let n = libc::dup(fd);
    assert!(n >= 0, "dup: {}", std::io::Error::last_os_error());
    n
}

/// posix_openpt/grantpt/unlockpt/ptsname rather than openpty: the latter lives
/// in libutil on glibc and would need an extra link flag.
#[cfg(unix)]
fn open_pty() -> (i32, i32) {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master >= 0, "posix_openpt: {}", std::io::Error::last_os_error());
        assert_eq!(libc::grantpt(master), 0, "grantpt");
        assert_eq!(libc::unlockpt(master), 0, "unlockpt");
        let name = libc::ptsname(master);
        assert!(!name.is_null(), "ptsname");
        let path = std::ffi::CStr::from_ptr(name).to_owned();
        let slave = libc::open(path.as_ptr(), libc::O_RDWR);
        assert!(slave >= 0, "open slave: {}", std::io::Error::last_os_error());
        (master, slave)
    }
}

/// Hand-write a blob into the store so tests can model corruption and
/// foreign-password entries without a second `s` invocation.
pub fn poison_store(path: &Path, key: &str, blob: &str) {
    let raw = std::fs::read_to_string(path).unwrap();
    let mut out = String::new();
    let mut wrote = false;
    for line in raw.lines() {
        out.push_str(line);
        out.push('\n');
        if line.trim() == "keys:" && !wrote {
            out.push_str(&format!("  {key}: \"{blob}\"\n"));
            wrote = true;
        }
    }
    if !wrote {
        out.push_str(&format!("keys:\n  {key}: \"{blob}\"\n"));
    }
    std::fs::write(path, out).unwrap();
}
