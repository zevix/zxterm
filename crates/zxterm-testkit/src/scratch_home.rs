//! A scratch `HOME`/`TMPDIR` for a test, under a short path (the 108-byte
//! Unix-socket path limit breaks the SSH-agent tests if `TMPDIR` is long).
//!
//! `ScratchHome` never touches this process's own environment. Cargo runs a
//! binary's `#[test]` functions on parallel threads, so mutating process-global
//! `HOME`/`TMPDIR`/`SSH_AUTH_SOCK` from one instance would race every other
//! test in the same binary (this is exactly why `std::env::set_var` is
//! `unsafe` as of this edition). Instead, `env()`/`command()` hand the
//! scratch values to a *child* process only — Rust code under test takes
//! `home`/`env` explicitly (mirroring ZBTerm's own `listCandidates({home,
//! env})` shape), so no test ever needs to change the process environment.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// A scratch directory standing in for a test's `HOME`, plus the values a
/// child process run against it should see for `HOME`, `TMPDIR` and
/// `SSH_AUTH_SOCK`. Removes the directory on `Drop`.
pub struct ScratchHome {
    dir: PathBuf,
    agent_sock: Option<OsString>,
}

impl ScratchHome {
    /// Creates a fresh short scratch directory under `/tmp/zx.*`.
    pub fn new() -> io::Result<Self> {
        let dir = create_scratch_dir()?;
        Ok(ScratchHome {
            dir,
            agent_sock: None,
        })
    }

    /// Builder: a child run against this scratch home sees `SSH_AUTH_SOCK`
    /// set to `path`, instead of the default (cleared, so the real
    /// environment's agent socket never leaks into a test that does not
    /// ask for one).
    pub fn with_agent_sock(mut self, path: impl Into<OsString>) -> Self {
        self.agent_sock = Some(path.into());
        self
    }

    /// The scratch directory this instance created.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// The `HOME` value a child process run against this scratch home
    /// should see (same directory as `path()`/`tmp()`).
    pub fn home(&self) -> &Path {
        &self.dir
    }

    /// The `TMPDIR` value a child process run against this scratch home
    /// should see (same directory as `path()`/`home()`).
    pub fn tmp(&self) -> &Path {
        &self.dir
    }

    /// The environment a child process should run with: `HOME` and
    /// `TMPDIR` set to this scratch directory, and `SSH_AUTH_SOCK` removed
    /// (`None`) unless `with_agent_sock` set one. Never applied to this
    /// process's own environment — callers apply it to a `Command` (see
    /// `command()`) or to whatever they spawn themselves.
    pub fn env(&self) -> Vec<(OsString, Option<OsString>)> {
        let dir = self.dir.clone().into_os_string();
        vec![
            (OsString::from("HOME"), Some(dir.clone())),
            (OsString::from("TMPDIR"), Some(dir)),
            (OsString::from("SSH_AUTH_SOCK"), self.agent_sock.clone()),
        ]
    }

    /// A `Command` for `program` with this scratch home's environment
    /// already applied (via `Command::env`/`env_remove`), so the child
    /// process — never this process — sees the scratch `HOME`/`TMPDIR` and
    /// the configured `SSH_AUTH_SOCK`.
    pub fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut cmd = Command::new(program);
        apply_env(&mut cmd, &self.env());
        cmd
    }
}

/// Applies `env` (as `ScratchHome::env()` returns it) to `cmd`: `Some` sets
/// the variable, `None` removes it from the child's inherited environment.
pub fn apply_env(cmd: &mut Command, env: &[(OsString, Option<OsString>)]) {
    for (key, value) in env {
        match value {
            Some(v) => {
                cmd.env(key, v);
            }
            None => {
                cmd.env_remove(key);
            }
        }
    }
}

impl Drop for ScratchHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn create_scratch_dir() -> io::Result<PathBuf> {
    let pid = std::process::id();
    for attempt in 0u32..1000 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        // Thread id folded in too: concurrent callers on different threads
        // of the same process share `pid`, and can land on the same nanos
        // tick, so `create_dir`'s atomicity (retried on `AlreadyExists`) is
        // what actually guarantees uniqueness — this suffix just keeps
        // collisions (and thus retries) rare.
        let thread_tag = format!("{:?}", std::thread::current().id());
        let mixed = nanos as u32 ^ thread_tag.len() as u32;
        let suffix = format!("{:x}{:x}", pid ^ mixed, attempt);
        let path = PathBuf::from(format!("/tmp/zx.{suffix}"));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other(
        "could not create a unique scratch dir under /tmp/zx.* after 1000 tries",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::thread;

    #[test]
    fn creates_a_short_scratch_dir_and_removes_it_on_drop() {
        let path = {
            let scratch = ScratchHome::new().expect("create scratch home");
            let p = scratch.path().to_path_buf();
            assert!(p.starts_with("/tmp"));
            assert!(p.to_str().unwrap().len() < 20, "TMPDIR must stay short");
            assert_eq!(scratch.home(), scratch.path());
            assert_eq!(scratch.tmp(), scratch.path());
            p
        };
        assert!(!path.exists(), "scratch dir must be removed on Drop");
    }

    #[test]
    fn env_sets_home_tmpdir_and_clears_agent_sock_by_default() {
        let scratch = ScratchHome::new().expect("create scratch home");
        let dir = scratch.path().as_os_str().to_owned();
        let env = scratch.env();
        assert_eq!(env.len(), 3);
        assert!(env.contains(&(OsString::from("HOME"), Some(dir.clone()))));
        assert!(env.contains(&(OsString::from("TMPDIR"), Some(dir))));
        assert!(env.contains(&(OsString::from("SSH_AUTH_SOCK"), None)));
    }

    #[test]
    fn with_agent_sock_overrides_the_default_clear() {
        let scratch = ScratchHome::new()
            .expect("create scratch home")
            .with_agent_sock("/tmp/my.sock");
        let env = scratch.env();
        assert!(env.contains(&(
            OsString::from("SSH_AUTH_SOCK"),
            Some(OsString::from("/tmp/my.sock"))
        )));
    }

    /// The red this guards against: two `ScratchHome`s racing on
    /// process-global `HOME`/`TMPDIR` would make every later parity test
    /// (K2-K4) flaky. This instance never touches the process environment,
    /// so running two concurrently must leave the process's own `HOME`
    /// alone and give each spawned child exactly its own scratch `HOME`.
    #[test]
    fn concurrent_scratch_homes_never_touch_the_process_environment() {
        let prior_home = env::var_os("HOME");

        let handles: Vec<_> = (0..2)
            .map(|_| {
                thread::spawn(|| {
                    let scratch = ScratchHome::new().expect("create scratch home");
                    let output = scratch
                        .command("sh")
                        .arg("-c")
                        .arg("echo $HOME")
                        .output()
                        .expect("run child under scratch home");
                    assert!(output.status.success());
                    let seen = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    (scratch.path().to_path_buf(), seen)
                })
            })
            .collect();

        let results: Vec<(PathBuf, String)> = handles
            .into_iter()
            .map(|h| h.join().expect("thread panicked"))
            .collect();

        // The process's own HOME must be untouched by either thread, the
        // whole time both scratch homes were live.
        assert_eq!(env::var_os("HOME"), prior_home);

        // Each child saw its own scratch home (not the ambient HOME, and
        // not the other thread's), and the two scratch homes are distinct.
        for (expected_path, seen) in &results {
            assert_eq!(seen, &expected_path.to_string_lossy().to_string());
        }
        assert_ne!(results[0].0, results[1].0);
    }
}
