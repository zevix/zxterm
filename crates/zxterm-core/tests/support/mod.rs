//! Shared test support for `crates/zxterm-core/tests/ssh_keys_*.rs`: a
//! short-path scratch `.ssh` directory, `ssh-keygen`, and a real `ssh-agent`
//! process this session starts and stops by PID (process safety: killed
//! only after its own `/proc/<pid>/cmdline` is checked to carry the scratch
//! socket path this session picked, never a pattern-based kill).
//!
//! This module is compiled fresh into each `tests/ssh_keys_*.rs` binary
//! (the standard `tests/support/mod.rs` sharing idiom); not every consuming
//! binary uses every helper, so unused-item warnings are expected and
//! silenced here rather than per call site.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

// K3 (identity claims/verification/GitHub): a raw-TCP loopback HTTP server
// for `tests/github_keys_ported.rs`, which needs redirects, non-2xx
// statuses, an oversized body and a stalled response — none of which
// `zxterm_testkit::KeysServer` supports.
mod http_server;
// Not every consuming test binary uses these (only `github_keys_ported.rs`
// does) — same rationale as this module's own `#![allow(dead_code)]`.
#[allow(unused_imports)]
pub use http_server::{RawServer, respond, respond_partial_and_stall};

pub fn require_ssh_keygen() -> Option<String> {
    zxterm_testkit::require_tool("ssh-keygen")
}

/// Creates and returns `home/.ssh`.
pub fn ssh_dir(home: &Path) -> PathBuf {
    let dir = home.join(".ssh");
    std::fs::create_dir_all(&dir).expect("create .ssh dir");
    dir
}

/// `ssh-keygen -q -t <key_type> -N <passphrase> -C <name>@test -f <dir>/<name>`,
/// returning the private-key path (mirrors the JS test file's own `keygen`
/// helper).
pub fn keygen(dir: &Path, name: &str, key_type: &str, passphrase: &str) -> PathBuf {
    let file = dir.join(name);
    let comment = format!("{name}@test");
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", key_type, "-N", passphrase, "-C", &comment, "-f"])
        .arg(&file)
        .status()
        .expect("spawn ssh-keygen");
    assert!(status.success(), "ssh-keygen failed for {name}");
    file
}

/// An empty environment map: no `SSH_AUTH_SOCK`, matching the JS test file's
/// `NO_AGENT = {}` (every test must be blind to the developer's own agent
/// and `~/.ssh`).
pub fn no_agent_env() -> HashMap<String, String> {
    HashMap::new()
}

/// An environment map with `SSH_AUTH_SOCK` pointed at `sock`.
pub fn agent_env(sock: &Path) -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert(
        "SSH_AUTH_SOCK".to_string(),
        sock.to_string_lossy().into_owned(),
    );
    env
}

/// A real `ssh-agent -D -a <sock>` process (foreground, so the spawned PID
/// *is* the agent, no shell-eval output to parse), stopped by PID on `Drop`.
pub struct RealAgent {
    child: Child,
    sock: PathBuf,
}

impl RealAgent {
    /// Starts listening on `sock` (keep this under a short `ScratchHome`
    /// directory: the 108-byte `AF_UNIX` path limit is real).
    pub fn start(sock: &Path) -> std::io::Result<Self> {
        let child = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(sock)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        // Give the agent a moment to create its listening socket before any
        // caller tries to connect.
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        Ok(RealAgent {
            child,
            sock: sock.to_path_buf(),
        })
    }

    /// `ssh-add <path>` against this agent.
    pub fn add(&self, key_path: &Path) {
        let output = Command::new("ssh-add")
            .env("SSH_AUTH_SOCK", &self.sock)
            .arg(key_path)
            .output()
            .expect("spawn ssh-add");
        assert!(
            output.status.success(),
            "ssh-add failed for {}: {}",
            key_path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

impl Drop for RealAgent {
    fn drop(&mut self) {
        // Process safety: only signal a PID this session started, and only
        // after checking its command line carries the scratch socket path
        // this session picked (never a pattern-based kill).
        let pid = self.child.id();
        let cmdline_path = format!("/proc/{pid}/cmdline");
        let sock_str = self.sock.to_string_lossy().into_owned();
        if let Ok(cmdline) = std::fs::read(&cmdline_path) {
            let text = String::from_utf8_lossy(&cmdline);
            if text.contains(sock_str.as_str()) {
                let _ = self.child.kill();
            }
        }
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.sock);
    }
}
