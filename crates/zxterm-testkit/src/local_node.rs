//! Rust twin of ZBTerm `test/helpers/freenet-node.js::startLocalNode`: a
//! throwaway local-mode Freenet node for tests. Each node gets its own
//! WebSocket port (never 7509 — the owner's node) and its own
//! `config`/`data`/`log` directories, and is stopped by the exact pid this
//! helper spawned, never by pattern. Tests that need `freenet` should skip
//! (via `freenet_available`/`require_tool`) when the binary is absent.

use std::fs;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::scratch_home::{self, ScratchHome};

const BINARY: &str = "freenet";
/// The owner's own node runs in network mode on this port; never touched.
pub const OWNER_PORT: u16 = 7509;
/// Matches ZBTerm `test/helpers/freenet-node.js::READY_TIMEOUT_MS`.
pub const READY_TIMEOUT: Duration = Duration::from_millis(30_000);

/// True if the `freenet` binary is on `PATH`.
pub fn freenet_available() -> bool {
    find_binary().is_some()
}

fn find_binary() -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(BINARY);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// A port nothing listens on right now (racy, like the JS helper's
/// `freePort()`, which this mirrors).
pub fn free_port() -> io::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.local_addr().map(|a| a.port())
}

fn can_connect(port: u16) -> bool {
    TcpStream::connect(("127.0.0.1", port)).is_ok()
}

fn mktemp_node_dir() -> io::Result<PathBuf> {
    let base = std::env::temp_dir();
    let pid = std::process::id();
    for attempt in 0u32..1000 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = base.join(format!(
            "zxterm-freenet-node-{:x}{:x}{attempt:x}",
            pid, nanos as u32
        ));
        match fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other(
        "could not create a unique freenet node scratch dir",
    ))
}

/// A throwaway `freenet local` process. Dropping it stops the process (by
/// its own pid) and removes its scratch directory, same as `stop()`.
#[derive(Debug)]
pub struct LocalNode {
    pub port: u16,
    pub pid: u32,
    pub dir: PathBuf,
    pub url: String,
    child: Option<Child>,
    stopped: bool,
}

impl LocalNode {
    /// Starts a node on a freshly chosen free port.
    pub fn start() -> io::Result<LocalNode> {
        Self::start_with(None, None)
    }

    /// Starts a node on `port`, or a freshly chosen free port if `None`.
    pub fn start_on_port(port: Option<u16>) -> io::Result<LocalNode> {
        Self::start_with(port, None)
    }

    /// Starts a node on a freshly chosen free port, with `home`'s scratch
    /// `HOME`/`TMPDIR`/`SSH_AUTH_SOCK` applied to the spawned `freenet`
    /// process only (never to this process's own environment — see
    /// `ScratchHome`).
    pub fn start_with_home(home: &ScratchHome) -> io::Result<LocalNode> {
        Self::start_with(None, Some(home))
    }

    fn start_with(port: Option<u16>, home: Option<&ScratchHome>) -> io::Result<LocalNode> {
        let binary = find_binary()
            .ok_or_else(|| io::Error::other(format!("{BINARY} binary not on PATH")))?;
        let port = match port {
            Some(p) => p,
            None => free_port()?,
        };
        if port == OWNER_PORT {
            return Err(io::Error::other("port 7509 belongs to the owner node"));
        }

        let dir = mktemp_node_dir()?;
        for sub in ["config", "data", "log"] {
            fs::create_dir_all(dir.join(sub))?;
        }

        // The node runs under a tiny `sh` watchdog: it stops the node when
        // this test process disappears without running `Drop` (an abort from
        // a stack overflow, SIGKILL from a timeout), which used to leave
        // orphaned `freenet local` processes and scratch directories behind.
        // Only the node this shell started is ever signalled.
        const WATCHDOG: &str = r#"p=$PPID; b=$1; shift
"$b" "$@" & c=$!
trap 'kill $c 2>/dev/null; wait $c 2>/dev/null; exit 0' TERM INT
while kill -0 $p 2>/dev/null && kill -0 $c 2>/dev/null; do sleep 1; done
kill $c 2>/dev/null; wait $c 2>/dev/null; exit 0"#;
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(WATCHDOG)
            .arg("zxterm-node-watchdog")
            .arg(&binary)
            .arg("local")
            .arg("--ws-api-port")
            .arg(port.to_string())
            .arg("--config-dir")
            .arg(dir.join("config"))
            .arg("--data-dir")
            .arg(dir.join("data"))
            .arg("--log-dir")
            .arg(dir.join("log"))
            .arg("--disable-auto-update")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(home) = home {
            scratch_home::apply_env(&mut command, &home.env());
        }
        let child = command.spawn()?;
        let pid = child.id();

        let mut node = LocalNode {
            port,
            pid,
            dir,
            url: format!("ws://127.0.0.1:{port}/v1/contract/command"),
            child: Some(child),
            stopped: false,
        };

        if let Err(e) = node.wait_ready() {
            let _ = node.stop();
            return Err(e);
        }
        Ok(node)
    }

    fn wait_ready(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            if let Some(status) = self
                .child
                .as_mut()
                .expect("child present while starting")
                .try_wait()?
            {
                return Err(io::Error::other(format!(
                    "{BINARY} local exited before port {} opened (status: {status})",
                    self.port
                )));
            }
            if can_connect(self.port) {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(io::Error::other(format!(
                    "{BINARY} local did not open port {} within {:?}",
                    self.port, READY_TIMEOUT
                )));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// True if `cmdline` for `self.pid` still carries this node's scratch
    /// directory — a defensive check before ever signalling a pid, so a
    /// pid the OS has already recycled for something else is never touched.
    fn pid_is_still_ours(&self) -> bool {
        let cmdline = match fs::read(format!("/proc/{}/cmdline", self.pid)) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let text = String::from_utf8_lossy(&cmdline);
        text.contains(&*self.dir.to_string_lossy())
    }

    /// Stops the node by the exact pid this call spawned (SIGTERM, then
    /// SIGKILL after a grace period if it has not exited), and removes its
    /// scratch directory. Idempotent.
    pub fn stop(&mut self) -> io::Result<()> {
        if self.stopped {
            return Ok(());
        }
        self.stopped = true;
        if let Some(mut child) = self.child.take() {
            if child.try_wait()?.is_none() && self.pid_is_still_ours() {
                // `Child` has no direct SIGTERM; ask the kernel by the pid
                // we hold (verified above), then fall back to `Child::kill`
                // (SIGKILL, on the same `Child` handle) if it lingers.
                let _ = Command::new("kill")
                    .arg("-TERM")
                    .arg(self.pid.to_string())
                    .status();
            }
            let deadline = Instant::now() + Duration::from_millis(5000);
            loop {
                if child.try_wait()?.is_some() {
                    break;
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        let _ = fs::remove_dir_all(&self.dir);
        Ok(())
    }

    /// The node's scratch directory root (`dir/{config,data,log}`).
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl Drop for LocalNode {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_port_is_never_the_owner_port() {
        for _ in 0..20 {
            let port = free_port().expect("free port");
            assert_ne!(port, OWNER_PORT);
        }
    }

    #[test]
    fn start_on_owner_port_is_refused() {
        if !freenet_available() {
            println!("SKIP start_on_owner_port_is_refused: freenet binary not on PATH");
            return;
        }
        let err = LocalNode::start_on_port(Some(OWNER_PORT)).expect_err("must refuse port 7509");
        assert!(err.to_string().contains("7509"));
    }

    #[test]
    fn start_with_home_applies_the_scratch_home_to_the_child_only() {
        if !freenet_available() {
            println!(
                "SKIP start_with_home_applies_the_scratch_home_to_the_child_only: freenet binary not on PATH"
            );
            return;
        }
        let prior_home = std::env::var_os("HOME");
        let home = ScratchHome::new().expect("create scratch home");

        let mut node = LocalNode::start_with_home(&home)
            .expect("start a local freenet node with a scratch home");
        assert_ne!(node.port, OWNER_PORT);
        node.stop().expect("stop the local freenet node");

        // This process's own HOME must be untouched by starting a node with
        // a scratch home applied to its child process.
        assert_eq!(std::env::var_os("HOME"), prior_home);
    }

    fn alive(pid: u32) -> bool {
        fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|c| !c.is_empty())
    }

    #[test]
    fn a_panic_unwinding_past_the_node_still_stops_it() {
        if !freenet_available() {
            println!(
                "SKIP a_panic_unwinding_past_the_node_still_stops_it: freenet binary not on PATH"
            );
            return;
        }
        let node = LocalNode::start().expect("start a local freenet node");
        let (pid, dir) = (node.pid, node.dir.clone());
        assert!(alive(pid));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _node = node;
            panic!("test panic with a live node");
        }));
        assert!(result.is_err());
        assert!(!alive(pid), "node pid {pid} outlived a panic");
        assert!(!dir.exists(), "scratch dir survived a panic");
    }
}
