//! Runs a Node helper script from `crates/zxterm-testkit/js/` against the
//! ZBTerm tree, so Rust test code can call into ZBTerm's JS functions
//! (every later parity test, K2 onward).

use std::env;
use std::path::PathBuf;
use std::process::{Command, Output};

use crate::scratch_home::{self, ScratchHome};

/// This crate's own Node helper scripts directory
/// (`crates/zxterm-testkit/js/`), resolved at compile time so it does not
/// depend on the caller's current directory.
pub fn js_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("js")
}

/// The ZBTerm tree parity tests read, from `ZX_ZBTERM` (`A-5`). By default,
/// the ZBTerm checkout this repository is a submodule of (`zbterm/zxterm/`),
/// else a `zbterm` checkout next to it (`../zbterm`).
pub fn zbterm_root() -> PathBuf {
    if let Some(dir) = env::var_os("ZX_ZBTERM") {
        return PathBuf::from(dir);
    }
    let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    if parent.join("engine").is_dir() {
        parent
    } else {
        parent.join("zbterm")
    }
}

/// The helper scripts whose ZBTerm JS is the Freenet backend's former JS
/// implementation (the contract client, `route.js`/`signal.js`,
/// `electron/rtc-host.js`), which K11 removed from ZBTerm's live tree when
/// its Freenet backend became a proxy to this core. They run against
/// [`reference_root`] instead, and need the npm packages
/// [`FREENET_REFERENCE_PACKAGES`] names from that tree's own `node_modules`
/// (ZBTerm no longer installs them); a test that runs one checks
/// [`freenet_reference_skip`] first and skips, naming
/// `scripts/prepare-js-reference.sh`, only while the tree is not prepared.
/// `ZX_ZBTERM_LIVE` names the live tree for what the reference predates
/// (the seam codec, `engine/zxterm/codec.js`).
pub const FREENET_REFERENCE_SCRIPTS: &[&str] = &[
    "freenet_fixtures.js",
    "freenet_node_get_verify.js",
    "freenet_node_mint_put.js",
    "freenet_backend_peer.js",
    "freenet_hypercore_smoke.js",
    "rtc_peer.js",
];

/// The npm packages the Freenet reference JS loads that K11 removed from
/// ZBTerm (`@freenetorg/freenet-stdlib`, `node-datachannel`, `bs58`).
pub const FREENET_REFERENCE_PACKAGES: &[&str] =
    &["bs58", "@freenetorg/freenet-stdlib", "node-datachannel"];

/// Why [`FREENET_REFERENCE_SCRIPTS`] cannot run here, or `None` when they
/// can: the reference tree cannot be built, or its `node_modules` (ZBTerm's
/// own, linked) lacks one of `packages`.
pub fn reference_missing(packages: &[&str]) -> Option<String> {
    let root = match reference_root() {
        Ok(root) => root,
        Err(e) => return Some(e),
    };
    for package in packages {
        if !root
            .join("node_modules")
            .join(package)
            .join("package.json")
            .is_file()
        {
            return Some(format!(
                "the prepared JS reference lacks `{package}`: rerun \
                 scripts/prepare-js-reference.sh"
            ));
        }
    }
    None
}

/// Why a test that runs [`FREENET_REFERENCE_SCRIPTS`] must skip here: no
/// `node` on `PATH`, or [`reference_missing`] for
/// [`FREENET_REFERENCE_PACKAGES`]. `None` when it can run.
pub fn freenet_reference_skip() -> Option<String> {
    crate::require_tool("node").or_else(|| reference_missing(FREENET_REFERENCE_PACKAGES))
}

/// A `node <js_dir>/<script> <args...>` command with `ZX_ZBTERM` set in its
/// environment: the live ZBTerm tree, or [`reference_root`] for one of
/// [`FREENET_REFERENCE_SCRIPTS`]. Callers that also need a scratch `HOME`
/// apply one with `scratch_home::apply_env` (see `run_with_home`) — this
/// never touches the calling process's own environment.
pub fn command(script: &str, args: &[&str]) -> Command {
    let path = js_dir().join(script);
    let root = if FREENET_REFERENCE_SCRIPTS.contains(&script) {
        reference_root().unwrap_or_else(|_| zbterm_root())
    } else {
        zbterm_root()
    };
    let mut cmd = Command::new("node");
    cmd.arg(&path)
        .args(args)
        .env("ZX_ZBTERM", root)
        .env("ZX_ZBTERM_LIVE", zbterm_root());
    cmd
}

/// Runs `node <js_dir>/<script> <args...>` with `ZX_ZBTERM` set in its
/// environment, and returns the captured output.
pub fn run(script: &str, args: &[&str]) -> std::io::Result<Output> {
    command(script, args).output()
}

/// The ZBTerm revision whose JS is the reference for the identity parity
/// suites (`A-5`): the last one whose identity code was ZBTerm's own. From
/// K9 on, ZBTerm's `engine/identity/*.js` are thin call-throughs to this very
/// core and `electron/ssh-keys.js`/`github-keys.js` are gone, so a parity
/// test against the live tree would compare the core with itself.
/// `ZX_ZBTERM_JS_REF` overrides it.
pub const ZBTERM_JS_REFERENCE_REV: &str = "bf5cdbd26f9a360b5c077301c336fdad908d6122";

/// The prepared copy of ZBTerm's JS at [`ZBTERM_JS_REFERENCE_REV`] (or
/// `ZX_ZBTERM_JS_REF`): `engine/`, `electron/` and the manifests taken with
/// `git archive`, with that revision's own `node_modules` installed by
/// `npm ci` from its own lockfile. `scripts/prepare-js-reference.sh` makes
/// it, in this repository's `target/js-reference/<rev>/`
/// (`ZX_JS_REFERENCE_DIR` overrides the parent directory); tests never
/// build or install it themselves (K11, `X-20`). `Err` says the tree is not
/// prepared and names the script, which callers print as a skip reason.
pub fn reference_root() -> Result<PathBuf, String> {
    let rev = env::var("ZX_ZBTERM_JS_REF").unwrap_or_else(|_| ZBTERM_JS_REFERENCE_REV.into());
    let parent = env::var("ZX_JS_REFERENCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/js-reference")
        });
    let dest = parent.join(&rev);
    if dest.join(".complete").is_file() && dest.join("node_modules").is_dir() {
        Ok(dest)
    } else {
        Err(format!(
            "ZBTerm's JS reference {rev} is not prepared at {}: run scripts/prepare-js-reference.sh",
            dest.display()
        ))
    }
}

/// Like `run`, but against [`reference_root`]: `ZX_ZBTERM` in the child
/// names the reference copy instead of the live tree.
pub fn run_reference(
    script: &str,
    args: &[&str],
    home: Option<&ScratchHome>,
) -> std::io::Result<Output> {
    let reference = reference_root().map_err(std::io::Error::other)?;
    let mut cmd = command(script, args);
    cmd.env("ZX_ZBTERM", reference);
    if let Some(home) = home {
        scratch_home::apply_env(&mut cmd, &home.env());
    }
    cmd.output()
}

/// Like `run`, but also applies `home`'s scratch `HOME`/`TMPDIR`/
/// `SSH_AUTH_SOCK` to the child Node process — never to this process's own
/// environment (`ScratchHome`'s whole point).
pub fn run_with_home(script: &str, args: &[&str], home: &ScratchHome) -> std::io::Result<Output> {
    let mut cmd = command(script, args);
    scratch_home::apply_env(&mut cmd, &home.env());
    cmd.output()
}

/// Like `run`, but pipes `stdin_data` to the child's stdin before reading
/// its output — the calling convention K5's `freenet_fixtures.js` (and any
/// later JSON-in/JSON-out helper script) uses instead of argv, since a
/// route or an entry does not fit comfortably on a command line.
pub fn run_with_stdin(script: &str, args: &[&str], stdin_data: &[u8]) -> std::io::Result<Output> {
    use std::io::Write;
    use std::process::Stdio;

    let mut cmd = command(script, args);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(stdin_data)?;
    child.wait_with_output()
}

/// A long-running Node helper process driven over newline-delimited JSON on
/// stdin/stdout (K6's `js/rtc_peer.js` and any later JSON-in/JSON-out
/// helper that must stay alive across several calls, unlike `run_with_stdin`'s
/// one-shot pipe). Each line written is one JSON value in; each line read
/// back is one JSON value out. `stderr` is drained on a background thread
/// into a buffer `stderr_text()` can read at any time (a helper script that
/// panics leaves its stack trace there, not silently lost).
pub struct LineChild {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    lines_rx: std::sync::mpsc::Receiver<String>,
    stderr_buf: std::sync::Arc<std::sync::Mutex<String>>,
}

impl LineChild {
    /// Spawns `node <js_dir>/<script> <args...>` with `ZX_ZBTERM` set and
    /// `home`'s scratch environment applied to the child only.
    pub fn spawn(script: &str, args: &[&str], home: &ScratchHome) -> std::io::Result<LineChild> {
        use std::io::{BufRead, Read};
        use std::process::Stdio;

        let mut cmd = command(script, args);
        scratch_home::apply_env(&mut cmd, &home.env());
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        let mut child = cmd.spawn()?;
        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");
        let mut stderr = child.stderr.take().expect("stderr was piped");

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // Split on raw bytes and decode lossily, rather than
            // `BufRead::lines()` (which decodes strict UTF-8 and yields
            // `Err` — permanently ending this thread's `for` loop — the
            // moment any single line is not valid UTF-8): a dependency's
            // native code (e.g. a WebRTC library's own C++ logging) can
            // write straight to fd 1, bypassing the child's own
            // newline-JSON protocol entirely, and one such line must not
            // take down every later line with it.
            let mut reader = std::io::BufReader::new(stdout);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                match reader.read_until(b'\n', &mut buf) {
                    Ok(0) => break,
                    Ok(_) => {
                        if buf.last() == Some(&b'\n') {
                            buf.pop();
                        }
                        let line = String::from_utf8_lossy(&buf).into_owned();
                        if tx.send(line).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let stderr_buf = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let stderr_buf_writer = stderr_buf.clone();
        std::thread::spawn(move || {
            // Appended incrementally (never `read_to_string`, which would
            // only return — and only then update the buffer — once the
            // child's stderr closes): `stderr_text()` must show what a
            // *still-running* child has written so far, not just a dead
            // one's.
            let mut chunk = [0u8; 4096];
            loop {
                match stderr.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Ok(mut guard) = stderr_buf_writer.lock() {
                            guard.push_str(&String::from_utf8_lossy(&chunk[..n]));
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(LineChild {
            child,
            stdin,
            lines_rx: rx,
            stderr_buf,
        })
    }

    /// Writes one JSON value as a single line to the child's stdin.
    pub fn send_json(&mut self, value: &serde_json::Value) -> std::io::Result<()> {
        use std::io::Write;
        let mut line = serde_json::to_string(value).expect("value must serialize to JSON");
        line.push('\n');
        self.stdin.write_all(line.as_bytes())?;
        self.stdin.flush()
    }

    /// Waits up to `timeout` for the next JSON line the child writes to
    /// stdout. `None` on timeout, or if the child's stdout closed and
    /// every buffered line has already been returned. A line that does
    /// not parse as JSON (some dependency's native code writing straight
    /// to fd 1, bypassing the child's own newline-JSON protocol) is
    /// skipped rather than treated as "no line arrived" — this call keeps
    /// reading within what remains of `timeout` until it finds a JSON
    /// line, the deadline passes, or the channel disconnects.
    pub fn recv_json(&self, timeout: std::time::Duration) -> Option<serde_json::Value> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let line = self.lines_rx.recv_timeout(remaining).ok()?;
            if let Ok(v) = serde_json::from_str(&line) {
                return Some(v);
            }
        }
    }

    /// The child's stderr collected so far (readable even before the child
    /// exits, though it may still be growing).
    pub fn stderr_text(&self) -> String {
        self.stderr_buf
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// The child's exit status, if it has already exited (never blocks).
    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    /// Terminates the child (`SIGKILL` via `Child::kill`, on the exact
    /// `Child` handle this call spawned) and waits for it to exit.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for LineChild {
    fn drop(&mut self) {
        self.kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::require_tool;

    #[test]
    fn runs_a_node_script() {
        if let Some(reason) = require_tool("node") {
            println!("SKIP runs_a_node_script: {reason}");
            return;
        }
        let output = run("ping.js", &[]).expect("spawn node");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("pong"), "stdout: {stdout}");
    }

    #[test]
    fn runs_a_node_script_with_a_scratch_home_applied_to_the_child_only() {
        if let Some(reason) = require_tool("node") {
            println!(
                "SKIP runs_a_node_script_with_a_scratch_home_applied_to_the_child_only: {reason}"
            );
            return;
        }
        let prior_home = env::var_os("HOME");
        let scratch = ScratchHome::new().expect("create scratch home");

        let output = run_with_home("ping.js", &[], &scratch).expect("spawn node with scratch home");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(&scratch.path().to_string_lossy().to_string()),
            "stdout: {stdout}"
        );

        // This process's own HOME must be untouched.
        assert_eq!(env::var_os("HOME"), prior_home);
    }

    #[test]
    fn line_child_sends_and_receives_json_lines() {
        if let Some(reason) = require_tool("node") {
            println!("SKIP line_child_sends_and_receives_json_lines: {reason}");
            return;
        }
        let home = ScratchHome::new().expect("create scratch home");
        let mut child = LineChild::spawn("line_echo.js", &[], &home).expect("spawn line_echo.js");
        child
            .send_json(&serde_json::json!({"a": 1}))
            .expect("send first line");
        let reply = child
            .recv_json(std::time::Duration::from_secs(5))
            .expect("first reply");
        assert_eq!(reply, serde_json::json!({"echo": {"a": 1}}));

        child
            .send_json(&serde_json::json!({"b": 2}))
            .expect("send second line");
        let reply2 = child
            .recv_json(std::time::Duration::from_secs(5))
            .expect("second reply");
        assert_eq!(reply2, serde_json::json!({"echo": {"b": 2}}));
        assert!(
            child
                .recv_json(std::time::Duration::from_millis(200))
                .is_none(),
            "no third line queued"
        );
    }
}
