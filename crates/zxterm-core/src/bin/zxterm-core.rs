//! `zxterm-core` binary entry point. K1 gave it `--version`; K7 (the seam,
//! spike S3) adds two subcommands: `sidecar --profile <dir>` (the
//! long-running process ZBTerm's Bare worker spawns) and
//! `ctl --profile <dir> <method> [json-args]` (a one-shot JSON-mirror
//! client: connects to the running sidecar's socket, sends one request,
//! prints the reply as JSON, exits). Later phases (K18) grow this into
//! `zxterm-core serve`.

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use zxterm_core::seam;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("zxterm-core {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    match args.first().map(String::as_str) {
        Some("sidecar") => sidecar_main(&args[1..]),
        Some("ctl") => ctl_main(&args[1..]),
        _ => {
            eprintln!("zxterm-core: no subcommand yet (try --version, sidecar, ctl)");
            ExitCode::FAILURE
        }
    }
}

/// Pulls `--profile <dir>` out of `args`, wherever it appears; returns the
/// profile path plus every other argument, in order.
fn take_profile_flag(args: &[String]) -> Result<(PathBuf, Vec<String>), String> {
    let mut profile: Option<PathBuf> = None;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--profile" {
            let value = args
                .get(i + 1)
                .ok_or_else(|| "--profile needs a directory argument".to_string())?;
            profile = Some(PathBuf::from(value));
            i += 2;
        } else {
            rest.push(args[i].clone());
            i += 1;
        }
    }
    let profile = profile.ok_or_else(|| "--profile <dir> is required".to_string())?;
    Ok((profile, rest))
}

/// `--exit-on-stdin-eof` (K9): exit as soon as stdin reaches end of file.
/// ZBTerm spawns the sidecar with a stdin pipe it never writes to, so the
/// pipe closes exactly when the spawning process goes away — however it
/// goes away (a crash included). The sidecar then exits with it instead of
/// outliving it and holding the profile lock.
fn watch_stdin_eof() {
    std::thread::spawn(|| {
        let mut sink = [0u8; 256];
        let mut stdin = std::io::stdin();
        loop {
            match std::io::Read::read(&mut stdin, &mut sink) {
                Ok(0) | Err(_) => std::process::exit(0),
                Ok(_) => {}
            }
        }
    });
}

fn sidecar_main(args: &[String]) -> ExitCode {
    let (profile, rest) = match take_profile_flag(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("zxterm-core sidecar: {e}");
            return ExitCode::FAILURE;
        }
    };
    if rest.iter().any(|a| a == "--exit-on-stdin-eof") {
        watch_stdin_eof();
    }

    // Profile ownership: acquire the exclusive lock before touching the
    // socket at all. A second `sidecar --profile <dir>` on the same
    // directory detects the lock is held and refuses to start a second
    // owner (never corrupts or duplicates the socket) — this phase's
    // Acceptance criteria.
    let lock = match seam::try_acquire_profile_lock(&profile) {
        Ok(seam::LockOutcome::Acquired(guard)) => guard,
        Ok(seam::LockOutcome::Held) => {
            eprintln!(
                "zxterm-core sidecar: profile {} is already owned by a running sidecar (lock held)",
                profile.display()
            );
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("zxterm-core sidecar: cannot acquire the profile lock: {e}");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("zxterm-core sidecar: cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result: std::io::Result<()> = runtime.block_on(async {
        let listener = bind_socket_for_platform(&profile)?;
        println!(
            "zxterm-core sidecar: profile {} listening on {}",
            profile.display(),
            seam::socket_path(&profile).display()
        );
        let dispatcher = std::sync::Arc::new(seam::Dispatcher::new(profile.clone()));
        seam::serve(listener, dispatcher).await;
        Ok(())
    });

    // Holds the lock for the process's whole lifetime; explicit for
    // clarity at the point the process is about to exit.
    drop(lock);

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("zxterm-core sidecar: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
fn bind_socket_for_platform(profile: &Path) -> std::io::Result<tokio::net::UnixListener> {
    seam::bind_socket(profile)
}

#[cfg(windows)]
fn bind_socket_for_platform(_profile: &Path) -> std::io::Result<std::convert::Infallible> {
    // K0 found no Windows target installed on this machine: this path is
    // written to the shape the design calls for (a named pipe behind
    // `#[cfg(windows)]`) but never compile-checked here — see this phase's
    // Handoff notes. A later phase building on Windows implements the named
    // pipe listener in `seam::server` and returns it here.
    Err(std::io::Error::other(
        "zxterm-core sidecar: Windows named-pipe support is not implemented yet",
    ))
}

fn ctl_main(args: &[String]) -> ExitCode {
    let (profile, rest) = match take_profile_flag(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("zxterm-core ctl: {e}");
            return ExitCode::FAILURE;
        }
    };
    let Some(method) = rest.first() else {
        eprintln!(
            "zxterm-core ctl: a method name is required (zxterm-core ctl --profile <dir> <method> [json-args])"
        );
        return ExitCode::FAILURE;
    };
    let json_args = rest.get(1).cloned().unwrap_or_else(|| "{}".to_string());

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("zxterm-core ctl: cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    runtime.block_on(run_ctl_call(&profile, method, &json_args))
}

/// One request/reply round trip against a running sidecar. Never hangs: a
/// missing socket fails immediately, and both the connect and the reply
/// wait are bounded.
async fn run_ctl_call(profile: &Path, method: &str, json_args: &str) -> ExitCode {
    let socket = seam::socket_path(profile);
    let connect = tokio::net::UnixStream::connect(&socket);
    let stream = match tokio::time::timeout(Duration::from_secs(5), connect).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            eprintln!(
                "zxterm-core ctl: no sidecar listening at {} ({e})",
                socket.display()
            );
            return ExitCode::FAILURE;
        }
        Err(_) => {
            eprintln!(
                "zxterm-core ctl: timed out connecting to {}",
                socket.display()
            );
            return ExitCode::FAILURE;
        }
    };

    let (mut read_half, mut write_half) = tokio::io::split(stream);
    let request = seam::Frame::Request {
        id: "1".to_string(),
        method: method.to_string(),
        args: json_args.to_string(),
    };
    if let Err(e) = seam::write_frame(&mut write_half, &request).await {
        eprintln!("zxterm-core ctl: failed to send the request: {e}");
        return ExitCode::FAILURE;
    }

    // A method like `test.flood` sends `Output`/`Event` frames before its
    // `Reply` — `ctl` is a one-shot JSON-mirror client for the *reply*, so
    // it drains and ignores those (printing a short marker to stderr, since
    // a caller watching interactively may want to know something is
    // streaming) rather than treating the first non-`Reply` frame as an
    // error. The whole wait is still bounded: never a hang.
    let reply = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match seam::read_frame(&mut read_half).await {
                Ok(Some(seam::Frame::Reply { ok, .. })) => return Ok(Some(ok)),
                Ok(Some(seam::Frame::Output { stream, bytes })) => {
                    eprintln!(
                        "zxterm-core ctl: (Output on {stream}, {} bytes)",
                        bytes.len()
                    );
                }
                Ok(Some(seam::Frame::Event { name, .. })) => {
                    eprintln!("zxterm-core ctl: (Event {name})");
                }
                Ok(Some(seam::Frame::Chan { chan, bytes })) => {
                    eprintln!("zxterm-core ctl: (Chan {chan}, {} bytes)", bytes.len());
                }
                Ok(Some(seam::Frame::Request { .. })) => {
                    // A sidecar never sends this; ignore rather than fail.
                }
                Ok(None) => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    })
    .await;
    match reply {
        Ok(Ok(Some(ok))) => match ok {
            Ok(value) => {
                println!("{value}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!(
                    "{}",
                    serde_json::json!({"code": err.code, "message": err.message})
                );
                ExitCode::FAILURE
            }
        },
        Ok(Ok(None)) => {
            eprintln!("zxterm-core ctl: the sidecar closed the connection with no reply");
            ExitCode::FAILURE
        }
        Ok(Err(e)) => {
            eprintln!("zxterm-core ctl: read error: {e}");
            ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("zxterm-core ctl: timed out waiting for a reply");
            ExitCode::FAILURE
        }
    }
}
