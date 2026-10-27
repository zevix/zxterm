//! Profile ownership (an exclusive lock file) and the sidecar's socket
//! server: accepts multiple client connections, each on its own task,
//! sharing one [`crate::seam::methods::Dispatcher`] (K7 Steps 2-3).

use std::fs;
use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::mpsc;

use super::methods::{ConnCtx, Dispatcher};
use super::protocol::{self, Frame};

/// `<profile>/zxterm-core.lock` — held for the sidecar process's lifetime.
pub fn lock_path(profile: &Path) -> PathBuf {
    profile.join("zxterm-core.lock")
}

/// `<profile>/zxterm-core.sock` on Linux/macOS. Windows uses a named pipe
/// under the same name, behind `#[cfg(windows)]` — K0 found no Windows
/// target installed on this machine, so that path is written but never
/// compile-checked here (see this phase's Handoff notes).
pub fn socket_path(profile: &Path) -> PathBuf {
    profile.join("zxterm-core.sock")
}

/// Holds the profile's exclusive lock for as long as this value lives.
pub struct LockGuard {
    _file: File,
}

/// Whether this process acquired the profile lock.
pub enum LockOutcome {
    Acquired(LockGuard),
    /// Another process already owns this profile.
    Held,
}

/// Tries to acquire `<profile>/zxterm-core.lock` exclusively
/// (`std::fs::File::try_lock`, stable since 1.89 — no new dependency and no
/// unsafe code needed for this). Creates `profile` if it does not exist yet.
pub fn try_acquire_profile_lock(profile: &Path) -> io::Result<LockOutcome> {
    fs::create_dir_all(profile)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path(profile))?;
    match file.try_lock() {
        Ok(()) => Ok(LockOutcome::Acquired(LockGuard { _file: file })),
        Err(TryLockError::WouldBlock) => Ok(LockOutcome::Held),
        Err(TryLockError::Error(e)) => Err(e),
    }
}

/// Removes a stale socket file, if any, then binds a fresh
/// [`tokio::net::UnixListener`] at `<profile>/zxterm-core.sock`. Only ever
/// called by a caller that already holds the profile's lock (see this
/// phase's Step 2): removing the old socket file is safe exactly because no
/// other owner can be listening on it while this process holds the lock.
#[cfg(unix)]
pub fn bind_socket(profile: &Path) -> io::Result<tokio::net::UnixListener> {
    let path = socket_path(profile);
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    tokio::net::UnixListener::bind(&path)
}

/// The outbound queue depth (in frames) before a client counts as
/// "behind" for [`super::backlog::OutputSink`] purposes. Small on purpose:
/// this is a spike proving the drop-to-snapshot mechanism works, not tuning
/// its exact threshold for production traffic (a later phase's real usage
/// may need a different value, per this phase's own Gotchas about
/// `RESYNC_SCROLLBACK`/`RESYNC_TAIL_BYTES` being a design choice, not a
/// spec).
pub const OUTBOUND_QUEUE_DEPTH: usize = 8;

/// Accepts connections on `listener` forever (until the listener errors),
/// each handled on its own task, all sharing `dispatcher`.
#[cfg(unix)]
pub async fn serve(listener: tokio::net::UnixListener, dispatcher: Arc<Dispatcher>) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let dispatcher = dispatcher.clone();
                tokio::spawn(async move {
                    handle_connection(stream, dispatcher).await;
                });
            }
            Err(e) => {
                eprintln!("zxterm-core: accept failed: {e}");
                return;
            }
        }
    }
}

/// The reply channel's queue depth: generous and non-droppable (unlike
/// `OUTBOUND_QUEUE_DEPTH`'s `Output`/`Event` traffic, a `Reply` is never
/// dropped — a full reply queue instead applies ordinary backpressure to
/// accepting new requests on this connection).
const REPLY_QUEUE_DEPTH: usize = 256;

/// Handles one client connection: reads `Request` frames and answers them
/// concurrently (each on its own task, so a slow call never blocks a fast
/// one behind it — see this phase's Gotchas on out-of-order replies), while
/// two independent outbound channels feed one writer task:
///
/// - `reply_tx`/`reply_rx`: `Reply` frames, never dropped.
/// - `output_tx`/`output_rx`: `Output`/`resync` `Event` frames, the
///   droppable class `super::backlog::OutputSink` manages — kept on its own
///   *bounded* channel precisely so a flood of `Output` can never starve
///   `Reply` delivery by filling a channel the two classes shared.
#[cfg(unix)]
async fn handle_connection(stream: tokio::net::UnixStream, dispatcher: Arc<Dispatcher>) {
    let (mut read_half, write_half) = tokio::io::split(stream);
    let (reply_tx, mut reply_rx) = mpsc::channel::<Frame>(REPLY_QUEUE_DEPTH);
    let (output_tx, mut output_rx) = mpsc::channel::<Frame>(OUTBOUND_QUEUE_DEPTH);

    let writer_task = tokio::spawn(async move {
        let mut write_half = write_half;
        let mut reply_open = true;
        let mut output_open = true;
        while reply_open || output_open {
            tokio::select! {
                biased;
                frame = reply_rx.recv(), if reply_open => {
                    match frame {
                        Some(frame) => {
                            if protocol::write_frame(&mut write_half, &frame).await.is_err() {
                                break;
                            }
                        }
                        None => reply_open = false,
                    }
                }
                frame = output_rx.recv(), if output_open => {
                    match frame {
                        Some(frame) => {
                            if protocol::write_frame(&mut write_half, &frame).await.is_err() {
                                break;
                            }
                        }
                        None => output_open = false,
                    }
                }
            }
        }
    });

    let (gone_tx, gone_rx) = tokio::sync::watch::channel(false);
    let ctx = Arc::new(ConnCtx::new(output_tx, reply_tx.clone(), gone_rx));
    let mut in_flight = Vec::new();

    loop {
        match protocol::read_frame(&mut read_half).await {
            Ok(Some(Frame::Request { id, method, args })) => {
                let dispatcher = dispatcher.clone();
                let ctx = ctx.clone();
                let reply_tx = reply_tx.clone();
                let handle = tokio::spawn(async move {
                    let (result, after) = dispatcher.dispatch_full(&method, &args, &ctx).await;
                    let reply = match result {
                        Ok(value) => Frame::Reply { id, ok: Ok(value) },
                        Err(err) => Frame::Reply {
                            id,
                            ok: Err(super::methods::to_wire_error(err)),
                        },
                    };
                    let _ = reply_tx.send(reply).await;
                    if let Some(after) = after {
                        after();
                    }
                });
                in_flight.push(handle);
                in_flight.retain(|h: &tokio::task::JoinHandle<()>| !h.is_finished());
            }
            Ok(Some(Frame::Chan { chan, bytes })) => {
                // In order with this connection's other `Chan` frames:
                // handled inline, never on a task of its own.
                dispatcher.chan_frame(chan, &bytes, &ctx).await;
            }
            Ok(Some(_other)) => {
                // A client is never expected to send Reply/Event/Output —
                // ignore rather than tear down the connection over an
                // unexpected-but-harmless frame.
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("zxterm-core: connection read error: {e}");
                break;
            }
        }
    }

    let _ = gone_tx.send(true);
    drop(reply_tx);
    drop(ctx);
    for handle in in_flight {
        let _ = handle.await;
    }
    let _ = writer_task.await;
}
