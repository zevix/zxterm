//! Publishing a session's history to `segment-v1` while it is shared, and
//! reading it back with the host offline (K16, `X-26`, `X-27`).
//!
//! [`SegmentPublisher::start`] takes a started [`Backend`] and the
//! session's [`SharedHistory`]. Its task makes sure the session's
//! contract instance exists on the node (`Get`, else `Put` of the empty
//! state), then sends every closed segment the contract lacks, with the
//! host-signed head, as `Update` deltas: a segment close wakes it through
//! [`SegmentFile::set_close_hook`], so each close costs one `Update`
//! carrying the new segment and the new head together (a viewer never
//! sees a head without its segments). A fresh publisher over an old
//! history sends only the suffix the contract would retain
//! (`super::contract::retained_start`), in chunks of at most
//! [`CHUNK_BYTES`]; a restarted host resumes after the highest index the
//! contract already holds. A refused or unanswered `Update` is retried
//! after [`RETRY_MS`] and counted in [`PublishStatus`] (the node never
//! answers a delta the contract refuses, `S-19`).
//!
//! The instance is `segment-v1` with the parameters
//! [`super::contract::params_bytes`] `(host device key, session id)`.
//! [`read_offline`] is the viewer's half: one `Get` on a connection of its
//! own (a multi-megabyte state must not share the request actor's socket,
//! `node::Shared`'s known residual), then
//! [`super::contract::verify_state`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use tokio::sync::Notify;

use crate::error::{Code, Error};
use crate::freenet::backend::Backend;
use crate::freenet::contracts::SEGMENT_V1;
use crate::freenet::node;

use super::contract::{
    self, ContractState, OfflineView, encode_parts, params_bytes, retained_start, sign_head,
    sign_segment,
};
use super::serve::SharedHistory;

/// The most bytes of sealed records one `Update` carries.
pub const CHUNK_BYTES: usize = 4 * 1024 * 1024;
/// How long a failed step waits before it is tried again.
pub const RETRY_MS: u64 = 1_000;

/// What a publisher has done so far.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublishStatus {
    /// The contract instance id (base58); empty until the task has run.
    pub instance: String,
    /// The instance exists on the node.
    pub ready: bool,
    /// The next segment index to send.
    pub next_index: u64,
    /// The length of the last head the contract acknowledged.
    pub head_length: u64,
    /// `Update`s acknowledged.
    pub updates: u64,
    /// Failed steps.
    pub errors: u64,
    pub last_error: Option<String>,
}

struct Inner {
    status: Mutex<PublishStatus>,
    wake: Notify,
    stop: AtomicBool,
    done: Notify,
}

/// The publishing task of one session. Cheap to clone.
#[derive(Clone)]
pub struct SegmentPublisher {
    inner: Arc<Inner>,
}

/// The instance id and parameters of a session's contract.
pub fn instance_of(host: &VerifyingKey, session_id: &str) -> (node::ContractAddr, Vec<u8>) {
    let params = params_bytes(&host.to_bytes(), session_id);
    (node::contract_key(SEGMENT_V1, &params), params)
}

impl SegmentPublisher {
    /// Starts publishing `history` through `backend` (which must be, or
    /// become, started: a step that finds it stopped is retried).
    pub fn start(backend: Backend, history: SharedHistory) -> SegmentPublisher {
        let inner = Arc::new(Inner {
            status: Mutex::new(PublishStatus::default()),
            wake: Notify::new(),
            stop: AtomicBool::new(false),
            done: Notify::new(),
        });
        let hook = inner.clone();
        history
            .0
            .lock()
            .expect("history")
            .set_close_hook(Box::new(move |_| hook.wake.notify_one()));
        inner.wake.notify_one();
        tokio::spawn(run(inner.clone(), backend, history));
        SegmentPublisher { inner }
    }

    pub fn status(&self) -> PublishStatus {
        self.inner.status.lock().expect("status").clone()
    }

    /// Wakes the task (a caller that closed segments by other means).
    pub fn kick(&self) {
        self.inner.wake.notify_one();
    }

    /// Waits until the contract has acknowledged a head of at least
    /// `length` segments (`E_NET` after `timeout`).
    pub async fn wait_published(&self, length: u64, timeout: Duration) -> Result<(), Error> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let st = self.inner.status.lock().expect("status");
                if st.head_length >= length {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                let st = self.status();
                return Err(Error::with_details(
                    Code::ENet,
                    "The history was not published in time",
                    format!(
                        "head {} of {length}, {} errors, last: {}",
                        st.head_length,
                        st.errors,
                        st.last_error.unwrap_or_default()
                    ),
                ));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Ends the task (after its current step).
    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        self.inner.wake.notify_one();
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::new(Code::EInternal, format!("publish task: {e}")))?
}

fn note_error(inner: &Inner, e: &Error) {
    let mut st = inner.status.lock().expect("status");
    st.errors += 1;
    st.last_error = Some(match &e.details {
        Some(d) => format!("{}: {d}", e.message),
        None => e.message.clone(),
    });
}

async fn run(inner: Arc<Inner>, backend: Backend, history: SharedHistory) {
    let (host, session_id) = {
        let f = history.0.lock().expect("history");
        (f.verifying_key(), f.session_id().to_string())
    };
    let (addr, params) = instance_of(&host, &session_id);
    inner.status.lock().expect("status").instance = addr.id.clone();
    loop {
        if inner.stop.load(Ordering::SeqCst) {
            break;
        }
        let failed = match step(&inner, &backend, &history, &addr, &params).await {
            Ok(()) => false,
            Err(e) => {
                note_error(&inner, &e);
                true
            }
        };
        if failed {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(RETRY_MS)) => {}
                _ = inner.wake.notified() => {}
            }
        } else {
            inner.wake.notified().await;
        }
    }
    inner.done.notify_waiters();
}

/// One pass: everything closed and unpublished, then the head.
async fn step(
    inner: &Inner,
    backend: &Backend,
    history: &SharedHistory,
    addr: &node::ContractAddr,
    params: &[u8],
) -> Result<(), Error> {
    let node = backend.node()?;
    if !inner.status.lock().expect("status").ready {
        let held = match node.get(addr.key.id(), node::ANNOUNCE_GET_MS).await {
            Ok(state) => Some(ContractState::decode(&state)?),
            Err(_) => {
                node.put(
                    SEGMENT_V1,
                    params,
                    ContractState::default().encode(),
                    node::REQUEST_TIMEOUT_MS,
                )
                .await?;
                None
            }
        };
        let h = history.clone();
        let held_head = held.as_ref().and_then(|s| s.head).map_or(0, |h| h.length);
        let next = blocking(move || {
            let f = h.0.lock().expect("history");
            let sizes: Vec<usize> = f.entries().iter().map(|e| e.len as usize).collect();
            let start = retained_start(&sizes) as u64;
            Ok(
                match held.as_ref().and_then(|s| s.segments.keys().next_back()) {
                    Some(&last) => (u64::from(last) + 1).max(start),
                    None => start,
                },
            )
        })
        .await?;
        let mut st = inner.status.lock().expect("status");
        st.ready = true;
        st.next_index = next;
        st.head_length = held_head;
    }
    loop {
        let (next, published_head) = {
            let st = inner.status.lock().expect("status");
            (st.next_index, st.head_length)
        };
        let h = history.clone();
        let (batch, key) = blocking(move || {
            let mut f = h.0.lock().expect("history");
            let batch = f.export(next, CHUNK_BYTES)?;
            Ok((batch, f.signing_key().clone()))
        })
        .await?;
        if batch.segments.is_empty() && published_head >= batch.length {
            return Ok(());
        }
        let last = next + batch.segments.len() as u64;
        let final_chunk = last >= batch.length;
        let records: Vec<contract::SegmentRecord> = batch
            .segments
            .into_iter()
            .map(|s| sign_segment(&key, params, s.index, s.prev_root, s.record))
            .collect();
        let head = final_chunk.then(|| sign_head(&key, params, batch.length, batch.root));
        let delta = encode_parts(head.as_ref(), &records);
        node.update(&addr.key, delta, node::REQUEST_TIMEOUT_MS)
            .await?;
        let mut st = inner.status.lock().expect("status");
        st.next_index = last;
        st.updates += 1;
        if final_chunk {
            st.head_length = batch.length;
            st.last_error = None;
        }
    }
}

/// The session's contract state as the node holds it (one `Get` on a
/// connection of its own).
pub async fn read_state(
    backend: &Backend,
    host: &VerifyingKey,
    session_id: &str,
) -> Result<Vec<u8>, Error> {
    let (addr, _) = instance_of(host, session_id);
    let mut client = node::Client::connect(&backend.node_url()).await?;
    client.get(addr.key.id(), node::REQUEST_TIMEOUT_MS).await
}

/// The viewer's half: reads the session's contract and verifies it
/// ([`contract::verify_state`]). The host may be offline: only the node
/// (and whatever it replicates) is asked.
pub async fn read_offline(
    backend: &Backend,
    host: &VerifyingKey,
    session_id: &str,
    min_head_length: u64,
) -> Result<OfflineView, Error> {
    let state = read_state(backend, host, session_id).await?;
    let host = *host;
    let sid = session_id.to_string();
    blocking(move || contract::verify_state(&state, &host, &sid, min_head_length)).await
}
