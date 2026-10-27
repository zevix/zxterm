//! The viewer (dial) and host (announce/accept) role state machines (K6,
//! spike S2), the Rust twin of ZBTerm `engine/backends/freenet/index.js`'s
//! RTC-facing half: minting/answering an offer, the candidate-after-answer
//! hold (`S-26`), and the fingerprint check (design §6 step 5, `S6`
//! conformance negative (i)).
//!
//! **Scope.** `index.js` is one class with announce/withdraw/dial, the
//! per-link admission limits of design §7 layer 4
//! (`MAX_ANSWERS_PER_MINUTE`, `MAX_HALF_OPEN*`, `HALF_OPEN_TIMEOUT_MS`),
//! signalling-entry batching (`FLUSH_MS`) and history (`./history.js`).
//! This module ports only what the WebRTC/channel core (`super::rtc`,
//! `super::channel`, `super::connection`) needs to actually connect over a
//! real signalling contract on a real node — one signalling entry per
//! outbound message (no `FLUSH_MS` batching: still correct, just more
//! entries per connection than ZBTerm's own numbers), no admission policy
//! ([`accept_one`]'s caller always admits, matching the S2 test harness's
//! `setAdmission(true)`), no half-open deadline, no withdraw/tombstones.
//! K10's brief note calls this out explicitly: admission checks are K10's
//! to add *around* [`dial`]/[`accept_one`], not something this phase
//! ports.
//!
//! > 2026-09-29, K10: done in `super::backend`, which reimplements both
//! > roles for many links and connections at once with `index.js`'s
//! > `FLUSH_MS` batching, withdraw/tombstones and the admission limits.
//! > This module stays as K6 left it, for `tests/rtc_parity.rs`.
//!
//! Each of [`dial`] and [`accept_one`] drives one connection to
//! `Connected` (or a definite failure) and hands back a
//! [`super::connection::Connection`]; the caller keeps polling
//! `rtc.recv_event()` and feeding it to `Connection::handle_rtc_event`
//! afterwards — signalling is only needed for the handshake, exactly as in
//! `index.js` (`_surface` never touches the node client again once a
//! connection's `conn` is set).

use std::collections::HashSet;
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_stdlib::prelude::ContractKey;
use serde_json::{Value, json};

use crate::error::{Code, Error};

use super::connection::Connection;
use super::node;
use super::rtc::{ConnId, IceState, RtcEvent, RtcHost, SignalMsg};
use super::signal;

fn err_auth(detail: &str) -> Error {
    Error::with_details(
        Code::EAuth,
        "The Freenet peer presented a certificate its signed SDP does not name",
        detail,
    )
}

/// Design §6 step 5's check, as one pure function so [`dial`] and
/// [`accept_one`] share it instead of duplicating the comparison inline:
/// `presented` (`RtcEvent::State`'s `remote_fingerprint`, whatever the DTLS
/// handshake actually presented) must equal `expected` (extracted from the
/// SDP the peer *signed* over the signalling contract — the offer's for a
/// host session, the answer's for a dial). Either side missing (no signed
/// SDP carried a fingerprint at all, or the RTC layer reported none) is
/// refused the same as an outright mismatch — `index.js::_onRtcState`'s own
/// `!owner.fingerprint || body.remoteFingerprint !== owner.fingerprint`.
fn check_fingerprint(expected: Option<&str>, presented: Option<&str>) -> Result<(), Error> {
    match (expected, presented) {
        (Some(e), Some(p)) if e == p => Ok(()),
        _ => Err(err_auth("fingerprint mismatch")),
    }
}

fn err_unreachable(detail: &str) -> Error {
    Error::with_details(
        Code::EHostUnreachable,
        "The Freenet peer connection failed",
        detail,
    )
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// `crypto.randomBytes(16).toString('hex')` (`index.js::_startDial`'s `cid`).
fn random_cid_hex() -> String {
    use crypto_secretbox::aead::rand_core::RngCore;
    let mut buf = [0u8; 16];
    crypto_secretbox::aead::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn signal_msg_to_json(msg: &SignalMsg) -> Value {
    match msg {
        SignalMsg::Offer { sdp } => json!({"type": "offer", "sdp": sdp}),
        SignalMsg::Answer { sdp } => json!({"type": "answer", "sdp": sdp}),
        SignalMsg::Candidate { candidate, mid } => {
            json!({"type": "candidate", "candidate": candidate, "mid": mid})
        }
    }
}

/// `index.js::_flush`'s payload shape: `{cid, re?, m}` (`re` present only
/// for a host's entry).
fn seal_message(payload_key: &[u8; 32], cid: &str, re: Option<&str>, msg: &SignalMsg) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("cid".to_string(), Value::String(cid.to_string()));
    if let Some(re) = re {
        obj.insert("re".to_string(), Value::String(re.to_string()));
    }
    obj.insert("m".to_string(), Value::Array(vec![signal_msg_to_json(msg)]));
    signal::seal(payload_key, &Value::Object(obj))
}

fn parse_entry(v: &Value) -> Option<signal::Entry> {
    Some(signal::Entry {
        l: v.get("l")?.as_str()?.to_string(),
        r: v.get("r")?.as_str()?.to_string(),
        s: v.get("s")?.as_u64()? as u32,
        t: v.get("t")?.as_u64().unwrap_or(0),
        d: v.get("d").and_then(Value::as_bool).unwrap_or(false),
        p: v.get("p").and_then(Value::as_str).unwrap_or("").to_string(),
        g: v.get("g")?.as_str()?.to_string(),
    })
}

/// The entries of a signalling state or delta (`index.js::entriesOf`).
fn parse_entries(bytes: &[u8]) -> Vec<Value> {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|v| v.get("e").cloned())
        .and_then(|e| e.as_array().cloned())
        .unwrap_or_default()
}

fn entry_to_json(e: &signal::Entry) -> Value {
    json!({"l": e.l, "r": e.r, "s": e.s, "t": e.t, "d": e.d, "p": e.p, "g": e.g})
}

async fn write_entry(
    client: &mut node::Client,
    key: &ContractKey,
    entry: &signal::Entry,
) -> Result<(), Error> {
    let delta =
        serde_json::to_vec(&json!({"e": [entry_to_json(entry)]})).expect("entry must serialize");
    client.update(key, delta, node::REQUEST_TIMEOUT_MS).await
}

/// The viewer (dial) role: mints an offer, holds its own outbound
/// candidates until the answer applies (`S-26`), verifies the answer's SDP
/// fingerprint against what actually connects (design §6 step 5).
///
/// `rtc.open`/`open_bootstrap_channel` are called by this function (unlike
/// `index.js::_startDial`, which calls them before the instance is even
/// fetched, so ICE gathering overlaps the network round trip — this
/// function does the same, opening the connection and bootstrap channel
/// before the `get`/`subscribe` calls below).
/// [`dial`]'s arguments, bundled to stay under clippy's argument-count
/// lint rather than nine loose parameters.
pub struct DialArgs<'a> {
    pub checked: &'a super::route::Checked,
    pub route_k: &'a str,
    pub expected_peer_key: &'a VerifyingKey,
    pub my_secret: &'a SigningKey,
    pub ice_servers: Vec<String>,
    pub timeout: Duration,
    /// Test seam only (default `None` in every real caller): rewrites the
    /// `remote_fingerprint` a `Connected` `RtcEvent::State` carries before
    /// [`check_fingerprint`] ever sees it, the same way `rtc_peer.js`'s
    /// `lieAboutFingerprint` relay rewrites `RtcHost`'s `state` event
    /// before `FreenetBackend`'s own check does — lets a test prove this
    /// side's own detection fires against a real, honest peer, without a
    /// real DTLS certificate mismatch (which would fail the connection at
    /// the transport layer instead, before this check ever runs).
    pub lie_about_fingerprint: Option<fn(String) -> String>,
}

pub async fn dial(
    client: &mut node::Client,
    rtc: &RtcHost,
    conn_id: ConnId,
    args: DialArgs<'_>,
) -> Result<Connection, Error> {
    let DialArgs {
        checked,
        route_k,
        expected_peer_key,
        my_secret,
        ice_servers,
        timeout,
        lie_about_fingerprint,
    } = args;
    let addr = node::contract_key(&checked.wasm, &checked.params);
    let my_hex = hex::encode(my_secret.verifying_key().to_bytes());
    let cid = random_cid_hex();
    let my_r = format!("v:{my_hex}");
    // `index.js::_startDial`'s `dial.hostR`: `r` is keyed by the *viewer's*
    // own hex in both prefixes (`v:` for the viewer's own entries, `h:` for
    // the host's replies to this specific viewer) — not the host's public
    // key, which never appears in `r` at all (a link has exactly one host,
    // so nothing needs to name it there).
    let host_r = format!("h:{my_hex}");
    let payload_key = signal::payload_key(route_k);

    rtc.open(conn_id, Some(ice_servers));
    let mut conn = Connection::new(conn_id, expected_peer_key.to_bytes().to_vec(), true, None);
    conn.open_bootstrap_channel(rtc);

    for _ in 0..10 {
        if client.get(addr.key.id(), 2000).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
    client.subscribe(addr.key.id()).await?;

    let mut seq: u32 = 0;
    let mut own_re: Option<String> = None;
    let mut answered = false;
    let mut own_held: Vec<SignalMsg> = Vec::new();
    let mut seen: HashSet<(String, String, u32)> = HashSet::new();
    let mut fingerprint: Option<String> = None;

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() > deadline {
            return Err(err_unreachable("dial timed out before connecting"));
        }
        tokio::select! {
            note = client.recv_notification(addr.key.id(), 500) => {
                if let Ok(parts) = note {
                    for part in parts {
                        for ev in parse_entries(&part) {
                            let Some(entry) = parse_entry(&ev) else { continue };
                            if entry.l != cid || entry.r != host_r { continue; }
                            let dedup = (entry.l.clone(), entry.r.clone(), entry.s);
                            if seen.contains(&dedup) { continue; }
                            seen.insert(dedup);
                            if !signal::verify_entry(expected_peer_key, &checked.params, &entry) { continue; }
                            if entry.d { continue; }
                            let Some(msg) = signal::open(&payload_key, &entry.p) else { continue };
                            if msg.get("cid").and_then(Value::as_str) != Some(cid.as_str()) { continue; }
                            let Some(ms) = msg.get("m").and_then(Value::as_array) else { continue };
                            for m in ms {
                                let ty = m.get("type").and_then(Value::as_str).unwrap_or("");
                                if ty == "answer" && !answered {
                                    if msg.get("re").and_then(Value::as_str) != own_re.as_deref() { continue; }
                                    let Some(sdp) = m.get("sdp").and_then(Value::as_str) else { continue };
                                    answered = true;
                                    fingerprint = signal::sdp_fingerprint(sdp);
                                    rtc.signal(conn_id, SignalMsg::Answer { sdp: sdp.to_string() });
                                    for held in own_held.drain(..) {
                                        let payload = seal_message(&payload_key, &cid, None, &held);
                                        let entry = signal::sign_entry(my_secret, &checked.params, &signal::EntryFields {
                                            l: &cid, r: &my_r, s: seq, t: now_ms(), d: false, p: &payload,
                                        });
                                        seq += 1;
                                        let _ = write_entry(client, &addr.key, &entry).await;
                                    }
                                } else if ty == "candidate"
                                    && let Some(candidate) = m.get("candidate").and_then(Value::as_str)
                                {
                                    let mid = m.get("mid").and_then(Value::as_str).unwrap_or("0");
                                    rtc.signal(conn_id, SignalMsg::Candidate { candidate: candidate.to_string(), mid: mid.to_string() });
                                }
                            }
                        }
                    }
                }
            }
            ev = rtc.recv_event() => {
                let Some(ev) = ev else { return Err(err_unreachable("rtc event stream ended")); };
                // Every event feeds `conn` too (`Channel`/`Data`/`Flow`;
                // `Signal`/`State` are a no-op there) — not just the ones
                // this loop itself acts on below. Without this, the
                // bootstrap channel's own `ChannelOpen` (which can arrive
                // before `Connected` — the exact race `S-26` guards
                // against) would never reach `conn.bootstrap_open`, so
                // every channel this side opens after `dial` returns would
                // stay deferred forever.
                conn.handle_rtc_event(rtc, &ev);
                match ev {
                    RtcEvent::Signal { conn_id: c, msg } if c == conn_id => {
                        // S-26: hold this side's own candidates until the
                        // answer has been applied.
                        if matches!(msg, SignalMsg::Candidate { .. }) && !answered {
                            own_held.push(msg);
                            continue;
                        }
                        let payload = seal_message(&payload_key, &cid, None, &msg);
                        let entry = signal::sign_entry(my_secret, &checked.params, &signal::EntryFields {
                            l: &cid, r: &my_r, s: seq, t: now_ms(), d: false, p: &payload,
                        });
                        if own_re.is_none()
                            && let SignalMsg::Offer { .. } = &msg
                        {
                            own_re = Some(signal::offer_ref(&entry.p));
                        }
                        seq += 1;
                        let _ = write_entry(client, &addr.key, &entry).await;
                    }
                    RtcEvent::State { conn_id: c, state: IceState::Connected, remote_fingerprint, .. } if c == conn_id => {
                        let remote_fingerprint = match (lie_about_fingerprint, remote_fingerprint) {
                            (Some(lie), Some(f)) => Some(lie(f)),
                            (_, f) => f,
                        };
                        if let Err(e) = check_fingerprint(fingerprint.as_deref(), remote_fingerprint.as_deref()) {
                            rtc.close(conn_id, "fingerprint mismatch");
                            return Err(e);
                        }
                        // Return the same `Connection` built before the
                        // handshake started (it already has the bootstrap
                        // channel wired) — `path_kind` is always `"host"`
                        // in this phase (no relay support; see
                        // `super::rtc`'s doc comment), the same as the
                        // `Direct` default this `Connection` was built
                        // with, so there is nothing to update.
                        return Ok(conn);
                    }
                    RtcEvent::Close { conn_id: c, .. } if c == conn_id => {
                        return Err(err_unreachable("connection closed before connecting"));
                    }
                    _ => {}
                }
            }
        }
    }
}

struct HostSession {
    cid: String,
    viewer_key: VerifyingKey,
    viewer_hex: String,
    r: String,
    re: String,
    fingerprint: Option<String>,
}

/// [`accept_one`]'s arguments, bundled for the same reason as [`DialArgs`].
pub struct AcceptArgs<'a> {
    pub link_params: &'a [u8],
    pub contract_key: &'a ContractKey,
    pub payload_key: &'a [u8; 32],
    pub my_secret: &'a SigningKey,
    pub ice_servers: Vec<String>,
    pub timeout: Duration,
    /// Test seam only — see [`DialArgs::lie_about_fingerprint`].
    pub lie_about_fingerprint: Option<fn(String) -> String>,
}

/// The host role: answers the first verified offer it sees on
/// `contract_key`'s instance, checking the fingerprint on `Connected`
/// (design §6 step 5). No admission policy — every offer is accepted
/// (see the module doc comment); K10 adds a check before this.
pub async fn accept_one(
    client: &mut node::Client,
    rtc: &RtcHost,
    conn_id: ConnId,
    args: AcceptArgs<'_>,
) -> Result<Connection, Error> {
    let AcceptArgs {
        link_params,
        contract_key,
        payload_key,
        my_secret,
        ice_servers,
        timeout,
        lie_about_fingerprint,
    } = args;
    let mut seq: u32 = 0;
    let mut seen: HashSet<(String, String, u32)> = HashSet::new();
    let mut session: Option<HostSession> = None;
    // `Channel`/`Data`/`Flow` events for `conn_id` that arrive before this
    // role's `Connection` exists (it is only constructed once `Connected`
    // fires, unlike the dial role's, wired up front) — most notably the
    // dial's own bootstrap channel, which the host never opens itself but
    // must still hear about. Replayed into `conn.handle_rtc_event` right
    // after it is built, mirroring `index.js::_surface`'s own `owner.early`
    // replay.
    let mut early: Vec<RtcEvent> = Vec::new();

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() > deadline {
            return Err(err_unreachable("host accept timed out"));
        }
        tokio::select! {
            note = client.recv_notification(contract_key.id(), 500) => {
                if let Ok(parts) = note {
                    for part in parts {
                        for ev in parse_entries(&part) {
                            let Some(entry) = parse_entry(&ev) else { continue };
                            if !entry.r.starts_with("v:") { continue; }
                            let dedup = (entry.l.clone(), entry.r.clone(), entry.s);
                            if seen.contains(&dedup) { continue; }
                            seen.insert(dedup);
                            let Some(role) = signal::role_of(&entry.r) else { continue };
                            let Ok(viewer_bytes) = hex::decode(&role.viewer) else { continue };
                            let Ok(viewer_arr): Result<[u8; 32], _> = viewer_bytes.try_into() else { continue };
                            let Ok(viewer_key) = VerifyingKey::from_bytes(&viewer_arr) else { continue };
                            if !signal::verify_entry(&viewer_key, link_params, &entry) { continue; }
                            if entry.d { continue; }
                            let Some(msg) = signal::open(payload_key, &entry.p) else { continue };
                            if msg.get("cid").and_then(Value::as_str) != Some(entry.l.as_str()) { continue; }
                            let Some(ms) = msg.get("m").and_then(Value::as_array) else { continue };
                            if session.is_none() {
                                let Some(offer_m) = ms.iter().find(|m| m.get("type").and_then(Value::as_str) == Some("offer")) else { continue };
                                let Some(sdp) = offer_m.get("sdp").and_then(Value::as_str) else { continue };
                                let fp = signal::sdp_fingerprint(sdp);
                                rtc.open(conn_id, Some(ice_servers.clone()));
                                rtc.signal(conn_id, SignalMsg::Offer { sdp: sdp.to_string() });
                                session = Some(HostSession {
                                    cid: entry.l.clone(),
                                    viewer_key,
                                    viewer_hex: role.viewer.clone(),
                                    r: format!("h:{}", role.viewer),
                                    re: signal::offer_ref(&entry.p),
                                    fingerprint: fp,
                                });
                            } else if let Some(sess) = &session {
                                if sess.cid != entry.l || sess.viewer_hex != role.viewer { continue; }
                                for m in ms {
                                    if m.get("type").and_then(Value::as_str) == Some("candidate")
                                        && let Some(candidate) = m.get("candidate").and_then(Value::as_str)
                                    {
                                        let mid = m.get("mid").and_then(Value::as_str).unwrap_or("0");
                                        rtc.signal(conn_id, SignalMsg::Candidate { candidate: candidate.to_string(), mid: mid.to_string() });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            ev = rtc.recv_event() => {
                let Some(ev) = ev else { return Err(err_unreachable("rtc event stream ended")); };
                match ev {
                    RtcEvent::Signal { conn_id: c, msg } if c == conn_id => {
                        if let Some(sess) = &session {
                            let payload = seal_message(payload_key, &sess.cid, Some(&sess.re), &msg);
                            let entry = signal::sign_entry(my_secret, link_params, &signal::EntryFields {
                                l: &sess.cid, r: &sess.r, s: seq, t: now_ms(), d: false, p: &payload,
                            });
                            seq += 1;
                            let _ = write_entry(client, contract_key, &entry).await;
                        }
                    }
                    RtcEvent::State { conn_id: c, state: IceState::Connected, remote_fingerprint, path_kind, .. } if c == conn_id => {
                        let Some(sess) = &session else { continue };
                        let remote_fingerprint = match (lie_about_fingerprint, remote_fingerprint) {
                            (Some(lie), Some(f)) => Some(lie(f)),
                            (_, f) => f,
                        };
                        if let Err(e) = check_fingerprint(sess.fingerprint.as_deref(), remote_fingerprint.as_deref()) {
                            rtc.close(conn_id, "fingerprint mismatch");
                            return Err(e);
                        }
                        let mut conn = Connection::new(conn_id, sess.viewer_key.to_bytes().to_vec(), false, path_kind);
                        for early_ev in early.drain(..) {
                            conn.handle_rtc_event(rtc, &early_ev);
                        }
                        return Ok(conn);
                    }
                    RtcEvent::Close { conn_id: c, .. } if c == conn_id => {
                        return Err(err_unreachable("connection closed before connecting"));
                    }
                    other => early.push(other),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_fingerprint_matching_is_ok() {
        assert!(check_fingerprint(Some("sha-256 AB:CD"), Some("sha-256 AB:CD")).is_ok());
    }

    #[test]
    fn check_fingerprint_mismatch_is_eauth() {
        let err = check_fingerprint(Some("sha-256 AB:CD"), Some("sha-256 EF:00")).unwrap_err();
        assert_eq!(err.code, Code::EAuth);
        assert_eq!(
            err.message,
            "The Freenet peer presented a certificate its signed SDP does not name"
        );
    }

    #[test]
    fn check_fingerprint_no_expected_is_eauth() {
        let err = check_fingerprint(None, Some("sha-256 AB:CD")).unwrap_err();
        assert_eq!(err.code, Code::EAuth);
        assert_eq!(
            err.message,
            "The Freenet peer presented a certificate its signed SDP does not name"
        );
    }

    #[test]
    fn check_fingerprint_no_presented_is_eauth() {
        let err = check_fingerprint(Some("sha-256 AB:CD"), None).unwrap_err();
        assert_eq!(err.code, Code::EAuth);
        assert_eq!(
            err.message,
            "The Freenet peer presented a certificate its signed SDP does not name"
        );
    }
}
