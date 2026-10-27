//! The session protocol over the seam (K13): `share.*` methods drive
//! `crate::session::SessionService` on the sidecar's one Freenet backend
//! (`freenet.start` first), and its events reach every connection that
//! called a `share.*` method as `share.*` `Event` frames, never dropped.
//! Product functionality, behind no feature flag.
//!
//! Bytes (PTY output and input, `Bootstrap`/`Timeline`/`Snapshot`
//! documents) travel as base64 inside the JSON payloads (K8's blockquote on
//! K13: `Request.args`, `Reply` values and `Event.data` are JSON text, and
//! `Output` is droppable, so no new frame kind); keys and envelopes as hex.
//!
//! Methods (arguments JSON, results JSON):
//!
//! | method | arguments | result |
//! |---|---|---|
//! | `share.subscribe` | – | `null` |
//! | `share.hostOpen` | `sessionId`, `logKey`, `metaKey`, `local`, `info?`, `sensitive?`, `quickCatchupKB?`, `inputMode?`, `firstEpoch?`, `caps?` (ignored) | `null` |
//! | `share.addLink` | `sessionId`, `linkId` (16 bytes hex), `type` (`single`/`group`), `maxViewers?`, `autoJoin?`, `caps?` | `null` |
//! | `share.approve` | `sessionId`, `joinId` | `null` |
//! | `share.deny` | `sessionId`, `joinId`, `reason?` (ignored: `JOIN_REASONS.DENIED`) | `null` |
//! | `share.revoke` | `sessionId`, `identityKey` | `{revoked}` |
//! | `share.revokeLink` | `sessionId`, `linkId` | `{revoked}` |
//! | `share.push` | `sessionId`, `data` (base64), `hd?` | `null` |
//! | `share.resize` | `sessionId`, `cols`, `rows` | `null` |
//! | `share.bootstrap` | `sessionId`, `requestId`, `data` (base64) | `null` |
//! | `share.timeline` / `share.snapshot` | `sessionId`, `data` (base64), `joinId?` | `null` |
//! | `share.info` | `sessionId`, `name?`, `inputMode?` | `null` |
//! | `share.end` | `sessionId`, `exit?` (`{code, signal}`) | `null` |
//! | `share.hostClose` | `sessionId` | `null` |
//! | `share.status` | `sessionId` | `{epoch, inputMode, confirmed, pending, members, links}` |
//! | `share.join` | `route`, `expectedPeerKey`, `linkId`, `local`, `caps?` (ignored) | `{joinId}` |
//! | `share.input` | `sessionId`, `data` (base64) | `{inputCtr}` |
//! | `share.history` | `sessionId`, `start`, `end`, `credit?` (`MAX_HISTORY_CREDIT`) | `{requestId}` |
//! | `share.historyCredit` | `sessionId`, `requestId`, `credit` | `null` |
//! | `share.leave` | `joinId` | `null` |
//!
//! `local` is `{deviceSecretKey, identityKey, identityProof, deviceName?,
//! claim?, authSecretKey?}` (hex; `claim` in `identity.*`'s claim shape).
//!
//! Events: `share.pending`, `share.approvalCancelled`, `share.granted`,
//! `share.peerLeft`, `share.epoch`, `share.bootstrapNeeded`, `share.input`
//! (host: decrypted input for the PTY; the same name as the viewer's
//! request method, told apart by direction), `share.inputRefused`,
//! `share.peerIdentity`, `share.joinChanged`, `share.output`,
//! `share.live`, `share.rekey`, `share.end`, `share.info`,
//! `share.offline`, `share.historySegment`, `share.historyDone`,
//! `share.error`, `share.debug`.

use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use crate::error::{Code, Error};
use crate::freenet::backend::{Backend, route_from_json};
use crate::identity::resolver::IdentityResolver;
use crate::identity::store::IdentityStore;
use crate::session::host::{LinkKind, LinkSpec};
use crate::session::messages::{Exit, InputMode, SessionInfo};
use crate::session::service::{HostOpen, JoinSpec, ServiceOptions, SessionEvent, SessionService};
use crate::session::{LocalIdentity, MAX_GROUP_VIEWERS};

use super::freenet_methods::FreenetSeam;
use super::methods::{ConnCtx, claim_from_json};
use super::protocol::Frame;

/// The sidecar's session service, built on the Freenet backend once it
/// exists (and rebuilt if `freenet.start` replaced the backend).
pub struct ShareSeam {
    store: IdentityStore,
    resolver: Arc<IdentityResolver>,
    service: Mutex<Option<SessionService>>,
    history: crate::history::serve::HistoryRegistry,
    subscribers: Arc<Mutex<Vec<mpsc::Sender<Frame>>>>,
}

fn bad_args(what: &str) -> Error {
    Error::new(Code::EInternal, format!("invalid arguments: {what}"))
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Result<&'a str, Error> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| bad_args(&format!("{key} must be a string")))
}

fn u64_arg(args: &Value, key: &str) -> Result<u64, Error> {
    args.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| bad_args(&format!("{key} must be a number")))
}

fn hex_n<const N: usize>(args: &Value, key: &str) -> Result<[u8; N], Error> {
    hex::decode(str_arg(args, key)?)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| bad_args(&format!("{key} must be {N} bytes of hex")))
}

fn b64_arg(args: &Value, key: &str) -> Result<Vec<u8>, Error> {
    B64.decode(str_arg(args, key)?)
        .map_err(|_| bad_args(&format!("{key} must be base64")))
}

fn input_mode_arg(args: &Value, key: &str) -> Result<Option<InputMode>, Error> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_str()
            .and_then(InputMode::parse)
            .map(Some)
            .ok_or_else(|| bad_args(&format!("{key} must be 'host' or 'all'"))),
    }
}

fn local_arg(args: &Value) -> Result<LocalIdentity, Error> {
    let l = args.get("local").ok_or_else(|| bad_args("local"))?;
    let auth_secret_key = match l.get("authSecretKey") {
        None | Some(Value::Null) => None,
        Some(_) => Some(hex_n::<64>(l, "authSecretKey")?),
    };
    Ok(LocalIdentity {
        device_secret_key: hex_n::<32>(l, "deviceSecretKey")?,
        identity_key: hex_n::<32>(l, "identityKey")?,
        identity_proof: hex::decode(str_arg(l, "identityProof")?)
            .map_err(|_| bad_args("identityProof must be hex"))?,
        device_name: l
            .get("deviceName")
            .and_then(Value::as_str)
            .unwrap_or("viewer")
            .to_string(),
        claim: l
            .get("claim")
            .filter(|c| c.is_object())
            .map(claim_from_json),
        auth_secret_key,
    })
}

fn info_arg(args: &Value) -> SessionInfo {
    let i = args.get("info").cloned().unwrap_or(Value::Null);
    let u = |v: &Value, k: &str| v.get(k).and_then(Value::as_u64);
    SessionInfo {
        name: i
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        created_at: u(&i, "createdAt").unwrap_or(0),
        sensitive: args
            .get("sensitive")
            .or_else(|| i.get("sensitive"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        quick_catchup_kb: args
            .get("quickCatchupKB")
            .or_else(|| i.get("quickCatchupKB"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32,
        cols: u(&i, "cols").unwrap_or(0) as u32,
        rows: u(&i, "rows").unwrap_or(0) as u32,
    }
}

fn info_json(i: &SessionInfo) -> Value {
    json!({
        "name": i.name, "createdAt": i.created_at, "sensitive": i.sensitive,
        "quickCatchupKB": i.quick_catchup_kb, "cols": i.cols, "rows": i.rows,
    })
}

/// A session event as the frame a seam client receives (`None`: not
/// forwarded).
pub fn event_frame(ev: SessionEvent) -> Option<Frame> {
    let (name, data) = match ev {
        SessionEvent::Pending {
            session_id,
            join_id,
            link_id,
            identity_key,
            device_key,
            device_name,
            caps,
        } => (
            "share.pending",
            json!({"sessionId": session_id, "joinId": join_id, "linkId": hex::encode(link_id),
                   "identityKey": hex::encode(identity_key), "deviceKey": hex::encode(device_key),
                   "deviceName": device_name, "caps": caps}),
        ),
        SessionEvent::ApprovalCancelled {
            session_id,
            join_id,
        } => (
            "share.approvalCancelled",
            json!({"sessionId": session_id, "joinId": join_id}),
        ),
        SessionEvent::Granted {
            session_id,
            join_id,
            link_id,
            identity_key,
            device_key,
            caps,
        } => (
            "share.granted",
            json!({"sessionId": session_id, "joinId": join_id, "linkId": hex::encode(link_id),
                   "identityKey": hex::encode(identity_key), "deviceKey": hex::encode(device_key), "caps": caps}),
        ),
        SessionEvent::PeerLeft {
            session_id,
            join_id,
        } => (
            "share.peerLeft",
            json!({"sessionId": session_id, "joinId": join_id}),
        ),
        SessionEvent::Epoch {
            session_id,
            epoch,
            reason,
            persist,
            local,
            envelopes,
            history,
        } => {
            let envelopes: serde_json::Map<String, Value> = envelopes
                .into_iter()
                .map(|(d, e)| (hex::encode(d), Value::String(hex::encode(e))))
                .collect();
            let history: Vec<Value> = history
                .into_iter()
                .map(|(d, n, e)| json!({"deviceKey": hex::encode(d), "epoch": n, "envelope": hex::encode(e)}))
                .collect();
            (
                "share.epoch",
                json!({"sessionId": session_id, "epoch": epoch, "reason": reason.as_str(),
                       "persist": persist, "local": hex::encode(local), "envelopes": envelopes,
                       "history": history}),
            )
        }
        SessionEvent::BootstrapNeeded {
            session_id,
            request_id,
            scrollback,
            tail_bytes,
        } => (
            "share.bootstrapNeeded",
            json!({"sessionId": session_id, "requestId": request_id,
                   "scrollback": scrollback, "tailBytes": tail_bytes}),
        ),
        SessionEvent::Input {
            session_id,
            join_id,
            data,
        } => (
            "share.input",
            json!({"sessionId": session_id, "joinId": join_id, "data": B64.encode(data)}),
        ),
        SessionEvent::InputRefused {
            session_id,
            join_id,
            error,
        } => (
            "share.inputRefused",
            json!({"sessionId": session_id, "joinId": join_id,
                   "code": error.code.as_str(), "message": error.message}),
        ),
        SessionEvent::PeerIdentity(p) => (
            "share.peerIdentity",
            json!({"sessionId": p.session_id, "direction": p.direction.as_str(),
                   "joinId": p.join_id, "identityKey": p.identity_key, "deviceKey": p.device_key,
                   "displayId": p.display_id, "provider": p.provider, "status": p.status,
                   "reason": p.reason}),
        ),
        SessionEvent::JoinChanged {
            join_id,
            status,
            session_id,
            code,
            reason,
            message,
            confirm,
        } => {
            let confirm = confirm.map(|c| {
                json!({"sessionId": c.session_id, "info": info_json(&c.info),
                       "inputMode": c.input_mode.as_str(), "logKey": hex::encode(c.log_key),
                       "metaKey": hex::encode(c.meta_key), "hostDeviceKey": hex::encode(c.host_device_key),
                       "envelope": hex::encode(&c.envelope), "epoch": c.epoch, "caps": c.caps})
            });
            (
                "share.joinChanged",
                json!({"joinId": join_id, "status": status.as_str(), "sessionId": session_id,
                       "code": code.map(|c| c.as_str()), "reason": reason.map(|r| r.as_str()),
                       "message": message, "confirm": confirm}),
            )
        }
        SessionEvent::Output {
            session_id,
            data,
            hd,
        } => (
            "share.output",
            json!({"sessionId": session_id, "data": B64.encode(data), "hd": hd}),
        ),
        SessionEvent::Live {
            session_id,
            kind,
            data,
        } => (
            "share.live",
            json!({"sessionId": session_id, "kind": kind.as_str(), "data": B64.encode(data)}),
        ),
        SessionEvent::Rekey {
            session_id,
            epoch,
            envelope,
        } => (
            "share.rekey",
            json!({"sessionId": session_id, "epoch": epoch, "envelope": hex::encode(envelope)}),
        ),
        SessionEvent::End { session_id, exit } => (
            "share.end",
            json!({"sessionId": session_id,
                   "exit": exit.map(|e| json!({"code": e.code, "signal": e.signal}))}),
        ),
        SessionEvent::Info {
            session_id,
            name,
            input_mode,
        } => (
            "share.info",
            json!({"sessionId": session_id, "name": name,
                   "inputMode": input_mode.map(|m| m.as_str())}),
        ),
        SessionEvent::Offline { session_id } => ("share.offline", json!({"sessionId": session_id})),
        SessionEvent::HistorySegment {
            session_id,
            request_id,
            start,
            data,
        } => (
            "share.historySegment",
            json!({"sessionId": session_id, "requestId": request_id, "start": start,
                   "data": B64.encode(data)}),
        ),
        SessionEvent::HistoryDone {
            session_id,
            request_id,
            next,
        } => (
            "share.historyDone",
            json!({"sessionId": session_id, "requestId": request_id, "next": next}),
        ),
        SessionEvent::Error { session_id, error } => (
            "share.error",
            json!({"sessionId": session_id, "code": error.code.as_str(), "message": error.message}),
        ),
        SessionEvent::Debug { event, details } => {
            ("share.debug", json!({"event": event, "details": details}))
        }
        SessionEvent::LiveFrame { .. } => return None,
    };
    Some(Frame::Event {
        name: name.to_string(),
        data: data.to_string(),
    })
}

impl ShareSeam {
    pub fn new(
        store: IdentityStore,
        resolver: Arc<IdentityResolver>,
        history: crate::history::serve::HistoryRegistry,
    ) -> ShareSeam {
        ShareSeam {
            store,
            resolver,
            history,
            service: Mutex::new(None),
            subscribers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// The service on the current backend, built (and its event forwarder
    /// started) on first use.
    fn service(&self, backend: Backend) -> SessionService {
        let mut slot = self.service.lock().expect("share seam");
        if let Some(s) = slot.as_ref()
            && s.backend().ptr_eq(&backend)
        {
            return s.clone();
        }
        let (service, mut rx) = SessionService::new(
            backend,
            ServiceOptions {
                resolver: Some(self.resolver.clone()),
                store: Some(self.store.clone()),
                tap_live: false,
                identity_timeout_ms: None,
                history: Some(self.history.clone()),
            },
        );
        let subscribers = self.subscribers.clone();
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                let Some(frame) = event_frame(ev) else {
                    continue;
                };
                let targets: Vec<mpsc::Sender<Frame>> =
                    subscribers.lock().expect("subscribers").clone();
                let mut gone = Vec::new();
                for (i, tx) in targets.iter().enumerate() {
                    if tx.send(frame.clone()).await.is_err() {
                        gone.push(i);
                    }
                }
                if !gone.is_empty() {
                    let mut subs = subscribers.lock().expect("subscribers");
                    subs.retain(|tx| !tx.is_closed());
                }
            }
        });
        *slot = Some(service.clone());
        service
    }

    fn subscribe(&self, ctx: &ConnCtx) {
        if ctx
            .share_listening
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return;
        }
        self.subscribers
            .lock()
            .expect("subscribers")
            .push(ctx.events.clone());
    }

    /// One `share.*` call.
    pub async fn dispatch(
        &self,
        method: &str,
        args: Value,
        ctx: &ConnCtx,
        freenet: &FreenetSeam,
    ) -> Result<Value, Error> {
        let backend = freenet.backend()?;
        let svc = self.service(backend);
        self.subscribe(ctx);
        let sid = || str_arg(&args, "sessionId");
        let null = Ok(Value::Null);
        match method {
            "share.subscribe" => null,
            "share.hostOpen" => {
                let first_epoch =
                    args.get("firstEpoch").and_then(Value::as_u64).unwrap_or(1) as u32;
                svc.host_open(HostOpen {
                    session_id: sid()?.to_string(),
                    info: info_arg(&args),
                    input_mode: input_mode_arg(&args, "inputMode")?.unwrap_or(InputMode::Host),
                    log_key: hex_n::<32>(&args, "logKey")?,
                    meta_key: hex_n::<32>(&args, "metaKey")?,
                    local: local_arg(&args)?,
                    first_epoch,
                })?;
                null
            }
            "share.addLink" => {
                let kind = match args.get("type").and_then(Value::as_str) {
                    Some("group") => LinkKind::Group,
                    Some("single") | None => LinkKind::Single,
                    Some(_) => return Err(bad_args("type must be 'single' or 'group'")),
                };
                svc.add_link(
                    sid()?,
                    LinkSpec {
                        link_id: hex_n::<16>(&args, "linkId")?,
                        kind,
                        max_viewers: args
                            .get("maxViewers")
                            .and_then(Value::as_u64)
                            .map(|v| v as u32)
                            .unwrap_or(if kind == LinkKind::Group {
                                MAX_GROUP_VIEWERS
                            } else {
                                1
                            }),
                        auto_join: args
                            .get("autoJoin")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        caps: args
                            .get("caps")
                            .and_then(Value::as_u64)
                            .map(crate::session::caps::normalize),
                    },
                )?;
                null
            }
            "share.approve" => {
                svc.approve(sid()?, str_arg(&args, "joinId")?)?;
                null
            }
            "share.deny" => {
                svc.deny(sid()?, str_arg(&args, "joinId")?)?;
                null
            }
            "share.revoke" => Ok(
                json!({"revoked": svc.revoke_member(sid()?, &hex_n::<32>(&args, "identityKey")?)?}),
            ),
            "share.revokeLink" => {
                Ok(json!({"revoked": svc.revoke_link(sid()?, &hex_n::<16>(&args, "linkId")?)?}))
            }
            "share.push" => {
                let hd = args.get("hd").and_then(Value::as_bool).unwrap_or(false);
                svc.push(sid()?, &b64_arg(&args, "data")?, hd)?;
                null
            }
            "share.resize" => {
                svc.resize(
                    sid()?,
                    u64_arg(&args, "cols")? as u32,
                    u64_arg(&args, "rows")? as u32,
                )?;
                null
            }
            "share.bootstrap" => {
                svc.provide_bootstrap(
                    sid()?,
                    u64_arg(&args, "requestId")?,
                    &b64_arg(&args, "data")?,
                )?;
                null
            }
            "share.timeline" | "share.snapshot" => {
                let kind = if method == "share.timeline" {
                    crate::session::service::LiveKind::Timeline
                } else {
                    crate::session::service::LiveKind::Snapshot
                };
                let join = args.get("joinId").and_then(Value::as_str);
                svc.send_live_json(sid()?, kind, &b64_arg(&args, "data")?, join)?;
                null
            }
            "share.info" => {
                let name = args.get("name").and_then(Value::as_str).map(str::to_string);
                svc.set_info(sid()?, name, input_mode_arg(&args, "inputMode")?)?;
                null
            }
            "share.end" => {
                let exit = args.get("exit").filter(|e| e.is_object()).map(|e| Exit {
                    code: e.get("code").and_then(Value::as_i64).map(|c| c as i32),
                    signal: e.get("signal").and_then(Value::as_str).map(str::to_string),
                });
                svc.end(sid()?, exit)?;
                null
            }
            "share.hostClose" => {
                svc.host_close(sid()?)?;
                null
            }
            "share.status" => {
                let s = svc
                    .host_status(sid()?)
                    .ok_or_else(|| Error::new(Code::EAuth, "No active share for this session"))?;
                Ok(json!({
                    "epoch": s.epoch,
                    "inputMode": s.input_mode.as_str(),
                    "confirmed": s.confirmed.iter().map(|(j, k)| json!({"joinId": j, "identityKey": hex::encode(k)})).collect::<Vec<_>>(),
                    "pending": s.pending,
                    "members": s.members.iter().map(|(k, st)| json!({"identityKey": hex::encode(k), "status": if *st == crate::session::host::MemberStatus::Active { "active" } else { "revoked" }})).collect::<Vec<_>>(),
                    "links": s.links.iter().map(|l| json!({"linkId": hex::encode(l.spec.link_id), "viewers": l.viewers, "consumed": l.consumed, "revoked": l.revoked})).collect::<Vec<_>>(),
                }))
            }
            "share.join" => {
                let route = route_from_json(args.get("route").ok_or_else(|| bad_args("route"))?)?;
                let join_id = svc.join(JoinSpec {
                    route,
                    expected_peer_key: hex_n::<32>(&args, "expectedPeerKey")?,
                    link_id: hex_n::<16>(&args, "linkId")?,
                    local: local_arg(&args)?,
                })?;
                Ok(json!({"joinId": join_id}))
            }
            "share.input" => {
                let ctr = svc.input(sid()?, &b64_arg(&args, "data")?)?;
                Ok(json!({"inputCtr": ctr}))
            }
            "share.history" => {
                let id = svc.request_history(
                    sid()?,
                    u64_arg(&args, "start")?,
                    u64_arg(&args, "end")?,
                    args.get("credit")
                        .and_then(Value::as_u64)
                        .unwrap_or(crate::history::MAX_HISTORY_CREDIT as u64)
                        as u32,
                )?;
                Ok(json!({"requestId": id}))
            }
            "share.historyCredit" => {
                svc.history_credit(
                    sid()?,
                    u64_arg(&args, "requestId")? as u32,
                    u64_arg(&args, "credit")? as u32,
                )?;
                null
            }
            "share.leave" => {
                svc.leave(str_arg(&args, "joinId")?);
                null
            }
            other => Err(Error::new(
                Code::EBackendUnsupported,
                format!("no such seam method: {other}"),
            )),
        }
    }
}
