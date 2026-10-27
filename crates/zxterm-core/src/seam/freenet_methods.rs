//! The Freenet transport service over the seam (K10): `freenet.*` methods
//! mirror `crate::freenet::backend::Backend` (every `BACKEND_MEMBERS`
//! method of `zbterm:engine/backends/types.js`, plus channels), its events
//! reach the client as `freenet.*` `Event` frames, and raw channel bytes
//! travel in both directions as `Frame::Chan` frames, which are never
//! dropped (unlike `Output`). ZBTerm's `FreenetBackend` proxies to this in
//! K11; `ctl` drives the same methods as JSON.
//!
//! One backend per sidecar. A connection that calls `freenet.start` or
//! `freenet.subscribe` receives every backend event from then on, in order
//! with its replies. A channel opened through the seam is held until its
//! `Reply` is queued, so a client always learns a channel's handle before
//! any of its bytes (`Backend::open_with`'s `hold`).
//!
//! Methods (arguments JSON, results JSON):
//!
//! | method | arguments | result |
//! |---|---|---|
//! | `freenet.describe` | – | `BackendDescriptor` |
//! | `freenet.probe` | `nodeUrl?`, `timeoutMs?` | `{state, detail}` |
//! | `freenet.start` | `secretKey` (hex, 32-byte seed or 64-byte secret key), `nodeUrl?`, `iceServers?`, `loopbackOnly?` | `{publicKey}` |
//! | `freenet.stop` | – | `null` |
//! | `freenet.health` | – | `{started, listening, detail}` |
//! | `freenet.localPeerKey` | – | hex or `null` |
//! | `freenet.announce` | `linkId`, `route?`, `tag?` | `{route, linkId}` |
//! | `freenet.withdraw` | `linkId` | `null` |
//! | `freenet.routeFor` | `linkId`, `stored?` (`{route}`) | route |
//! | `freenet.dial` | `route`, `expectedPeerKey` (hex), `tag?` | `{dial}`; then `freenet.dialConnected`/`freenet.dialError` |
//! | `freenet.cancelDial` | `dial` | `null` |
//! | `freenet.setAdmission` | `policy`: `true`, `false` or an array of hex keys | `null` |
//! | `freenet.setIceServers` | `iceServers` (array or `null`) | `null` |
//! | `freenet.serveHistory` / `freenet.attachHistory` | `conn` (`keys?`) | `{chan}` |
//! | `freenet.historyRouteFor` | – | `null` |
//! | `freenet.diagnostics` | – | diagnostics |
//! | `freenet.openChannel` | `conn`, `protocol`, `id` (hex) | `{chan}` (a raw channel) |
//! | `freenet.send` | `chan`, `data` (base64) | `{more}` |
//! | `freenet.closeChannel` | `chan` | `null` |
//! | `freenet.closeConnection` | `conn`, `reason?` | `null` |
//! | `freenet.subscribe` | – | `null` |
//!
//! Events: `freenet.connection {conn, remotePeerKey, initiator, linkId,
//! path}`, `freenet.connectionClosed {conn, reason}`,
//! `freenet.incomingChannel {conn, protocol, id}`, `freenet.channelOpened
//! {chan}`, `freenet.message {chan, value}`, `freenet.drain {chan}`,
//! `freenet.backpressure {chan}` (a `Chan` frame the channel took over its
//! mark), `freenet.channelClosed {chan}`, `freenet.dialConnected {dial,
//! conn}`, `freenet.dialError {dial, code, message}`, `freenet.debug
//! {event, details}`.

use std::collections::HashSet;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use crate::error::{Code, Error};
use crate::freenet::backend::{
    self, Admission, Backend, BackendEvent, BackendOptions, route_from_json, route_to_json,
};
use crate::freenet::connection::Path;
use crate::freenet::node;

use super::methods::{After, ConnCtx};
use super::protocol::Frame;

/// The sidecar's one Freenet backend.
#[derive(Default)]
pub struct FreenetSeam {
    backend: Mutex<Option<Backend>>,
}

fn bad_args(what: &str) -> Error {
    Error::new(Code::EInternal, format!("invalid arguments: {what}"))
}

fn u64_arg(args: &Value, key: &str) -> Result<u64, Error> {
    args.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| bad_args(&format!("{key} must be a number")))
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Result<&'a str, Error> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| bad_args(&format!("{key} must be a string")))
}

fn key32(hex_str: &str, what: &str) -> Result<[u8; 32], Error> {
    hex::decode(hex_str)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| bad_args(&format!("{what} must be 32 bytes of hex")))
}

fn ice_arg(args: &Value) -> Option<Vec<String>> {
    args.get("iceServers").and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .or_else(|| v.get("urls").and_then(Value::as_str).map(str::to_string))
            })
            .collect()
    })
}

fn path_str(p: Path) -> &'static str {
    match p {
        Path::Direct => "DIRECT",
        Path::Relay => "RELAY",
    }
}

/// A backend event as the frame a seam client receives.
pub fn event_frame(ev: BackendEvent) -> Frame {
    let (name, data) = match ev {
        BackendEvent::Bytes { chan, bytes } => return Frame::Chan { chan, bytes },
        BackendEvent::Connection {
            conn,
            remote_peer_key,
            initiator,
            link_id,
            path,
        } => (
            "freenet.connection",
            json!({
                "conn": conn,
                "remotePeerKey": hex::encode(remote_peer_key),
                "initiator": initiator,
                "linkId": link_id,
                "path": path_str(path),
            }),
        ),
        BackendEvent::ConnectionClosed { conn, reason } => (
            "freenet.connectionClosed",
            json!({"conn": conn, "reason": reason}),
        ),
        BackendEvent::IncomingChannel { conn, protocol, id } => (
            "freenet.incomingChannel",
            json!({"conn": conn, "protocol": protocol, "id": hex::encode(id)}),
        ),
        BackendEvent::ChannelOpened { chan } => ("freenet.channelOpened", json!({"chan": chan})),
        BackendEvent::Message { chan, value } => {
            ("freenet.message", json!({"chan": chan, "value": value}))
        }
        BackendEvent::Backpressure { chan } => ("freenet.backpressure", json!({"chan": chan})),
        BackendEvent::Drain { chan } => ("freenet.drain", json!({"chan": chan})),
        BackendEvent::ChannelClosed { chan } => ("freenet.channelClosed", json!({"chan": chan})),
        BackendEvent::DialConnected { dial, conn } => {
            ("freenet.dialConnected", json!({"dial": dial, "conn": conn}))
        }
        BackendEvent::DialError { dial, error } => {
            let wire = super::methods::to_wire_error(error);
            (
                "freenet.dialError",
                json!({"dial": dial, "code": wire.code, "message": wire.message}),
            )
        }
        BackendEvent::Debug { event, details } => {
            ("freenet.debug", json!({"event": event, "details": details}))
        }
    };
    Frame::Event {
        name: name.to_string(),
        data: data.to_string(),
    }
}

impl FreenetSeam {
    pub(super) fn backend(&self) -> Result<Backend, Error> {
        self.backend
            .lock()
            .expect("freenet seam")
            .clone()
            .ok_or_else(|| {
                Error::with_details(
                    Code::EBackendUnavailable,
                    "The 'freenet' share backend is not started",
                    "not started",
                )
            })
    }

    /// Starts forwarding every backend event to this connection, once.
    fn listen(&self, backend: &Backend, ctx: &ConnCtx) {
        if ctx
            .freenet_listening
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return;
        }
        let mut rx: mpsc::UnboundedReceiver<BackendEvent> = backend.subscribe();
        let tx = ctx.events.clone();
        let mut gone = ctx.gone.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    ev = rx.recv() => {
                        let Some(ev) = ev else { break };
                        if tx.send(event_frame(ev)).await.is_err() {
                            break;
                        }
                    }
                    changed = gone.changed() => {
                        if changed.is_err() || *gone.borrow() {
                            break;
                        }
                    }
                }
            }
        });
    }

    /// A `Chan` frame from the client: bytes for raw channel `chan`. A
    /// refusal reaches the client as the backend's own
    /// `freenet.backpressure` event, in order with the `freenet.drain`
    /// that ends it (K11, `R-12`; K10 sent it from here, where it could
    /// overtake that drain).
    pub async fn chan_frame(&self, chan: u64, bytes: &[u8], _ctx: &ConnCtx) {
        let Ok(backend) = self.backend() else { return };
        backend.send_bytes(chan, bytes);
    }

    /// One `freenet.*` call. The second value runs once the reply is
    /// queued.
    pub async fn dispatch(
        &self,
        method: &str,
        args: Value,
        ctx: &ConnCtx,
    ) -> Result<(Value, Option<After>), Error> {
        let plain = |v: Value| Ok((v, None));
        match method {
            "freenet.describe" => {
                let b = self
                    .backend()
                    .unwrap_or_else(|_| Backend::new(BackendOptions::default()));
                plain(b.describe())
            }
            "freenet.probe" => {
                let url = args
                    .get("nodeUrl")
                    .and_then(Value::as_str)
                    .unwrap_or(node::DEFAULT_NODE_URL);
                let ms = args
                    .get("timeoutMs")
                    .and_then(Value::as_u64)
                    .unwrap_or(node::PROBE_TIMEOUT_MS);
                plain(Backend::probe(url, ms).await)
            }
            "freenet.start" => {
                let secret = hex::decode(str_arg(&args, "secretKey")?)
                    .map_err(|_| bad_args("secretKey must be hex"))?;
                if secret.len() != 32 && secret.len() != 64 {
                    return Err(bad_args("secretKey must be 32 or 64 bytes"));
                }
                let seed: [u8; 32] = secret[..32].try_into().expect("32 bytes");
                let key = SigningKey::from_bytes(&seed);
                if secret.len() == 64 && secret[32..] != key.verifying_key().to_bytes() {
                    return Err(bad_args("secretKey's public half does not match its seed"));
                }
                let backend = {
                    let mut slot = self.backend.lock().expect("freenet seam");
                    match slot.as_ref() {
                        Some(b) if b.health()["started"] == true => b.clone(),
                        _ => {
                            let b = Backend::new(BackendOptions {
                                node_url: args
                                    .get("nodeUrl")
                                    .and_then(Value::as_str)
                                    .unwrap_or(node::DEFAULT_NODE_URL)
                                    .to_string(),
                                ice_servers: ice_arg(&args),
                                clock: None,
                                loopback_only: args
                                    .get("loopbackOnly")
                                    .and_then(Value::as_bool)
                                    .unwrap_or(false),
                                legacy_v1_routes: false,
                            });
                            *slot = Some(b.clone());
                            b
                        }
                    }
                };
                self.listen(&backend, ctx);
                backend.start(key.clone()).await?;
                plain(json!({"publicKey": hex::encode(key.verifying_key().to_bytes())}))
            }
            "freenet.subscribe" => {
                let b = self.backend()?;
                self.listen(&b, ctx);
                plain(Value::Null)
            }
            "freenet.stop" => {
                if let Ok(b) = self.backend() {
                    b.stop().await;
                }
                plain(Value::Null)
            }
            "freenet.health" => match self.backend() {
                Ok(b) => plain(b.health()),
                Err(_) => plain(json!({"started": false, "listening": false, "detail": null})),
            },
            "freenet.localPeerKey" => plain(
                self.backend()
                    .ok()
                    .and_then(|b| b.local_peer_key())
                    .map(hex::encode)
                    .map_or(Value::Null, Value::String),
            ),
            "freenet.announce" => {
                let b = self.backend()?;
                let link = str_arg(&args, "linkId")?;
                let r = match args.get("route") {
                    Some(v) if !v.is_null() => Some(route_from_json(v)?),
                    _ => None,
                };
                let ann = b.announce(link, r, args.get("tag").cloned()).await?;
                plain(json!({"route": route_to_json(&ann.route), "linkId": ann.link_id}))
            }
            "freenet.withdraw" => {
                let b = self.backend()?;
                b.withdraw(str_arg(&args, "linkId")?).await;
                plain(Value::Null)
            }
            "freenet.routeFor" => {
                let b = self.backend()?;
                let stored = match args.get("stored").and_then(|s| s.get("route")) {
                    Some(v) if !v.is_null() => Some(route_from_json(v)?),
                    _ => None,
                };
                let r = b.route_for(str_arg(&args, "linkId")?, stored)?;
                plain(route_to_json(&r))
            }
            "freenet.dial" => {
                let b = self.backend()?;
                let r = route_from_json(args.get("route").ok_or_else(|| bad_args("route"))?)?;
                let expected = key32(str_arg(&args, "expectedPeerKey")?, "expectedPeerKey")?;
                self.listen(&b, ctx);
                let handle = b.dial(r, expected, args.get("tag").cloned());
                plain(json!({"dial": handle.id}))
            }
            "freenet.cancelDial" => {
                self.backend()?.cancel_dial(u64_arg(&args, "dial")?);
                plain(Value::Null)
            }
            "freenet.setAdmission" => {
                let b = self.backend()?;
                let policy = match args.get("policy") {
                    Some(Value::Bool(v)) => Admission::All(*v),
                    Some(Value::Array(keys)) => {
                        let mut set = HashSet::new();
                        for k in keys {
                            let k = k
                                .as_str()
                                .ok_or_else(|| bad_args("policy keys must be hex"))?;
                            set.insert(key32(k, "policy key")?);
                        }
                        Admission::Keys(set)
                    }
                    _ => return Err(bad_args("policy must be a boolean or an array of hex keys")),
                };
                b.set_admission(policy);
                plain(Value::Null)
            }
            "freenet.setIceServers" => {
                self.backend()?.set_ice_servers(ice_arg(&args));
                plain(Value::Null)
            }
            "freenet.serveHistory" | "freenet.attachHistory" => {
                let b = self.backend()?;
                let conn = u64_arg(&args, "conn")?;
                let chan = b.open_with(
                    conn,
                    crate::wire::HISTORY_PROTOCOL,
                    &backend::HISTORY_ID,
                    true,
                    true,
                );
                let chan = match chan {
                    Ok(c) => c,
                    // Already open: idempotent per connection.
                    Err(_) => b.serve_history(conn)?,
                };
                let b2 = b.clone();
                Ok((
                    json!({"chan": chan}),
                    Some(Box::new(move || b2.release(chan)) as After),
                ))
            }
            "freenet.historyRouteFor" => plain(Value::Null),
            "freenet.diagnostics" => match self.backend() {
                Ok(b) => plain(b.diagnostics()),
                Err(_) => plain(json!({"backend": "freenet", "started": false, "announced": 0})),
            },
            "freenet.openChannel" => {
                let b = self.backend()?;
                let conn = u64_arg(&args, "conn")?;
                let protocol = str_arg(&args, "protocol")?;
                let id =
                    hex::decode(str_arg(&args, "id")?).map_err(|_| bad_args("id must be hex"))?;
                let chan = b.open_with(conn, protocol, &id, true, true)?;
                let b2 = b.clone();
                Ok((
                    json!({"chan": chan}),
                    Some(Box::new(move || b2.release(chan)) as After),
                ))
            }
            "freenet.send" => {
                let b = self.backend()?;
                let data = B64
                    .decode(str_arg(&args, "data")?)
                    .map_err(|_| bad_args("data must be base64"))?;
                plain(json!({"more": b.send_bytes(u64_arg(&args, "chan")?, &data)}))
            }
            "freenet.closeChannel" => {
                self.backend()?.close_channel(u64_arg(&args, "chan")?);
                plain(Value::Null)
            }
            "freenet.closeConnection" => {
                let reason = args
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("closed");
                self.backend()?
                    .close_connection(u64_arg(&args, "conn")?, reason);
                plain(Value::Null)
            }
            other => Err(Error::new(
                Code::EBackendUnsupported,
                format!("no such seam method: {other}"),
            )),
        }
    }
}
