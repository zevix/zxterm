//! C3 history over the seam (K15): the `history.*` methods drive
//! `crate::history` for the sidecar's sessions. An opened history is also
//! registered with the session service (`crate::history::serve::
//! HistoryRegistry`), so once `history.open` (or `history.import`) has
//! returned, a viewer's `share.history` range is served from it live.
//! Product functionality, behind no feature flag.
//!
//! Bytes are base64 and keys hex inside the JSON payloads, as in
//! `share_methods`. `epochKeys` is `{"<epoch>": "<history key hex>"}`.
//!
//! | method | arguments | result |
//! |---|---|---|
//! | `history.open` | `sessionId`, `dir`, `signingKey` (32-byte seed hex), `snapshotKey`, `cols`, `rows`, `epochKeys`, `epoch?`, `firstSeq?`, `create?` | `{segments, nextSeq}` |
//! | `history.import` | `open`'s arguments minus `create`, plus `epoch`, `historyKey`, `packets` | `{segments, nextSeq}` |
//! | `history.setEpoch` | `sessionId`, `epoch`, `key?` (hex, registers it) | `null` |
//! | `history.append` | `sessionId`, `packets` | `{firstSeq, nextSeq}` |
//! | `history.flush` | `sessionId` | `{segments}` |
//! | `history.close` | `sessionId` | `null` |
//! | `history.head` | `sessionId` | `{length, chainRoot, signature, nextSeq, closedEndSeq, verifyingKey}` |
//! | `history.read` | `sessionId`, `start`, `end` | `{packets}` |
//! | `history.screenAt` | `sessionId`, `seq` | `{cols, rows, text, formatted}` |
//! | `history.setMetadata` / `history.metadata` | `sessionId`, `metadata` / `sessionId` | `null` / `{metadata}` |
//! | `history.verify` | `sessionId`, `requestId`, `verifyingKey`, `epochKeys`, `data`, `minHeadLength?` | `{index, firstSeq, packets}` |
//! | `history.verifyDone` | `sessionId`, `requestId`, `start`, `next` | `null` |
//! | `history.publish` | `sessionId` | `{instance, host}` |
//! | `history.publishStatus` | `sessionId`, `waitLength?`, `timeoutMs?` | `{instance, ready, nextIndex, headLength, updates, errors, lastError}` |
//! | `history.unpublish` | `sessionId` | `null` |
//! | `history.readContract` | `sessionId`, `verifyingKey`, `epochKeys`, `minHeadLength?`, `from?`, `count?` | `{headLength, chainRoot, firstIndex, held, beyondHead, segments}` |
//!
//! **Offline history (K16, `X-26`).** `history.publish` (or `publish: true` in
//! `history.open`/`history.import`) starts publishing an opened history to its
//! `segment-v1` instance through the started Freenet backend
//! (`crate::history::publish`): every closed segment and the host-signed head
//! reach the contract, in that order, whatever the viewers do; `history.close`
//! waits (at most 10 s) for the last flush to be acknowledged and stops it.
//! `history.publishStatus` reports progress (`waitLength` waits until the
//! contract acknowledged a head of that many segments, `timeoutMs` bounds the
//! wait, default 10 s). `history.readContract` is the viewer's read with the
//! host offline: one `Get` on the contract, every signature and the chain to
//! the head checked, then segments `[from, from + count)` (default from the
//! first held, at most 64) opened under `epochKeys` like `history.verify`'s;
//! `segments` is `[{index, firstSeq, packets}]`, `held` the verified segments
//! the contract holds and `beyondHead` those past the head (not returned).
//! `verifyingKey` is the host's device signing key (the head's).
//!
//! A packet is `{tsMs, kind, cols?, rows?, payload? (base64), hd?}` (a
//! read adds `seq`). `history.verify` takes the `data` of one
//! `share.historySegment` event; the first call of a `(sessionId,
//! requestId)` must carry the request's proof (the first segment does),
//! and the verifier for it ends at `history.verifyDone` or on an error.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{Value, json};

use crate::error::{Code, Error};
use crate::history::fetch::RangeVerifier;
use crate::history::import::import;
use crate::history::metadata::{
    EnvelopeEntry, EpochEntry, InfoEntry, LinkEntry, MemberEntry, MetadataBody,
};
use crate::history::packet::{FLAG_COLS, FLAG_HD, FLAG_PAYLOAD, FLAG_ROWS, PlainPacket, VERSION};
use crate::history::publish::{self, SegmentPublisher};
use crate::history::serve::{HistoryRegistry, SharedHistory};
use crate::history::{HistoryConfig, MAX_SEGMENTS_PER_REQUEST, SegmentFile};

use super::freenet_methods::FreenetSeam;

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
    hex_value(args.get(key), key)
}

fn hex_value<const N: usize>(v: Option<&Value>, what: &str) -> Result<[u8; N], Error> {
    v.and_then(Value::as_str)
        .and_then(|s| hex::decode(s).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| bad_args(&format!("{what} must be {N} bytes of hex")))
}

fn b64_value(v: Option<&Value>, what: &str) -> Result<Vec<u8>, Error> {
    v.and_then(Value::as_str)
        .and_then(|s| B64.decode(s).ok())
        .ok_or_else(|| bad_args(&format!("{what} must be base64")))
}

fn epoch_keys(args: &Value) -> Result<BTreeMap<u32, [u8; 32]>, Error> {
    let mut out = BTreeMap::new();
    let map = args
        .get("epochKeys")
        .and_then(Value::as_object)
        .ok_or_else(|| bad_args("epochKeys must be an object"))?;
    for (k, v) in map {
        let epoch: u32 = k
            .parse()
            .map_err(|_| bad_args("epochKeys names an epoch"))?;
        out.insert(epoch, hex_value::<32>(Some(v), "an epoch key")?);
    }
    Ok(out)
}

fn packet_from_json(p: &Value) -> Result<PlainPacket, Error> {
    let kind = p
        .get("kind")
        .and_then(Value::as_u64)
        .ok_or_else(|| bad_args("packet kind"))? as u8;
    let mut flags = 0u8;
    let opt_u32 = |k: &str, flag: u8, flags: &mut u8| -> Option<u32> {
        p.get(k).and_then(Value::as_u64).map(|v| {
            *flags |= flag;
            v as u32
        })
    };
    let cols = opt_u32("cols", FLAG_COLS, &mut flags);
    let rows = opt_u32("rows", FLAG_ROWS, &mut flags);
    let payload = match p.get("payload") {
        None | Some(Value::Null) => None,
        Some(v) => {
            flags |= FLAG_PAYLOAD;
            Some(b64_value(Some(v), "payload")?)
        }
    };
    if p.get("hd").and_then(Value::as_bool).unwrap_or(false) {
        flags |= FLAG_HD;
    }
    let packet = PlainPacket {
        version: VERSION,
        ts_ms: u64_arg(p, "tsMs")?,
        kind,
        flags,
        cols,
        rows,
        payload,
    };
    packet.validate()?;
    Ok(packet)
}

fn packet_json(seq: Option<u64>, p: &PlainPacket) -> Value {
    let mut v = json!({"tsMs": p.ts_ms, "kind": p.kind, "hd": p.flags & FLAG_HD != 0});
    if let Some(seq) = seq {
        v["seq"] = json!(seq);
    }
    if let Some(c) = p.cols {
        v["cols"] = json!(c);
    }
    if let Some(r) = p.rows {
        v["rows"] = json!(r);
    }
    if let Some(pl) = &p.payload {
        v["payload"] = json!(B64.encode(pl));
    }
    v
}

fn packets_arg(args: &Value) -> Result<Vec<PlainPacket>, Error> {
    args.get("packets")
        .and_then(Value::as_array)
        .ok_or_else(|| bad_args("packets must be an array"))?
        .iter()
        .map(packet_from_json)
        .collect()
}

fn metadata_from_json(sid: &str, m: &Value) -> Result<MetadataBody, Error> {
    let arr = |k: &str| -> Result<&Vec<Value>, Error> {
        m.get(k)
            .and_then(Value::as_array)
            .ok_or_else(|| bad_args(&format!("metadata.{k} must be an array")))
    };
    let info = m.get("info").ok_or_else(|| bad_args("metadata.info"))?;
    let info = InfoEntry {
        name: str_arg(info, "name")?.to_string(),
        created_at: u64_arg(info, "createdAt")?,
        sensitive: info
            .get("sensitive")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        cols: u64_arg(info, "cols")? as u32,
        rows: u64_arg(info, "rows")? as u32,
    };
    let epochs = arr("epochs")?
        .iter()
        .map(|e| {
            Ok(EpochEntry {
                epoch: u64_arg(e, "epoch")? as u32,
                first_seq: u64_arg(e, "firstSeq")?,
            })
        })
        .collect::<Result<_, Error>>()?;
    let envelopes = arr("envelopes")?
        .iter()
        .map(|e| {
            Ok(EnvelopeEntry {
                epoch: u64_arg(e, "epoch")? as u32,
                device_key: hex_n::<32>(e, "deviceKey")?,
                sealed: b64_value(e.get("sealed"), "sealed")?,
            })
        })
        .collect::<Result<_, Error>>()?;
    let members = arr("members")?
        .iter()
        .map(|e| {
            Ok(MemberEntry {
                identity_key: hex_n::<32>(e, "identityKey")?,
                device_key: hex_n::<32>(e, "deviceKey")?,
                device_name: str_arg(e, "deviceName")?.to_string(),
                caps: u64_arg(e, "caps")? as u8,
                link_id: hex_n::<16>(e, "linkId")?,
                revoked: e.get("revoked").and_then(Value::as_bool).unwrap_or(false),
            })
        })
        .collect::<Result<_, Error>>()?;
    let links = arr("links")?
        .iter()
        .map(|e| {
            Ok(LinkEntry {
                link_id: hex_n::<16>(e, "linkId")?,
                group: e.get("group").and_then(Value::as_bool).unwrap_or(false),
                max_viewers: u64_arg(e, "maxViewers")? as u32,
                auto_join: e.get("autoJoin").and_then(Value::as_bool).unwrap_or(false),
                caps: e.get("caps").and_then(Value::as_u64).map(|c| c as u8),
                revoked: e.get("revoked").and_then(Value::as_bool).unwrap_or(false),
            })
        })
        .collect::<Result<_, Error>>()?;
    Ok(MetadataBody::new(
        sid, info, epochs, envelopes, members, links,
    ))
}

fn metadata_json(b: &MetadataBody) -> Value {
    json!({
        "info": {"name": b.info.name, "createdAt": b.info.created_at,
                 "sensitive": b.info.sensitive, "cols": b.info.cols, "rows": b.info.rows},
        "epochs": b.epochs.iter().map(|e| json!({"epoch": e.epoch, "firstSeq": e.first_seq})).collect::<Vec<_>>(),
        "envelopes": b.envelopes.iter().map(|e| json!({"epoch": e.epoch,
            "deviceKey": hex::encode(e.device_key), "sealed": B64.encode(&e.sealed)})).collect::<Vec<_>>(),
        "members": b.members.iter().map(|m| json!({"identityKey": hex::encode(m.identity_key),
            "deviceKey": hex::encode(m.device_key), "deviceName": m.device_name, "caps": m.caps,
            "linkId": hex::encode(m.link_id), "revoked": m.revoked})).collect::<Vec<_>>(),
        "links": b.links.iter().map(|l| json!({"linkId": hex::encode(l.link_id), "group": l.group,
            "maxViewers": l.max_viewers, "autoJoin": l.auto_join, "caps": l.caps,
            "revoked": l.revoked})).collect::<Vec<_>>(),
    })
}

fn config_from_args(args: &Value) -> Result<HistoryConfig, Error> {
    Ok(HistoryConfig {
        dir: PathBuf::from(str_arg(args, "dir")?),
        session_id: str_arg(args, "sessionId")?.to_string(),
        signer: SigningKey::from_bytes(&hex_n::<32>(args, "signingKey")?),
        snapshot_key: hex_n::<32>(args, "snapshotKey")?,
        cols: u64_arg(args, "cols")?.clamp(1, u16::MAX as u64) as u16,
        rows: u64_arg(args, "rows")?.clamp(1, u16::MAX as u64) as u16,
        epoch_keys: if args.get("epochKeys").is_some() {
            epoch_keys(args)?
        } else {
            BTreeMap::new()
        },
        first_seq: args.get("firstSeq").and_then(Value::as_u64).unwrap_or(0),
    })
}

/// The sidecar's open histories and the viewer-side verifiers.
pub struct HistorySeam {
    registry: HistoryRegistry,
    open: Mutex<HashMap<String, SharedHistory>>,
    verifiers: Mutex<HashMap<(String, u64), RangeVerifier>>,
    publishers: Mutex<HashMap<String, SegmentPublisher>>,
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::new(Code::EInternal, format!("history task: {e}")))?
}

impl HistorySeam {
    pub fn new(registry: HistoryRegistry) -> HistorySeam {
        HistorySeam {
            registry,
            open: Mutex::new(HashMap::new()),
            verifiers: Mutex::new(HashMap::new()),
            publishers: Mutex::new(HashMap::new()),
        }
    }

    fn get(&self, sid: &str) -> Result<SharedHistory, Error> {
        self.open
            .lock()
            .expect("histories")
            .get(sid)
            .cloned()
            .ok_or_else(|| Error::new(Code::EAuth, "No history is open for this session"))
    }

    fn register(&self, sid: &str, file: SegmentFile) -> Result<Value, Error> {
        let (segments, next_seq) = (file.segment_count(), file.next_seq());
        let shared = SharedHistory::new(file);
        self.registry.insert(sid, Arc::new(shared.clone()));
        self.open
            .lock()
            .expect("histories")
            .insert(sid.to_string(), shared);
        Ok(json!({"segments": segments, "nextSeq": next_seq}))
    }

    fn start_publisher(&self, sid: &str, freenet: &FreenetSeam) -> Result<Value, Error> {
        let backend = freenet.backend()?;
        let h = self.get(sid)?;
        let mut all = self.publishers.lock().expect("publishers");
        if all.contains_key(sid) {
            return Err(Error::new(Code::EInternal, "history is already published"));
        }
        let host = h.0.lock().expect("history").verifying_key();
        let (addr, _) = publish::instance_of(&host, sid);
        all.insert(sid.to_string(), SegmentPublisher::start(backend, h));
        Ok(json!({"instance": addr.id, "host": hex::encode(host.to_bytes())}))
    }

    /// One `history.*` call.
    pub async fn dispatch(
        &self,
        method: &str,
        args: Value,
        freenet: &FreenetSeam,
    ) -> Result<Value, Error> {
        let sid = || str_arg(&args, "sessionId").map(str::to_string);
        match method {
            "history.open" => {
                let cfg = config_from_args(&args)?;
                let sid = cfg.session_id.clone();
                if self.open.lock().expect("histories").contains_key(&sid) {
                    return Err(Error::new(Code::EInternal, "history is already open"));
                }
                let create = args.get("create").and_then(Value::as_bool).unwrap_or(false);
                let epoch = args.get("epoch").and_then(Value::as_u64).map(|e| e as u32);
                let file = blocking(move || {
                    let mut f = if create {
                        SegmentFile::create(cfg)?
                    } else {
                        SegmentFile::open(cfg)?
                    };
                    if let Some(e) = epoch {
                        f.set_epoch(e)?;
                    }
                    Ok(f)
                })
                .await?;
                let out = self.register(&sid, file)?;
                if args
                    .get("publish")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    self.start_publisher(&sid, freenet)?;
                }
                Ok(out)
            }
            "history.import" => {
                let cfg = config_from_args(&args)?;
                let sid = cfg.session_id.clone();
                if self.open.lock().expect("histories").contains_key(&sid) {
                    return Err(Error::new(Code::EInternal, "history is already open"));
                }
                let packets = packets_arg(&args)?;
                let epoch = u64_arg(&args, "epoch")? as u32;
                let key = hex_n::<32>(&args, "historyKey")?;
                let file = blocking(move || import(cfg, packets, epoch, key)).await?;
                let out = self.register(&sid, file)?;
                if args
                    .get("publish")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    self.start_publisher(&sid, freenet)?;
                }
                Ok(out)
            }
            "history.setEpoch" => {
                let h = self.get(&sid()?)?;
                let epoch = u64_arg(&args, "epoch")? as u32;
                let key = match args.get("key") {
                    None | Some(Value::Null) => None,
                    Some(_) => Some(hex_n::<32>(&args, "key")?),
                };
                blocking(move || {
                    let mut f = h.0.lock().expect("history");
                    if let Some(k) = key {
                        f.add_epoch_key(epoch, k);
                    }
                    f.set_epoch(epoch)
                })
                .await?;
                Ok(Value::Null)
            }
            "history.append" => {
                let h = self.get(&sid()?)?;
                let packets = packets_arg(&args)?;
                blocking(move || {
                    let mut f = h.0.lock().expect("history");
                    let first = f.next_seq();
                    for p in packets {
                        f.append(p)?;
                    }
                    Ok(json!({"firstSeq": first, "nextSeq": f.next_seq()}))
                })
                .await
            }
            "history.flush" => {
                let h = self.get(&sid()?)?;
                blocking(move || {
                    let mut f = h.0.lock().expect("history");
                    f.flush()?;
                    Ok(json!({"segments": f.segment_count()}))
                })
                .await
            }
            "history.close" => {
                let sid = sid()?;
                let h = self.get(&sid)?;
                let closed = blocking({
                    let h = h.clone();
                    move || {
                        let mut f = h.0.lock().expect("history");
                        f.flush()?;
                        Ok(f.segment_count())
                    }
                })
                .await?;
                let publisher = self.publishers.lock().expect("publishers").remove(&sid);
                if let Some(p) = publisher {
                    // Best effort: the flush's segment reaches the contract
                    // before the publisher stops.
                    p.kick();
                    let _ = p.wait_published(closed, Duration::from_secs(10)).await;
                    p.stop();
                }
                self.registry.remove(&sid);
                self.open.lock().expect("histories").remove(&sid);
                Ok(Value::Null)
            }
            "history.head" => {
                let h = self.get(&sid()?)?;
                let f = h.0.lock().expect("history");
                let head = f.head();
                Ok(
                    json!({"length": head.length, "chainRoot": hex::encode(head.chain_root),
                          "signature": hex::encode(head.signature), "nextSeq": f.next_seq(),
                          "closedEndSeq": f.closed_end_seq(),
                          "verifyingKey": hex::encode(f.verifying_key().to_bytes())}),
                )
            }
            "history.read" => {
                let h = self.get(&sid()?)?;
                let (start, end) = (u64_arg(&args, "start")?, u64_arg(&args, "end")?);
                let packets =
                    blocking(move || h.0.lock().expect("history").read(start, end)).await?;
                Ok(
                    json!({"packets": packets.iter().map(|(s, p)| packet_json(Some(*s), p)).collect::<Vec<_>>()}),
                )
            }
            "history.screenAt" => {
                let h = self.get(&sid()?)?;
                let seq = u64_arg(&args, "seq")?;
                let s = blocking(move || h.0.lock().expect("history").screen_at(seq)).await?;
                Ok(json!({"cols": s.cols, "rows": s.rows, "text": s.text,
                          "formatted": B64.encode(&s.formatted)}))
            }
            "history.setMetadata" => {
                let sid = sid()?;
                let h = self.get(&sid)?;
                let body = metadata_from_json(
                    &sid,
                    args.get("metadata").ok_or_else(|| bad_args("metadata"))?,
                )?;
                blocking(move || h.0.lock().expect("history").set_metadata(&body)).await?;
                Ok(Value::Null)
            }
            "history.metadata" => {
                let h = self.get(&sid()?)?;
                let m = blocking(move || h.0.lock().expect("history").metadata()).await?;
                Ok(json!({"metadata": m.as_ref().map(metadata_json)}))
            }
            "history.verify" => {
                let key = (sid()?, u64_arg(&args, "requestId")?);
                let data = b64_value(args.get("data"), "data")?;
                let mut v = {
                    let mut all = self.verifiers.lock().expect("verifiers");
                    match all.remove(&key) {
                        Some(v) => v,
                        None => {
                            let vk = VerifyingKey::from_bytes(&hex_n::<32>(&args, "verifyingKey")?)
                                .map_err(|_| bad_args("verifyingKey"))?;
                            RangeVerifier::new(&key.0, vk, epoch_keys(&args)?).with_min_head_length(
                                args.get("minHeadLength")
                                    .and_then(Value::as_u64)
                                    .unwrap_or(0),
                            )
                        }
                    }
                };
                // An error drops the verifier: the request is over.
                let seg = v.accept(&data)?;
                self.verifiers.lock().expect("verifiers").insert(key, v);
                Ok(json!({"index": seg.index, "firstSeq": seg.header.first_seq,
                          "packets": seg.packets.iter().map(|(s, p)| packet_json(Some(*s), p)).collect::<Vec<_>>()}))
            }
            "history.verifyDone" => {
                let key = (sid()?, u64_arg(&args, "requestId")?);
                let (start, next) = (u64_arg(&args, "start")?, u64_arg(&args, "next")?);
                let v = self.verifiers.lock().expect("verifiers").remove(&key);
                match v {
                    Some(v) => v.finish(next, start)?,
                    None if next == start => {}
                    None => {
                        return Err(Error::new(
                            Code::ECorrupt,
                            "Done names segments that were never served",
                        ));
                    }
                }
                Ok(Value::Null)
            }
            "history.publish" => self.start_publisher(&sid()?, freenet),
            "history.publishStatus" => {
                let sid = sid()?;
                let p = self
                    .publishers
                    .lock()
                    .expect("publishers")
                    .get(&sid)
                    .cloned()
                    .ok_or_else(|| Error::new(Code::EAuth, "This history is not published"))?;
                if let Some(len) = args.get("waitLength").and_then(Value::as_u64) {
                    let ms = args
                        .get("timeoutMs")
                        .and_then(Value::as_u64)
                        .unwrap_or(10_000);
                    p.wait_published(len, Duration::from_millis(ms)).await?;
                }
                let s = p.status();
                Ok(
                    json!({"instance": s.instance, "ready": s.ready, "nextIndex": s.next_index,
                          "headLength": s.head_length, "updates": s.updates, "errors": s.errors,
                          "lastError": s.last_error}),
                )
            }
            "history.unpublish" => {
                let p = self.publishers.lock().expect("publishers").remove(&sid()?);
                if let Some(p) = p {
                    p.stop();
                }
                Ok(Value::Null)
            }
            "history.readContract" => {
                let sid = sid()?;
                let backend = freenet.backend()?;
                let host = VerifyingKey::from_bytes(&hex_n::<32>(&args, "verifyingKey")?)
                    .map_err(|_| bad_args("verifyingKey"))?;
                let keys = epoch_keys(&args)?;
                let min = args
                    .get("minHeadLength")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let view = publish::read_offline(&backend, &host, &sid, min).await?;
                let from = args.get("from").and_then(Value::as_u64).unwrap_or(0);
                let count = args
                    .get("count")
                    .and_then(Value::as_u64)
                    .unwrap_or(64)
                    .min(MAX_SEGMENTS_PER_REQUEST as u64);
                let segs = blocking(move || {
                    let segs = view.open_range(from, count, &keys)?;
                    Ok((view, segs))
                })
                .await?;
                let (view, segs) = segs;
                Ok(
                    json!({"headLength": view.head_length, "chainRoot": hex::encode(view.chain_root),
                          "firstIndex": view.first_index, "held": view.len(),
                          "beyondHead": view.beyond_head,
                          "segments": segs.iter().map(|s| json!({"index": s.index,
                              "firstSeq": s.header.first_seq,
                              "packets": s.packets.iter().map(|(q, p)| packet_json(Some(*q), p)).collect::<Vec<_>>()})).collect::<Vec<_>>()}),
                )
            }
            other => Err(Error::new(
                Code::EBackendUnsupported,
                format!("no such seam method: {other}"),
            )),
        }
    }
}
