//! One WebSocket client of a Freenet node (design §4.3, §10; K5), the Rust
//! twin of ZBTerm `engine/backends/freenet/node-client.js`.
//!
//! Built against `freenet-stdlib` 0.12.1 (see `Cargo.toml`'s comment for
//! why: this machine's node is 0.2.139, built on 0.12.1, not the `=0.10.0`
//! ZBTerm JS pins).
//!
//! `node-client.js`'s header documents four SDK/node quirks (`S-05`),
//! re-probed here (once `R-01` was resolved and the live gate could
//! actually reach the node) against this machine's real `freenet`/SDK
//! versions — the old JS-side symptoms were not assumed to still hold, and
//! two of the four no longer do (`docs/register.md` `R-02`-`R-05` record
//! what was actually observed, each with its own row):
//!
//! (a) does **not** reproduce (`R-02`): the SDK's own `subscribe` acks
//!     promptly with a genuine `SubscribeResponse`. `subscribe` here still
//!     also accepts a `PutResponse` for the same key (cheap, defensive);
//! (b) reproduces (`R-03`): a second `Put` of an instance the node already
//!     holds is answered with an `UpdateResponse`, which `put`'s own ack
//!     wait never matches — callers never `Put` the same instance twice;
//! (c) does **not** reproduce (`R-04`): a `Get` of a genuinely missing
//!     instance answers promptly with a clean typed error, not silence.
//!     `get` still takes its own `timeout_ms` regardless — nothing here
//!     promises every future case answers this fast;
//! (d) reproduces (`R-05`): a delta the contract refuses is never answered
//!     (`S-19`), so `update` always carries its own timeout; the
//!     notification after a successful update carried the whole `State`
//!     variant, not an incremental `Delta` — `notification_parts` extracts
//!     whichever of `state`/`delta` a notification actually carries,
//!     defensively, like `notificationParts`.
//!
//! No wire, signature or derivation string lives here: the node URL and
//! timeouts below are plain numbers/paths, not wire strings (K1's
//! convention only binds strings that cross the wire as bytes). The one
//! exception, `ENCODING_PROTOCOL_NATIVE`, is not a *ZBTerm* wire string
//! (ZBTerm's JS SDK never sends it — it sends `"flatbuffers"`, `node_modules/
//! @freenetorg/freenet-stdlib/dist/src/websocket-interface.js`'s
//! `ENCODING_PROTOC`), so `wire.rs`'s "every ZBTerm wire string" charter
//! does not cover it; it is this Rust client's own connection detail and
//! lives beside the client that uses it, per K1's convention for
//! non-ZBTerm strings.
//!
//! R-01 (resolved): this machine's node defaults its public WS endpoint to
//! the flatbuffers encoding (same default the JS SDK opts into explicitly),
//! which none of this crate's Rust client code encodes — every
//! `freenet-stdlib` Rust client (`regular.rs`, `browser.rs`) speaks bincode,
//! the node's `EncodingProtocol::Native` path
//! (`freenet_stdlib::client_api::client_events`'s wire-format-pin doc
//! comments say so explicitly). The fix is `connect`'s own job: every
//! connection appends `?encodingProtocol=native` to the URL, confirmed
//! empirically against this machine's `freenet` 0.2.139 (a `Get` of a
//! genuinely missing instance now round-trips as a clean, well-typed
//! `ContractError::MissingContract`, not a decode error).

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use freenet_stdlib::client_api::Error as SdkError;
use freenet_stdlib::client_api::{
    ClientError, ClientRequest, ContractRequest, ContractResponse, HostResponse, WebApi,
};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractInstanceId, ContractKey, ContractWasmAPIVersion,
    Parameters, RelatedContracts, StateDelta, UpdateData, WrappedContract, WrappedState,
};
use tokio::time::timeout;

use crate::error::{Code, Error};

/// `node-client.js::OPEN_TIMEOUT_MS`.
pub const OPEN_TIMEOUT_MS: u64 = 5_000;
/// `node-client.js::REQUEST_TIMEOUT_MS`.
pub const REQUEST_TIMEOUT_MS: u64 = 10_000;

/// `index.js::DEFAULT_NODE_URL`.
pub const DEFAULT_NODE_URL: &str = "ws://127.0.0.1:7509/v1/contract/command";
/// `index.js::PROBE_TIMEOUT_MS`.
pub const PROBE_TIMEOUT_MS: u64 = 2_000;
/// `index.js::ANNOUNCE_GET_MS`.
pub const ANNOUNCE_GET_MS: u64 = 2_000;
/// `index.js::DIAL_GET_GAP_MS`.
pub const DIAL_GET_GAP_MS: u64 = 1_000;
/// `index.js::POINTER_GET_MS`.
pub const POINTER_GET_MS: u64 = 5_000;
/// `index.js::TOMBSTONE_TIMEOUT_MS`.
pub const TOMBSTONE_TIMEOUT_MS: u64 = 3_000;
/// `index.js::FLUSH_MS`.
pub const FLUSH_MS: u64 = 25;
/// `index.js::POINTER_VER`.
pub const POINTER_VER: u64 = 1;

/// The query parameter this client's `connect` appends to every node URL to
/// select the node's native (bincode) wire encoding.
pub const ENCODING_PROTOCOL_QUERY_PARAM: &str = "encodingProtocol";
/// The value that selects bincode (`EncodingProtocol::Native` in
/// freenet-core). Confirmed against this machine's `freenet` 0.2.139:
/// `native` (this exact lowercase spelling) is accepted; `Native` and
/// `bincode` are both rejected with an HTTP 400 at the WS handshake, and
/// omitting the parameter (or passing `flatbuffers`, the JS SDK's own
/// value) defaults to flatbuffers, which no `freenet-stdlib` Rust client
/// decodes.
pub const ENCODING_PROTOCOL_NATIVE: &str = "native";

/// Appends `encodingProtocol=native` to `url` (`&` if it already carries a
/// query string, `?` otherwise).
fn with_native_encoding(url: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}{ENCODING_PROTOCOL_QUERY_PARAM}={ENCODING_PROTOCOL_NATIVE}")
}

fn io_err(what: &str) -> Error {
    Error::with_details(
        Code::ENet,
        "The Freenet node request failed",
        what.to_string(),
    )
}

fn client_err(what: &str, e: ClientError) -> Error {
    Error::with_details(
        Code::ENet,
        "The Freenet node request failed",
        format!("{what}: {e}"),
    )
}

fn sdk_err(what: &str, e: SdkError) -> Error {
    Error::with_details(
        Code::ENet,
        "The Freenet node request failed",
        format!("{what}: {e}"),
    )
}

/// blake3(codeHash ‖ params): the id a contract instance is addressed by
/// (`node-client.js::instanceId`). Distinct from `route::instance_id_b58`,
/// which base58-encodes this same digest — the two files export a
/// function of the same name for two different things.
pub fn instance_id(code_hash: &[u8; 32], params: &[u8]) -> [u8; 32] {
    let mut both = Vec::with_capacity(32 + params.len());
    both.extend_from_slice(code_hash);
    both.extend_from_slice(params);
    blake3::hash(&both).into()
}

/// `node-client.js::contractKey`: the raw wasm's blake3 code hash, the
/// derived `ContractKey`, and the instance id's base58 string.
pub struct ContractAddr {
    pub key: ContractKey,
    /// base58(instance id).
    pub id: String,
    pub code_hash: [u8; 32],
}

pub fn contract_key(wasm: &[u8], params: &[u8]) -> ContractAddr {
    let code_hash: [u8; 32] = blake3::hash(wasm).into();
    let code = ContractCode::from(wasm.to_vec());
    let parameters = Parameters::from(params.to_vec());
    let key = ContractKey::from_params_and_code(&parameters, &code);
    ContractAddr {
        id: key.encoded_contract_id(),
        key,
        code_hash,
    }
}

/// A short, debug-only label for a `HostResponse`'s shape (`PutResponse`,
/// `UpdateResponse`, `SubscribeResponse`, …) — for S-05 diagnostics only,
/// not used by any production call path.
pub fn response_kind(resp: &HostResponse) -> &'static str {
    match resp {
        HostResponse::ContractResponse(ContractResponse::PutResponse { .. }) => "PutResponse",
        HostResponse::ContractResponse(ContractResponse::GetResponse { .. }) => "GetResponse",
        HostResponse::ContractResponse(ContractResponse::UpdateResponse { .. }) => "UpdateResponse",
        HostResponse::ContractResponse(ContractResponse::SubscribeResponse { .. }) => {
            "SubscribeResponse"
        }
        HostResponse::ContractResponse(ContractResponse::UpdateNotification { .. }) => {
            "UpdateNotification"
        }
        HostResponse::ContractResponse(ContractResponse::NotFound { .. }) => "NotFound",
        HostResponse::Ok => "Ok",
        _ => "other",
    }
}

/// A short, debug-only label for which `UpdateData` variant an
/// `UpdateNotification` actually carried (S-05 d diagnostics: "1 part"
/// alone does not say whether that part was the whole state or an
/// incremental delta — this does).
pub fn update_data_kind(update: &UpdateData<'_>) -> &'static str {
    match update {
        UpdateData::State(_) => "State",
        UpdateData::Delta(_) => "Delta",
        UpdateData::StateAndDelta { .. } => "StateAndDelta",
        UpdateData::RelatedState { .. } => "RelatedState",
        UpdateData::RelatedDelta { .. } => "RelatedDelta",
        UpdateData::RelatedStateAndDelta { .. } => "RelatedStateAndDelta",
        _ => "other",
    }
}

/// The state or delta bytes an `UpdateNotification` carries, whichever the
/// node actually sent — extracted defensively, matching
/// `notificationParts` (S-05 d: never assumed to be an incremental delta).
pub fn notification_parts(update: &UpdateData<'_>) -> Vec<Vec<u8>> {
    match update {
        UpdateData::State(s) => vec![s.as_ref().to_vec()],
        UpdateData::Delta(d) => vec![d.as_ref().to_vec()],
        UpdateData::StateAndDelta { state, delta } => {
            vec![state.as_ref().to_vec(), delta.as_ref().to_vec()]
        }
        UpdateData::RelatedState { state, .. } => vec![state.as_ref().to_vec()],
        UpdateData::RelatedDelta { delta, .. } => vec![delta.as_ref().to_vec()],
        UpdateData::RelatedStateAndDelta { state, delta, .. } => {
            vec![state.as_ref().to_vec(), delta.as_ref().to_vec()]
        }
        _ => Vec::new(),
    }
}

/// One WebSocket client of a Freenet node (`node-client.js::connect`'s
/// twin). Every request carries its own timeout; nothing waits on the
/// SDK's internal 30 s timer.
pub struct Client {
    api: WebApi,
    /// Responses read while waiting for a different match, replayed to the
    /// next matching call — the Rust analogue of `node-client.js`'s
    /// `putListeners` array (one predicate at a time is enough for K5's
    /// sequential test usage; a later phase can generalise to concurrent
    /// in-flight requests if it needs to).
    backlog: VecDeque<HostResponse>,
}

impl Client {
    /// Opens one client. Resolves once the socket is open; errors if it
    /// does not open within `OPEN_TIMEOUT_MS`.
    pub async fn connect(url: &str) -> Result<Client, Error> {
        let url = with_native_encoding(url);
        let connect_fut = tokio_tungstenite::connect_async(&url);
        let (stream, _response) = timeout(Duration::from_millis(OPEN_TIMEOUT_MS), connect_fut)
            .await
            .map_err(|_| io_err(&format!("not open within {OPEN_TIMEOUT_MS} ms")))?
            .map_err(|e| io_err(&format!("connect: {e}")))?;
        Ok(Client {
            api: WebApi::start(stream),
            backlog: VecDeque::new(),
        })
    }

    async fn send(&mut self, req: ClientRequest<'static>) -> Result<(), Error> {
        self.api.send(req).await.map_err(|e| sdk_err("send", e))
    }

    /// Waits up to `timeout_ms` for a response `pred` accepts, checking the
    /// backlog first. Non-matching responses (including unsolicited
    /// notifications) are kept in the backlog for a later call.
    async fn recv_matching<F>(
        &mut self,
        mut pred: F,
        timeout_ms: u64,
    ) -> Result<HostResponse, Error>
    where
        F: FnMut(&HostResponse) -> bool,
    {
        if let Some(pos) = self.backlog.iter().position(&mut pred) {
            return Ok(self.backlog.remove(pos).expect("position() found it"));
        }
        let deadline = Instant::now() + Duration::from_millis(timeout_ms.min(REQUEST_TIMEOUT_MS));
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io_err("no answer within the request timeout"));
            }
            match timeout(remaining, self.api.recv()).await {
                Err(_) => return Err(io_err("no answer within the request timeout")),
                Ok(Err(e)) => return Err(client_err("recv", e)),
                Ok(Ok(resp)) => {
                    if pred(&resp) {
                        return Ok(resp);
                    }
                    self.backlog.push_back(resp);
                }
            }
        }
    }

    /// (b) Only ever call for an instance this client has never `Put`.
    pub async fn put(&mut self, wasm: &[u8], params: &[u8], state: Vec<u8>) -> Result<(), Error> {
        let addr = contract_key(wasm, params);
        let code = ContractCode::from(wasm.to_vec());
        let parameters = Parameters::from(params.to_vec());
        let contract = WrappedContract::new(Arc::new(code), parameters);
        let container = ContractContainer::Wasm(ContractWasmAPIVersion::V1(contract));
        self.send(
            ContractRequest::Put {
                contract: container,
                state: WrappedState::from(state),
                related_contracts: RelatedContracts::new(),
                subscribe: false,
                blocking_subscribe: false,
            }
            .into(),
        )
        .await?;
        let want_id = addr.key.encoded_contract_id();
        self.recv_matching(
            |r| matches!(r, HostResponse::ContractResponse(ContractResponse::PutResponse{ key }) if key.encoded_contract_id() == want_id),
            REQUEST_TIMEOUT_MS,
        )
        .await?;
        Ok(())
    }

    /// (c) A local-mode node never answers a miss: this always carries its
    /// own `timeout_ms`, never the SDK's.
    pub async fn get(
        &mut self,
        instance: &ContractInstanceId,
        timeout_ms: u64,
    ) -> Result<Vec<u8>, Error> {
        self.send(
            ContractRequest::Get {
                key: *instance,
                return_contract_code: false,
                subscribe: false,
                blocking_subscribe: false,
            }
            .into(),
        )
        .await?;
        let want = *instance;
        let resp = self
            .recv_matching(
                |r| match r {
                    HostResponse::ContractResponse(ContractResponse::GetResponse {
                        key, ..
                    }) => *key.id() == want,
                    HostResponse::ContractResponse(ContractResponse::NotFound { instance_id }) => {
                        *instance_id == want
                    }
                    _ => false,
                },
                timeout_ms,
            )
            .await?;
        match resp {
            HostResponse::ContractResponse(ContractResponse::GetResponse { state, .. }) => {
                Ok(state.as_ref().to_vec())
            }
            HostResponse::ContractResponse(ContractResponse::NotFound { .. }) => {
                Err(Error::with_details(
                    Code::ENet,
                    "The Freenet node has no state for this instance",
                    "not found",
                ))
            }
            _ => unreachable!("recv_matching only returns what its predicate accepted"),
        }
    }

    /// (a) The SDK's own subscribe ack may never arrive; a `PutResponse`
    /// for the same key is accepted too (S-05 a's documented substitute
    /// ack). Whichever this machine's node actually sends is recorded in
    /// K5's handoff notes.
    /// Returns which response actually acked the subscription
    /// (`"SubscribeResponse"` or `"PutResponse"`, see `response_kind`) —
    /// useful for S-05(a) diagnostics; production callers can ignore it.
    pub async fn subscribe(
        &mut self,
        instance: &ContractInstanceId,
    ) -> Result<&'static str, Error> {
        self.send(
            ContractRequest::Subscribe {
                key: *instance,
                summary: None,
            }
            .into(),
        )
        .await?;
        let want = *instance;
        let resp = self
            .recv_matching(
                |r| match r {
                    HostResponse::ContractResponse(ContractResponse::SubscribeResponse {
                        key,
                        ..
                    }) => *key.id() == want,
                    HostResponse::ContractResponse(ContractResponse::PutResponse { key }) => {
                        *key.id() == want
                    }
                    _ => false,
                },
                REQUEST_TIMEOUT_MS,
            )
            .await?;
        Ok(response_kind(&resp))
    }

    /// Debug-only: the response kinds currently buffered in the backlog
    /// (unmatched responses from earlier calls), for S-05 diagnostics —
    /// not used by any production call path.
    pub fn backlog_kinds(&self) -> Vec<&'static str> {
        self.backlog.iter().map(response_kind).collect()
    }

    /// A delta the contract refuses is never answered (`S-19`); this always
    /// carries its own `timeout_ms`.
    pub async fn update(
        &mut self,
        key: &ContractKey,
        delta: Vec<u8>,
        timeout_ms: u64,
    ) -> Result<(), Error> {
        self.send(
            ContractRequest::Update {
                key: *key,
                data: UpdateData::Delta(StateDelta::from(delta)),
            }
            .into(),
        )
        .await?;
        let want = *key.id();
        self.recv_matching(
            |r| matches!(r, HostResponse::ContractResponse(ContractResponse::UpdateResponse { key, .. }) if *key.id() == want),
            timeout_ms,
        )
        .await?;
        Ok(())
    }

    /// Waits up to `timeout_ms` for the next `UpdateNotification` for
    /// `instance` (any earlier one already buffered in the backlog is
    /// returned first), returning its raw parts (`notification_parts`).
    pub async fn recv_notification(
        &mut self,
        instance: &ContractInstanceId,
        timeout_ms: u64,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let (parts, _kind) = self
            .recv_notification_with_kind(instance, timeout_ms)
            .await?;
        Ok(parts)
    }

    /// Like `recv_notification`, but also returns which `UpdateData`
    /// variant the node actually sent (`update_data_kind`) — S-05(d)
    /// diagnostics; production callers use `recv_notification`.
    pub async fn recv_notification_with_kind(
        &mut self,
        instance: &ContractInstanceId,
        timeout_ms: u64,
    ) -> Result<(Vec<Vec<u8>>, &'static str), Error> {
        let want = *instance;
        let resp = self
            .recv_matching(
                |r| matches!(r, HostResponse::ContractResponse(ContractResponse::UpdateNotification { key, .. }) if *key.id() == want),
                timeout_ms,
            )
            .await?;
        match resp {
            HostResponse::ContractResponse(ContractResponse::UpdateNotification {
                update, ..
            }) => Ok((notification_parts(&update), update_data_kind(&update))),
            _ => unreachable!("recv_matching only returns what its predicate accepted"),
        }
    }
}

/// What a [`Shared`] client reports besides request answers.
#[derive(Debug)]
pub enum NodeEvent {
    /// An `UpdateNotification` for instance `id` (base58), its state or
    /// delta parts (`notification_parts`).
    Notification { id: String, parts: Vec<Vec<u8>> },
    /// The WebSocket closed; every later request fails.
    Closed,
}

type Matcher = Box<dyn Fn(&HostResponse) -> bool + Send>;

struct Waiter {
    matcher: Matcher,
    /// The instance the request names, to route a keyed error to it.
    instance: ContractInstanceId,
    deadline: Instant,
    reply: tokio::sync::oneshot::Sender<Result<HostResponse, Error>>,
}

enum Cmd {
    Request {
        req: Box<ClientRequest<'static>>,
        waiter: Waiter,
    },
    Close,
}

/// One WebSocket client of a Freenet node shared by many concurrent
/// requests (K10): `super::backend` puts, gets, updates and subscribes for
/// every link and dial on one connection, as `index.js` does with its one
/// `node-client.js` socket (subscriptions are per WebSocket connection, K6).
/// An actor task owns the socket; each request registers a matcher and a
/// deadline, answers go to the first matching waiter, and
/// `UpdateNotification`s go to the [`NodeEvent`] stream `connect` returns.
///
/// An error answer that names a contract (`ContractError::{Get, Put,
/// Update, Subscribe, MissingContract}`) fails the waiters of that
/// instance; one that names none fails the oldest waiter. The SDK's
/// `recv()` is not cancellation-safe for *streamed* responses; the actor
/// drives it in `select!` beside its command queue, so a streamed answer
/// (a multi-megabyte state, which no contract here holds) could be lost
/// when a command arrives mid-stream: a known residual, bounded by every
/// request's own timeout.
#[derive(Clone)]
pub struct Shared {
    tx: tokio::sync::mpsc::UnboundedSender<Cmd>,
}

fn error_instance(e: &ClientError) -> Option<ContractInstanceId> {
    use freenet_stdlib::client_api::{ContractError, ErrorKind, RequestError};
    match e.kind() {
        ErrorKind::RequestError(RequestError::ContractError(ce)) => match ce {
            ContractError::Get { key, .. }
            | ContractError::Put { key, .. }
            | ContractError::Update { key, .. }
            | ContractError::Subscribe { key, .. } => Some(*key.id()),
            ContractError::MissingContract { key } | ContractError::MissingRelated { key } => {
                Some(*key)
            }
            _ => None,
        },
        _ => None,
    }
}

async fn run_shared(
    mut api: WebApi,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Cmd>,
    events: tokio::sync::mpsc::UnboundedSender<NodeEvent>,
) {
    let mut waiters: Vec<Waiter> = Vec::new();
    loop {
        let next = waiters
            .iter()
            .map(|w| w.deadline)
            .min()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));
        tokio::select! {
            cmd = rx.recv() => match cmd {
                Some(Cmd::Request { req, waiter }) => {
                    if let Err(e) = api.send(*req).await {
                        let _ = waiter.reply.send(Err(sdk_err("send", e)));
                    } else {
                        waiters.push(waiter);
                    }
                }
                Some(Cmd::Close) | None => break,
            },
            res = api.recv() => match res {
                Ok(HostResponse::ContractResponse(ContractResponse::UpdateNotification { key, update })) => {
                    let _ = events.send(NodeEvent::Notification {
                        id: key.encoded_contract_id(),
                        parts: notification_parts(&update),
                    });
                }
                Ok(resp) => {
                    if let Some(pos) = waiters.iter().position(|w| (w.matcher)(&resp)) {
                        let w = waiters.remove(pos);
                        let _ = w.reply.send(Ok(resp));
                    }
                }
                Err(e) => {
                    use freenet_stdlib::client_api::ErrorKind;
                    if matches!(e.kind(), ErrorKind::ChannelClosed | ErrorKind::Disconnect | ErrorKind::TransportProtocolDisconnect) {
                        break;
                    }
                    let target = error_instance(&e)
                        .and_then(|id| waiters.iter().position(|w| w.instance == id))
                        .or(if waiters.is_empty() { None } else { Some(0) });
                    if let Some(pos) = target {
                        let w = waiters.remove(pos);
                        let _ = w.reply.send(Err(client_err("recv", e)));
                    }
                }
            },
            () = tokio::time::sleep_until(tokio::time::Instant::from_std(next)) => {
                let now = Instant::now();
                let (expired, kept): (Vec<Waiter>, Vec<Waiter>) =
                    waiters.drain(..).partition(|w| w.deadline <= now);
                waiters = kept;
                for w in expired {
                    let _ = w.reply.send(Err(io_err("no answer within the request timeout")));
                }
            }
        }
    }
    for w in waiters {
        let _ = w.reply.send(Err(io_err("the node connection closed")));
    }
    let _ = events.send(NodeEvent::Closed);
}

impl Shared {
    /// Opens one shared client; errors if the socket does not open within
    /// `open_timeout_ms`.
    pub async fn connect(
        url: &str,
        open_timeout_ms: u64,
    ) -> Result<(Shared, tokio::sync::mpsc::UnboundedReceiver<NodeEvent>), Error> {
        let url = with_native_encoding(url);
        let (stream, _response) = timeout(
            Duration::from_millis(open_timeout_ms),
            tokio_tungstenite::connect_async(&url),
        )
        .await
        .map_err(|_| io_err(&format!("not open within {open_timeout_ms} ms")))?
        .map_err(|e| io_err(&format!("connect: {e}")))?;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let (etx, erx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(run_shared(WebApi::start(stream), rx, etx));
        Ok((Shared { tx }, erx))
    }

    async fn request(
        &self,
        req: ClientRequest<'static>,
        instance: ContractInstanceId,
        matcher: Matcher,
        timeout_ms: u64,
    ) -> Result<HostResponse, Error> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        let waiter = Waiter {
            matcher,
            instance,
            deadline: Instant::now() + Duration::from_millis(timeout_ms.min(REQUEST_TIMEOUT_MS)),
            reply,
        };
        self.tx
            .send(Cmd::Request {
                req: Box::new(req),
                waiter,
            })
            .map_err(|_| io_err("the node connection closed"))?;
        rx.await.map_err(|_| io_err("the node connection closed"))?
    }

    /// `Client::put`'s twin: only for an instance never put before (`R-03`).
    pub async fn put(
        &self,
        wasm: &[u8],
        params: &[u8],
        state: Vec<u8>,
        timeout_ms: u64,
    ) -> Result<(), Error> {
        let addr = contract_key(wasm, params);
        let code = ContractCode::from(wasm.to_vec());
        let parameters = Parameters::from(params.to_vec());
        let contract = WrappedContract::new(Arc::new(code), parameters);
        let container = ContractContainer::Wasm(ContractWasmAPIVersion::V1(contract));
        let want = *addr.key.id();
        self.request(
            ContractRequest::Put {
                contract: container,
                state: WrappedState::from(state),
                related_contracts: RelatedContracts::new(),
                subscribe: false,
                blocking_subscribe: false,
            }
            .into(),
            want,
            Box::new(move |r| {
                matches!(r, HostResponse::ContractResponse(ContractResponse::PutResponse { key }) if *key.id() == want)
            }),
            timeout_ms,
        )
        .await
        .map(|_| ())
    }

    /// `Client::get`'s twin: the instance's state bytes.
    pub async fn get(
        &self,
        instance: &ContractInstanceId,
        timeout_ms: u64,
    ) -> Result<Vec<u8>, Error> {
        let want = *instance;
        let resp = self
            .request(
                ContractRequest::Get {
                    key: want,
                    return_contract_code: false,
                    subscribe: false,
                    blocking_subscribe: false,
                }
                .into(),
                want,
                Box::new(move |r| match r {
                    HostResponse::ContractResponse(ContractResponse::GetResponse {
                        key, ..
                    }) => *key.id() == want,
                    HostResponse::ContractResponse(ContractResponse::NotFound { instance_id }) => {
                        *instance_id == want
                    }
                    _ => false,
                }),
                timeout_ms,
            )
            .await?;
        match resp {
            HostResponse::ContractResponse(ContractResponse::GetResponse { state, .. }) => {
                Ok(state.as_ref().to_vec())
            }
            _ => Err(Error::with_details(
                Code::ENet,
                "The Freenet node has no state for this instance",
                "not found",
            )),
        }
    }

    /// `Client::subscribe`'s twin (a `PutResponse` for the key also acks,
    /// S-05 a, defensively).
    pub async fn subscribe(&self, instance: &ContractInstanceId) -> Result<(), Error> {
        let want = *instance;
        self.request(
            ContractRequest::Subscribe {
                key: want,
                summary: None,
            }
            .into(),
            want,
            Box::new(move |r| match r {
                HostResponse::ContractResponse(ContractResponse::SubscribeResponse {
                    key, ..
                }) => *key.id() == want,
                HostResponse::ContractResponse(ContractResponse::PutResponse { key }) => {
                    *key.id() == want
                }
                _ => false,
            }),
            REQUEST_TIMEOUT_MS,
        )
        .await
        .map(|_| ())
    }

    /// `Client::update`'s twin: a delta the contract refuses is never
    /// answered (`S-19`), so this always carries `timeout_ms`.
    pub async fn update(
        &self,
        key: &ContractKey,
        delta: Vec<u8>,
        timeout_ms: u64,
    ) -> Result<(), Error> {
        let want = *key.id();
        self.request(
            ContractRequest::Update {
                key: *key,
                data: UpdateData::Delta(StateDelta::from(delta)),
            }
            .into(),
            want,
            Box::new(move |r| {
                matches!(r, HostResponse::ContractResponse(ContractResponse::UpdateResponse { key, .. }) if *key.id() == want)
            }),
            timeout_ms,
        )
        .await
        .map(|_| ())
    }

    /// Closes the socket; pending requests fail.
    pub fn close(&self) {
        let _ = self.tx.send(Cmd::Close);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_native_encoding_appends_query_param() {
        assert_eq!(
            with_native_encoding("ws://127.0.0.1:7509/v1/contract/command"),
            "ws://127.0.0.1:7509/v1/contract/command?encodingProtocol=native"
        );
    }

    #[test]
    fn with_native_encoding_uses_ampersand_when_a_query_string_is_already_present() {
        assert_eq!(
            with_native_encoding("ws://127.0.0.1:7509/v1/contract/command?foo=bar"),
            "ws://127.0.0.1:7509/v1/contract/command?foo=bar&encodingProtocol=native"
        );
    }

    #[test]
    fn instance_id_is_raw_blake3_not_base58() {
        let code_hash = [7u8; 32];
        let params = b"params";
        let id = instance_id(&code_hash, params);
        let mut both = Vec::new();
        both.extend_from_slice(&code_hash);
        both.extend_from_slice(params);
        assert_eq!(id, <[u8; 32]>::from(blake3::hash(&both)));
        // route::instance_id_b58 of the same inputs is the base58 string of
        // this same digest, not equal to it as bytes.
        let b58 = crate::freenet::route::instance_id_b58(&hex::encode(code_hash), params);
        assert_eq!(b58, bs58::encode(id).into_string());
    }

    #[test]
    fn contract_key_derives_from_wasm_and_params() {
        let wasm = b"pretend-wasm-bytes";
        let params = b"pretend-params";
        let addr = contract_key(wasm, params);
        assert_eq!(addr.code_hash, <[u8; 32]>::from(blake3::hash(wasm)));
        assert!(!addr.id.is_empty());
    }

    #[test]
    fn notification_parts_extracts_state_and_delta_defensively() {
        let state = UpdateData::State(freenet_stdlib::prelude::State::from(vec![1u8, 2, 3]));
        assert_eq!(notification_parts(&state), vec![vec![1u8, 2, 3]]);

        let delta = UpdateData::Delta(StateDelta::from(vec![4u8, 5]));
        assert_eq!(notification_parts(&delta), vec![vec![4u8, 5]]);

        let both = UpdateData::StateAndDelta {
            state: freenet_stdlib::prelude::State::from(vec![1u8]),
            delta: StateDelta::from(vec![2u8]),
        };
        assert_eq!(notification_parts(&both), vec![vec![1u8], vec![2u8]]);
    }
}
