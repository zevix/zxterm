//! The seam (K7, spike S3): ZBTerm's Bare worker spawns the `zxterm-core`
//! binary as a sidecar and talks to it over a local socket with a
//! length-prefixed `postcard` frame protocol (`protocol`). `server` owns
//! profile ownership (an exclusive lock file) and the socket's connection
//! loop; `methods` is the method dispatcher (`core.version`, `core.health`,
//! every `identity.*` method); `backlog` is the droppable-`Output`
//! back-pressure mechanism (`S-35` moved to this seam); `test_methods`
//! (behind the `seam-test` Cargo feature) adds `test.flood`/`test.echo`.
//!
//! Not yet wired into any existing ZBTerm code path — K9 does that (this
//! phase's Goal).
//!
//! > 2026-09-29, K9: wired. ZBTerm's worker now reaches every identity path
//! > through this seam; K9 adds `identity.get`, the byte-layout helpers
//! > (`identity.claimBytes`, `identity.challengeBytes`,
//! > `identity.fingerprint`, `identity.parseSignature`,
//! > `identity.verifySshSignature`), the live-challenge pair
//! > (`identity.signChallenge`, `identity.verifyChallenge`) and the
//! > identity-key methods of `idkey_methods` (`idkey.create`,
//! > `idkey.derive`, `idkey.verify`).
//!
//! > 2026-09-29, K10: `freenet_methods` adds the Freenet transport service
//! > (`freenet.*` methods and events) and `protocol::Frame::Chan`, the
//! > non-droppable raw-channel frame (`X-17`).
//!
//! > 2026-09-30, K13: `share_methods` adds the session protocol v2
//! > (`crate::session`) as the `share.*` methods and events, bytes as base64
//! > in the JSON payloads (no new frame kind).
//!
//! > 2026-09-30, K15: `history_methods` adds C3 history (`crate::history`) as
//! > the `history.*` methods, and `share.historyCredit`; a history opened
//! > through the seam is served live on the `history` channel.

pub mod backlog;
pub mod freenet_methods;
pub mod history_methods;
pub mod idkey_methods;
pub mod methods;
pub mod protocol;
pub mod server;
pub mod share_methods;

#[cfg(feature = "seam-test")]
pub mod test_methods;

pub use methods::{After, ConnCtx, Dispatcher, to_wire_error};
pub use protocol::{Frame, MAX_FRAME_BYTES, WireError, decode, encode, read_frame, write_frame};
pub use server::{
    LockGuard, LockOutcome, OUTBOUND_QUEUE_DEPTH, lock_path, socket_path, try_acquire_profile_lock,
};

#[cfg(unix)]
pub use server::{bind_socket, serve};
