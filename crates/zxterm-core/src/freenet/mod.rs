//! Freenet transport (design §4.3, `A-5`; spike S1, K5): a node client
//! wire-identical to ZBTerm's JS backend, route minting/verification, and
//! signalling/pointer-record signing and verification.
//!
//! No wire, signature or derivation string lives anywhere in this module:
//! every one is a `crate::wire` constant, referenced from `route`/`signal`,
//! never redefined here (`A-2`).
//!
//! `pointer.rs` is folded into `signal.rs` rather than kept as its own
//! module: ZBTerm itself has no separate pointer-signing file
//! (`signal.js` covers both signalling entries and pointer records), and
//! K5's brief explicitly allows matching that shape over inventing a new
//! module boundary. Likewise the contract-manifest loader
//! (`contracts.js`'s mirror) lives in `zxterm-testkit::contracts` rather
//! than here: it is test/dev-only (no `include_bytes!` until K10's `A-6`),
//! and the brief names `zxterm-testkit` as the alternative to a
//! `#[cfg(test)]`-gated module — chosen here because a `#[cfg(test)]` item
//! in this crate is invisible to the `tests/freenet_parity.rs` integration
//! test, which links against this crate built without `cfg(test)`.
//!
//! > 2026-09-29, K10: `contracts` now embeds the shipped contracts with
//! > `include_bytes!` (`A-6`, `X-16`); `backend` is the transport service
//! > (every `BACKEND_MEMBERS` method, admission limits, JSON and raw
//! > channels) on `node::Shared`, `rtc`, `connection` and `channel`; `stun`
//! > gives `rtc` server-reflexive candidates. `dial`'s single-connection
//! > `dial`/`accept_one` stay for the K6 parity tests.
//!
//! > 2026-09-29, K11: ZBTerm's Freenet backend is now a proxy to `backend`
//! > over the seam (ZBTerm `D-34`), and K11 removed the JS files this
//! > module's doc comments cite as twins (`index.js`, `rtc-host.js`,
//! > `channel.js`, `connection.js`, `signal.js`, `route.js`,
//! > `node-client.js`, `contracts.js`, `blake3.js`) from ZBTerm's live tree.
//! > Those citations name ZBTerm's JS reference revision
//! > (`zxterm_testkit::js::ZBTERM_JS_REFERENCE_REV`), where they still
//! > exist. K11 also changed `rtc`'s flow control (`R-11`) and made
//! > `backend` emit `Backpressure` in order with `Drain` (`R-12`).
//!
//! > 2026-09-30, K13: `route` carries the route protocol version `pv`
//! > (`protocol.md` §12, rules PV-1–PV-3), `channel`/`connection`/`backend`
//! > gain the binary message channel the session channels ride
//! > (`crate::session`), and `backend::BackendOptions::legacy_v1_routes`
//! > keeps a v1 backend for the interop tests (`X-23`).

pub mod backend;
pub mod channel;
pub mod connection;
pub mod contracts;
pub mod dial;
pub mod node;
pub mod route;
pub mod rtc;
pub mod signal;
pub mod stun;
