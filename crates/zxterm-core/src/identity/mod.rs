//! Identity claims, two-layer verification and GitHub key resolution (design
//! spike S4, part 2), ported from ZBTerm `engine/identity/{claim,verify,
//! providers,resolver,store}.js` and `electron/github-keys.js` with
//! byte-identical behaviour.
//!
//! The handshake inside `engine/share-manager.js` (`_issueIdentityChallenge`,
//! `_answerIdentityChallenge`, `_verifyViewerIdentity`, `_verifyHostIdentity`)
//! is **not** ported here — K9 routes ZBTerm's calls into this module over
//! the seam; this module only builds the library code the seam will call.
//!
//! The worker-to-shell `identity:resolve-request` round trip
//! (`resolver.js`'s `emit`/`handleResponse`/`pending` machinery) has no
//! counterpart here: the core resolves in-process, so `resolver` calls the
//! `github` client directly. The *cache semantics* (TTLs, in-flight dedupe,
//! cache-first, stale-on-failure) are ported exactly.

pub mod claim;
pub mod github;
pub mod providers;
pub mod resolver;
pub mod store;
pub mod verify;

pub use claim::{Challenge, Claim};
pub use providers::{GITHUB, UNKNOWN, get_provider};
pub use resolver::IdentityResolver;
pub use store::IdentityStore;
