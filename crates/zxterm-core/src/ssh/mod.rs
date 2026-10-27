//! SSH key discovery and SSHSIG signing (design spike S4, part 1), ported
//! from ZBTerm `electron/ssh-keys.js` (constants imported there from
//! `engine/identity/claim.js`) with byte-identical behaviour: config-based
//! and default key discovery, candidate listing and ranking, OpenSSH
//! private-key and public-key-line parsing, an ssh-agent client, and SSHSIG
//! signing/verification.
//!
//! Passphrase handling: never, anywhere in this module or its submodules.
//! No prompt, no `bcrypt_pbkdf` — an encrypted private key is reported
//! `encrypted: true` with no secret key material, exactly as ZBTerm's
//! `parseOpenSshPrivateKey` does.

pub mod agent;
pub mod candidates;
// K3: `pub(crate)` (was module-private) so `crate::identity::claim` can reuse
// `write_string`/`read_string`/`strip_mpint` for its own SSH-wire-format
// pubkey-blob encoders (`encode_ed25519_public_key`/`encode_rsa_public_key`)
// rather than duplicating them — no change to `codec.rs` itself.
pub(crate) mod codec;
pub mod config;
pub mod key;
pub mod sshsig;

pub use candidates::{Candidate, Source, inspect_key, list_candidates};
pub use config::identity_files_for_host;
