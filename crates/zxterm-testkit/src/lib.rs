//! `zxterm-testkit`: dev-only helpers shared by every crate's tests in this
//! workspace — a scratch `HOME`/`TMPDIR` (`ScratchHome`), a throwaway local
//! Freenet node (`LocalNode`, the Rust twin of ZBTerm
//! `test/helpers/freenet-node.js::startLocalNode`), a way to call into
//! ZBTerm's JS from Rust test code (`js::run`), a scriptable fake ssh-agent
//! and a loopback `.keys` HTTP server (for K2/K3's parity tests), and a
//! tool-presence skip helper (`require_tool`).
//!
//! This crate is `publish = false`: it never ships to crates.io.
//!
//! `ScratchHome` never mutates this process's own environment (a
//! process-global mutation would race every other `#[test]` in the same
//! binary); callers that need a scratch `HOME` for a child process take it
//! explicitly (`ScratchHome::env`/`command`). No file in this crate carries
//! unsafe code.

#![forbid(unsafe_code)]

pub mod contracts;
pub mod fake_agent;
pub mod js;
pub mod keys_server;
pub mod local_node;
pub mod require_tool;
pub mod scratch_home;

pub use contracts::Contracts;
pub use fake_agent::FakeAgent;
pub use keys_server::KeysServer;
pub use local_node::LocalNode;
pub use require_tool::require_tool;
pub use scratch_home::ScratchHome;
