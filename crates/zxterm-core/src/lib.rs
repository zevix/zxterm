//! `zxterm-core`: the Rust core of the ZXTerm family (design `D-20`).
//!
//! This crate owns SSH keys, GitHub identity, the identity key and every
//! wire/signature/derivation string ZBTerm puts on the Freenet wire. It
//! carries no unsafe code.

#![forbid(unsafe_code)]

pub mod error;
pub mod freenet;
pub mod history;
pub mod identity;
pub mod idkey;
pub mod seam;
pub mod session;
pub mod ssh;
pub mod wire;

pub use error::{Code, Error};
