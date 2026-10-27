//! The viewer's per-join state (`protocol.md` §5, §8, §10): the dial, the
//! three channels, the `ctl` queue that serialises every non-identity
//! message behind a `Confirm` still in its identity step
//! (`state.messageQueue`), the `live` messages held until `Confirm` is
//! applied, the epoch keys the envelopes opened, and the input counter,
//! which restarts in every epoch the viewer installs (**v2**, ZBTerm
//! `S-43`).

use std::collections::{BTreeMap, VecDeque};

use super::LocalIdentity;
use super::messages::{CtlMsg, InputMode, Key32, LiveMsg, SessionInfo};
use crate::freenet::backend::{ChanHandle, ConnHandle};

/// One installed epoch's keys, as the envelope carried them.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ViewerKeys {
    pub history_key: Option<[u8; 32]>,
    pub live_key: Option<[u8; 32]>,
}

impl std::fmt::Debug for ViewerKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewerKeys")
            .field("history", &self.history_key.is_some())
            .field("live", &self.live_key.is_some())
            .finish()
    }
}

/// The session a confirmed join joined.
#[derive(Debug, Clone)]
pub struct Joined {
    pub session_id: String,
    pub info: SessionInfo,
    pub input_mode: InputMode,
    pub host_device_key: Key32,
    pub caps: u8,
}

/// One join (`share-manager.js::join`'s `state`).
pub struct ViewerJoin {
    pub join_id: String,
    pub link_id: [u8; 16],
    pub expected_peer_key: Key32,
    pub local: LocalIdentity,
    pub device_key: Key32,
    pub dial: u64,
    pub conn: Option<ConnHandle>,
    pub ctl: Option<ChanHandle>,
    pub live: Option<ChanHandle>,
    pub history: Option<ChanHandle>,
    pub done: bool,
    pub confirmed: bool,
    /// The first `Bootstrap` arrived (`state.joined`).
    pub joined: bool,
    /// The join timer's token (0: none armed).
    pub timer: u64,
    /// A `Confirm` in its identity step blocks the `ctl` queue.
    pub blocked: bool,
    pub queue: VecDeque<CtlMsg>,
    /// `live` messages that arrived before `Confirm` was applied.
    pub held: Vec<LiveMsg>,
    pub pending_confirm: Option<CtlMsg>,
    pub challenge: Option<super::service::PendingChallenge>,
    pub session: Option<Joined>,
    pub keys: BTreeMap<u32, ViewerKeys>,
    pub epoch: u32,
    /// The last input counter sealed in [`Self::epoch`].
    pub input_ctr: u64,
    pub next_history_request: u32,
}

impl ViewerJoin {
    /// Installs an opened envelope's keys for `epoch`; a higher epoch
    /// becomes the current one and restarts the input counter (`S-43`).
    pub fn install(&mut self, epoch: u32, keys: ViewerKeys) {
        self.keys.insert(epoch, keys);
        if epoch > self.epoch {
            self.epoch = epoch;
            self.input_ctr = 0;
        }
    }

    /// The next input counter in the current epoch.
    pub fn next_input_ctr(&mut self) -> u64 {
        self.input_ctr += 1;
        self.input_ctr
    }
}
