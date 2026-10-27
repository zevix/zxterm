//! Epochs and their keys (`protocol.md` §3.1, §4): the epoch master key
//! `K_e`, the history and live keys derived from it with ZBTerm's kdf
//! contexts (`crate::wire::HIST_CONTEXT`/`LIVE_CONTEXT`, ZBTerm `D-36`),
//! and the envelopes a rotation seals for each member device.
//!
//! [`derive_key`] is libsodium's `crypto_kdf_derive_from_key`
//! (`kdf_blake2b`) byte for byte: BLAKE2b, 32-byte output, key = the
//! master key, salt = `id` u64 LE then 8 zero bytes, personal = the 8
//! context bytes then 8 zero bytes, empty message.
//! `tests/session_crypto_parity.rs` pins it against ZBTerm's
//! `engine/crypto.js` on `sodium-native`.

use std::collections::BTreeMap;

use blake2::digest::FixedOutput;
use blake2::digest::consts::U32;
use crypto_box::aead::OsRng;
use crypto_box::aead::rand_core::RngCore;

use super::caps::{FULL_CAPS, READ_HISTORY, VIEW_LIVE, has_cap};
use super::envelope::{self, ENVELOPE_VERSION, Envelope};
use super::messages::Key32;
use crate::wire;

/// `crypto.js::deriveKey(masterKey, id, context)`.
pub fn derive_key(master_key: &[u8; 32], id: u64, context: &[u8; 8]) -> [u8; 32] {
    let mut salt = [0u8; 16];
    salt[..8].copy_from_slice(&id.to_le_bytes());
    let mut personal = [0u8; 16];
    personal[..8].copy_from_slice(context);
    let mac =
        blake2::Blake2bMac::<U32>::new_with_salt_and_personal(Some(master_key), &salt, &personal)
            .expect("key, salt and personal are within BLAKE2b's limits");
    mac.finalize_fixed().into()
}

fn context(c: &str) -> [u8; 8] {
    c.as_bytes()
        .try_into()
        .expect("kdf contexts are exactly 8 bytes")
}

/// `crypto.js::deriveHistoryKey`: `deriveKey(K_e, 1, "zxt-hist")`.
pub fn derive_history_key(master_key: &[u8; 32]) -> [u8; 32] {
    derive_key(master_key, 1, &context(wire::HIST_CONTEXT))
}

/// `crypto.js::deriveLiveKey`: `deriveKey(K_e, 2, "zxt-live")`.
pub fn derive_live_key(master_key: &[u8; 32]) -> [u8; 32] {
    derive_key(master_key, 2, &context(wire::LIVE_CONTEXT))
}

/// `crypto.js::deriveSnapshotKey`: `deriveKey(generichash32(local secret
/// key), 3, "zxt-snap")`. Never on the wire; here so the three contexts
/// have one home.
pub fn derive_snapshot_key(local_secret_key: &[u8]) -> [u8; 32] {
    let master = crate::idkey::proof::blake2b_256(local_secret_key);
    derive_key(&master, 3, &context(wire::SNAP_CONTEXT))
}

/// `crypto.js::generateEpochKey`: 32 random bytes.
pub fn generate_epoch_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    k
}

/// One epoch's keys (host side: all three).
#[derive(Clone, PartialEq, Eq)]
pub struct EpochKeys {
    pub number: u32,
    pub master_key: [u8; 32],
    pub history_key: [u8; 32],
    pub live_key: [u8; 32],
}

impl std::fmt::Debug for EpochKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochKeys")
            .field("number", &self.number)
            .finish_non_exhaustive()
    }
}

impl EpochKeys {
    /// The keys of epoch `number` from its master key.
    pub fn from_master(number: u32, master_key: [u8; 32]) -> EpochKeys {
        EpochKeys {
            number,
            history_key: derive_history_key(&master_key),
            live_key: derive_live_key(&master_key),
            master_key,
        }
    }

    /// A fresh epoch `number`.
    pub fn generate(number: u32) -> EpochKeys {
        EpochKeys::from_master(number, generate_epoch_key())
    }

    /// A member's envelope for this epoch (`session-store.js::rotateEpoch`):
    /// `historyKey` iff `READ_HISTORY`, `liveKey` iff `VIEW_LIVE`, never
    /// the master key.
    pub fn member_envelope(&self, session_id: &str, caps: u8) -> Envelope {
        Envelope {
            version: ENVELOPE_VERSION,
            session_id: session_id.to_string(),
            epoch: self.number as u64,
            caps: caps as u64,
            master_key: None,
            history_key: has_cap(caps, READ_HISTORY).then(|| self.history_key.to_vec()),
            live_key: has_cap(caps, VIEW_LIVE).then(|| self.live_key.to_vec()),
        }
    }

    /// The host's own envelope (`env/<n>/local`): all three keys,
    /// `FULL_CAPS`.
    pub fn local_envelope(&self, session_id: &str) -> Envelope {
        Envelope {
            version: ENVELOPE_VERSION,
            session_id: session_id.to_string(),
            epoch: self.number as u64,
            caps: FULL_CAPS as u64,
            master_key: Some(self.master_key.to_vec()),
            history_key: Some(self.history_key.to_vec()),
            live_key: Some(self.live_key.to_vec()),
        }
    }

    /// `session-store.js::sealHistoryForMember`'s envelope for one earlier
    /// epoch: `historyKey` only.
    pub fn history_envelope(&self, session_id: &str, caps: u8) -> Envelope {
        Envelope {
            version: ENVELOPE_VERSION,
            session_id: session_id.to_string(),
            epoch: self.number as u64,
            caps: caps as u64,
            master_key: None,
            history_key: Some(self.history_key.to_vec()),
            live_key: None,
        }
    }
}

/// A member device a rotation seals to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberDevice {
    pub device_key: Key32,
    pub caps: u8,
}

/// What a rotation produced (`rotateEpoch`'s `{epoch, envelopes}` plus
/// the host's own envelope).
#[derive(Debug, Clone)]
pub struct Rotation {
    pub epoch: u32,
    /// The host's `env/<n>/local`, sealed to the host device key.
    pub local: Vec<u8>,
    /// One sealed envelope per still-member device.
    pub envelopes: BTreeMap<Key32, Vec<u8>>,
}

/// The host's epoch state: every epoch this process minted (so
/// `sealHistoryForMember` can cover them) and the current one.
#[derive(Debug, Clone)]
pub struct EpochState {
    epochs: BTreeMap<u32, EpochKeys>,
    current: u32,
}

impl EpochState {
    /// Starts at a fresh epoch `number` (1 for a new session).
    pub fn start(number: u32) -> EpochState {
        let keys = EpochKeys::generate(number);
        EpochState {
            epochs: BTreeMap::from([(number, keys)]),
            current: number,
        }
    }

    pub fn number(&self) -> u32 {
        self.current
    }

    pub fn current(&self) -> &EpochKeys {
        &self.epochs[&self.current]
    }

    pub fn get(&self, number: u32) -> Option<&EpochKeys> {
        self.epochs.get(&number)
    }

    /// Every epoch this state holds, oldest first.
    pub fn all(&self) -> impl Iterator<Item = &EpochKeys> {
        self.epochs.values()
    }

    /// `session-store.js::rotateEpoch(members, reason)`: mints `epoch + 1`
    /// and seals one envelope per member device (a device without
    /// `READ_HISTORY` gets none of the history key) plus the host's own.
    pub fn rotate(
        &mut self,
        session_id: &str,
        host_device_key: &Key32,
        members: &[MemberDevice],
    ) -> Rotation {
        let next = self.current + 1;
        let keys = EpochKeys::generate(next);
        let local = envelope::seal(host_device_key, &keys.local_envelope(session_id));
        let envelopes = members
            .iter()
            .map(|m| {
                (
                    m.device_key,
                    envelope::seal(&m.device_key, &keys.member_envelope(session_id, m.caps)),
                )
            })
            .collect();
        self.epochs.insert(next, keys);
        self.current = next;
        Rotation {
            epoch: next,
            local,
            envelopes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::caps::SEND_INPUT;
    use crate::session::envelope::{generate_device_key, open};

    #[test]
    fn contexts_give_distinct_keys() {
        let k = [9u8; 32];
        let (h, l) = (derive_history_key(&k), derive_live_key(&k));
        assert_ne!(h, l);
        assert_ne!(derive_snapshot_key(&k), h);
        assert_eq!(derive_key(&k, 1, b"zxt-hist"), h);
    }

    #[test]
    fn rotation_seals_per_member_and_drops_history_without_read_history() {
        let sid = "cd".repeat(32);
        let (host_pk, host_sk) = generate_device_key();
        let (a_pk, a_sk) = generate_device_key();
        let (b_pk, b_sk) = generate_device_key();
        let mut st = EpochState::start(1);
        let r = st.rotate(
            &sid,
            &host_pk,
            &[
                MemberDevice {
                    device_key: a_pk,
                    caps: FULL_CAPS,
                },
                MemberDevice {
                    device_key: b_pk,
                    caps: VIEW_LIVE | SEND_INPUT,
                },
            ],
        );
        assert_eq!((r.epoch, st.number()), (2, 2));
        let a = open(&a_sk, &r.envelopes[&a_pk]).unwrap();
        assert_eq!(
            a.history_key.as_deref(),
            Some(&st.current().history_key[..])
        );
        assert_eq!(a.master_key, None);
        let b = open(&b_sk, &r.envelopes[&b_pk]).unwrap();
        assert_eq!(b.history_key, None);
        assert_eq!(b.live_key.as_deref(), Some(&st.current().live_key[..]));
        let local = open(&host_sk, &r.local).unwrap();
        assert_eq!(
            local.master_key.as_deref(),
            Some(&st.current().master_key[..])
        );
        assert_eq!(local.caps, FULL_CAPS as u64);
        assert!(st.get(1).is_some());
    }
}
