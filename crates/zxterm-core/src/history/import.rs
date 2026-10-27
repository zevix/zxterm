//! The one-shot import of a session's existing packets (`X-02`): the caller
//! (ZBTerm, K17) reads its Hypercore log itself, decrypts the packets and
//! hands the plaintext to [`import`], which re-segments them into a new
//! [`SegmentFile`] under one epoch's history key. The core never reads
//! Hypercore. Packet `i` of the iterator gets sequence number
//! `cfg.first_seq + i`, so the caller's log positions are preserved.
//!
//! The core does not enforce "once": [`SegmentFile::create`] refuses a
//! directory that already holds a history, and the caller (K17) keeps the
//! bookkeeping of which sessions it has imported.

use crate::error::Error;

use super::packet::PlainPacket;
use super::store::{HistoryConfig, SegmentFile};

/// Writes `packets` into a new history at `cfg.dir` under `epoch`'s
/// `history_key`, closes the last segment and returns the file.
pub fn import(
    mut cfg: HistoryConfig,
    packets: impl IntoIterator<Item = PlainPacket>,
    epoch: u32,
    history_key: [u8; 32],
) -> Result<SegmentFile, Error> {
    cfg.epoch_keys.insert(epoch, history_key);
    let mut file = SegmentFile::create(cfg)?;
    file.set_epoch(epoch)?;
    for p in packets {
        file.append(p)?;
    }
    file.flush()?;
    Ok(file)
}
