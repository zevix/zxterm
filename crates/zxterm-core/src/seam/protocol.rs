//! The seam's wire protocol (K7, spike S3): a `u32` little-endian length
//! prefix followed by one `postcard`-encoded [`Frame`] per message, over a
//! Unix domain socket (a named pipe on Windows, `#[cfg(windows)]`).
//!
//! Every payload field (`Request::args`, `Reply`'s `Ok`/`Err` value,
//! `Event::data`) is carried as a JSON *string*, not a `postcard`-encoded
//! structured value: `postcard`'s wire format is not self-describing (no
//! type tags), so a generically-typed value like `serde_json::Value` cannot
//! round-trip through it (`serde_json::Value`'s own `Deserialize` impl calls
//! `deserialize_any`, which a non-self-describing format cannot answer).
//! Carrying JSON text inside the postcard frame keeps every field's `postcard`
//! shape concrete (a `String`) while still giving `ctl` (a "JSON-mirror
//! client") and `codec.js` exactly what they need: text that is already
//! valid JSON, printed or parsed with no extra step.
//!
//! `id` is a caller-chosen string the sidecar echoes back on `Reply`, so two
//! concurrent requests on one connection can complete in either order and
//! still be matched to their own reply (see `tests/seam-golden`'s
//! `concurrent_replies_match_their_own_request` and this module's own
//! `Frame` doc comment).

use std::io;

use serde::{Deserialize, Serialize};

/// Max single-frame byte length this side ever reads: high enough that no
/// legitimate payload (an `Output` chunk, a `Reply` to a large `identity.*`
/// call) is ever truncated, low enough that a corrupt or hostile length
/// prefix cannot force an unbounded allocation. `test.flood` chunks its 16
/// MiB payload into many frames well under this bound (see
/// `crate::seam::test_methods::FLOOD_CHUNK_BYTES`).
pub const MAX_FRAME_BYTES: u32 = 8 * 1024 * 1024;

/// The sidecar's one error shape on the wire, matching ZBTerm
/// `engine/errors.js::EngineError`'s `{code, message}` (`details` is folded
/// into `message` at the seam boundary — see `crate::seam::methods::wire_error`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireError {
    /// One of `crate::error::Code::as_str()` (`engine/errors.js::CODES`).
    pub code: String,
    pub message: String,
}

/// One seam message. `postcard` encodes an enum as a varint variant index
/// (0 = `Request`, 1 = `Reply`, 2 = `Event`, 3 = `Output`, in declaration
/// order; K10 adds 4 = `Chan`) followed by its fields in declaration order — `codec.js`'s
/// hand-written decoder mirrors this exactly, checked against the golden
/// files this crate's own tests write to `tests/seam-golden/*.bin`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Frame {
    /// client -> sidecar. `args` is a JSON object/value as text (`"{}"` for
    /// no arguments).
    Request {
        id: String,
        method: String,
        args: String,
    },
    /// sidecar -> client, `id` matches the `Request` it answers. `Ok(text)`
    /// carries the JSON result; `Err` carries `{code, message}`.
    Reply {
        id: String,
        ok: Result<String, WireError>,
    },
    /// sidecar -> client, unsolicited (no `id`). `data` is a JSON value as
    /// text.
    Event { name: String, data: String },
    /// sidecar -> client, unsolicited and droppable: a client that falls
    /// behind gets a snapshot-plus-tail instead of an ever-growing backlog
    /// (`crate::seam::backlog`, the `S-35` rule moved to this seam).
    /// `stream` names the source (`"test-flood"`, `"snapshot"`, …) — a
    /// plain string, not a closed enum, since a later phase's real usage
    /// (terminal output) will need stream names this phase does not know
    /// yet.
    Output { stream: String, bytes: Vec<u8> },
    /// K10, both directions, never dropped: one message of raw ordered
    /// byte channel `chan` of the Freenet transport service
    /// (`crate::seam::freenet_methods`). Sidecar -> client: bytes that
    /// arrived on the channel, one data-channel message per frame.
    /// Client -> sidecar: bytes to send on it. Variant index 4, so the
    /// four earlier variants keep their bytes.
    Chan { chan: u64, bytes: Vec<u8> },
}

/// Encodes one frame to its raw `postcard` bytes (no length prefix) — used
/// directly by the golden-fixture test, which writes exactly these bytes to
/// `tests/seam-golden/*.bin`.
pub fn encode(frame: &Frame) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_stdvec(frame)
}

/// Decodes raw `postcard` bytes (no length prefix) back to a [`Frame`].
pub fn decode(bytes: &[u8]) -> Result<Frame, postcard::Error> {
    postcard::from_bytes(bytes)
}

/// Writes one length-prefixed frame: `u32` LE byte length of the `postcard`
/// encoding, then the encoding itself.
pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let bytes = encode(frame).map_err(|e| io::Error::other(format!("postcard encode: {e}")))?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| io::Error::other("frame too large to encode (over u32::MAX bytes)"))?;
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await
}

/// Reads one length-prefixed frame. `Ok(None)` on a clean EOF before any
/// byte of the next frame arrives (the connection closed between frames,
/// not mid-frame); a partial length prefix or a partial payload is an
/// `UnexpectedEof` error, never silently treated as "no frame".
pub async fn read_frame<R>(reader: &mut R) -> io::Result<Option<Frame>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    let n = read_or_eof(reader, &mut len_buf).await?;
    if n == 0 {
        return Ok(None);
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::other(format!(
            "frame of {len} bytes exceeds the {MAX_FRAME_BYTES}-byte limit"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    decode(&buf)
        .map(Some)
        .map_err(|e| io::Error::other(format!("postcard decode: {e}")))
}

/// Reads exactly `buf.len()` bytes, except that a EOF on the very first byte
/// is reported as `Ok(0)` (a clean "no more frames") rather than an error —
/// `AsyncReadExt::read_exact` itself always turns a short read into
/// `UnexpectedEof`, so this loops by hand for the first byte only.
async fn read_or_eof<R>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..]).await?;
        if n == 0 {
            if filled == 0 {
                return Ok(0);
            }
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        filled += n;
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(frame: Frame) {
        let bytes = encode(&frame).expect("encode");
        let back = decode(&bytes).expect("decode");
        assert_eq!(frame, back);
    }

    #[test]
    fn every_frame_kind_round_trips_through_postcard() {
        roundtrip(Frame::Request {
            id: "1".into(),
            method: "core.version".into(),
            args: "{}".into(),
        });
        roundtrip(Frame::Reply {
            id: "1".into(),
            ok: Ok("{\"version\":\"0.1.0\"}".into()),
        });
        roundtrip(Frame::Reply {
            id: "2".into(),
            ok: Err(WireError {
                code: "E_AUTH".into(),
                message: "bad signature".into(),
            }),
        });
        roundtrip(Frame::Event {
            name: "core.ready".into(),
            data: "{}".into(),
        });
        roundtrip(Frame::Output {
            stream: "test-flood".into(),
            bytes: vec![1, 2, 3, 4, 5],
        });
        roundtrip(Frame::Chan {
            chan: 300,
            bytes: vec![0, 255, 7],
        });
    }

    #[tokio::test]
    async fn write_then_read_frame_round_trips_over_a_pipe() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let frame = Frame::Request {
            id: "abc".into(),
            method: "core.health".into(),
            args: "{}".into(),
        };
        write_frame(&mut client, &frame).await.expect("write");
        let back = read_frame(&mut server)
            .await
            .expect("read")
            .expect("some frame");
        assert_eq!(frame, back);
    }

    #[tokio::test]
    async fn read_frame_reports_clean_eof_as_none_between_frames() {
        let (client, mut server) = tokio::io::duplex(4096);
        drop(client);
        let result = read_frame(&mut server).await.expect("no io error");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn an_oversized_length_prefix_is_refused_not_allocated() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = client.write_all(&(MAX_FRAME_BYTES + 1).to_le_bytes()).await;
        });
        let err = read_frame(&mut server).await.unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }
}
