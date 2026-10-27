//! `test.flood`/`test.echo` (K7 Step 4): test-only seam methods behind the
//! `seam-test` Cargo feature, so they never ship in a release build built
//! without it. `test.flood` proves the seam's `Output` back-pressure
//! (`super::backlog::OutputSink`) under a real flood; `test.echo` measures
//! round-trip latency during and after one, the same shape
//! `test/pipe-backpressure-flood.test.js` uses for ZBTerm's own pipe.

use serde_json::{Value, json};

use crate::error::{Code, Error};

use super::backlog::OutputSink;
use super::methods::ConnCtx;

/// Each `Output` chunk `test.flood` sends, well under
/// `super::protocol::MAX_FRAME_BYTES`.
pub const FLOOD_CHUNK_BYTES: usize = 16 * 1024;

/// `test.echo { payload }`: replies with the same payload, verbatim.
pub fn echo(args: Value) -> Result<Value, Error> {
    let payload = args.get("payload").cloned().unwrap_or(Value::Null);
    Ok(json!({ "payload": payload }))
}

/// `test.flood { bytes }`: streams `bytes` worth of `Output` frames to the
/// requesting client as fast as it can, through the connection's droppable
/// output sink — a client that cannot keep up gets folded into a capped
/// tail instead of growing this sidecar's own memory without bound. Waits
/// briefly for any final resync to drain before replying, so a caller that
/// immediately measures `test.echo` latency after this reply sees a sink
/// that is not still mid-recovery.
pub async fn flood(args: Value, ctx: &ConnCtx) -> Result<Value, Error> {
    let total_bytes = args
        .get("bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| Error::new(Code::EInternal, "bytes is required"))?;

    let sink = OutputSink::new(ctx.outbound.clone());
    let mut pattern = [0u8; FLOOD_CHUNK_BYTES];
    for (i, b) in pattern.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }

    let mut sent: u64 = 0;
    let mut chunks: u64 = 0;
    let mut dropped_chunks: u64 = 0;
    while sent < total_bytes {
        let remaining = (total_bytes - sent) as usize;
        let chunk_len = remaining.min(FLOOD_CHUNK_BYTES);
        let outcome = sink.send("test-flood", &pattern[..chunk_len]);
        sent += chunk_len as u64;
        chunks += 1;
        if matches!(
            outcome,
            super::backlog::SendOutcome::Dropped | super::backlog::SendOutcome::StillLagging
        ) {
            dropped_chunks += 1;
        }
        if matches!(outcome, super::backlog::SendOutcome::Closed) {
            return Err(Error::new(
                Code::ENet,
                "client disconnected during test.flood",
            ));
        }
        // Cooperative: this loop can run many thousands of iterations for a
        // large flood, and must never starve the connection's other tasks
        // (in particular a concurrent test.echo, the whole point of this
        // method existing).
        if chunks.is_multiple_of(32) {
            tokio::task::yield_now().await;
        }
    }

    // Give a lagging sink a bounded chance to actually deliver its final
    // resync (the writer task drains as the client reads) before this call
    // returns — otherwise a caller's very next test.echo could race a
    // resync that is still sitting in memory, unsent.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while sink.is_lagging() && tokio::time::Instant::now() < deadline {
        sink.poll_resync();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    Ok(json!({
        "bytesSent": sent,
        "chunks": chunks,
        "droppedChunks": dropped_chunks,
        "stillLagging": sink.is_lagging(),
    }))
}
