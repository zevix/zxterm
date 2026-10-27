// Minimal unkeyed BLAKE3 (32-byte output), dependency-free so it loads under Bare:
// @noble/hashes pulls in `node:crypto`, which Bare cannot resolve (S-06). Ported
// unchanged from spikes/freenet/lib/blake3.js; test/backends/freenet-client.test.js
// pins it to known vectors.
const IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
])
const PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
const CHUNK_START = 1
const CHUNK_END = 2
const PARENT = 4
const ROOT = 8

const rotr = (x, n) => (x >>> n) | (x << (32 - n))

function g(v, a, b, c, d, mx, my) {
  v[a] = (v[a] + v[b] + mx) | 0
  v[d] = rotr(v[d] ^ v[a], 16)
  v[c] = (v[c] + v[d]) | 0
  v[b] = rotr(v[b] ^ v[c], 12)
  v[a] = (v[a] + v[b] + my) | 0
  v[d] = rotr(v[d] ^ v[a], 8)
  v[c] = (v[c] + v[d]) | 0
  v[b] = rotr(v[b] ^ v[c], 7)
}

// Returns the full 16-word compression output.
function compress(cv, block, counter, blockLen, flags) {
  let m = Array.from(block)
  const v = new Uint32Array(16)
  v.set(cv, 0)
  v.set(IV.subarray(0, 4), 8)
  v[12] = counter >>> 0
  v[13] = Math.floor(counter / 0x100000000)
  v[14] = blockLen
  v[15] = flags
  for (let r = 0; r < 7; r++) {
    g(v, 0, 4, 8, 12, m[0], m[1])
    g(v, 1, 5, 9, 13, m[2], m[3])
    g(v, 2, 6, 10, 14, m[4], m[5])
    g(v, 3, 7, 11, 15, m[6], m[7])
    g(v, 0, 5, 10, 15, m[8], m[9])
    g(v, 1, 6, 11, 12, m[10], m[11])
    g(v, 2, 7, 8, 13, m[12], m[13])
    g(v, 3, 4, 9, 14, m[14], m[15])
    m = PERM.map((i) => m[i])
  }
  for (let i = 0; i < 8; i++) {
    v[i] ^= v[i + 8]
    v[i + 8] ^= cv[i]
  }
  return v
}

function words(bytes, offset, len) {
  const padded = new Uint8Array(64)
  padded.set(bytes.subarray(offset, offset + len))
  const out = new Uint32Array(16)
  const dv = new DataView(padded.buffer)
  for (let i = 0; i < 16; i++) out[i] = dv.getUint32(i * 4, true)
  return out
}

// Chaining value of one chunk (<= 1024 bytes), or the root output when `root`.
function chunkOutput(input, offset, len, counter, root) {
  let cv = IV
  const blocks = Math.max(1, Math.ceil(len / 64))
  for (let b = 0; b < blocks; b++) {
    const blockLen = Math.min(64, len - b * 64)
    let flags = 0
    if (b === 0) flags |= CHUNK_START
    if (b === blocks - 1) flags |= CHUNK_END | (root ? ROOT : 0)
    cv = compress(
      cv,
      words(input, offset + b * 64, Math.max(0, blockLen)),
      counter,
      Math.max(0, blockLen),
      flags
    ).subarray(0, 8)
  }
  return cv
}

function parentOutput(left, right, root) {
  const block = new Uint32Array(16)
  block.set(left, 0)
  block.set(right, 8)
  return compress(IV, block, 0, 64, PARENT | (root ? ROOT : 0)).subarray(0, 8)
}

// Largest power of two strictly less than the chunk count decides the left subtree.
function subtree(input, offset, len, counter, root) {
  if (len <= 1024) return chunkOutput(input, offset, len, counter, root)
  const chunks = Math.ceil(len / 1024)
  let leftChunks = 1
  while (leftChunks * 2 < chunks) leftChunks *= 2
  const leftLen = leftChunks * 1024
  const left = subtree(input, offset, leftLen, counter, false)
  const right = subtree(input, offset + leftLen, len - leftLen, counter + leftChunks, false)
  return parentOutput(left, right, root)
}

function blake3(input) {
  const cv = subtree(input, 0, input.length, 0, true)
  const out = new Uint8Array(32)
  const dv = new DataView(out.buffer)
  for (let i = 0; i < 8; i++) dv.setUint32(i * 4, cv[i], true)
  return out
}

module.exports = { blake3 }
