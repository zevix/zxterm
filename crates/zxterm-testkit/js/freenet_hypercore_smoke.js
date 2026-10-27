// K10 step 8: Hypercore replication over a raw channel the core provides,
// driven from this Node process.
//
//   node freenet_hypercore_smoke.js <nodeUrl> <zxterm-core binary>
//
// K13: both ends are `zxterm-core sidecar`s on scratch profiles, talked to
// over the seam (ZBTerm's engine/zxterm/codec.js framing). (Until K13 the
// host was ZBTerm's former JS FreenetBackend from the reference revision;
// a v2 core dials only `pv: 2` routes, protocol.md §12, and that backend
// mints v1 ones.) The host sidecar announces a link on the test's LocalNode
// (freenet.start, freenet.setAdmission, freenet.announce) and, on the
// viewer's connection, opens the raw `zbterm/history 00` channel with
// freenet.serveHistory; the viewer sidecar dials the route (freenet.dial)
// and opens the same channel with freenet.attachHistory. Over the two
// channels' Chan frames this process runs, on each end, the stream
// history.js::historyStream makes (u32 LE length frames cut into messages
// of at most 65 536 bytes, NoiseSecretStream on top, the dialing side the
// initiator) and replicates the host's two Hypercores into the viewer's,
// downloading every block. The last stdout line is
//   {"result": {ok, blocks, bytes, intact, meta, chanFrames, ms}}.
//
// It spawns exactly two children, the sidecars, and stops each by its own
// ChildProcess handle (and --exit-on-stdin-eof ends them with this process).
'use strict'
const { spawn } = require('child_process')
const crypto = require('crypto')
const fs = require('fs')
const net = require('net')
const os = require('os')
const path = require('path')

const root = process.env.ZX_ZBTERM
if (!root) throw new Error('ZX_ZBTERM not set')
const [nodeUrl, bin] = process.argv.slice(2)
if (!nodeUrl || !bin) throw new Error('usage: freenet_hypercore_smoke.js <nodeUrl> <zxterm-core>')

const Hypercore = require(root + '/node_modules/hypercore')
const NoiseSecretStream = require(root + '/node_modules/@hyperswarm/secret-stream')
const { Duplex } = require(root + '/node_modules/streamx')
// The seam codec is newer than the reference revision: the live tree's.
const codec = require((process.env.ZX_ZBTERM_LIVE || root) + '/engine/zxterm/codec')

const BLOCK = 128 * 1024
const BLOCKS = 12
const MAX_MESSAGE_SIZE = 65536
const FRAME_HEADER = 4

const log = (...args) => process.stderr.write(args.join(' ') + '\n')

function within(ms, promise, what) {
  let timer
  const timeout = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`${what}: nothing within ${ms} ms`)), ms)
  })
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer))
}

// A minimal seam client: requests with ids, replies matched by id, events
// and Chan frames to listeners.
class Seam {
  constructor(socket) {
    this.socket = socket
    this.decoder = new codec.FrameDecoder()
    this.pending = new Map()
    this.nextId = 1
    this.onEvent = () => {}
    this.onChan = () => {}
    socket.on('data', (chunk) => {
      for (const frame of this.decoder.push(chunk)) this._frame(frame)
    })
  }

  _frame(frame) {
    if (frame.kind === 'Reply') {
      const p = this.pending.get(frame.id)
      if (!p) return
      this.pending.delete(frame.id)
      if (frame.ok.ok) p.resolve(JSON.parse(frame.ok.value))
      else p.reject(Object.assign(new Error(frame.ok.error.message), { code: frame.ok.error.code }))
    } else if (frame.kind === 'Event') {
      this.onEvent(frame.name, JSON.parse(frame.data))
    } else if (frame.kind === 'Chan') {
      this.onChan(frame.chan, frame.bytes)
    }
  }

  call(method, args = {}) {
    const id = String(this.nextId++)
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
      this.socket.write(codec.encodeMessage({ kind: 'Request', id, method, args: JSON.stringify(args) }))
    })
  }

  sendChan(chan, bytes) {
    return this.socket.write(codec.encodeMessage({ kind: 'Chan', chan, bytes }))
  }
}

// history.js::historyStream over the seam's raw channel `chan`.
function seamHistoryStream(seam, chan, counters) {
  let head = null
  let need = -1
  let parts = []
  let have = 0
  const stream = new Duplex({
    write(data, cb) {
      const frame = Buffer.allocUnsafe(FRAME_HEADER + data.byteLength)
      frame.writeUInt32LE(data.byteLength, 0)
      frame.set(data, FRAME_HEADER)
      for (let at = 0; at < frame.byteLength; at += MAX_MESSAGE_SIZE) {
        seam.sendChan(chan, frame.subarray(at, Math.min(frame.byteLength, at + MAX_MESSAGE_SIZE)))
        counters.out++
      }
      cb(null)
    }
  })
  stream.on('error', () => {})
  const onPart = (part) => {
    counters.in++
    let buf = head ? Buffer.concat([head, part]) : part
    head = null
    while (buf.byteLength) {
      if (need < 0) {
        if (buf.byteLength < FRAME_HEADER) {
          head = buf
          return
        }
        need = buf.readUInt32LE(0)
        buf = buf.subarray(FRAME_HEADER)
        parts = []
        have = 0
      }
      const take = Math.min(need - have, buf.byteLength)
      parts.push(buf.subarray(0, take))
      have += take
      buf = buf.subarray(take)
      if (have === need) {
        stream.push(parts.length === 1 ? parts[0] : Buffer.concat(parts))
        need = -1
        parts = []
        have = 0
      }
    }
  }
  return { stream, onPart }
}

// Spawns `zxterm-core sidecar` on `profile` and connects a seam client.
async function startSidecar(bin, profile, children) {
  const child = spawn(bin, ['sidecar', '--profile', profile, '--exit-on-stdin-eof'], {
    stdio: ['pipe', 'pipe', 'inherit']
  })
  children.push(child)
  await within(
    10000,
    new Promise((resolve, reject) => {
      let out = ''
      child.stdout.on('data', (d) => {
        out += d
        if (out.includes('listening on')) resolve()
      })
      child.on('exit', (code) => reject(new Error(`sidecar exited ${code}`)))
    }),
    'the sidecar'
  )
  const socket = net.connect(path.join(profile, 'zxterm-core.sock'))
  await new Promise((resolve, reject) => socket.once('connect', resolve).once('error', reject))
  const seam = new Seam(socket)
  const events = []
  const waiters = []
  const listeners = []
  seam.onEvent = (name, data) => {
    events.push({ name, data })
    for (const l of listeners) l(name, data)
    for (const w of waiters.splice(0)) w()
  }
  seam.waitEvent = (pred, what) =>
    within(
      30000,
      new Promise((resolve) => {
        const check = () => {
          const hit = events.find(pred)
          if (hit) resolve(hit)
          else waiters.push(check)
        }
        check()
      }),
      what
    )
  seam.listen = (fn) => listeners.push(fn)
  seam.socket = socket
  return seam
}

// A raw channel's Chan frames into a history stream, with frames that
// arrive before the channel handle is known kept for it.
function historyEnd(seam, counters) {
  const buffered = []
  let history = null
  seam.onChan = (chan, bytes) => {
    if (history && chan === history.chan) history.onPart(bytes)
    else buffered.push([chan, bytes])
  }
  return (chan) => {
    const { stream, onPart } = seamHistoryStream(seam, chan, counters)
    history = { chan, onPart }
    for (const [c, bytes] of buffered.splice(0)) if (c === chan) onPart(bytes)
    return stream
  }
}

async function main() {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'hc-'))
  const cores = []
  const open = async (name, key) => {
    const core = new Hypercore(path.join(dir, name), key)
    cores.push(core)
    await core.ready()
    return core
  }
  const children = []
  const seams = []
  const result = { ok: false }
  try {
    // The host's session store.
    const hostStore = { log: await open('host-log'), metaCore: await open('host-meta') }
    const blocks = []
    for (let i = 0; i < BLOCKS; i++) blocks.push(crypto.randomBytes(BLOCK))
    await hostStore.log.append(blocks)
    await hostStore.metaCore.append(Buffer.from('meta-0'))

    // The host sidecar: announces, and serves history on every connection.
    const host = await startSidecar(bin, path.join(dir, 'h'), children)
    seams.push(host)
    const hostCounters = { in: 0, out: 0 }
    const hostHistory = historyEnd(host, hostCounters)
    const { publicKey } = await host.call('freenet.start', {
      secretKey: crypto.randomBytes(32).toString('hex'),
      nodeUrl,
      iceServers: []
    })
    await host.call('freenet.setAdmission', { policy: true })
    const { route } = await host.call('freenet.announce', { linkId: 'link-hypercore' })
    if (!route.params || route.params.pv !== 2) throw new Error(`not a v2 route: ${JSON.stringify(route)}`)
    host.listen((name, data) => {
      if (name !== 'freenet.connection') return
      host.call('freenet.serveHistory', { conn: data.conn }).then(({ chan }) => {
        const noise = new NoiseSecretStream(false, hostHistory(chan))
        noise.on('error', () => {})
        hostStore.log.replicate(noise)
        hostStore.metaCore.replicate(noise)
      }, (err) => log('serveHistory:', err.message))
    })

    // The viewer sidecar: dials the host.
    const seam = await startSidecar(bin, path.join(dir, 'v'), children)
    seams.push(seam)
    const counters = { in: 0, out: 0 }
    const viewerHistory = historyEnd(seam, counters)
    await seam.call('freenet.start', {
      secretKey: crypto.randomBytes(32).toString('hex'),
      nodeUrl,
      iceServers: []
    })
    const { dial } = await seam.call('freenet.dial', { route, expectedPeerKey: publicKey })
    const settled = await seam.waitEvent(
      (e) => (e.name === 'freenet.dialConnected' || e.name === 'freenet.dialError') && e.data.dial === dial,
      'the dial'
    )
    if (settled.name !== 'freenet.dialConnected') throw new Error(`dial failed: ${JSON.stringify(settled.data)}`)
    const conn = settled.data.conn

    const viewerStore = {
      log: await open('viewer-log', hostStore.log.key),
      metaCore: await open('viewer-meta', hostStore.metaCore.key)
    }
    const started = Date.now()
    const { chan } = await seam.call('freenet.attachHistory', { conn })
    const noise = new NoiseSecretStream(true, viewerHistory(chan))
    noise.on('error', () => {})
    viewerStore.log.replicate(noise)
    viewerStore.metaCore.replicate(noise)
    await within(
      60000,
      viewerStore.log.download({ start: 0, end: BLOCKS, linear: true }).done(),
      'the history download'
    )
    const ms = Date.now() - started
    const last = await viewerStore.log.get(BLOCKS - 1, { wait: false })
    const meta = await within(20000, viewerStore.metaCore.get(0), 'the meta core')
    Object.assign(result, {
      ok: viewerStore.log.contiguousLength === BLOCKS,
      blocks: viewerStore.log.contiguousLength,
      bytes: BLOCK * BLOCKS,
      intact: !!last && last.equals(blocks[BLOCKS - 1]),
      meta: !!meta && meta.equals(Buffer.from('meta-0')),
      chanFrames: counters.in + counters.out,
      framesIn: counters.in,
      framesOut: counters.out,
      hostFrames: hostCounters.in + hostCounters.out,
      ms
    })
    for (const s of seams) await s.call('freenet.stop').catch(() => {})
  } catch (err) {
    result.error = String((err && err.stack) || err)
  } finally {
    for (const s of seams) s.socket.destroy()
    for (const child of children) {
      if (child.exitCode === null) {
        child.stdin.end()
        child.kill()
      }
    }
    for (const core of cores) await core.close().catch(() => {})
    await fs.promises.rm(dir, { recursive: true, force: true }).catch(() => {})
  }
  process.stdout.write(JSON.stringify({ result }) + '\n')
  process.exit(result.ok ? 0 : 1)
}

main().catch((err) => {
  log('freenet_hypercore_smoke.js:', (err && err.stack) || err)
  process.exit(2)
})
