// K6 (WebRTC and channels, spike S2): the JS peer for the S2 gate test.
// Wraps ZBTerm's real FreenetBackend (engine/backends/freenet/index.js)
// with a real electron/rtc-host.js RtcHost on a LocalNode, exactly as
// test/backends/freenet-backend.test.js's own peer() helper does, driven
// over newline-JSON on stdin/stdout (zxterm_testkit::js::LineChild's
// protocol) so a Rust test can drive it as "the JS peer".
//
// Commands in (one JSON object per line on stdin):
//   {cmd:"start", nodeUrl, secretHex?}
//   {cmd:"announce", linkId}
//   {cmd:"dial", route, expectedPeerKeyHex}
//   {cmd:"onChannel", handle, protocol}
//   {cmd:"openChannel", handle, protocol, idHex}
//   {cmd:"send", handle, label, message}
//   {cmd:"openOrder"}
//   {cmd:"stop"}
// Each reply is one line, {ok:true, ...} or {ok:false, error}. Independent
// of replies, this script also emits event lines {event:"...", ...} at any
// time: "connection" (a backend 'connection' event; also "dialConnected"/
// "dialError" for the dial() promise specifically), "incomingChannel",
// "message", "channelClosed", "debug" (the backend's own 'debug' stream,
// filtered to the events K6's tests care about).
'use strict'
const readline = require('readline')

const root = process.env.ZX_ZBTERM
if (!root) throw new Error('ZX_ZBTERM not set')

const { EventEmitter } = require('events')
const sodium = require(root + '/node_modules/sodium-native')
const FreenetBackend = require(root + '/engine/backends/freenet')
const { RtcHost } = require(root + '/electron/rtc-host')

// 'a=fingerprint:sha-256 AB:CD:…' -> the first hex digit after the space,
// changed (test/backends/freenet-backend.test.js::flipHexDigit's twin, but
// operating on the bare "sha-256 AB:CD:…" shape `state`'s
// `remoteFingerprint` carries, not a whole SDP line).
function flipHexDigit(fingerprint) {
  return fingerprint.replace(/(\S+ )([0-9A-Fa-f])/, (all, head, digit) => {
    const flipped = digit.toUpperCase() === 'A' ? 'B' : 'A'
    return head + flipped
  })
}

function hex(buf) {
  return Buffer.from(buf).toString('hex')
}
function fromHex(s) {
  return Buffer.from(s, 'hex')
}

function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n')
}

function keyPairFrom(secretHex) {
  const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  if (secretHex) {
    sodium.crypto_sign_seed_keypair(publicKey, secretKey, fromHex(secretHex))
  } else {
    sodium.crypto_sign_keypair(publicKey, secretKey)
  }
  return { publicKey, secretKey }
}

// A relay in front of the real RtcHost (test/backends/freenet-backend.test.js's
// own `relayed()` helper, K6's twin of it): FreenetBackend sees only what
// crosses this object, so it can both record every 'channel' event's label
// in arrival order (the structural evidence for "bootstrap opens before any
// other channel") and, for the fingerprint-tamper negative gate
// (`lieAboutFingerprint`), rewrite a connected 'state' event's
// `remoteFingerprint` before FreenetBackend's own check ever sees it —
// without touching electron/rtc-host.js or engine/backends/freenet/index.js.
function relayRtcHost(rtc, { lieAboutFingerprint } = {}) {
  const relay = new EventEmitter()
  for (const name of ['open', 'signal', 'openChannel', 'closeChannel', 'send', 'close', 'closeAll']) {
    relay[name] = (...args) => rtc[name](...args)
  }
  rtc.on('channel', (body) => {
    if (body.op === 'opened') openOrder.push(body.label)
    relay.emit('channel', body)
  })
  rtc.on('state', (body) => {
    const mapped =
      lieAboutFingerprint && body.state === 'connected'
        ? { ...body, remoteFingerprint: flipHexDigit(body.remoteFingerprint) }
        : body
    relay.emit('state', mapped)
  })
  for (const name of ['signal', 'data', 'flow', 'close']) {
    rtc.on(name, (body) => relay.emit(name, body))
  }
  return relay
}

let backend = null
let keyPair = null
let openOrder = []
// handle -> FreenetConnection
const conns = new Map()
// `${handle}:${label}` -> FreenetChannel
const channels = new Map()
let nextHandle = 1

function registerConnection(conn, info) {
  const handle = nextHandle++
  conns.set(handle, conn)
  emit({
    event: 'connection',
    handle,
    initiator: conn.initiator,
    remoteKeyHex: hex(conn.remotePeerKey),
    linkId: info ? info.linkId : null
  })
  return handle
}

// `FreenetBackend`'s 'connection' event fires on both sides, including the
// dialer's own (index.js::_surface's `if (dialing) { ...; this.emit(...) }`
// branch) — so a dial's own connection is normally registered by the
// shared 'connection' listener below before `dial().connected` resolves;
// this only registers it itself in the (unlikely) case the promise settles
// first, so a dial never gets two handles for the same connection.
function handleForConn(conn, info) {
  for (const [handle, c] of conns) {
    if (c === conn) return handle
  }
  return registerConnection(conn, info)
}

async function handleCommand(msg) {
  switch (msg.cmd) {
    case 'start': {
      keyPair = keyPairFrom(msg.secretHex)
      const rtc = relayRtcHost(new RtcHost({ iceServers: [] }), {
        lieAboutFingerprint: !!msg.lieAboutFingerprint
      })
      backend = new FreenetBackend({ nodeUrl: msg.nodeUrl, rtcHost: rtc, iceServers: [] })
      backend.on('connection', (conn, info) => registerConnection(conn, info))
      backend.on('debug', (e) => emit({ event: 'debug', name: e.event, details: e.details }))
      await backend.start({ keyPair: () => keyPair })
      return { ok: true, publicKeyHex: hex(keyPair.publicKey) }
    }
    case 'announce': {
      backend.setAdmission(true)
      const { route, linkId } = await backend.announce(msg.linkId, {})
      return { ok: true, route, linkId }
    }
    case 'dial': {
      const handle = backend.dial(msg.route, fromHex(msg.expectedPeerKeyHex))
      handle.connected.then(
        (conn) => {
          const h = handleForConn(conn, { linkId: null })
          emit({ event: 'dialConnected', handle: h })
        },
        (err) => {
          emit({
            event: 'dialError',
            code: err.code,
            message: err.message,
            details: err.details || null
          })
        }
      )
      return { ok: true }
    }
    case 'onChannel': {
      const conn = conns.get(msg.handle)
      conn.onChannel(msg.protocol, (idBuf) => {
        emit({ event: 'incomingChannel', handle: msg.handle, protocol: msg.protocol, idHex: hex(idBuf) })
      })
      return { ok: true }
    }
    case 'openChannel': {
      const conn = conns.get(msg.handle)
      const id = fromHex(msg.idHex)
      const ch = conn.openChannel(msg.protocol, id, {
        onmessage: (value) => emit({ event: 'message', handle: msg.handle, label: ch.label, value }),
        onclose: () => emit({ event: 'channelClosed', handle: msg.handle, label: ch.label })
      })
      channels.set(`${msg.handle}:${ch.label}`, ch)
      return { ok: true, label: ch.label }
    }
    case 'send': {
      const ch = channels.get(`${msg.handle}:${msg.label}`)
      const result = ch.send(msg.message)
      return { ok: true, result }
    }
    case 'openOrder': {
      return { ok: true, order: openOrder }
    }
    case 'stop': {
      if (backend) await backend.stop()
      return { ok: true }
    }
    default:
      return { ok: false, error: `unknown cmd ${msg.cmd}` }
  }
}

const rl = readline.createInterface({ input: process.stdin })
rl.on('line', (line) => {
  let msg
  try {
    msg = JSON.parse(line)
  } catch (err) {
    emit({ ok: false, error: `bad JSON line: ${err.message}` })
    return
  }
  handleCommand(msg).then(
    (reply) => emit(reply),
    (err) => emit({ ok: false, error: String((err && err.stack) || err) })
  )
})

process.on('uncaughtException', (err) => {
  process.stderr.write(`rtc_peer.js uncaught: ${String((err && err.stack) || err)}\n`)
})
