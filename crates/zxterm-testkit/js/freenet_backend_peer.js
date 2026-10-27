// K10 (C1 transport service): the JS peer for tests/freenet_backend_js.rs.
// ZBTerm's current FreenetBackend (engine/backends/freenet/index.js) with a
// real electron/rtc-host.js RtcHost, on the test's own LocalNode, driven
// over newline-JSON on stdin/stdout (zxterm_testkit::js::LineChild).
//
// Commands in (one JSON object per line):
//   {cmd:"start", nodeUrl}                       -> {publicKeyHex}
//   {cmd:"setAdmission", policy}
//   {cmd:"announce", linkId}                     -> {route}
//   {cmd:"withdraw", linkId}
//   {cmd:"dial", route, expectedPeerKeyHex}      (events dialConnected/dialError)
//   {cmd:"onChannel", handle, protocol}          (events incomingChannel)
//   {cmd:"openChannel", handle, protocol, idHex, raw}  -> {label}
//   {cmd:"send", handle, label, message}         (a JSON channel)
//   {cmd:"sendRaw", handle, label, b64}          (a raw channel)
//   {cmd:"closeChannel", handle, label}
//   {cmd:"diagnostics"}                          -> {diagnostics}
//   {cmd:"stop"}
// Replies are {ok:true, ...} or {ok:false, error}; events are {event, ...}:
// connection, dialConnected, dialError, incomingChannel, message, bytes
// ({b64}), channelClosed, connectionClosed.
'use strict'
const readline = require('readline')

const root = process.env.ZX_ZBTERM
if (!root) throw new Error('ZX_ZBTERM not set')

const sodium = require(root + '/node_modules/sodium-native')
const FreenetBackend = require(root + '/engine/backends/freenet')
const { HistoryChannel } = require(root + '/engine/backends/freenet/history')
const { RtcHost } = require(root + '/electron/rtc-host')

const hex = (buf) => Buffer.from(buf).toString('hex')
const emit = (obj) => process.stdout.write(JSON.stringify(obj) + '\n')

let backend = null
let rtc = null
let keyPair = null
const conns = new Map()
const channels = new Map()
let nextHandle = 1

function handleOf(conn, info) {
  for (const [h, c] of conns) if (c === conn) return h
  const handle = nextHandle++
  conns.set(handle, conn)
  conn.on('close', () => emit({ event: 'connectionClosed', handle }))
  emit({
    event: 'connection',
    handle,
    initiator: conn.initiator,
    remoteKeyHex: hex(conn.remotePeerKey),
    linkId: info ? info.linkId : null
  })
  return handle
}

async function command(msg) {
  switch (msg.cmd) {
    case 'start': {
      const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
      const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
      sodium.crypto_sign_keypair(publicKey, secretKey)
      keyPair = { publicKey, secretKey }
      rtc = new RtcHost({ iceServers: [] })
      backend = new FreenetBackend({ nodeUrl: msg.nodeUrl, rtcHost: rtc, iceServers: [] })
      backend.on('connection', (conn, info) => handleOf(conn, info))
      await backend.start({ keyPair: () => keyPair })
      return { ok: true, publicKeyHex: hex(publicKey) }
    }
    case 'setAdmission':
      backend.setAdmission(msg.policy)
      return { ok: true }
    case 'announce': {
      const { route } = await backend.announce(msg.linkId, {})
      return { ok: true, route }
    }
    case 'withdraw':
      await backend.withdraw(msg.linkId)
      return { ok: true }
    case 'dial': {
      const handle = backend.dial(msg.route, Buffer.from(msg.expectedPeerKeyHex, 'hex'))
      handle.connected.then(
        (conn) => emit({ event: 'dialConnected', handle: handleOf(conn, { linkId: null }) }),
        (err) => emit({ event: 'dialError', code: err.code, message: err.message })
      )
      return { ok: true }
    }
    case 'onChannel': {
      conns.get(msg.handle).onChannel(msg.protocol, (id) => {
        emit({ event: 'incomingChannel', handle: msg.handle, protocol: msg.protocol, idHex: hex(id) })
      })
      return { ok: true }
    }
    case 'openChannel': {
      const conn = conns.get(msg.handle)
      const id = Buffer.from(msg.idHex, 'hex')
      const handlers = {
        onmessage: (value) =>
          msg.raw
            ? emit({ event: 'bytes', handle: msg.handle, label: ch.label, b64: Buffer.from(value).toString('base64') })
            : emit({ event: 'message', handle: msg.handle, label: ch.label, value }),
        onclose: () => emit({ event: 'channelClosed', handle: msg.handle, label: ch.label })
      }
      const ch = msg.raw
        ? conn._openChannel(msg.protocol, id, handlers, HistoryChannel)
        : conn.openChannel(msg.protocol, id, handlers)
      channels.set(`${msg.handle}:${ch.label}`, ch)
      return { ok: true, label: ch.label }
    }
    case 'send':
      return { ok: true, result: channels.get(`${msg.handle}:${msg.label}`).send(msg.message) }
    case 'sendRaw':
      return {
        ok: true,
        result: channels.get(`${msg.handle}:${msg.label}`).send(Buffer.from(msg.b64, 'base64'))
      }
    case 'closeChannel':
      channels.get(`${msg.handle}:${msg.label}`).close()
      return { ok: true }
    case 'diagnostics':
      return { ok: true, diagnostics: backend.diagnostics() }
    case 'stop':
      if (backend) await backend.stop()
      if (rtc) rtc.closeAll('stopped')
      return { ok: true }
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
  command(msg).then(emit, (err) => emit({ ok: false, error: String((err && err.stack) || err) }))
})
rl.on('close', () => {
  const done = backend ? backend.stop().catch(() => {}) : Promise.resolve()
  done.then(() => {
    if (rtc) rtc.closeAll('stdin closed')
    process.exit(0)
  })
})
process.on('uncaughtException', (err) => {
  process.stderr.write(`freenet_backend_peer.js uncaught: ${String((err && err.stack) || err)}\n`)
})
