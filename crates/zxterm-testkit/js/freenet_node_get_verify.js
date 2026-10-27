// K5 parity: connects to the same local node a Rust test just `Put`/
// `Update`d, `Get`s the signalling instance the input `route` names, and
// verifies the entry the input names with `signal.js::verifyEntry`, and the
// route itself with `route.js::verify` — direction "Rust minted/wrote, JS
// reads/verifies".
//
// Input (stdin, JSON): { nodeUrl, route, viewerPublicKeyHex, hostPublicKeyHex,
//   entryL, entryR, entrySeq }
// Output (stdout, JSON): { entryVerified, routeChecked, entryFound }
'use strict'
const fs = require('fs')

const root = process.env.ZX_ZBTERM
if (!root) throw new Error('ZX_ZBTERM not set')

const nodeClient = require(root + '/engine/backends/freenet/node-client.js')
const route = require(root + '/engine/backends/freenet/route.js')
const signal = require(root + '/engine/backends/freenet/signal.js')
const contracts = require(root + '/engine/backends/freenet/contracts.js')

function fromHex(s) {
  return Buffer.from(s, 'hex')
}

async function main() {
  const input = JSON.parse(fs.readFileSync(0, 'utf8'))

  let routeChecked = false
  try {
    route.verify(input.route, fromHex(input.hostPublicKeyHex), contracts)
    routeChecked = true
  } catch (err) {
    routeChecked = false
  }

  const wasm = contracts.known.get(input.route.code)
  if (!wasm) throw new Error('unknown signalling code: ' + input.route.code)
  const paramsBytes = route.paramsBytes(input.route.params)
  const { key } = nodeClient.contractKey(wasm, paramsBytes)

  const client = await nodeClient.connect(input.nodeUrl)
  let entryFound = false
  let entryVerified = false
  try {
    const res = await client.get(key)
    const state = JSON.parse(Buffer.from(res.state).toString('utf8'))
    const entry = (state.e || []).find(
      (e) => e.l === input.entryL && e.r === input.entryR && e.s === input.entrySeq
    )
    if (entry) {
      entryFound = true
      const viewerKey = fromHex(input.viewerPublicKeyHex)
      entryVerified = signal.verifyEntry(viewerKey, paramsBytes, entry)
    }
  } finally {
    await client.close()
  }

  process.stdout.write(JSON.stringify({ entryVerified, routeChecked, entryFound }))
}

main().catch((err) => {
  process.stderr.write(String(err && err.stack ? err.stack : err) + '\n')
  process.exit(1)
})
