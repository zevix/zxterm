// K6: a trivial newline-JSON echo server, for testkit::js::LineChild's own
// smoke test — not itself a parity fixture.
'use strict'
const readline = require('readline')

const rl = readline.createInterface({ input: process.stdin })
rl.on('line', (line) => {
  let value
  try {
    value = JSON.parse(line)
  } catch {
    return
  }
  process.stdout.write(JSON.stringify({ echo: value }) + '\n')
})
