// Smoke-test script for zxterm_testkit::js::{run,run_with_home}: proves the
// Rust helper can spawn Node, capture its stdout, and (via run_with_home)
// that the child sees the scratch HOME applied to it, not the ambient one.
console.log('pong ' + (process.env.HOME || ''))
