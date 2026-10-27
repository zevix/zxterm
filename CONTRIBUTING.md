# Contributing to zxterm

Bug reports, fixes and focused improvements are welcome.

## Before you open a pull request

- `cargo fmt --check` and `cargo clippy --workspace --all-targets` are clean.
- `cargo test --workspace` passes. If a test skips because a tool is missing, say so in the pull
  request.
- Changes to anything ZBTerm reads (the seam protocol, wire strings, key derivations, contract
  hashes) are checked against ZBTerm too: run the JS parity tests with a ZBTerm checkout at
  `../zbterm` or `ZX_ZBTERM`.
- A new dependency passes `cargo deny check licenses`. Don't widen the licence allow list in
  `deny.toml` without discussing it in an issue first, and add any attribution the licence needs
  to `THIRD-PARTY-NOTICES.md`.
- No `unsafe` code; the crate forbids it.

For larger changes (protocol or storage format changes, new network backends), please open an
issue first so we can agree on the approach.

## Freenet contracts

The compiled contracts in `contracts/` are pinned by BLAKE3 in `contracts/hashes.json`.
`scripts/build-contracts.sh` rebuilds them and checks the pins; it never rewrites them. Changing a
contract changes its key on the network, so it is a breaking change for every ZBTerm user.

## Security issues

Please don't report vulnerabilities in public issues. See [SECURITY.md](SECURITY.md).

## Licence

By contributing, you agree that your contributions are licensed under the [MIT licence](LICENSE).
