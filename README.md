# zxterm

`zxterm-core` is the Rust core behind [ZBTerm](https://github.com/zevix/zbterm), a terminal
recorder with peer-to-peer live sharing. It runs as a sidecar process next to the ZBTerm app and
owns the parts that are security-sensitive or need native networking:

- SSH key handling and SSH-agent signing
- GitHub identity claims and the identity key (mnemonic, identity key, device proofs)
- Session history storage and session crypto
- The Freenet share backend: the node client, contracts and WebRTC data channels
- Every wire, signature and key-derivation string ZBTerm puts on the network

The crate forbids `unsafe` code.

## Repository layout

| Path                           | What it is                                                              |
| ------------------------------ | ----------------------------------------------------------------------- |
| `crates/zxterm-core/`          | The library and the `zxterm-core` binary.                               |
| `crates/zxterm-testkit/`       | Test helpers: scratch homes, a fake SSH agent, a local Freenet node, JS parity runners. |
| `contracts/`                   | The Freenet contracts (Rust sources) and their compiled, BLAKE3-pinned `.wasm`. |
| `scripts/`                     | Build helpers for the contracts and the JS parity tests.                |

## Building

The toolchain is pinned in `rust-toolchain.toml`; `rustup` installs it on first use. Building
`aws-lc-sys` (pulled in by the WebRTC stack) also needs a C compiler and CMake.

```sh
cargo build --release -p zxterm-core
./target/release/zxterm-core --version
```

The binary has two subcommands:

```sh
zxterm-core sidecar --profile <dir> [--exit-on-stdin-eof]   # the long-running sidecar ZBTerm spawns
zxterm-core ctl --profile <dir> <method> [json-args]        # one request to a running sidecar
```

## Testing

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --check
cargo deny check licenses          # needs cargo-deny
```

Some tests need extra tools and skip with a printed reason when they are missing:

- **JS parity tests** compare the Rust code against ZBTerm's JavaScript. They read the ZBTerm
  checkout this repository is a submodule of, else one next to it (`../zbterm`), or the one named
  by `ZX_ZBTERM`, with its
  `node_modules` installed. The tests that compare against ZBTerm's former JS Freenet backend
  need `scripts/prepare-js-reference.sh` to run first.
- **Freenet tests** need a local `freenet` node binary on `PATH`.

## How ZBTerm ships it

ZBTerm includes this repository as a git submodule (`zxterm/`) and builds the binary in its own
release workflow, one npm package per platform. This repository publishes nothing to npm. To run
ZBTerm against a local build, set `ZXTERM_CORE_BIN=/path/to/zxterm-core`.

Supported targets: Linux x64 and arm64 (glibc), macOS arm64 and x64. Windows builds are not
supported yet: the sidecar's Windows listener (a named pipe) and SSH-agent client are not
implemented.

## Licence

MIT, see [LICENSE](LICENSE). The binary statically links third-party crates under their own
licences, listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). Among them is
`freenet-stdlib` under the LGPL-3.0: this repository is its corresponding source, and you can
rebuild the binary against a modified `freenet-stdlib` with the build steps above.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities privately, as described in
[SECURITY.md](SECURITY.md).
