# Third-party notices

This project (`zxterm-core` and its workspace crates) is MIT-licensed (`LICENSE`, `X-04`). This
file carries the attribution and licence text each dependency's licence requires, grouped by
licence family. A heading is added only once a phase actually depends on a crate under that
family; until then its body carries only the fill marker below.

## Apache-2.0

K4 (2026-09-29): `zxterm_core::idkey` ports the identity-key derivation scheme (mnemonic → identity
key → device proof) algorithm-for-algorithm from Holepunch Inc.'s `keet-identity-key` npm package,
version 3.2.0, read directly from ZBTerm's `node_modules/keet-identity-key` on 2026-09-28. No code
from that package is compiled into or linked with any binary in this repository — only its algorithm
is ported, in Rust, with the two name-bearing constants replaced (`X-01`/`A-4`) — but its attribution
is carried here regardless, per `A-8`. This is the only place in either repository allowed to name
it; every mention inside `crates/` describes it only as "the upstream identity-key package".

Licensed under the Apache License, Version 2.0. Full licence text:
`http://www.apache.org/licenses/LICENSE-2.0` (identical to the copy shipped in the package's own
`LICENSE` file). The package ships no `NOTICE` file. Copyright: Holepunch Inc. (`package.json`'s
`author` field); the package's own `LICENSE` file carries the standard Apache License boilerplate
template with its bracketed `[yyyy] [name of copyright owner]` line left unfilled.

K5 (2026-09-29) added `zxterm_core::freenet::node`'s flatbuffers dependency (`flatbuffers`, pulled in
transitively by `freenet-stdlib`), the one crate in this project's graph offering only Apache-2.0 (no
MIT alternative). Licensed under the Apache License, Version 2.0, same full text as above. The
package ships no licence file of its own in its published source (only the `license = "Apache-2.0"`
field in its own `Cargo.toml`); upstream is `https://github.com/google/flatbuffers`.

K6 (2026-09-29) added `zxterm_core::freenet::rtc`'s WebRTC dependency (`str0m`) and, transitively via
its DTLS layer (`dimpl`)'s default `rcgen` feature, `flagset`, which offers only Apache-2.0 (no MIT
alternative), same full text as above. Its own `LICENSE` file carries no filled-in copyright line.

## CC0-1.0

K4 (2026-09-29) added `zxterm_core::idkey`'s BIP-39 dependency (`bip39`) and its own CC0-1.0
transitive dependency (`bitcoin_hashes`). CC0-1.0 is a public-domain dedication with a fallback
permissive licence; neither crate's own licence file carries a filled-in copyright line (a public-
domain dedication names no rights-holder to attribute).

K5 (2026-09-29) added three more, all reached via `zxterm_core::freenet`: `blake3` (offered as `CC0-
1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception`; this project's choice is CC0-1.0, needing no
attribution, same as the two below), `hex-conservative` (transitive, via `bs58`; CC0-1.0 only) and
`constant_time_eq` (transitive, via `blake3`; offered as `CC0-1.0 OR MIT-0 OR Apache-2.0`, its own
CC0 file chosen for the same reason).

| crate | version |
|---|---|
| bip39 | 3.0.0 |
| bitcoin_hashes | 0.14.101 |
| blake3 | 1.8.7 |
| constant_time_eq | 0.4.2 |
| hex-conservative | 0.2.3 |

Full text: `https://creativecommons.org/publicdomain/zero/1.0/legalcode` (identical to the copy
shipped in `bip39`'s own `LICENSE` file, `blake3`'s own `LICENSE_CC0` and `constant_time_eq`'s own
`LICENSE-CC0`; `bitcoin_hashes` and `hex-conservative` ship no licence file of their own, only the
`license = "CC0-1.0"` field in their own `Cargo.toml`).

## LGPL-3.0-only

K5 (2026-09-29) added `zxterm_core::freenet::node`'s Freenet node-client dependency, `freenet-stdlib`
(`X-04`/`X-06`; the Rust client's own version choice, `0.12.1`, distinct from ZBTerm JS's `=0.10.0`
contract pin — see `X-06`), statically linked while its source stays public, and its own build-time
proc-macro dependency `freenet-macros` (same upstream, same licence, not a separate acceptance —
`deny.toml`'s exception list carries both).

| crate | version |
|---|---|
| freenet-macros | 0.3.1 |
| freenet-stdlib | 0.12.1 |

Licensed under the GNU Lesser General Public License, version 3.0 only. Full licence text:
`https://www.gnu.org/licenses/lgpl-3.0.txt`. Source: `https://github.com/freenet/freenet-core`
(the workspace `freenet-stdlib` and `freenet-macros` are published from). `freenet-stdlib` ships the
licence text itself (`LICENSE`), whose only copyright line is the FSF's own, of the licence text, not
of the crate: `Copyright (C) 2007 Free Software Foundation, Inc.`. `freenet-macros` ships no licence
file of its own at all, only the `license = "LGPL-3.0-only"` field in its own `Cargo.toml`.

## MIT

K2 (2026-09-29) added `zxterm-core`'s SSH-key/SSHSIG dependencies (`sha2`, `ed25519-dalek`, `rsa`)
and their transitive dependency graph. Every crate below is licensed MIT (several dual/triple-
licensed MIT OR Apache-2.0, sometimes also OR/AND a third term; this project's choice for each is
MIT). The permission text is identical across all of them (the standard MIT licence); each crate's
own copyright line, as printed in that crate's own licence file, is listed once under it — a crate
with no copyright line printed in its own licence file is marked as such rather than inventing one.

K4 (2026-09-29) added `zxterm_core::idkey`'s BLAKE2b, hex and HMAC dependencies (`blake2`, `hex`,
`hmac`) and `bip39`'s non-CC0 transitive dependency (`unicode-normalization`, pulled in by its
default `std`/`alloc` features even though this project calls only `Mnemonic::to_seed_normalized`,
which does not itself need Unicode normalisation).

K5 (2026-09-29) added `zxterm_core::freenet`'s node-client, route, signal and pointer-record
dependencies (`crypto_secretbox`, `bs58`, `serde_json`, `freenet-stdlib`'s own `tokio`/
`tokio-tungstenite`/`futures` transport stack) and their transitive dependency graph. Every crate
below this point is likewise MIT (several dual-licensed MIT OR Apache-2.0, some with a third or
fourth term such as `Unlicense`; this project's choice for each is MIT, same convention as K2/K4's
rows above). Appended after `zeroize` rather than interleaved alphabetically with the existing rows,
so this edit touches no line any earlier phase wrote.

K6 (2026-09-29) added `zxterm_core::freenet::rtc`'s WebRTC dependency (`str0m`, spike S2) and its own
transitive dependency graph: the SDP/SCTP/DTLS stack (`sctp-proto`, `dimpl`, and `dimpl`'s default
`aws-lc-rs` cryptography and `rcgen` certificate-generation features) and their own further
dependencies. Every crate in this batch is likewise dual/triple-licensed with an MIT option (this
project's choice MIT); the one exception is `aws-lc-rs`/`aws-lc-sys` themselves, which also carry an
unconditional ISC-licensed portion — recorded separately below (`## ISC`), not in this table, since
ISC is a distinct licence text from MIT. Appended after `zmij` rather than interleaved alphabetically
with the existing rows, so this edit touches no line any earlier phase wrote.

> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
> associated documentation files (the "Software"), to deal in the Software without restriction,
> including without limitation the rights to use, copy, modify, merge, publish, distribute,
> sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or
> substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
> NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
> NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
> DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
> OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

| crate | version | copyright (from the crate's own licence file) |
|---|---|---|
| blake2 | 0.11.0 | Copyright (c) 2017-2026 The RustCrypto Project Developers; Copyright (c) 2017 Artyom Pavlov |
| block-buffer | 0.12.1 | Copyright (c) 2018-2025 The RustCrypto Project Developers |
| cfg-if | 1.0.5 | Copyright (c) 2014 Alex Crichton |
| const-oid | 0.9.6 | Copyright (c) 2020-2022 The RustCrypto Project Developers |
| const-oid | 0.10.2 | Copyright (c) 2020-2026 The RustCrypto Project Developers |
| cpufeatures | 0.3.1 | Copyright (c) 2020-2026 The RustCrypto Project Developers |
| crypto-common | 0.1.7 | Copyright (c) 2021 RustCrypto Developers |
| crypto-common | 0.2.2 | Copyright (c) 2021-2026 RustCrypto Developers |
| curve25519-dalek-derive | 0.1.1 | (no copyright line in its own licence file) |
| der | 0.7.10 | Copyright (c) 2020-2023 The RustCrypto Project Developers |
| digest | 0.10.7 | Copyright (c) 2017 Artyom Pavlov |
| digest | 0.11.3 | Copyright (c) 2017-2025 RustCrypto Developers; Copyright (c) 2017 Artyom Pavlov |
| ed25519 | 3.0.0 | Copyright (c) 2018-2026 RustCrypto Developers |
| generic-array | 0.14.7 | Copyright (c) 2015 Bartłomiej Kamiński |
| getrandom | 0.2.17 | Copyright (c) 2018-2024 The rust-random Project Developers; Copyright (c) 2014 The Rust Project Developers |
| hex | 0.4.3 | Copyright (c) 2013-2014 The Rust Project Developers.; Copyright (c) 2015-2020 The rust-hex Developers |
| hmac | 0.13.0 | Copyright (c) 2017 Artyom Pavlov |
| hybrid-array | 0.4.15 | Copyright (c) 2022-2026 The RustCrypto Project Developers |
| lazy_static | 1.5.0 | Copyright (c) 2010 The Rust Project Developers |
| libc | 0.2.189 | Copyright (c) The Rust Project Developers |
| libm | 0.2.16 | (no copyright line in its own licence file) |
| num-bigint-dig | 0.8.6 | Copyright (c) 2014 The Rust Project Developers |
| num-integer | 0.1.47 | Copyright (c) 2014 The Rust Project Developers |
| num-iter | 0.1.46 | Copyright (c) 2014 The Rust Project Developers |
| num-traits | 0.2.19 | Copyright (c) 2014 The Rust Project Developers |
| pkcs1 | 0.7.5 | Copyright (c) 2021-2023 The RustCrypto Project Developers |
| pkcs8 | 0.10.2 | Copyright (c) 2020-2023 The RustCrypto Project Developers |
| ppv-lite86 | 0.2.21 | Copyright (c) 2019 The CryptoCorrosion Contributors |
| proc-macro2 | 1.0.107 | (no copyright line in its own licence file; build-time proc-macro tooling, not linked into any binary) |
| quote | 1.0.47 | (no copyright line in its own licence file; build-time proc-macro tooling, not linked into any binary) |
| rand | 0.8.8 | Copyright 2018 Developers of the Rand project; Copyright (c) 2014 The Rust Project Developers |
| rand_chacha | 0.3.1 | Copyright 2018 Developers of the Rand project; Copyright (c) 2014 The Rust Project Developers |
| rand_core | 0.6.4 | Copyright 2018 Developers of the Rand project; Copyright (c) 2014 The Rust Project Developers |
| rsa | 0.9.10 | (no copyright line in its own licence file) |
| sha2 | 0.11.0 | Copyright (c) 2016-2026 The RustCrypto Project Developers; Copyright (c) 2016 Artyom Pavlov; Copyright (c) 2009-2013 Mozilla Foundation |
| signature | 2.2.0 | Copyright (c) 2018-2023 RustCrypto Developers |
| signature | 3.0.0 | Copyright (c) 2018-2026 RustCrypto Developers |
| smallvec | 1.16.2 | Copyright (c) 2018 The Servo Project Developers |
| spin | 0.9.9 | Copyright (c) 2014 Mathijs van de Nes |
| spki | 0.7.3 | Copyright (c) 2021-2023 The RustCrypto Project Developers |
| syn | 2.0.119 | (no copyright line in its own licence file; build-time proc-macro tooling, not linked into any binary) |
| tinyvec | 1.13.3 | (no copyright line in its own licence file; triple-licensed Zlib OR Apache-2.0 OR MIT, this project's choice MIT) |
| unicode-ident | 1.0.26 | (no copyright line in its own licence file; build-time proc-macro tooling, not linked into any binary; also carries the Unicode-3.0 licence for its generated character-property tables, reproduced below) |
| unicode-normalization | 0.1.25 | Copyright (c) 2015 The Rust Project Developers |
| typenum | 1.20.1 | Copyright (c) 2014 Paho Lurie-Gregg |
| zerocopy | 0.8.59 | Copyright 2023 The Fuchsia Authors (MIT text; also available under BSD-2-Clause/Apache-2.0) |
| zeroize | 1.9.0 | Copyright (c) 2018-2026 The RustCrypto Project Developers |
| aead | 0.5.2 | Copyright (c) 2019 The RustCrypto Project Developers |
| arrayvec | 0.7.8 | Copyright (c) Ulrik Sverdrup "bluss" 2015-2023 |
| base64 | 0.22.1 | Copyright (c) 2015 Alice Maz |
| bincode | 1.3.3 | Copyright (c) 2014 Ty Overby |
| bitflags | 1.3.2 | Copyright (c) 2014 The Rust Project Developers |
| byteorder | 1.5.0 | Copyright (c) 2015 Andrew Gallant (dual `Unlicense OR MIT`; this project's choice MIT) |
| bytes | 1.12.1 | Copyright (c) 2018 Carl Lerche |
| chrono | 0.4.45 | Copyright (c) 2014, Kang Seonghoon. |
| cipher | 0.4.4 | Copyright (c) 2016-2020 RustCrypto Developers |
| cmov | 0.5.4 | Copyright (c) 2022-2026 The RustCrypto Project Developers |
| crypto_secretbox | 0.1.1 | Copyright (c) 2019-2023 The RustCrypto Project Developers |
| ctutils | 0.4.2 | Copyright (c) 2025-2026 The RustCrypto Project Developers |
| darling | 0.24.1 | Copyright (c) 2017 Ted Driggs |
| darling_core | 0.24.1 | Copyright (c) 2017 Ted Driggs |
| darling_macro | 0.24.1 | Copyright (c) 2017 Ted Driggs |
| data-encoding | 2.11.1 | Copyright (c) 2015-2020 Julien Cretin |
| futures | 0.3.34 | Copyright (c) 2016 Alex Crichton |
| futures-channel | 0.3.34 | Copyright (c) 2016 Alex Crichton |
| futures-core | 0.3.34 | Copyright (c) 2016 Alex Crichton |
| futures-executor | 0.3.34 | Copyright (c) 2016 Alex Crichton |
| futures-io | 0.3.34 | Copyright (c) 2016 Alex Crichton |
| futures-macro | 0.3.34 | Copyright (c) 2016 Alex Crichton |
| futures-sink | 0.3.34 | Copyright (c) 2016 Alex Crichton |
| futures-task | 0.3.34 | Copyright (c) 2016 Alex Crichton |
| futures-util | 0.3.34 | Copyright (c) 2016 Alex Crichton |
| http | 1.5.0 | Copyright (c) 2017 http-rs authors |
| httparse | 1.10.1 | Copyright (c) 2015-2025 Sean McArthur |
| ident_case | 1.0.1 | (no copyright line in its own licence file) |
| itoa | 1.0.18 | (no copyright line in its own licence file) |
| lock_api | 0.4.14 | Copyright (c) 2016 The Rust Project Developers |
| log | 0.4.34 | Copyright (c) 2014 The Rust Project Developers |
| matchers | 0.2.0 | Copyright (c) 2019 Eliza Weisman |
| memchr | 2.8.3 | Copyright (c) 2015 Andrew Gallant (dual `Unlicense OR MIT`; this project's choice MIT) |
| mio | 1.2.3 | Copyright (c) 2014 Carl Lerche and other MIO contributors |
| nu-ansi-term | 0.50.3 | Copyright (c) 2014 Benjamin Sago |
| once_cell | 1.21.4 | (no copyright line in its own licence file) |
| opaque-debug | 0.3.1 | Copyright (c) 2018-2024 The RustCrypto Project Developers |
| parking_lot | 0.12.5 | Copyright (c) 2016 The Rust Project Developers |
| parking_lot_core | 0.9.12 | Copyright (c) 2016 The Rust Project Developers |
| pin-project-lite | 0.2.17 | (no copyright line in its own licence file) |
| poly1305 | 0.8.0 | Copyright (c) 2015-2019 RustCrypto Developers |
| regex-automata | 0.4.18 | Copyright (c) 2014 The Rust Project Developers |
| regex-syntax | 0.8.11 | Copyright (c) 2014 The Rust Project Developers |
| salsa20 | 0.10.2 | Copyright (c) 2019 Eric McCorkle |
| scopeguard | 1.2.0 | Copyright (c) 2016-2019 Ulrik Sverdrup "bluss" and scopeguard developers |
| semver | 1.0.28 | (no copyright line in its own licence file) |
| serde | 1.0.229 | (no copyright line in its own licence file) |
| serde_core | 1.0.229 | (no copyright line in its own licence file) |
| serde_derive | 1.0.229 | (no copyright line in its own licence file) |
| serde_json | 1.0.151 | (no copyright line in its own licence file) |
| serde_with | 3.24.0 | Copyright (c) 2015 |
| serde_with_macros | 3.24.0 | Copyright (c) 2015 |
| sha1 | 0.10.7 | Copyright (c) 2006-2009 Graydon Hoare |
| sharded-slab | 0.1.7 | Copyright (c) 2019 Eliza Weisman |
| slab | 0.4.12 | Copyright (c) 2019 Carl Lerche |
| socket2 | 0.6.5 | Copyright (c) 2014 Alex Crichton |
| strsim | 0.11.1 | Copyright (c) 2015 Danny Guo |
| syn | 3.0.6 | (no copyright line in its own licence file; build-time proc-macro tooling, not linked into any binary) |
| thiserror | 2.0.21 | (no copyright line in its own licence file) |
| thiserror-impl | 2.0.21 | (no copyright line in its own licence file; build-time proc-macro tooling, not linked into any binary) |
| thread_local | 1.1.10 | Copyright (c) 2016 The Rust Project Developers |
| tokio | 1.53.1 | Copyright (c) Tokio Contributors |
| tokio-macros | 2.7.2 | Copyright (c) 2019 Yoshua Wuyts |
| tokio-tungstenite | 0.27.0 | Copyright (c) 2017 Daniel Abramov |
| tracing | 0.1.44 | Copyright (c) 2019 Tokio Contributors |
| tracing-attributes | 0.1.31 | Copyright (c) 2019 Tokio Contributors |
| tracing-core | 0.1.36 | Copyright (c) 2019 Tokio Contributors |
| tracing-log | 0.2.0 | Copyright (c) 2019 Tokio Contributors |
| tracing-subscriber | 0.3.23 | Copyright (c) 2019 Tokio Contributors |
| tungstenite | 0.27.0 | Copyright (c) 2017 Alexey Galakhov |
| universal-hash | 0.5.1 | Copyright (c) 2019-2020 RustCrypto Developers |
| utf-8 | 0.7.6 | (no copyright line in its own licence file) |
| zmij | 1.0.23 | (no copyright line in its own licence file) |
| aes | 0.8.4 | Copyright (c) 2018 Artyom Pavlov |
| base16ct | 0.2.0 | Copyright (c) 2014 Steve "Sc00bz" Thomas (steve at tobtu dot com); Copyright (c) 2022 The RustCrypto Project Developers |
| base64ct | 1.8.3 | Copyright (c) 2014 Steve "Sc00bz" Thomas (steve at tobtu dot com); Copyright (c) 2021-2025 The RustCrypto Project Developers |
| ccm | 0.5.0 | Copyright (c) 2020 The RustCrypto Project Developers |
| combine | 4.6.8 | Copyright (c) 2015 Markus Westerlind |
| crc | 3.4.0 | Copyright (c) 2017 crc-rs Developers |
| crc-catalog | 2.5.0 | (no copyright line in its own licence file) |
| ctr | 0.9.2 | Copyright (c) 2018-2022 RustCrypto Developers; Copyright (c) 2018 Artyom Pavlov |
| der_derive | 0.7.3 | Copyright (c) 2020-2022 The RustCrypto Project Developers |
| deranged | 0.5.8 | Copyright (c) 2024 Jacob Pratt et al. |
| dimpl | 0.7.4 | Copyright 2022 Martin Algesten |
| fastrand | 2.5.0 | (no copyright line in its own licence file) |
| is | 0.11.1 | (no licence file of its own in its published source; `license = "MIT OR Apache-2.0"` in its own `Cargo.toml`) |
| nom | 8.0.0 | Copyright (c) 2014-2019 Geoffroy Couprie |
| num-conv | 0.2.2 | Copyright (c) Jacob Pratt |
| pem-rfc7468 | 0.7.0 | Copyright (c) 2021 The RustCrypto Project Developers |
| powerfmt | 0.2.0 | Copyright (c) 2023 Jacob Pratt et al. |
| rcgen | 0.14.10 | Copyright (c) 2019-2026 est31 <MTest31@outlook.com> and contributors |
| rustc-hash | 2.1.3 | (no copyright line in its own licence file) |
| sctp-proto | 0.10.5 | Copyright (c) 2021-2026 WebRTC.rs; Copyright (c) 2026 Martin Algesten |
| sec1 | 0.7.3 | Copyright (c) 2021-2022 The RustCrypto Project Developers |
| str0m | 0.24.0 | Copyright 2022 Martin Algesten |
| str0m-aws-lc-rs | 0.6.0 | (no licence file of its own in its published source; part of the `str0m` workspace, `license = "MIT OR Apache-2.0"` in its own `Cargo.toml`, same copyright as `str0m` above) |
| str0m-proto | 0.7.0 | (no licence file of its own in its published source; same note as `str0m-aws-lc-rs` above) |
| time | 0.3.55 | Copyright (c) Jacob Pratt et al. |
| time-core | 0.1.9 | Copyright (c) Jacob Pratt et al. |
| x509-cert | 0.2.5 | Copyright (c) 2021 The RustCrypto Project Developers |
| yasna | 0.6.0 | Copyright (c) 2016 Masaki Hara |

K3 (2026-09-29, `X-08`) added `zxterm_core::identity::github`'s HTTP-client dependency (`ureq`,
spike S4 part 2) and its own dependency graph not already covered above. `base64` 0.23.1 is a
*second*, different version from the 0.22.1 this crate already depends on directly (K1) — `ureq`
pins its own; both are listed since `cargo` can and does link two versions of the same crate.

| crate | version | copyright (from the crate's own licence file) |
|---|---|---|
| base64 | 0.23.1 | Copyright (c) 2025 Alice Maz, Marshall Pierce |
| percent-encoding | 2.3.2 | Copyright (c) 2013-2025 The rust-url developers |
| rustls | 0.23.45 | Copyright (c) 2016 Joseph Birr-Pixton <jpixton@gmail.com> |
| rustls-pki-types | 1.15.1 | Copyright (c) 2023 Dirkjan Ochtman <dirkjan@ochtman.nl> |
| ureq | 3.4.2 | Copyright (c) 2019 Martin Algesten |
| ureq-proto | 0.6.4 | Copyright 2022 Martin Algesten |
| utf8-zero | 0.8.1 | (no copyright line in its own licence file) |

K7 (2026-09-29) added `zxterm_core::seam`'s frame-protocol dependency (`postcard`, spike S3) and its
own dependency graph not already covered above. All dual-licensed MIT OR Apache-2.0 (this project's
choice MIT, same convention as every row above). `heapless`'s own optional `atomic-polyfill`/
`critical-section`/`embedded-io` dependencies resolve in `Cargo.lock` (for targets without native
atomics) but are not compiled for this workspace's `x86_64-unknown-linux-gnu`/`wasm32-unknown-unknown`
targets, so they carry no attribution obligation here and are not listed.

| crate | version | copyright (from the crate's own licence file) |
|---|---|---|
| cobs | 0.3.0 | Copyright (c) 2015 The cobs.rs Developers |
| hash32 | 0.2.1 | Copyright (c) 2018 Jorge Aparicio |
| heapless | 0.7.17 | Copyright (c) 2017 Jorge Aparicio |
| postcard | 1.1.3 | Copyright (c) 2019 Anthony James Munns |
| stable_deref_trait | 1.2.1 | Copyright (c) 2017 Robert Grosse |

### Unicode-3.0 (`unicode-ident`)

`unicode-ident` 1.0.26's data tables are additionally licensed under the Unicode Licence v3
(`https://www.unicode.org/license.txt`), reproduced from its own `LICENSE-UNICODE` file:

> Copyright © 1991-2023 Unicode, Inc. NOTICE TO USER: Carefully read the following legal agreement.
> BY DOWNLOADING, INSTALLING, COPYING OR OTHERWISE USING UNICODE INC.'S DATA FILES ("DATA FILES"),
> AND/OR SOFTWARE ("SOFTWARE"), YOU UNEQUIVOCALLY ACCEPT, AND AGREE TO BE BOUND BY, ALL OF THE TERMS
> AND CONDITIONS OF THIS AGREEMENT. IF YOU DO NOT AGREE, DO NOT DOWNLOAD, INSTALL, COPY, DISTRIBUTE
> OR USE THE DATA FILES OR SOFTWARE. See `https://www.unicode.org/license.txt` for the full text.

K13 (2026-09-30) added `zxterm_core::session`'s AEAD and sealed-box dependencies (`chacha20poly1305`,
RustCrypto's XChaCha20-Poly1305, for the live-frame AEAD; `crypto_box` with its `seal` feature, for
libsodium's anonymous-sender `crypto_box_seal`) and the part of their dependency graph not already
covered above. All dual-licensed MIT OR Apache-2.0 (this project's choice MIT, same convention as
every row above). `blake2` 0.10.6 is a *second* version beside the 0.11.0 this crate depends on
directly (K4): `crypto_box` pins its own for the sealed box's nonce. `curve25519-dalek` 4.1.3 (a
second version beside K2's 5.0.0) is BSD-3-Clause and listed under that heading below.
`fiat-crypto` 0.2.9 resolves in `Cargo.lock` as `curve25519-dalek`'s backend for other targets but
is not compiled for this workspace's targets, so it carries no attribution obligation here. `inout`
0.1.4 (a `cipher` dependency since K5's `crypto_secretbox`) was missing from K5's rows and is added
here.

| crate | version | copyright (from the crate's own licence file) |
|---|---|---|
| blake2 | 0.10.6 | Copyright (c) 2015-2016 The blake2-rfc Developers, Cesar Barros; Copyright (c) 2017 Artyom Pavlov |
| chacha20 | 0.9.1 | Copyright (c) 2019-2023 The RustCrypto Project Developers |
| chacha20poly1305 | 0.10.1 | Copyright (c) 2019 The RustCrypto Project Developers |
| crypto_box | 0.9.1 | Copyright (c) 2020-2023 The RustCrypto Project Developers |
| inout | 0.1.4 | Copyright (c) 2022 The RustCrypto Project Developers; Copyright (c) 2022 Artyom Pavlov |

K15 (2026-09-30) added `zxterm_core::history`'s segment-compression and screen-snapshot dependencies
(`zstd`, the Rust binding to Zstandard, and `vt100`, the terminal-screen parser) and the part of
their dependency graph not already covered above. `zstd`, `vt100` are MIT; `vte`, `unicode-width` and
`pkg-config` are dual-licensed MIT OR Apache-2.0 (this project's choice MIT, same convention as every
row above). `zstd-safe` and `zstd-sys` (with the Zstandard C library it compiles) are BSD-3-Clause and
listed under that heading below. `cc` (already in the graph as a build dependency of `aws-lc-sys`
through `cmake`, and missing from the K6 rows), `shlex`, `find-msvc-tools` and `jobserver` are
MIT OR Apache-2.0 build-time tooling that compiles `zstd-sys`'s C sources; none is linked into a
binary, and they are listed for completeness.

| crate | version | copyright (from the crate's own licence file) |
|---|---|---|
| cc | 1.5.1 | Copyright (c) 2014 Alex Crichton (build-time tooling) |
| find-msvc-tools | 0.1.14 | Copyright (c) 2014 Alex Crichton (build-time tooling) |
| jobserver | 0.1.35 | Copyright (c) 2014 Alex Crichton (build-time tooling) |
| pkg-config | 0.3.34 | Copyright (c) 2014 Alex Crichton (build-time tooling) |
| shlex | 2.0.1 | Copyright (c) 2015 Nicholas Allegra (comex) (build-time tooling) |
| unicode-width | 0.2.2 | Copyright (c) 2015 The Rust Project Developers |
| vt100 | 0.16.2 | Copyright (c) 2016 Jesse Luehrs |
| vte | 0.15.0 | Copyright (c) 2016 Joe Wilm |
| zstd | 0.13.3 | Copyright (c) 2016 Alexandre Bury |

## BSD-2-Clause / BSD-3-Clause

K2 (2026-09-29) added three BSD-3-Clause dependencies of `zxterm-core::ssh::sshsig`
(`ed25519-dalek`'s ed25519 signing, and its own dependencies `curve25519-dalek` and `subtle`).

`ed25519-dalek` 3.0.0, from its own `LICENSE`:

> Copyright (c) 2017-2019 isis agora lovecruft. All rights reserved.
>
> Redistribution and use in source and binary forms, with or without modification, are permitted
> provided that the following conditions are met:
>
> 1. Redistributions of source code must retain the above copyright notice, this list of conditions
>    and the following disclaimer.
>
> 2. Redistributions in binary form must reproduce the above copyright notice, this list of
>    conditions and the following disclaimer in the documentation and/or other materials provided
>    with the distribution.
>
> 3. Neither the name of the copyright holder nor the names of its contributors may be used to
>    endorse or promote products derived from this software without specific prior written
>    permission.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
> IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
> FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
> CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
> DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
> DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
> IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
> OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

`curve25519-dalek` 5.0.0, from its own `LICENSE` (same terms as above, different copyright holders):

> Copyright (c) 2016-2021 isis agora lovecruft. All rights reserved.
> Copyright (c) 2016-2021 Henry de Valence. All rights reserved.

`subtle` 2.6.1, from its own `LICENSE` (same terms as above, different copyright holders):

> Copyright (c) 2016-2017 Isis Agora Lovecruft, Henry de Valence. All rights reserved.
> Copyright (c) 2016-2024 Isis Agora Lovecruft. All rights reserved.

K13 (2026-09-30) added `curve25519-dalek` 4.1.3 (through `crypto_box`, the X25519 of
`crypto_box_seal`), from its own `LICENSE` (same terms as above):

> Copyright (c) 2016-2021 isis agora lovecruft. All rights reserved.
> Copyright (c) 2016-2021 Henry de Valence. All rights reserved.

K15 (2026-09-30) added `zstd-safe` 7.3.0 and `zstd-sys` 2.1.0+zstd.1.5.7 (through `zstd`, the segment
compression of `zxterm_core::history`), both BSD-3-Clause, and the Zstandard C library `zstd-sys`
compiles and links (version 1.5.7, BSD-3-Clause as the offered alternative to GPL-2.0-only).

`zstd-safe` and `zstd-sys`, from their own `LICENSE` (BSD-3-Clause, the same three conditions and
disclaimer as `ed25519-dalek`'s above):

> Copyright (c) 2026, Alexandre Bury

The Zstandard C library, from `zstd-sys`'s bundled `zstd/LICENSE` (same terms, other holder):

> Copyright (c) Meta Platforms, Inc. and affiliates. All rights reserved.

## MPL-2.0

<!-- filled by K<n> -->

## ISC

K6 (2026-09-29) added `zxterm_core::freenet::rtc`'s WebRTC dependency (`str0m`, spike S2), whose
default cryptography backend (`dimpl`'s `aws-lc-rs` feature) pulls in `aws-lc-rs` and `aws-lc-sys`.
Both declare a compound SPDX expression (`aws-lc-rs`: `ISC AND (Apache-2.0 OR ISC)`; `aws-lc-sys`:
`ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT)
AND (Apache-2.0 OR ISC OR MIT-0)`), reflecting AWS-LC's own origin as a fork of BoringSSL (itself a
fork of OpenSSL): most of the bundled code is already Apache-2.0/MIT/BSD-3-Clause/MIT-0, covered by
this file's existing sections, but a portion — code inherited from BoringSSL before its own
relicensing to Apache-2.0 — is ISC-only, with no Apache-2.0/MIT alternative, hence this section (`ISC`
is added to `deny.toml`'s global `allow` list rather than as a per-crate exception, since it is
unconditionally permissive on its own, the same reasoning as this project's other allowed licences).

Full text (identical in both crates' own `LICENSE` files, `ISC license` section), copyright from
`aws-lc-rs`'s own `LICENSE` file (`aws-lc-sys`'s ISC-licensed portions carry per-file copyright lines
inherited from Google's BoringSSL and, further back, OpenSSL — not reproduced individually here):

> Copyright Amazon.com, Inc. or its affiliates.
>
> Permission to use, copy, modify, and/or distribute this software for any purpose with or without
> fee is hereby granted, provided that the above copyright notice and this permission notice appear
> in all copies.
>
> THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
> SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
> AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
> WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
> NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
> THIS SOFTWARE.

K3 (2026-09-29, `X-08`) added three more, all reached via `zxterm_core::identity::github`'s HTTP
client (`ureq`, built on `rustls`): `ring` (`Apache-2.0 AND ISC` — the Apache-2.0 portion is already
covered by this file's Apache-2.0 section; the ISC portion is BoringSSL/OpenSSL-derived code, same
provenance as `aws-lc-rs`/`aws-lc-sys` above), `rustls-webpki` (ISC-only) and `untrusted` (ISC-only,
`ring`'s own dependency). Same licence text as above; copyright per each crate's own `LICENSE` file.

| crate | version |
|---|---|
| aws-lc-rs | 1.18.1 |
| aws-lc-sys | 0.45.0 |
| ring | 0.17.14 |
| rustls-webpki | 0.103.15 |
| untrusted | 0.9.0 |

## CDLA-Permissive-2.0

K3 (2026-09-29, `X-08`) added `webpki-roots` (transitive, via `ureq`'s `rustls-webpki-roots`
feature): Mozilla's bundled set of root CA certificates, licensed under the Community Data License
Agreement – Permissive, version 2.0 — a permissive, no-copyleft data licence, not a software licence
(the crate's own content is that certificate data, compiled to Rust source at its build time).

Full text: `https://cdla.dev/permissive-2-0/` (the crate ships no separate `LICENSE` file of its own;
its `Cargo.toml` names `CDLA-Permissive-2.0` and its `README` points to the Mozilla root-store data
this is compiled from, which carries no per-entry copyright line to reproduce).

| crate | version |
|---|---|
| webpki-roots | 1.0.9 |
