# blvm-primitives

[![crates.io](https://img.shields.io/crates/v/blvm-primitives.svg)](https://crates.io/crates/blvm-primitives)
[![docs.rs](https://docs.rs/blvm-primitives/badge.svg)](https://docs.rs/blvm-primitives)
[![CI](https://github.com/BTCDecoded/blvm-primitives/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/BTCDecoded/blvm-primitives/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Foundational types, serialization, crypto, and config for Bitcoin consensus and protocol layers.

Part of [Bitcoin Commons](https://btcdecoded.org) BLVM. This crate is the shared foundation that **blvm-consensus** and **blvm-protocol** depend on, enabling parallel compilation and a clear split between consensus rules and protocol abstraction.

## Contents

- **Types** — `Hash`, `ByteString`, `Witness`, `Natural`, `Integer`, `Transaction`, `TransactionInput`, `TransactionOutput`, `Block`, `BlockHeader`, `OutPoint`, `UTXO`, network enum, and related structs.
- **Serialization** — block/transaction encoding and decoding, varint handling.
- **Crypto** — SHA-256 (with optional asm/SHA-NI), hash comparison helpers, consensus-critical crypto using pinned versions.
- **Opcodes** — script opcode constants and helpers.
- **Constants** — consensus and tuning constants (e.g. IBD).
- **Config** — shared config types used by node and consensus.
- **spec_types** — optional spec-aware wrappers (`SpecVec`, `SpecHashMap`, `spec_wrap!`) for formal verification / Orange Paper alignment with [blvm-spec-lock](https://github.com/BTCDecoded/blvm-spec-lock).

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
blvm-primitives = { path = "../blvm-primitives" }
# or from git:
# blvm-primitives = { git = "https://github.com/BTCDecoded/blvm-primitives" }
```

Optional features:

- **`production`** — enables `smallvec` and `rustc-hash` for lower-allocation, production-oriented builds (used by blvm-consensus when built with `production`).

## Building

```bash
cargo build
cargo test
```

## License

MIT. See [LICENSE](LICENSE) if present.

## Links

- [Bitcoin Commons](https://btcdecoded.org)
- [blvm-consensus](https://github.com/BTCDecoded/blvm-consensus) — depends on this crate
- [blvm-protocol](https://github.com/BTCDecoded/blvm-protocol) — depends on this crate
