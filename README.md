# Volkenborn-2 — Rust Implementation

![Language](https://img.shields.io/badge/language-Rust-dea584?style=flat-square&logo=rust)
![Status](https://img.shields.io/badge/status-research--prototype-orange?style=flat-square)
![License](https://img.shields.io/badge/license-UNLICENSED-lightgrey?style=flat-square)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-brightgreen?style=flat-square)

[Features](#features) | [Build](#build) | [Usage](#usage) | [Large Files](#large-file-support) | [Tests](#tests) | [Tools](#analysis-tools) | [Security](#security-notice)

A synchronous stream cipher based on 2-adic arithmetic, Mahler coefficient state, and Volkenborn integration. Processes data as a continuous byte stream with constant memory usage, suitable for encrypting files of any size.

**Status:** Research prototype. Not production-secure. Requires external cryptanalysis.

## Features

- Synchronous stream cipher with 256-bit key and 128-bit IV/nonce
- 32-byte block size with 32 coefficients, each 256 bits wide
- 24-round ARX internal permutation with nothing-up-my-sleeve constants
- Inter-coefficient MDS mixing layer for cross-lane diffusion
- Non-linear keystream post-processing via permutation
- Sponge feedback loop — keystream output drives future state
- Streaming I/O — encrypts/decrypts in 4KB chunks, constant RAM regardless of file size
- Authenticated encryption with Poly1305 (donna32 implementation)
- Auto-nonce mode — OS-generated random nonce, no reuse risk
- Legacy native MAC mode retained for compatibility
- Tag comparison uses `black_box` to resist timing side-channels
- Precomputed inverse coefficients for performance
- No floating point, no heap allocation in cipher core
- Cross-platform: Linux, macOS, Windows

## Build

Requires Rust 1.70+ (stable).

```
cargo build --release
```

## Usage

Encrypt (raw, no authentication):

```
cargo run --release --bin v2tool -- enc <64-hex-key> <32-hex-iv> < input > ciphertext
```

Decrypt (raw):

```
cargo run --release --bin v2tool -- dec <64-hex-key> <32-hex-iv> < ciphertext > plaintext
```

Seal with Poly1305 (recommended):

```
cargo run --release --bin v2tool -- sealp <64-hex-key> <32-hex-nonce> < plaintext > sealed
```

Open with Poly1305:

```
cargo run --release --bin v2tool -- openp <64-hex-key> <32-hex-nonce> < sealed > plaintext
```

Seal with auto-generated nonce (recommended for production):

```
cargo run --release --bin v2tool -- seal-auto <64-hex-key> < plaintext > sealed
```

Open auto-nonce sealed file:

```
cargo run --release --bin v2tool -- open-auto <64-hex-key> < sealed > plaintext
```

Legacy seal/open (native MAC, kept for compatibility):

```
cargo run --release --bin v2tool -- seal <64-hex-key> <32-hex-iv> < plaintext > sealed
cargo run --release --bin v2tool -- open <64-hex-key> <32-hex-iv> < sealed > plaintext
```

Generate keystream for statistical testing:

```
cargo run --release --bin v2tool -- stream <64-hex-key> <32-hex-iv> <bytes> > keystream.bin
```

All modes stream data in 4KB chunks. A 100GB file uses the same amount of RAM as a 1KB file.

## Large File Support

This is a stream cipher. All encrypt/decrypt operations process data in fixed-size chunks (4KB) through stdin/stdout pipes. Memory usage is constant:

| File Size | RAM Used |
|-----------|----------|
| 1 KB | ~4 KB |
| 1 GB | ~4 KB |
| 100 GB | ~4 KB |

No buffering, no seeking, no length prefix. Works with pipes, redirects, and network streams.

## Tests

All unit tests (fixed vectors, roundtrips, tamper rejection):

```
cargo test
```

Random encrypt/decrypt/tamper/uniqueness tests (4000+ cases):

```
cargo test --test random_crosscheck
```

Quick benchmark:

```
cargo run --release --bin v2bench -- 4096 2
```

Deterministic fuzz smoke test:

```
cargo run --release --bin v2fuzz -- 128 256
```

## Analysis Tools

| Tool | Purpose |
|------|---------|
| `tools/analysis/avalanche.py` | Measure key/IV bit avalanche into keystream |
| `tools/analysis/reduced_model.py` | Reduced-state model for cryptanalysis experiments |
| `tools/analysis/smt_export.py` | Export reduced model to SMT-LIB for Z3/CVC5 |
| `tools/analysis/run_dieharder.sh` | Run Dieharder statistical tests on keystream |
| `tools/analysis/run_testu01.sh` | Run TestU01 SmallCrush on keystream |
| `tools/audit/dudect_smoke.c` | Timing side-channel smoke test |
| `tools/audit/inspect_assembly.sh` | Inspect assembly for constant-time violations |
| `tools/sanitize.sh` | Build with ASan/UBSan/leak sanitizer (requires nightly) |

## Security Notice

This is experimental cryptography. It has not been peer-reviewed, standardized, or audited. Do not use it to protect real secrets without extensive public cryptanalysis.

See `SECURITY.txt` for details.
