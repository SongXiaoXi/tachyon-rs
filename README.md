# tachyon

**tachyon** is a high-performance algorithm library written in Rust, providing SIMD-accelerated implementations for both x86 (AVX/SSE) and ARM (NEON) architectures.

## Features

- Optimized for both **x86_64** (SSE, AVX) and **aarch64** (NEON) platforms. (AVX-512? Still waiting for it to stabilize... maybe someday.)
- Focused on **performance** — carefully tuned SIMD intrinsics for critical code paths.
- SIMD implementations often outperform well-known on ARM NEON.
- Designed for performance-critical applications like embedded systems, secure networking, and data processing.

## Supported Algorithms

### Cryptographic

#### Block Ciphers
- `AES-128`

#### Stream Ciphers
- `ChaCha20`

#### MACs
- `GMAC`
- `Poly1305`

#### AEAD
- `AES-128-GCM`
- `ChaCha20-Poly1305`

#### Hash Functions
- `SHA-1`
- `SHA-256`
- `SHA-512`

## Performance Highlights (For Example)

AES-128-GCM encryption of 64 KiB:

| Platform      | tachyon-rs | ring(v0.17.14)  | Speedup       |
|---------------|------------|----------|---------------|
| Apple M4      | 5.73 µs    | 7.54 µs  | ~31% faster   |
| Apple M1      | 8.00 µs    | 9.29 µs  | ~15% faster   |
| Apple A16     | 8.32 µs    | 9.28 µs  | ~10% faster   |
| Snapdragon 888 | 14.56 µs   | 16.58 µs | ~12% faster   |

Tip: On older Apple devices (e.g., A7–A10), compiling with `rust nightly` and `-Ztune-cpu=cortex-a53` may produce more favorable NEON code generation.

## Security Notice

This library is designed for **performance benchmarking and experimentation**.  
It has **not** been formally audited for cryptographic soundness.  
**Do not** use in production unless you fully understand the risks.

## Acknowledgements

This project builds upon the work and ideas of several excellent Rust cryptography projects:

- [crypto2](https://github.com/shadowsocks/crypto2): for its clean and pragmatic API design around cryptographic primitives, as well as software fallback implementations of several algorithms.
- [RustCrypto AES](https://github.com/RustCrypto/block-ciphers/tree/master/aes): used as a software fallback for the AES fixslicing implementation.
