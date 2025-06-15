# tachyon

**tachyon** is a high-performance algorithm library written in Rust, providing SIMD-accelerated implementations for both x86 (AVX/SSE) and ARM (NEON) architectures, to outperform even hand-tuned assembly in many cases.

## Features

- Optimized for both **x86_64** (SSE, AVX) and **aarch64** (NEON) platforms. (AVX-512? Still waiting for it to stabilize... maybe someday.)
- Focused on **performance** — carefully tuned SIMD intrinsics for critical code paths.
- SIMD implementations often outperform well-known on ARM NEON.
- Designed for performance-critical applications like embedded systems, secure networking, and data processing.

## Usage

Add to your `Cargo.toml`:
```toml
tachyon = { git = "https://github.com/SongXiaoXi/tachyon-rs" }
```
or use cargo:
```bash
cargo add tachyon --git https://github.com/SongXiaoXi/tachyon-rs
```

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
- `MD5` (**do not use except for non-cryptographic checksums**)
- `SHA-1` (**for legacy compatibility only**)
- `SHA-256`
- `SHA-512`

## Performance Highlights

### AES-128-GCM encryption of 64 KiB:

| Platform      | tachyon-rs | ring(v0.17.14)  | OpenSSL |
|---------------|------------|----------|-----------|
| Apple M4      | 11700.03 MiB/s    | 8751.87 MiB/s  | 11043.29 MiB/s(3.5.0) |
| Apple M1      | 8222.73 MiB/s    | 7051.54 MiB/s  | 8142.95 MiB/s(3.5.0) |
| Apple A16     | 9029.59 MiB/s    | 7663.91 MiB/s  | 7329.87 MiB/s(3.2.1) |
| Snapdragon 888 | 4473.29 MiB/s   | 3950.03 MiB/s | 3972.17 MiB/s(3.4.1) |

### Chacha20-Poly1305 encryption of 64 KiB:

| Platform       | tachyon-rs      | tachyon-rs(tune-cpu=generic) | ring(v0.17.14)  | OpenSSL |
|----------------|-----------------|------------------------------|-----------------|---------|
| Apple M4       | 1729.85 MiB/s   | 2672.39 MiB/s | 2168.00 MiB/s  | 2355.95 MiB/s(3.5.0) |
| Apple M1       | 1147.70 MiB/s   | 2010.69 MiB/s | 1620.36 MiB/s  | 1816.42 MiB/s(3.5.0) |
| Apple A16      | 1240.64 MiB/s   | 1926.21 MiB/s | 1738.82 MiB/s  | 1932.54 MiB/s(3.2.1) |
| Snapdragon 888 | 1435.37 MiB/s   | N/A     | 1325.19 MiB/s | 1277.12 MiB/s(3.4.1) |

### MD5 hashing of 64 KiB:

| Platform       | tachyon-rs | md5(v0.7.0)  | OpenSSL |
|----------------|------------|----------|-----------|
| Apple M4       | 952.30 MiB/s    | 848.33 MiB/s  | 981.83 MiB/s(3.5.0) |
| Apple M1       | 693.20 MiB/s    | 607.06 MiB/s  | 692.56 MiB/s(3.5.0) |
| Apple A16      | 751.58 MiB/s    | 652.44 MiB/s  | 682.52 MiB/s(3.2.1) |
| Snapdragon 888 | 620.08 MiB/s    | 477.37 MiB/s  | 588.63 MiB/s(3.4.1) |
| i7-10700K      | 1096.69 MiB/s   | 609.86 MiB/s  | 1048.98 MiB/s(3.5.0) |
| i7-3770        | 809.03 MiB/s    | 455.70 MiB/s  | 757.12 MiB/s(3.4.1) |
| Ryzen 9 9950X  | 1243.69 MiB/s   | 813.45 MiB/s  | 1186.78 MiB/s(3.4.1) |
| BCM2711 (RPi4) | 323.22 MiB/s    | 186.70 MiB/s  | 279.40 MiB/s(3.5.0) |

Tip: On older Apple devices (e.g., A7–A10), compiling with `rust nightly` and `-Ztune-cpu=generic` may produce more favorable NEON code generation.

## Security Notice

This library is designed for **performance benchmarking and experimentation**.  
It has **not** been formally audited for cryptographic soundness.  
**Do not** use in production unless you fully understand the risks.

## Acknowledgements

This project builds upon the work and ideas of several excellent Rust cryptography projects:

- [crypto2](https://github.com/shadowsocks/crypto2): for its clean and pragmatic API design around cryptographic primitives, as well as software fallback implementations of several algorithms.
- [RustCrypto AES](https://github.com/RustCrypto/block-ciphers/tree/master/aes): used as a software fallback for the AES fixslicing implementation.
