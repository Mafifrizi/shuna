<h1 align="center">
<br>
Shuna
<br>
</h1>

<p align="center">
  <i>Post-quantum hybrid cryptography, envelope encryption, memory-safe key handling, and mTLS 1.3 PKI engine for the <a href="https://github.com/Mafifrizi/ciel">Ciel</a>, <a href="https://github.com/Mafifrizi/tempest">Tempest</a>, and <a href="https://github.com/Mafifrizi/tanuki">Tanuki</a> ecosystem.</i>
</p>

<p align="center">
  <a href="docs/ARCHITECTURE.md">Architecture</a> |
  <a href="docs/WIRE_FORMAT.md">Wire Formats</a> |
  <a href="docs/CLI.md">CLI Reference</a>
</p>

## Overview

Shuna provides the Go `1.24+` cryptographic foundation shared across `ciel-teamserver` and fleet tooling using standard library and vetted `golang.org/x/crypto` primitives only:

- **Vault & KDF (`pkg/kdf`, `pkg/vault`)**: `Argon2id` (`t=3, m=64 MiB, p=4`), domain-separated `HKDF-SHA512`, `mlock` / `MADV_DONTDUMP`, `WipeBytes`, persisted brute-force lockout, and dual-read online key rotation.
- **Authenticated Envelopes (`pkg/envelope`)**: Self-describing `SHUNA1` record AEAD (`XChaCha20-Poly1305` / `AES-256-GCM`) and `SHUNAS1` 64 KiB chunked streaming AEAD.
- **Hybrid Post-Quantum Recovery (`pkg/pqc`)**: `ML-KEM-1024` (`crypto/mlkem`) + `X25519` + `HKDF-SHA512` offline admin recovery key wrapping.
- **PQC-Hybrid mTLS 1.3 PKI (`pkg/mtls`)**: ECDSA P-384 CA, short-lived leaf certificates, live-reloaded PEM CRL (`ca.crl`), and `X25519MLKEM768` TLS 1.3 helpers.

## Build & Verify

```sh
make vet
make test-race
make build
```

## Documentation

- [Architecture, Memory Protection, and Key Lifecycle](docs/ARCHITECTURE.md)
- [SHUNA1, SHUNAS1, and Hybrid Recovery Wire Formats](docs/WIRE_FORMAT.md)
- [CLI Reference and Semantic Exit Contract](docs/CLI.md)
