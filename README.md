<h1 align="center">
<br>
<img src="shuna_banner.jpg" width="400">
<br>
Shuna
</h1>

A post-quantum hybrid cryptography, envelope encryption, and mTLS 1.3 PKI engine built for Go 1.24+. <br>
Designed as the cryptographic core for [Ciel](https://github.com/Mafifrizi/ciel), [Tempest](https://github.com/Mafifrizi/tempest), and [Tanuki](https://github.com/Mafifrizi/tanuki). <br>

### Modules
- **Envelope & Vault**: `SHUNA1` (`XChaCha20-Poly1305` / `AES-256-GCM`) and `SHUNAS1` streaming AEAD with `Argon2id` + `HKDF-SHA512`, `mlock` memory pinning, dual-read rotation, and persisted lockout.
- **Hybrid Recovery**: `ML-KEM-1024` + `X25519` + `HKDF-SHA512` offline admin recovery key wrapping (`pkg/pqc`).
- **PKI & mTLS 1.3**: ECDSA P-384 CA, short-lived leaf certificates, signed `ca.crl` reload, and `X25519MLKEM768` mutual TLS helpers (`pkg/mtls`).

### NOTE
Built solely on the Go standard library and vetted `golang.org/x/crypto` primitives with zero homegrown crypto. <br>
Key zeroization, brute-force lockout, and ciphertext verification fail closed across both CLI and library boundaries. <br>
Detailed documentation lives in [Architecture](docs/ARCHITECTURE.md), [Wire Formats](docs/WIRE_FORMAT.md), and [CLI Reference](docs/CLI.md).
