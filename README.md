<h1 align="center">
<br>
<img src="shuna_banner.jpg" width="400">
<br>
Shuna
</h1>

A post-quantum hybrid cryptography, envelope encryption, and mTLS 1.3 PKI engine written in Go. <br>
Built as the cryptographic core for [Ciel](https://github.com/Mafifrizi/ciel), [Tempest](https://github.com/Mafifrizi/tempest), and [Tanuki](https://github.com/Mafifrizi/tanuki). <br>

### Modules
- **Envelope and Vault**: SHUNA1 and streaming SHUNAS1 authenticated encryption backed by Argon2id, HKDF-SHA512, mlock memory pinning, dual-read key rotation, and persisted unlock lockout.
- **Hybrid Recovery**: offline admin recovery keys combining ML-KEM-1024 and X25519 to unwrap vault keys without touching live passphrases.
- **PKI and mTLS 1.3**: ECDSA P-384 certificate authority, short-lived leaf certificates, signed CRL reloading, and hybrid X25519MLKEM768 mutual TLS.

### NOTE
Built strictly on Go standard library primitives and vetted golang.org/x/crypto packages without custom ciphers. <br>
Key zeroization, brute-force lockout, and ciphertext verification fail closed across both library calls and the CLI. <br>
Full architecture, wire format diagrams, and CLI flags live in [Architecture](docs/ARCHITECTURE.md), [Wire Formats](docs/WIRE_FORMAT.md), and [CLI Reference](docs/CLI.md).
