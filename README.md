# shuna

Post-quantum hybrid cryptography, envelope encryption, memory-safe key handling, and mTLS 1.3 PKI engine in Go 1.24+.

## Packages

- `pkg/contract`: 5-state semantic exit contract (`0` OK, `1` USAGE, `2` POLICY_STOP/LOCKED/REVOKED, `3` MISSING, `4` CORRUPT_CIPHERTEXT) and JSON output envelope.
- `pkg/kdf`: Argon2id (RFC 9106: `t=3`, `m=65536 KiB`, `p=4`), HKDF-SHA512 (RFC 5869) domain-separated subkey derivation, `WipeBytes`, and `mlock` / `MADV_DONTDUMP` memory pinning.
- `pkg/envelope`: `SHUNA1` AEAD (`XChaCha20-Poly1305` / `AES-256-GCM`) with strict `AlgID`-first nonce validation, plus `SHUNAS1` chunked streaming AEAD.
- `pkg/pqc`: Hybrid `ML-KEM-1024` + `X25519` + `HKDF-SHA512` key encapsulation and offline admin recovery keys.
- `pkg/mtls`: ECDSA P-384 CA, short-lived leaf certificates, signed PEM CRL (`ca.crl`), and TLS 1.3 `X25519MLKEM768` mutual-TLS helpers.
- `pkg/vault`: Dual-read versioned encryption engine, online key rotation, persisted brute-force lockout (`1s, 2s, 4s, 8s` backoff, 15m lockout / strict wipe at 5 failures), and admin recovery reset.
- `cmd/shuna`: CLI entrypoint (`keygen`, `init-pki`, `issue-cert`, `revoke`, `seal`, `unseal`, `rotate`, `verify`, `unlock-reset`).

## Build & Verify

```sh
make vet
make test-race
make build
```
