# Architecture

Shuna (github.com/Mafifrizi/shuna) isolates key derivation, memory protection, envelope AEAD, hybrid post-quantum KEM recovery, and mTLS 1.3 PKI behind pure Go 1.24+ packages with zero homegrown cryptographic primitives.

## Package Layout

- **pkg/contract**: Five-state semantic exit contract (0..4) and structured JSON output envelope.
- **pkg/kdf**: Argon2id password-based KDF, HKDF-SHA512 domain subkeys, WipeBytes, and mlock / MADV_DONTDUMP page locking.
- **pkg/envelope**: SHUNA1 record AEAD (XChaCha20-Poly1305 and AES-256-GCM) and SHUNAS1 chunked streaming AEAD.
- **pkg/pqc**: Hybrid ML-KEM-1024 + X25519 key generation, encapsulation, and offline admin recovery key wrapping.
- **pkg/mtls**: ECDSA P-384 CA, short-lived leaf issuance, signed ca.crl management with change-detection reload, and TLS 1.3 X25519MLKEM768 configuration builders.
- **pkg/vault**: Dual-read versioned encryption engine, online RotatePrepare / RetireKey lifecycle, and persisted brute-force lockout.
- **cmd/shuna**: Standalone CLI exposing vault, envelope, stream, PKI, revocation, and recovery workflows.

## Key Derivation & Memory Safety

### Argon2id + HKDF-SHA512

- **Argon2id (RFC 9106)**: time = 3, memory = 65536 KiB (64 MiB), threads = 4, keyLen = 32, with a random 16-byte salt per key record.
- Domain-separated **HKDF-SHA512 (RFC 5869)** contexts defined in pkg/kdf:
  - shuna:v1:kek
  - shuna:v1:dek
  - shuna:v1:blind-index
  - shuna:v1:stream
  - shuna:v1:hybrid-kek

### Sensitive Memory Hygiene

- WipeBytes is marked go:noinline, clears the slice via Go's clear built-in, and calls runtime.KeepAlive so compiler dead-store elimination does not strip key zeroization.
- On Unix targets, LockSensitiveMemory aligns the backing address range to os.Getpagesize(), invokes unix.Mlock, and marks pages unix.MADV_DONTDUMP so sensitive keys do not leak to swap or core dumps.
- Passing --strict-mlock fails closed with exit code 2 (POLICY_STOP) whenever mlock cannot be enforced (for example due to low RLIMIT_MEMLOCK).

## Vault Lifecycle & Brute-Force Protection

### Overwrite Safety & Dual-Read Rotation

- InitVault refuses to overwrite an existing vault.json (fails with POLICY_STOP) to avoid silently clobbering active sealed keys.
- vault.Engine maintains one active encryption key version alongside any unretired historical DEKs:
  1. RotatePrepare(newPassphrase) derives a new wrapped DEK at active_version + 1 while retaining prior keys as decrypt_only.
  2. Callers re-encrypt existing ciphertexts in batches (Encrypt always uses active_version, while Decrypt reads the KeyVersion header field first).
  3. RetireKey(version) drops older wrapped keys and calls WipeBytes on their in-memory material.

### Persisted Lockout & Admin Recovery

- Unlock failures persist via vault.LockoutStore (default lockout.json with 0600 permissions, or PostgreSQL vault_lockout in ciel-teamserver) so restarts do not reset counters.
- Attempts 1..4 incur exponential cooldown backoff (1s, 2s, 4s, 8s).
- Attempt 5 triggers a 15-minute hard lockout (VAULT_LOCKED, exit 2). If --strict-lockout-wipe is enabled, in-memory key material is zeroized and wiped_locked = true remains enforced until an operator resets lockout using the offline hybrid ML-KEM-1024 + X25519 recovery private key (unlock-reset).

## Post-Quantum Hybrid mTLS 1.3 PKI

- InitPKI generates an ECDSA P-384 CA (365d validity), initializes an empty signed ca.crl, and issues 7d certificates for server and postgres roles.
- Client leaf certificates default to a 24h lifetime (DefaultClientTTL), limiting compromise exposure without long-lived static credentials.
- ServerTLSConfig and ClientTLSConfig enforce tls.VersionTLS13 and prefer tls.X25519MLKEM768 ahead of tls.X25519 and tls.CurveP384 (disabling classical curves entirely unless AllowClassicalFallback is set).
- Peer certificates are verified against the CA, ca.crl (automatically reloaded on file change), and any optional external revocation hook (ExtraRevokedCheck, used by Ciel for live PostgreSQL revoked_certs lookups).
