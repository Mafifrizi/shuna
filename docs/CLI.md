# CLI Reference

Every shuna subcommand supports --json for structured machine output and maps failures to the five-state semantic exit contract.

## Exit Codes

| Code | Status | Meaning |
| :--- | :--- | :--- |
| 0 | OK | Operation or verification succeeded cleanly |
| 1 | USAGE | Invalid flags, missing required arguments, or malformed JSON/key input |
| 2 | POLICY_STOP | Vault locked (VAULT_LOCKED), certificate revoked, overwrite denied, or --strict-mlock failure |
| 3 | MISSING | Key file, vault directory, PKI artifact, or input file not found |
| 4 | CORRUPT_CIPHERTEXT | Corrupt SHUNA1/SHUNAS1 header, tag failure, AAD mismatch, truncated stream, or non-zero GCM padding |

## Vault & Key Management

### keygen

Initialize a new vault (vault.json), hybrid recovery keypair (recovery.key, recovery.pub), and active version-1 DEK:

```sh
SHUNA_PASSPHRASE="strong-passphrase" shuna keygen \
  --out ./vault \
  --alg xchacha20 \
  --strict-lockout-wipe \
  --json
```

Flags: --out [dir], --passphrase-env [VAR], --alg [xchacha20|aes256gcm], --strict-mlock, --strict-lockout-wipe, --json.

### rotate

Generate a new active DEK version while preserving prior versions for dual-read decryption (or retire immediately with --retire-old):

```sh
shuna rotate --vault ./vault --passphrase-env CURR_PASS [--new-passphrase-env NEW_PASS] [--retire-old] [--strict-mlock] [--json]
```

### unlock-reset

Clear persisted brute-force lockout (including wiped_locked) using the offline ML-KEM-1024 + X25519 recovery private key:

```sh
shuna unlock-reset --vault ./vault --recovery-key ./vault/recovery.key [--new-passphrase-env NEW_PASS] [--strict-mlock] [--json]
```

## Envelope Seal & Unseal

Both seal and unseal accept either a vault directory (--passphrase-env / SHUNA_PASSPHRASE) or a raw 32-byte key file (32 raw bytes, 64 hex chars, or base64).

### Discrete SHUNA1 Record

```sh
shuna seal --key ./vault --aad "secrets:v1" --in plaintext.bin --out sealed.shuna1 --alg xchacha20
shuna unseal --key ./vault --aad "secrets:v1" --in sealed.shuna1 --out plaintext.bin
```

### Chunked SHUNAS1 Stream

```sh
shuna seal --stream --key ./vault --aad "pg_dump:v1" --in dump.sql --out dump.shunas1
shuna unseal --stream --key ./vault --aad "pg_dump:v1" --in dump.shunas1 --out dump.sql
```

Use --in - for stdin streaming. --stream supports XChaCha20-Poly1305 and requires --out [file] when paired with --json.

## PKI & mTLS Certificates

### init-pki

Provision ECDSA P-384 CA (ca.crt, ca.key), signed ca.crl, and 7-day server and postgres leaf certificates:

```sh
shuna init-pki --out ./pki --hosts 127.0.0.1,localhost --pg-hosts postgres,127.0.0.1 [--leaf-ttl 168h] [--json]
```

### issue-cert

Issue a client (24h default TTL), server (7d default), or postgres (7d default) leaf certificate:

```sh
shuna issue-cert --pki-dir ./pki --cn operator-01 --role client [--hosts ...] [--ttl 24h] [--json]
```

### revoke & verify

```sh
shuna revoke --pki-dir ./pki --serial <hex> [--reason key_compromise] [--json]
shuna verify --pki-dir ./pki [--cert ./pki/operator-01.crt] [--json]
```

Supported revocation reasons: unspecified, key_compromise, ca_compromise, affiliation_changed, superseded, cessation_of_operation, certificate_hold.
