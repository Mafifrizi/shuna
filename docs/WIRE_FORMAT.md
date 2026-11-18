# Wire Formats

Shuna defines two authenticated wire formats in `pkg/envelope`: `SHUNA1` for discrete records and `SHUNAS1` for chunked streams, alongside offline hybrid key wrapping in `pkg/pqc`.

## 1. `SHUNA1` Record Envelope (35-Byte Header + Payload + 16-Byte Tag)

```text
 0      6  7      11                                  35
 +------+--+------+------------------------------------+--------------------+--------+
 |Magic |A |KeyVer|             Nonce Slot             |     Ciphertext     |  Tag   |
 |  6B  |1B|  4B  |                24B                 |        N B         |  16B   |
 +------+--+------+------------------------------------+--------------------+--------+
 "SHUNA1"  uint32 BE
```

- **Magic (`0..5`, 6 bytes)**: ASCII `"SHUNA1"`.
- **AlgID (`6`, 1 byte)**:
  - `0x01`: `XChaCha20-Poly1305` (uses full 24-byte nonce at `[11:35]`).
  - `0x02`: `AES-256-GCM` (uses 12-byte nonce at `[11:23]`).
- **KeyVersion (`7..10`, 4 bytes)**: Big-endian `uint32` identifying the DEK version used during `Seal`.
- **Nonce Slot (`11..34`, 24 bytes)**: CSPRNG nonce generated per record.

### Strict `AlgID`-First Invariant

Decryption inspects `AlgID` before reading the nonce:
- When `AlgID == 0x02` (`AES-256-GCM`), bytes `[23:35]` MUST all be `0x00`. Any non-zero padding byte is rejected immediately with exit code `4` (`CORRUPT_CIPHERTEXT`).
- Effective AEAD AAD binds the immutable header prefix `[0:11]` ahead of caller-supplied context:

```text
EffectiveAAD = header[0:11] || caller_aad
```

This prevents algorithm-downgrade, version-spoofing, and cross-table/cross-row ciphertext relocation attacks when callers supply table/row identifiers in `caller_aad`.

## 2. `SHUNAS1` Chunked Streaming AEAD

Used for arbitrarily large files and streaming `pg_dump` backups without buffering full plaintext in RAM. `SHUNAS1` uses `XChaCha20-Poly1305` (`0x01`) across bounded chunks (`DefaultStreamChunkSize = 65536`, bounds `[4096, 4194304]`).

### Stream Header (32 Bytes)

```text
 0       7  8      12        16                 32
 +-------+--+------+---------+------------------+
 | Magic |A |KeyVer|ChunkSize|     StreamID     |
 |  7B   |1B|  4B  |   4B    |       16B        |
 +-------+--+------+---------+------------------+
 "SHUNAS1"  uint32 BE uint32 BE   CSPRNG random
```

### Chunk Frame Sequence

Each chunk repeats `[1B FinalFlag | 4B PlainLen | AEAD(plaintext) + 16B Tag]`:
- `FinalFlag`: `0x00` for intermediate chunks, `0x01` for the final chunk. Trailing bytes after `FinalFlag == 0x01` or EOF before receiving `FinalFlag == 0x01` fail with `CORRUPT_CIPHERTEXT`.
- `PlainLen`: Big-endian `uint32` (`<= ChunkSize`). Zero-length chunks are rejected unless `counter == 0 && FinalFlag == 0x01` (empty input stream).
- **Per-Chunk Nonce (24 bytes)**: `StreamID (16B) || uint64_be(counter) (8B)`, starting at `counter = 0` and incrementing strictly by `+1`.
- **Per-Chunk Effective AAD**:

```text
ChunkAAD = caller_aad || "SHUNAS1" || uint32_be(KeyVersion) || StreamID (16B) || uint64_be(counter) || FinalFlag (1B)
```

This binds every chunk to its caller context, stream identity, exact position, and end-of-stream marker, blocking chunk reordering, truncation, and stream splicing.

## 3. Hybrid `ML-KEM-1024 + X25519` Recovery Wrapping (`pkg/pqc`)

Offline admin recovery keys combine `crypto/mlkem` (`ML-KEM-1024`) with static `ecdh.X25519`:

1. Encapsulate an `ML-KEM-1024` shared secret (`ss_pq`) and generate an ephemeral `X25519` shared secret (`ss_x`).
2. Derive a hybrid KEK via `HKDF-SHA512`:
   - `ikm = ss_pq || ss_x`
   - `info = "shuna:v1:hybrid-kek"`
3. Seal the vault DEK under `SHUNA1` (`XChaCha20-Poly1305`) using `aad = "shuna:v1:admin-recovery:<version>"`.
4. Store `kem_ciphertext = mlkem_ct || eph_x25519_pub` (`1568 + 32 = 1600` bytes) alongside `wrapped_dek` in `vault.json`.
