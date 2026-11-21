# Changelog

## v1.0.0 (2026-11-22)

- Added `internal/fsutil.WriteAtomic` with symlink-refusal checks on output directories and targets, `0600`/configured permissions, `fsync`, and atomic rename across `pkg/mtls/pki.go`, `pkg/mtls/crl.go`, `pkg/pqc/hybrid.go`, and `pkg/vault/vault.go`.
- Added `LockoutState.ResetAt`, `StrictLockoutWipe()`, and `lockoutUpdater` support for atomic lockout state transitions and offline recovery resets.
- Added `tests/atomic_write_test.go` covering symlink rejection and concurrent atomic overwrite/read parity.
