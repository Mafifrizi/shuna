package vault

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Mafifrizi/shuna/internal/flock"
	"github.com/Mafifrizi/shuna/pkg/contract"
	"github.com/Mafifrizi/shuna/pkg/envelope"
	"github.com/Mafifrizi/shuna/pkg/kdf"
	"github.com/Mafifrizi/shuna/pkg/pqc"
)

const (
	MaxFailedAttempts   = 5
	HardLockoutDuration = 15 * time.Minute
	VaultFileName       = "vault.json"
	LockoutFileName     = "lockout.json"
)

var (
	ErrVaultLocked       = contract.NewError(contract.ExitPolicyStop, "VAULT_LOCKED", "vault is locked", nil)
	ErrInvalidPassphrase = contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "invalid vault passphrase", nil)
	ErrVaultNotFound     = contract.NewError(contract.ExitMissing, "MISSING", "vault metadata not found", nil)
	ErrKeyNotFound       = contract.NewError(contract.ExitMissing, "MISSING", "key version not found or retired", nil)
)

// Engine defines the Shuna dual-read envelope encryption and key-rotation contract.
type Engine interface {
	ActiveKeyVersion() uint32
	Encrypt(aad []byte, plaintext []byte) ([]byte, error)
	Decrypt(aad []byte, blob []byte) ([]byte, error)
	RotatePrepare(newPassphrase []byte) (newVersion uint32, err error)
	RetireKey(version uint32) error
	Zeroize()
}

// Options configures Vault memory pinning, lockout wipe behavior, and clock/sleep hooks.
type Options struct {
	Algorithm         byte
	StrictMlock       bool
	StrictLockoutWipe bool
	LockoutStore      LockoutStore
	Now               func() time.Time
	Sleep             func(time.Duration)
}

// LockoutState tracks persisted brute-force unlock state across restarts.
type LockoutState struct {
	FailedAttempts int       `json:"failed_attempts"`
	LockedUntil    time.Time `json:"locked_until,omitempty"`
	CooldownUntil  time.Time `json:"cooldown_until,omitempty"`
	LastFailureAt  time.Time `json:"last_failure_at,omitempty"`
	WipedLocked    bool      `json:"wiped_locked,omitempty"`
}

// LockoutStore persists LockoutState durably.
type LockoutStore interface {
	Load() (LockoutState, error)
	Save(LockoutState) error
}

type lockoutUpdater interface {
	Update(func(LockoutState) (LockoutState, error)) error
}

// FileLockoutStore persists LockoutState in a 0600 JSON file.
type FileLockoutStore struct {
	path string
}

func NewFileLockoutStore(path string) *FileLockoutStore {
	return &FileLockoutStore{path: path}
}

func (s *FileLockoutStore) loadUnlocked() (LockoutState, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return LockoutState{}, nil
		}
		return LockoutState{}, fmt.Errorf("read lockout store: %w", err)
	}
	var st LockoutState
	if err := json.Unmarshal(raw, &st); err != nil {
		return LockoutState{}, fmt.Errorf("parse lockout store: %w", err)
	}
	return st, nil
}

func (s *FileLockoutStore) saveUnlocked(st LockoutState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.path, data, 0600)
}

func (s *FileLockoutStore) Load() (LockoutState, error) {
	if _, err := os.Stat(filepath.Dir(s.path)); os.IsNotExist(err) {
		return LockoutState{}, nil
	}
	var st LockoutState
	err := flock.WithShared(s.path, 0600, true, func() error {
		var loadErr error
		st, loadErr = s.loadUnlocked()
		return loadErr
	})
	return st, err
}

func (s *FileLockoutStore) Save(st LockoutState) error {
	return flock.WithExclusive(s.path, 0600, func() error {
		return s.saveUnlocked(st)
	})
}

func (s *FileLockoutStore) Update(fn func(LockoutState) (LockoutState, error)) error {
	if fn == nil {
		return nil
	}
	return flock.WithExclusive(s.path, 0600, func() error {
		cur, err := s.loadUnlocked()
		if err != nil {
			return err
		}
		next, err := fn(cur)
		if err != nil {
			return err
		}
		return s.saveUnlocked(next)
	})
}

// KeyRecord holds wrapped DEK metadata for a specific key version.
type KeyRecord struct {
	Version               uint32     `json:"version"`
	Salt                  []byte     `json:"salt"`
	WrappedDEK            []byte     `json:"wrapped_dek,omitempty"`
	RecoveryWrappedDEK    []byte     `json:"recovery_wrapped_dek,omitempty"`
	RecoveryKEMCiphertext []byte     `json:"recovery_kem_ciphertext,omitempty"`
	Active                bool       `json:"active"`
	DecryptOnly           bool       `json:"decrypt_only"`
	Retired               bool       `json:"retired"`
	CreatedAt             time.Time  `json:"created_at"`
	RotatedAt             *time.Time `json:"rotated_at,omitempty"`
	RetiredAt             *time.Time `json:"retired_at,omitempty"`
}

type vaultMetadata struct {
	Format            string                `json:"format"`
	Algorithm         byte                  `json:"algorithm"`
	ActiveVersion     uint32                `json:"active_version"`
	StrictLockoutWipe bool                  `json:"strict_lockout_wipe,omitempty"`
	RecoveryPublicKey *pqc.HybridPublicKey  `json:"recovery_public_key"`
	Keys              map[uint32]*KeyRecord `json:"keys"`
}

// InitResult reports files and metadata created by InitVault.
type InitResult struct {
	VaultDir           string `json:"vault_dir"`
	VaultPath          string `json:"vault_path"`
	RecoveryPubPath    string `json:"recovery_pub_path"`
	RecoveryKeyPath    string `json:"recovery_key_path"`
	RecoveryFingerprnt string `json:"recovery_fingerprint"`
	ActiveVersion      uint32 `json:"active_version"`
	MlockWarning       string `json:"mlock_warning,omitempty"`
}

// Vault implements Engine with Argon2id wrapping, mlock/wipe, hybrid PQC recovery, and persisted brute-force lockout.
type Vault struct {
	mu           sync.RWMutex
	unlockMu     sync.Mutex
	dir          string
	metaPath     string
	opts         Options
	meta         vaultMetadata
	deks         map[uint32][]byte
	mlockWarning string
}

var _ Engine = (*Vault)(nil)

func normalizeOpts(dir string, opts Options) Options {
	if opts.Algorithm == 0 {
		opts.Algorithm = envelope.AlgXChaCha20Poly1305
	}
	if opts.LockoutStore == nil && dir != "" {
		opts.LockoutStore = NewFileLockoutStore(filepath.Join(dir, LockoutFileName))
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Sleep == nil {
		opts.Sleep = time.Sleep
	}
	return opts
}

// InitVault initializes a new Vault directory with key version 1, Argon2id KEK wrapping, and an offline hybrid PQC recovery keypair.
func InitVault(dir string, passphrase []byte, opts Options) (*Vault, *InitResult, error) {
	if dir == "" {
		return nil, nil, contract.NewError(contract.ExitUsage, "USAGE", "vault directory is required", nil)
	}
	if len(passphrase) == 0 {
		return nil, nil, contract.NewError(contract.ExitUsage, "USAGE", "passphrase must not be empty", kdf.ErrInvalidPassphrase)
	}
	opts = normalizeOpts(dir, opts)
	if opts.Algorithm != envelope.AlgXChaCha20Poly1305 && opts.Algorithm != envelope.AlgAES256GCM {
		return nil, nil, contract.NewError(contract.ExitUsage, "USAGE", "unsupported vault algorithm", envelope.ErrUnsupportedAlg)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, fmt.Errorf("create vault dir: %w", err)
	}
	metaPath := filepath.Join(dir, VaultFileName)
	if _, err := os.Stat(metaPath); err == nil {
		return nil, nil, contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "vault already exists", nil)
	} else if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("stat vault metadata: %w", err)
	}

	recPriv, recPub, err := pqc.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	defer recPriv.Zeroize()

	pubPath, privPath, err := pqc.SaveRecoveryKeyPair(dir, recPriv, recPub)
	if err != nil {
		return nil, nil, err
	}

	dek := make([]byte, envelope.KeySize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, nil, fmt.Errorf("generate DEK: %w", err)
	}
	warn, err := kdf.LockSensitiveMemory(dek, opts.StrictMlock)
	if err != nil {
		kdf.WipeBytes(dek)
		return nil, nil, contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "strict mlock failed", err)
	}

	salt, wrappedDEK, err := wrapDEKWithPassphrase(1, dek, passphrase)
	if err != nil {
		kdf.WipeBytes(dek)
		_ = kdf.UnlockSensitiveMemory(dek)
		return nil, nil, err
	}

	recWrapped, recCT, err := pqc.WrapKey(recPub, dek, recoveryAAD(1))
	if err != nil {
		kdf.WipeBytes(dek)
		_ = kdf.UnlockSensitiveMemory(dek)
		return nil, nil, err
	}

	now := opts.Now().UTC()
	meta := vaultMetadata{
		Format:            "SHUNA-VAULT-V1",
		Algorithm:         opts.Algorithm,
		ActiveVersion:     1,
		StrictLockoutWipe: opts.StrictLockoutWipe,
		RecoveryPublicKey: recPub,
		Keys: map[uint32]*KeyRecord{
			1: {
				Version:               1,
				Salt:                  salt,
				WrappedDEK:            wrappedDEK,
				RecoveryWrappedDEK:    recWrapped,
				RecoveryKEMCiphertext: recCT,
				Active:                true,
				CreatedAt:             now,
			},
		},
	}

	v := &Vault{
		dir:          dir,
		metaPath:     metaPath,
		opts:         opts,
		meta:         meta,
		deks:         map[uint32][]byte{1: dek},
		mlockWarning: warn,
	}
	if err := v.saveMetaLocked(); err != nil {
		v.Zeroize()
		return nil, nil, err
	}
	if err := opts.LockoutStore.Save(LockoutState{}); err != nil {
		v.Zeroize()
		return nil, nil, err
	}

	return v, &InitResult{
		VaultDir:           dir,
		VaultPath:          metaPath,
		RecoveryPubPath:    pubPath,
		RecoveryKeyPath:    privPath,
		RecoveryFingerprnt: recPub.Fingerprint,
		ActiveVersion:      1,
		MlockWarning:       warn,
	}, nil
}

// OpenVault loads vault metadata from dir in a locked state (call Unlock or UnlockWithRecoveryKey before Encrypt/Decrypt).
func OpenVault(dir string, opts Options) (*Vault, error) {
	if dir == "" {
		return nil, contract.NewError(contract.ExitUsage, "USAGE", "vault directory is required", nil)
	}
	metaPath := filepath.Join(dir, VaultFileName)
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrVaultNotFound
		}
		return nil, fmt.Errorf("read vault metadata: %w", err)
	}
	var meta vaultMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, contract.NewError(contract.ExitCorruptCiphertext, "CORRUPT_CIPHERTEXT", "invalid vault metadata JSON", err)
	}
	if meta.StrictLockoutWipe {
		opts.StrictLockoutWipe = true
	}
	if opts.Algorithm == 0 && meta.Algorithm != 0 {
		opts.Algorithm = meta.Algorithm
	}
	opts = normalizeOpts(dir, opts)
	if opts.Algorithm != envelope.AlgXChaCha20Poly1305 && opts.Algorithm != envelope.AlgAES256GCM {
		return nil, contract.NewError(contract.ExitUsage, "USAGE", "unsupported vault algorithm", envelope.ErrUnsupportedAlg)
	}

	return &Vault{
		dir:      dir,
		metaPath: metaPath,
		opts:     opts,
		meta:     meta,
		deks:     make(map[uint32][]byte),
	}, nil
}

// Algorithm returns the active SHUNA1 algorithm configured on the Vault.
func (v *Vault) Algorithm() byte {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.opts.Algorithm
}

// MlockWarning returns any non-fatal memory-locking warning observed during key initialization or unlock.
func (v *Vault) MlockWarning() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.mlockWarning
}

// LockoutStatus returns the currently persisted lockout state.
func (v *Vault) LockoutStatus() (LockoutState, error) {
	return v.opts.LockoutStore.Load()
}

// Unlock evaluates rate-limited Argon2id passphrase verification and loads non-retired DEKs into pinned RAM.
func (v *Vault) Unlock(passphrase []byte) error {
	v.unlockMu.Lock()
	defer v.unlockMu.Unlock()

	state, err := v.opts.LockoutStore.Load()
	if err != nil {
		return err
	}

	now := v.opts.Now().UTC()
	if state.WipedLocked {
		return contract.NewError(contract.ExitPolicyStop, "VAULT_LOCKED", "vault wiped due to strict lockout; admin unlock-reset required", ErrVaultLocked)
	}
	if state.FailedAttempts >= MaxFailedAttempts && now.Before(state.LockedUntil) {
		rem := int(state.LockedUntil.Sub(now).Seconds())
		if rem < 1 {
			rem = 1
		}
		return contract.NewError(contract.ExitPolicyStop, "VAULT_LOCKED", fmt.Sprintf("vault locked for %ds", rem), ErrVaultLocked)
	}
	if state.FailedAttempts >= 1 && state.FailedAttempts < MaxFailedAttempts && now.Before(state.CooldownUntil) {
		v.opts.Sleep(state.CooldownUntil.Sub(now))
		now = v.opts.Now().UTC()
	}

	v.mu.Lock()
	activeVer := v.meta.ActiveVersion
	activeRec := v.meta.Keys[activeVer]
	if activeRec == nil || activeRec.Retired {
		v.mu.Unlock()
		return ErrKeyNotFound
	}
	recordsSnapshot := make(map[uint32]*KeyRecord, len(v.meta.Keys))
	for k, r := range v.meta.Keys {
		recordsSnapshot[k] = r
	}
	v.mu.Unlock()

	if len(passphrase) == 0 {
		return v.recordUnlockFailure(state, now)
	}

	activeDEK, err := unwrapDEKWithPassphrase(activeRec, passphrase)
	if err != nil {
		return v.recordUnlockFailure(state, now)
	}

	warn, mlockErr := kdf.LockSensitiveMemory(activeDEK, v.opts.StrictMlock)
	if mlockErr != nil {
		kdf.WipeBytes(activeDEK)
		return contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "strict mlock failed", mlockErr)
	}

	loaded := map[uint32][]byte{activeVer: activeDEK}
	for ver, rec := range recordsSnapshot {
		if ver == activeVer || rec.Retired || len(rec.WrappedDEK) == 0 {
			continue
		}
		dek, decErr := unwrapDEKWithPassphrase(rec, passphrase)
		if decErr == nil {
			if w, err := kdf.LockSensitiveMemory(dek, v.opts.StrictMlock); err == nil {
				if warn == "" {
					warn = w
				}
				loaded[ver] = dek
			} else {
				kdf.WipeBytes(dek)
				for _, d := range loaded {
					kdf.WipeBytes(d)
					_ = kdf.UnlockSensitiveMemory(d)
				}
				return contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "strict mlock failed", err)
			}
		}
	}

	if err := v.opts.LockoutStore.Save(LockoutState{}); err != nil {
		for _, d := range loaded {
			kdf.WipeBytes(d)
			_ = kdf.UnlockSensitiveMemory(d)
		}
		return err
	}

	v.mu.Lock()
	for ver, old := range v.deks {
		kdf.WipeBytes(old)
		_ = kdf.UnlockSensitiveMemory(old)
		delete(v.deks, ver)
	}
	v.deks = loaded
	if warn != "" {
		v.mlockWarning = warn
	}
	v.mu.Unlock()
	return nil
}

func applyFailureTransition(state LockoutState, now time.Time, strictWipe bool) LockoutState {
	state.FailedAttempts++
	state.LastFailureAt = now
	if state.FailedAttempts >= MaxFailedAttempts {
		state.LockedUntil = now.Add(HardLockoutDuration)
		state.CooldownUntil = time.Time{}
		if strictWipe {
			state.WipedLocked = true
		}
		return state
	}
	backoff := time.Duration(1<<(state.FailedAttempts-1)) * time.Second
	state.CooldownUntil = now.Add(backoff)
	return state
}

func (v *Vault) recordUnlockFailure(state LockoutState, now time.Time) error {
	if updater, ok := v.opts.LockoutStore.(lockoutUpdater); ok {
		var shouldZeroize bool
		var hardLocked bool
		err := updater.Update(func(cur LockoutState) (LockoutState, error) {
			if cur.WipedLocked {
				if v.opts.StrictLockoutWipe {
					shouldZeroize = true
				}
				return cur, contract.NewError(contract.ExitPolicyStop, "VAULT_LOCKED", "vault wiped due to strict lockout; admin unlock-reset required", ErrVaultLocked)
			}
			if cur.FailedAttempts >= MaxFailedAttempts && now.Before(cur.LockedUntil) {
				rem := int(cur.LockedUntil.Sub(now).Seconds())
				if rem < 1 {
					rem = 1
				}
				return cur, contract.NewError(contract.ExitPolicyStop, "VAULT_LOCKED", fmt.Sprintf("vault locked for %ds", rem), ErrVaultLocked)
			}
			next := applyFailureTransition(cur, now, v.opts.StrictLockoutWipe)
			if next.WipedLocked {
				shouldZeroize = true
			}
			if next.FailedAttempts >= MaxFailedAttempts {
				hardLocked = true
			}
			return next, nil
		})
		if shouldZeroize {
			v.Zeroize()
		}
		if err != nil {
			return err
		}
		if hardLocked {
			return contract.NewError(contract.ExitPolicyStop, "VAULT_LOCKED", fmt.Sprintf("max failed attempts (%d) reached; vault locked for 15m", MaxFailedAttempts), ErrVaultLocked)
		}
		return ErrInvalidPassphrase
	}

	next := applyFailureTransition(state, now, v.opts.StrictLockoutWipe)
	if next.WipedLocked {
		v.Zeroize()
	}
	if err := v.opts.LockoutStore.Save(next); err != nil {
		return err
	}
	if next.FailedAttempts >= MaxFailedAttempts {
		return contract.NewError(contract.ExitPolicyStop, "VAULT_LOCKED", fmt.Sprintf("max failed attempts (%d) reached; vault locked for 15m", MaxFailedAttempts), ErrVaultLocked)
	}
	return ErrInvalidPassphrase
}

// UnlockWithRecoveryKey clears any persisted brute-force lockout using the offline hybrid ML-KEM-1024 + X25519 Admin Recovery Key,
// unwraps non-retired DEKs into pinned RAM, and optionally re-wraps the active DEK under newPassphrase.
func (v *Vault) UnlockWithRecoveryKey(priv *pqc.HybridPrivateKey, newPassphrase []byte) error {
	v.unlockMu.Lock()
	defer v.unlockMu.Unlock()

	v.mu.Lock()
	defer v.mu.Unlock()

	activeRec := v.meta.Keys[v.meta.ActiveVersion]
	if activeRec == nil || activeRec.Retired {
		return ErrKeyNotFound
	}
	if len(activeRec.RecoveryWrappedDEK) == 0 || len(activeRec.RecoveryKEMCiphertext) == 0 {
		return contract.NewError(contract.ExitMissing, "MISSING", "active key has no recovery wrapping", nil)
	}

	activeDEK, err := pqc.UnwrapKey(priv, activeRec.RecoveryWrappedDEK, activeRec.RecoveryKEMCiphertext, recoveryAAD(activeRec.Version))
	if err != nil {
		return err
	}

	warn, mlockErr := kdf.LockSensitiveMemory(activeDEK, v.opts.StrictMlock)
	if mlockErr != nil {
		kdf.WipeBytes(activeDEK)
		return contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "strict mlock failed", mlockErr)
	}

	loaded := map[uint32][]byte{v.meta.ActiveVersion: activeDEK}
	for ver, rec := range v.meta.Keys {
		if ver == v.meta.ActiveVersion || rec.Retired || len(rec.RecoveryWrappedDEK) == 0 {
			continue
		}
		dek, uerr := pqc.UnwrapKey(priv, rec.RecoveryWrappedDEK, rec.RecoveryKEMCiphertext, recoveryAAD(ver))
		if uerr != nil {
			continue
		}
		w, merr := kdf.LockSensitiveMemory(dek, v.opts.StrictMlock)
		if merr != nil {
			kdf.WipeBytes(dek)
			for _, d := range loaded {
				kdf.WipeBytes(d)
				_ = kdf.UnlockSensitiveMemory(d)
			}
			return contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "strict mlock failed", merr)
		}
		if warn == "" && w != "" {
			warn = w
		}
		loaded[ver] = dek
	}

	if len(newPassphrase) > 0 {
		type savedWrap struct {
			rec     *KeyRecord
			salt    []byte
			wrapped []byte
		}
		var backups []savedWrap
		rollback := func() {
			for _, b := range backups {
				b.rec.Salt = b.salt
				b.rec.WrappedDEK = b.wrapped
			}
			for _, d := range loaded {
				kdf.WipeBytes(d)
				_ = kdf.UnlockSensitiveMemory(d)
			}
		}
		for ver, dek := range loaded {
			rec := v.meta.Keys[ver]
			if rec == nil {
				continue
			}
			salt, wrapped, err := wrapDEKWithPassphrase(ver, dek, newPassphrase)
			if err != nil {
				rollback()
				return err
			}
			backups = append(backups, savedWrap{rec: rec, salt: rec.Salt, wrapped: rec.WrappedDEK})
			rec.Salt = salt
			rec.WrappedDEK = wrapped
		}
		if err := v.saveMetaLocked(); err != nil {
			rollback()
			return err
		}
	}

	if err := v.opts.LockoutStore.Save(LockoutState{}); err != nil {
		for _, d := range loaded {
			kdf.WipeBytes(d)
			_ = kdf.UnlockSensitiveMemory(d)
		}
		return err
	}

	for ver, old := range v.deks {
		kdf.WipeBytes(old)
		_ = kdf.UnlockSensitiveMemory(old)
		delete(v.deks, ver)
	}
	v.deks = loaded
	if warn != "" {
		v.mlockWarning = warn
	}

	return nil
}

func (v *Vault) ActiveKeyVersion() uint32 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.meta.ActiveVersion
}

// Encrypt seals plaintext under the active key version using the vault's configured SHUNA1 algorithm.
func (v *Vault) Encrypt(aad []byte, plaintext []byte) ([]byte, error) {
	v.mu.RLock()
	ver := v.meta.ActiveVersion
	alg := v.opts.Algorithm
	dek := v.deks[ver]
	if len(dek) == 0 {
		v.mu.RUnlock()
		return nil, ErrVaultLocked
	}
	dekCopy := make([]byte, len(dek))
	copy(dekCopy, dek)
	v.mu.RUnlock()
	defer kdf.WipeBytes(dekCopy)

	return envelope.Seal(alg, ver, dekCopy, aad, plaintext)
}

// Decrypt verifies and opens a SHUNA1 blob, selecting the key matching blob[7:11] (dual-read).
func (v *Vault) Decrypt(aad []byte, blob []byte) ([]byte, error) {
	hdr, err := envelope.InspectHeader(blob)
	if err != nil {
		return nil, err
	}

	v.mu.RLock()
	if len(v.deks) == 0 {
		v.mu.RUnlock()
		return nil, ErrVaultLocked
	}
	dek := v.deks[hdr.KeyVersion]
	if len(dek) == 0 {
		v.mu.RUnlock()
		return nil, ErrKeyNotFound
	}
	dekCopy := make([]byte, len(dek))
	copy(dekCopy, dek)
	v.mu.RUnlock()
	defer kdf.WipeBytes(dekCopy)

	pt, _, err := envelope.Open(dekCopy, aad, blob)
	return pt, err
}

// RotatePrepare generates a new active DEK version, marks the previous active key decrypt-only, and keeps both live in memory.
func (v *Vault) RotatePrepare(newPassphrase []byte) (uint32, error) {
	if len(newPassphrase) == 0 {
		return 0, contract.NewError(contract.ExitUsage, "USAGE", "new passphrase required for rotation", kdf.ErrInvalidPassphrase)
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	oldVer := v.meta.ActiveVersion
	if len(v.deks[oldVer]) == 0 {
		return 0, ErrVaultLocked
	}
	oldRec := v.meta.Keys[oldVer]
	if oldRec == nil {
		return 0, ErrKeyNotFound
	}

	newVer := oldVer + 1
	newDEK := make([]byte, envelope.KeySize)
	if _, err := io.ReadFull(rand.Reader, newDEK); err != nil {
		return 0, fmt.Errorf("generate rotated DEK: %w", err)
	}
	warn, err := kdf.LockSensitiveMemory(newDEK, v.opts.StrictMlock)
	if err != nil {
		kdf.WipeBytes(newDEK)
		return 0, contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "strict mlock failed", err)
	}
	if warn != "" && v.mlockWarning == "" {
		v.mlockWarning = warn
	}

	salt, wrappedDEK, err := wrapDEKWithPassphrase(newVer, newDEK, newPassphrase)
	if err != nil {
		kdf.WipeBytes(newDEK)
		_ = kdf.UnlockSensitiveMemory(newDEK)
		return 0, err
	}

	var recWrapped, recCT []byte
	if v.meta.RecoveryPublicKey != nil {
		recWrapped, recCT, err = pqc.WrapKey(v.meta.RecoveryPublicKey, newDEK, recoveryAAD(newVer))
		if err != nil {
			kdf.WipeBytes(newDEK)
			_ = kdf.UnlockSensitiveMemory(newDEK)
			return 0, err
		}
	}

	type savedWrap struct {
		rec     *KeyRecord
		salt    []byte
		wrapped []byte
	}
	var rewrapBackups []savedWrap
	rollbackRewraps := func() {
		for _, b := range rewrapBackups {
			b.rec.Salt = b.salt
			b.rec.WrappedDEK = b.wrapped
		}
	}
	for ver, dek := range v.deks {
		rec := v.meta.Keys[ver]
		if rec == nil || rec.Retired || len(dek) == 0 {
			continue
		}
		rsalt, rwrapped, rerr := wrapDEKWithPassphrase(ver, dek, newPassphrase)
		if rerr != nil {
			rollbackRewraps()
			kdf.WipeBytes(newDEK)
			_ = kdf.UnlockSensitiveMemory(newDEK)
			return 0, rerr
		}
		rewrapBackups = append(rewrapBackups, savedWrap{rec: rec, salt: rec.Salt, wrapped: rec.WrappedDEK})
		rec.Salt = rsalt
		rec.WrappedDEK = rwrapped
	}

	now := v.opts.Now().UTC()
	oldRec.Active = false
	oldRec.DecryptOnly = true
	oldRec.RotatedAt = &now

	v.meta.Keys[newVer] = &KeyRecord{
		Version:               newVer,
		Salt:                  salt,
		WrappedDEK:            wrappedDEK,
		RecoveryWrappedDEK:    recWrapped,
		RecoveryKEMCiphertext: recCT,
		Active:                true,
		CreatedAt:             now,
	}
	v.meta.ActiveVersion = newVer
	v.deks[newVer] = newDEK

	if err := v.saveMetaLocked(); err != nil {
		rollbackRewraps()
		oldRec.Active = true
		oldRec.DecryptOnly = false
		oldRec.RotatedAt = nil
		delete(v.meta.Keys, newVer)
		v.meta.ActiveVersion = oldVer
		kdf.WipeBytes(newDEK)
		_ = kdf.UnlockSensitiveMemory(newDEK)
		delete(v.deks, newVer)
		return 0, err
	}

	return newVer, nil
}

// RetireKey zeroizes and removes an old decrypt-only key version after batch re-encryption.
func (v *Vault) RetireKey(version uint32) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if version == v.meta.ActiveVersion {
		return contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "cannot retire active key version", nil)
	}
	rec, ok := v.meta.Keys[version]
	if !ok {
		return ErrKeyNotFound
	}

	if dek, exists := v.deks[version]; exists {
		kdf.WipeBytes(dek)
		_ = kdf.UnlockSensitiveMemory(dek)
		delete(v.deks, version)
	}

	now := v.opts.Now().UTC()
	rec.Active = false
	rec.DecryptOnly = false
	rec.Retired = true
	rec.RetiredAt = &now
	kdf.WipeBytes(rec.WrappedDEK)
	kdf.WipeBytes(rec.RecoveryWrappedDEK)
	rec.WrappedDEK = nil
	rec.RecoveryWrappedDEK = nil
	rec.RecoveryKEMCiphertext = nil

	return v.saveMetaLocked()
}

// Zeroize wipes all active and decrypt-only DEKs from RAM and unlocks pinned memory.
func (v *Vault) Zeroize() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for ver, dek := range v.deks {
		kdf.WipeBytes(dek)
		_ = kdf.UnlockSensitiveMemory(dek)
		delete(v.deks, ver)
	}
}

// SealStream encrypts r to w using SHUNAS1 and the vault's active key version.
func (v *Vault) SealStream(r io.Reader, w io.Writer, aad []byte) error {
	v.mu.RLock()
	ver := v.meta.ActiveVersion
	dek := v.deks[ver]
	if len(dek) == 0 {
		v.mu.RUnlock()
		return ErrVaultLocked
	}
	dekCopy := make([]byte, len(dek))
	copy(dekCopy, dek)
	v.mu.RUnlock()
	defer kdf.WipeBytes(dekCopy)

	streamKey, err := kdf.DeriveSubkey(dekCopy, nil, kdf.InfoStream, envelope.KeySize)
	if err != nil {
		return err
	}
	defer kdf.WipeBytes(streamKey)

	return envelope.SealStreamWithOptions(r, w, streamKey, ver, envelope.DefaultStreamChunkSize, aad)
}

// UnsealStream decrypts a SHUNAS1 stream using the vault key version encoded in the stream header.
func (v *Vault) UnsealStream(r io.Reader, w io.Writer, aad []byte) error {
	var streamKeyToWipe []byte
	defer func() {
		kdf.WipeBytes(streamKeyToWipe)
	}()

	return envelope.UnsealStreamWithKeyLookup(r, w, func(keyVersion uint32) ([]byte, error) {
		v.mu.RLock()
		if len(v.deks) == 0 {
			v.mu.RUnlock()
			return nil, ErrVaultLocked
		}
		dek := v.deks[keyVersion]
		if len(dek) == 0 {
			v.mu.RUnlock()
			return nil, ErrKeyNotFound
		}
		dekCopy := make([]byte, len(dek))
		copy(dekCopy, dek)
		v.mu.RUnlock()
		defer kdf.WipeBytes(dekCopy)

		sk, err := kdf.DeriveSubkey(dekCopy, nil, kdf.InfoStream, envelope.KeySize)
		if err != nil {
			return nil, err
		}
		streamKeyToWipe = sk
		return sk, nil
	}, aad)
}

// DeriveBlindIndexKey derives a domain-separated 32-byte key for pseudonymous host_id HMAC indexing.
func (v *Vault) DeriveBlindIndexKey() ([]byte, error) {
	v.mu.RLock()
	dek := v.deks[v.meta.ActiveVersion]
	if len(dek) == 0 {
		v.mu.RUnlock()
		return nil, ErrVaultLocked
	}
	dekCopy := make([]byte, len(dek))
	copy(dekCopy, dek)
	v.mu.RUnlock()
	defer kdf.WipeBytes(dekCopy)

	return kdf.DeriveSubkey(dekCopy, nil, kdf.InfoBlindIndex, 32)
}

func (v *Vault) saveMetaLocked() error {
	data, err := json.MarshalIndent(v.meta, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(v.metaPath, data, 0600)
}

func wrapDEKWithPassphrase(version uint32, dek, passphrase []byte) ([]byte, []byte, error) {
	salt, err := kdf.GenerateSalt()
	if err != nil {
		return nil, nil, err
	}
	master, err := kdf.DeriveMasterKey(passphrase, salt)
	if err != nil {
		return nil, nil, err
	}
	defer kdf.WipeBytes(master)

	kek, err := kdf.DeriveSubkey(master, salt, kdf.InfoKEK, envelope.KeySize)
	if err != nil {
		return nil, nil, err
	}
	defer kdf.WipeBytes(kek)

	wrapped, err := envelope.Seal(envelope.AlgXChaCha20Poly1305, version, kek, wrapAAD(version), dek)
	if err != nil {
		return nil, nil, err
	}
	return salt, wrapped, nil
}

func unwrapDEKWithPassphrase(rec *KeyRecord, passphrase []byte) ([]byte, error) {
	master, err := kdf.DeriveMasterKey(passphrase, rec.Salt)
	if err != nil {
		return nil, err
	}
	defer kdf.WipeBytes(master)

	kek, err := kdf.DeriveSubkey(master, rec.Salt, kdf.InfoKEK, envelope.KeySize)
	if err != nil {
		return nil, err
	}
	defer kdf.WipeBytes(kek)

	dek, _, err := envelope.Open(kek, wrapAAD(rec.Version), rec.WrappedDEK)
	if err != nil {
		return nil, err
	}
	return dek, nil
}

func wrapAAD(version uint32) []byte {
	return []byte(fmt.Sprintf("shuna:v1:vault-dek|%d", version))
}

func recoveryAAD(version uint32) []byte {
	return []byte(fmt.Sprintf("%s|%d", pqc.RecoveryAADPrefix, version))
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".shuna.tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
