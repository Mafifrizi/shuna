package pqc

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Mafifrizi/shuna/pkg/contract"
	"github.com/Mafifrizi/shuna/pkg/envelope"
	"github.com/Mafifrizi/shuna/pkg/kdf"
)

const (
	X25519KeySize        = 32
	HybridCiphertextSize = mlkem.CiphertextSize1024 + X25519KeySize
	RecoveryAADPrefix    = "shuna:v1:admin-recovery"
)

var (
	ErrInvalidHybridKey        = errors.New("invalid hybrid ML-KEM-1024/X25519 key")
	ErrInvalidHybridCiphertext = contract.NewError(contract.ExitCorruptCiphertext, "CORRUPT_CIPHERTEXT", "invalid hybrid KEM ciphertext", nil)
)

// HybridPublicKey holds the ML-KEM-1024 encapsulation key and X25519 static public key.
type HybridPublicKey struct {
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"`
	MLKEM1024   []byte `json:"mlkem1024"`
	X25519      []byte `json:"x25519"`
}

// HybridPrivateKey holds the ML-KEM-1024 decapsulation seed and X25519 static private key.
type HybridPrivateKey struct {
	Algorithm     string `json:"algorithm"`
	Fingerprint   string `json:"fingerprint"`
	MLKEM1024Seed []byte `json:"mlkem1024_seed"`
	X25519        []byte `json:"x25519"`
}

// Zeroize overwrites sensitive private key material in memory.
func (k *HybridPrivateKey) Zeroize() {
	if k == nil {
		return
	}
	kdf.WipeBytes(k.MLKEM1024Seed)
	kdf.WipeBytes(k.X25519)
}

func computeFingerprint(mlkemPub, xPub []byte) string {
	h := sha256.New()
	h.Write(mlkemPub)
	h.Write(xPub)
	return hex.EncodeToString(h.Sum(nil))
}

// GenerateKeyPair generates a hybrid ML-KEM-1024 + X25519 key pair.
func GenerateKeyPair() (*HybridPrivateKey, *HybridPublicKey, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, nil, fmt.Errorf("generate mlkem1024 key: %w", err)
	}
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate x25519 key: %w", err)
	}

	mlkemPub := dk.EncapsulationKey().Bytes()
	xPub := xPriv.PublicKey().Bytes()
	fp := computeFingerprint(mlkemPub, xPub)

	priv := &HybridPrivateKey{
		Algorithm:     "ML-KEM-1024+X25519",
		Fingerprint:   fp,
		MLKEM1024Seed: dk.Bytes(),
		X25519:        xPriv.Bytes(),
	}
	pub := &HybridPublicKey{
		Algorithm:   "ML-KEM-1024+X25519",
		Fingerprint: fp,
		MLKEM1024:   mlkemPub,
		X25519:      xPub,
	}
	return priv, pub, nil
}

// Encapsulate derives a 32-byte hybrid shared secret and returns (sharedSecret, kemCiphertext, err).
// Combiner: ss_combined = HKDF-SHA512(ss_mlkem1024 || ss_x25519, info="shuna:v1:hybrid-kek").
func Encapsulate(pub *HybridPublicKey) ([]byte, []byte, error) {
	if pub == nil || len(pub.MLKEM1024) != mlkem.EncapsulationKeySize1024 || len(pub.X25519) != X25519KeySize {
		return nil, nil, ErrInvalidHybridKey
	}

	ek, err := mlkem.NewEncapsulationKey1024(pub.MLKEM1024)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidHybridKey, err)
	}
	peerXPub, err := ecdh.X25519().NewPublicKey(pub.X25519)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidHybridKey, err)
	}

	ssMLKEM, ctMLKEM := ek.Encapsulate()
	defer kdf.WipeBytes(ssMLKEM)

	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral x25519: %w", err)
	}
	ssX25519, err := ephPriv.ECDH(peerXPub)
	if err != nil {
		return nil, nil, fmt.Errorf("x25519 ecdh: %w", err)
	}
	defer kdf.WipeBytes(ssX25519)

	ikm := make([]byte, 0, len(ssMLKEM)+len(ssX25519))
	ikm = append(ikm, ssMLKEM...)
	ikm = append(ikm, ssX25519...)
	defer kdf.WipeBytes(ikm)

	ssCombined, err := kdf.DeriveSubkey(ikm, nil, kdf.InfoHybridKEK, 32)
	if err != nil {
		return nil, nil, err
	}

	kemCT := make([]byte, HybridCiphertextSize)
	copy(kemCT[:mlkem.CiphertextSize1024], ctMLKEM)
	copy(kemCT[mlkem.CiphertextSize1024:], ephPriv.PublicKey().Bytes())
	return ssCombined, kemCT, nil
}

// Decapsulate recovers the 32-byte hybrid shared secret from kemCiphertext using priv.
func Decapsulate(priv *HybridPrivateKey, kemCiphertext []byte) ([]byte, error) {
	if priv == nil || len(priv.MLKEM1024Seed) != mlkem.SeedSize || len(priv.X25519) != X25519KeySize {
		return nil, ErrInvalidHybridKey
	}
	if len(kemCiphertext) != HybridCiphertextSize {
		return nil, ErrInvalidHybridCiphertext
	}

	dk, err := mlkem.NewDecapsulationKey1024(priv.MLKEM1024Seed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidHybridKey, err)
	}
	xPriv, err := ecdh.X25519().NewPrivateKey(priv.X25519)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidHybridKey, err)
	}

	ctMLKEM := kemCiphertext[:mlkem.CiphertextSize1024]
	ephPubBytes := kemCiphertext[mlkem.CiphertextSize1024:]

	ssMLKEM, err := dk.Decapsulate(ctMLKEM)
	if err != nil {
		return nil, contract.NewError(contract.ExitCorruptCiphertext, "CORRUPT_CIPHERTEXT", "mlkem1024 decapsulation failed", err)
	}
	defer kdf.WipeBytes(ssMLKEM)

	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, contract.NewError(contract.ExitCorruptCiphertext, "CORRUPT_CIPHERTEXT", "invalid ephemeral x25519 public key", err)
	}
	ssX25519, err := xPriv.ECDH(ephPub)
	if err != nil {
		return nil, contract.NewError(contract.ExitCorruptCiphertext, "CORRUPT_CIPHERTEXT", "x25519 decapsulation failed", err)
	}
	defer kdf.WipeBytes(ssX25519)

	ikm := make([]byte, 0, len(ssMLKEM)+len(ssX25519))
	ikm = append(ikm, ssMLKEM...)
	ikm = append(ikm, ssX25519...)
	defer kdf.WipeBytes(ikm)

	ssCombined, err := kdf.DeriveSubkey(ikm, nil, kdf.InfoHybridKEK, 32)
	if err != nil {
		return nil, err
	}
	return ssCombined, nil
}

// WrapKey encapsulates a hybrid KEK to pub and seals dek with XChaCha20-Poly1305 (SHUNA1).
func WrapKey(pub *HybridPublicKey, dek, aad []byte) (wrappedDEK []byte, kemCiphertext []byte, err error) {
	if len(dek) == 0 {
		return nil, nil, errors.New("dek must not be empty")
	}
	kek, kemCT, err := Encapsulate(pub)
	if err != nil {
		return nil, nil, err
	}
	defer kdf.WipeBytes(kek)

	wrapped, err := envelope.Seal(envelope.AlgXChaCha20Poly1305, 1, kek, aad, dek)
	if err != nil {
		return nil, nil, err
	}
	return wrapped, kemCT, nil
}

// UnwrapKey decapsulates the hybrid KEK using priv and decrypts wrappedDEK.
func UnwrapKey(priv *HybridPrivateKey, wrappedDEK, kemCiphertext, aad []byte) ([]byte, error) {
	kek, err := Decapsulate(priv, kemCiphertext)
	if err != nil {
		return nil, err
	}
	defer kdf.WipeBytes(kek)

	dek, _, err := envelope.Open(kek, aad, wrappedDEK)
	if err != nil {
		return nil, err
	}
	return dek, nil
}

// SaveRecoveryKeyPair writes recovery.pub (0644) and recovery.key (0600) into dir.
func SaveRecoveryKeyPair(dir string, priv *HybridPrivateKey, pub *HybridPublicKey) (string, string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", fmt.Errorf("create recovery dir: %w", err)
	}
	pubPath := filepath.Join(dir, "recovery.pub")
	privPath := filepath.Join(dir, "recovery.key")

	pubBytes, err := json.MarshalIndent(pub, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(pubPath, pubBytes, 0644); err != nil {
		return "", "", fmt.Errorf("write recovery.pub: %w", err)
	}

	privBytes, err := json.MarshalIndent(priv, "", "  ")
	if err != nil {
		return "", "", err
	}
	defer kdf.WipeBytes(privBytes)
	if err := os.WriteFile(privPath, privBytes, 0600); err != nil {
		return "", "", fmt.Errorf("write recovery.key: %w", err)
	}
	return pubPath, privPath, nil
}

// LoadRecoveryPublicKey reads a JSON-encoded HybridPublicKey from path.
func LoadRecoveryPublicKey(path string) (*HybridPublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, contract.NewError(contract.ExitMissing, "MISSING", "recovery public key not found", err)
		}
		return nil, err
	}
	var pub HybridPublicKey
	if err := json.Unmarshal(raw, &pub); err != nil {
		return nil, contract.NewError(contract.ExitCorruptCiphertext, "CORRUPT_CIPHERTEXT", "invalid recovery public key JSON", err)
	}
	if len(pub.MLKEM1024) != mlkem.EncapsulationKeySize1024 || len(pub.X25519) != X25519KeySize {
		return nil, ErrInvalidHybridKey
	}
	return &pub, nil
}

// LoadRecoveryPrivateKey reads a JSON-encoded HybridPrivateKey from path.
func LoadRecoveryPrivateKey(path string) (*HybridPrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, contract.NewError(contract.ExitMissing, "MISSING", "recovery private key not found", err)
		}
		return nil, err
	}
	defer kdf.WipeBytes(raw)

	var priv HybridPrivateKey
	if err := json.Unmarshal(raw, &priv); err != nil {
		return nil, contract.NewError(contract.ExitCorruptCiphertext, "CORRUPT_CIPHERTEXT", "invalid recovery private key JSON", err)
	}
	if len(priv.MLKEM1024Seed) != mlkem.SeedSize || len(priv.X25519) != X25519KeySize {
		priv.Zeroize()
		return nil, ErrInvalidHybridKey
	}
	return &priv, nil
}
