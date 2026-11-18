package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/Mafifrizi/shuna/pkg/contract"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Magic         = "SHUNA1"
	MagicLen      = 6
	HeaderSize    = 35 // 6 (Magic) + 1 (AlgID) + 4 (KeyVersion) + 24 (Nonce slot)
	NonceSlotSize = 24
	GCMNonceSize  = 12
	TagSize       = 16
	KeySize       = 32

	AlgXChaCha20Poly1305 byte = 0x01
	AlgAES256GCM         byte = 0x02
)

var (
	ErrCorruptCiphertext = contract.NewError(contract.ExitCorruptCiphertext, "CORRUPT_CIPHERTEXT", "corrupt or unauthenticated ciphertext", nil)
	ErrInvalidKey        = errors.New("key must be 32 bytes")
	ErrUnsupportedAlg    = errors.New("unsupported envelope algorithm")
)

// Header holds parsed SHUNA1 header metadata.
type Header struct {
	AlgID      byte
	KeyVersion uint32
}

func corruptErr(reason string, cause error) error {
	return contract.NewError(contract.ExitCorruptCiphertext, "CORRUPT_CIPHERTEXT", reason, errors.Join(ErrCorruptCiphertext, cause))
}

// ParseAlg converts an algorithm name ("xchacha20", "aes256gcm") into its wire AlgID.
func ParseAlg(name string) (byte, error) {
	switch name {
	case "", "xchacha20", "xchacha20-poly1305", "xchacha20poly1305":
		return AlgXChaCha20Poly1305, nil
	case "aes256gcm", "aes-256-gcm":
		return AlgAES256GCM, nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrUnsupportedAlg, name)
	}
}

// AlgName returns the human-readable algorithm identifier for a wire AlgID.
func AlgName(alg byte) string {
	switch alg {
	case AlgXChaCha20Poly1305:
		return "xchacha20-poly1305"
	case AlgAES256GCM:
		return "aes-256-gcm"
	default:
		return fmt.Sprintf("unknown(0x%02x)", alg)
	}
}

// InspectHeader validates the SHUNA1 magic and extracts AlgID and KeyVersion before decryption.
func InspectHeader(blob []byte) (Header, error) {
	if len(blob) < HeaderSize+TagSize {
		return Header{}, corruptErr("envelope shorter than minimum SHUNA1 frame", nil)
	}
	if string(blob[:MagicLen]) != Magic {
		return Header{}, corruptErr("invalid SHUNA1 magic header", nil)
	}
	alg := blob[6]
	if alg != AlgXChaCha20Poly1305 && alg != AlgAES256GCM {
		return Header{}, corruptErr(fmt.Sprintf("unknown SHUNA1 algorithm 0x%02x", alg), nil)
	}
	if alg == AlgAES256GCM {
		var padCheck byte
		for _, b := range blob[23:35] {
			padCheck |= b
		}
		if padCheck != 0 {
			return Header{}, corruptErr("non-zero padding in AES-256-GCM nonce slot", nil)
		}
	}
	return Header{
		AlgID:      alg,
		KeyVersion: binary.BigEndian.Uint32(blob[7:11]),
	}, nil
}

// Seal encrypts plaintext using the specified SHUNA1 algorithm (0x01 or 0x02), keyVersion, 32-byte key, and AAD.
func Seal(alg byte, keyVersion uint32, key, aad, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	var aead cipher.AEAD
	var nonceLen int
	switch alg {
	case AlgXChaCha20Poly1305:
		c, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, fmt.Errorf("init xchacha20poly1305: %w", err)
		}
		aead = c
		nonceLen = NonceSlotSize
	case AlgAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("init aes256: %w", err)
		}
		c, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("init aes-gcm: %w", err)
		}
		aead = c
		nonceLen = GCMNonceSize
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedAlg, alg)
	}

	out := make([]byte, HeaderSize, HeaderSize+len(plaintext)+TagSize)
	copy(out[:MagicLen], Magic)
	out[6] = alg
	binary.BigEndian.PutUint32(out[7:11], keyVersion)

	if _, err := io.ReadFull(rand.Reader, out[11:11+nonceLen]); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	// out[11+nonceLen : 35] remains strictly 0x00 for AES-256-GCM.

	effectiveAAD := buildEffectiveAAD(out[:11], aad)
	out = aead.Seal(out, out[11:11+nonceLen], plaintext, effectiveAAD)
	return out, nil
}

// Open verifies and decrypts a SHUNA1 blob following the strict AlgID-first nonce parsing invariant.
func Open(key, aad, blob []byte) ([]byte, uint32, error) {
	if len(key) != KeySize {
		return nil, 0, ErrInvalidKey
	}
	hdr, err := InspectHeader(blob)
	if err != nil {
		return nil, 0, err
	}

	var aead cipher.AEAD
	var nonce []byte
	switch hdr.AlgID {
	case AlgXChaCha20Poly1305:
		nonce = blob[11:35]
		c, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, 0, fmt.Errorf("init xchacha20poly1305: %w", err)
		}
		aead = c
	case AlgAES256GCM:
		// Strict AlgID-first invariant: blob[23:35] MUST be 12 zero bytes.
		var padCheck byte
		for _, b := range blob[23:35] {
			padCheck |= b
		}
		if padCheck != 0 {
			return nil, 0, corruptErr("non-zero padding in AES-256-GCM nonce slot", nil)
		}
		nonce = blob[11:23]
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, 0, fmt.Errorf("init aes256: %w", err)
		}
		c, err := cipher.NewGCM(block)
		if err != nil {
			return nil, 0, fmt.Errorf("init aes-gcm: %w", err)
		}
		aead = c
	default:
		return nil, 0, corruptErr(fmt.Sprintf("unknown SHUNA1 algorithm 0x%02x", hdr.AlgID), nil)
	}

	effectiveAAD := buildEffectiveAAD(blob[:11], aad)
	pt, err := aead.Open(nil, nonce, blob[HeaderSize:], effectiveAAD)
	if err != nil {
		return nil, 0, corruptErr("AEAD authentication failed", err)
	}
	return pt, hdr.KeyVersion, nil
}

func buildEffectiveAAD(headerPrefix, callerAAD []byte) []byte {
	eff := make([]byte, len(headerPrefix)+len(callerAAD))
	copy(eff, headerPrefix)
	copy(eff[len(headerPrefix):], callerAAD)
	return eff
}
