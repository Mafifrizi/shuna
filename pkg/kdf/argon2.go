package kdf

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	// Argon2id parameters aligned with RFC 9106 and Shuna specification v1.2.
	Argon2Time    uint32 = 3
	Argon2Memory  uint32 = 65536 // 64 MiB in KiB
	Argon2Threads uint8  = 4
	Argon2KeyLen  uint32 = 32
	SaltLen              = 16

	// Domain-separated HKDF-SHA512 info strings.
	InfoKEK        = "shuna:v1:kek"
	InfoDEK        = "shuna:v1:dek"
	InfoBlindIndex = "shuna:v1:blind-index"
	InfoStream     = "shuna:v1:stream"
	InfoHybridKEK  = "shuna:v1:hybrid-kek"

	maxHKDFOutputLen = 255 * sha512.Size
)

var (
	ErrInvalidPassphrase = errors.New("passphrase must not be empty")
	ErrInvalidSalt       = errors.New("salt must be 16 bytes")
	ErrInvalidHKDFInput  = errors.New("invalid HKDF parameters")
)

// GenerateSalt generates a 16-byte CSPRNG salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// DeriveMasterKey derives a 32-byte master key from passphrase and a 16-byte salt using Argon2id.
func DeriveMasterKey(passphrase, salt []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrInvalidPassphrase
	}
	if len(salt) != SaltLen {
		return nil, ErrInvalidSalt
	}
	key := argon2.IDKey(passphrase, salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
	return key, nil
}

// DeriveSubkey derives a domain-separated subkey using HKDF-SHA512 (RFC 5869).
func DeriveSubkey(ikm, salt []byte, info string, length int) ([]byte, error) {
	if len(ikm) == 0 || length <= 0 || length > maxHKDFOutputLen || info == "" {
		return nil, ErrInvalidHKDFInput
	}
	r := hkdf.New(sha512.New, ikm, salt, []byte(info))
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		WipeBytes(out)
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}
	return out, nil
}
