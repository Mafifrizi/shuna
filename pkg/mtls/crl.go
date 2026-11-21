package mtls

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Mafifrizi/shuna/internal/flock"
	"github.com/Mafifrizi/shuna/pkg/contract"
)

const DefaultCRLValidity = 7 * 24 * time.Hour

var (
	ErrCertRevoked = contract.NewError(contract.ExitPolicyStop, "REVOKED", "certificate serial is revoked", nil)
	ErrInvalidCRL  = contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "invalid or untrusted CRL", nil)
)

// FormatSerial formats a certificate serial number into canonical 32-char lowercase hex.
func FormatSerial(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	h := strings.ToLower(serial.Text(16))
	if len(h) < 32 {
		return strings.Repeat("0", 32-len(h)) + h
	}
	return h
}

// ParseSerial parses a hex serial string (with optional 0x prefix or colons) into *big.Int and canonical hex.
func ParseSerial(serialHex string) (*big.Int, string, error) {
	cleaned := strings.TrimSpace(serialHex)
	cleaned = strings.TrimPrefix(cleaned, "0x")
	cleaned = strings.TrimPrefix(cleaned, "0X")
	cleaned = strings.ReplaceAll(cleaned, ":", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	if cleaned == "" {
		return nil, "", contract.NewError(contract.ExitUsage, "USAGE", "empty certificate serial", nil)
	}
	n, ok := new(big.Int).SetString(cleaned, 16)
	if !ok || n.Sign() <= 0 {
		return nil, "", contract.NewError(contract.ExitUsage, "USAGE", fmt.Sprintf("invalid certificate serial %q", serialHex), nil)
	}
	return n, FormatSerial(n), nil
}

// ParseReason maps a human-readable revocation reason to an RFC 5280 reason code.
func ParseReason(reason string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case "", "unspecified":
		return 0, nil
	case "key_compromise", "keycompromise":
		return 1, nil
	case "ca_compromise", "cacompromise":
		return 2, nil
	case "affiliation_changed", "affiliationchanged":
		return 3, nil
	case "superseded":
		return 4, nil
	case "cessation_of_operation", "cessationofoperation":
		return 5, nil
	case "certificate_hold", "certificatehold":
		return 6, nil
	default:
		return 0, contract.NewError(contract.ExitUsage, "USAGE", fmt.Sprintf("unsupported revocation reason %q", reason), nil)
	}
}

// CRLManager maintains a signed PEM CRL on disk and an O(1) in-memory revocation set.
type CRLManager struct {
	mu          sync.RWMutex
	caCert      *x509.Certificate
	caKey       *ecdsa.PrivateKey
	crlPath     string
	entries     map[string]x509.RevocationListEntry
	crlNumber   *big.Int
	lastModTime time.Time
	lastSize    int64
	lastDigest  [32]byte
	hasDigest   bool
}

func readCRLFile(path string) ([]byte, os.FileInfo, [32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	return raw, info, sha256.Sum256(raw), nil
}

func parseSignedCRL(raw []byte, caCert *x509.Certificate) (map[string]x509.RevocationListEntry, *big.Int, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "X509 CRL" {
		return nil, nil, ErrInvalidCRL
	}
	rl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, nil, contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "parse CRL failed", err)
	}
	if err := rl.CheckSignatureFrom(caCert); err != nil {
		return nil, nil, contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "CRL signature verification failed", err)
	}
	entries := make(map[string]x509.RevocationListEntry, len(rl.RevokedCertificateEntries))
	for _, e := range rl.RevokedCertificateEntries {
		entries[FormatSerial(e.SerialNumber)] = e
	}
	var nextNum *big.Int
	if rl.Number != nil {
		nextNum = new(big.Int).Add(rl.Number, big.NewInt(1))
	}
	return entries, nextNum, nil
}

// LoadCRL loads and verifies an existing signed PEM CRL against caCert for read-only lookups.
func LoadCRL(crlPath string, caCert *x509.Certificate) (*CRLManager, error) {
	return OpenCRLManager(caCert, nil, crlPath)
}

// OpenCRLManager loads an existing signed CRL if present, or initializes a new signed CRL when caKey is provided.
func OpenCRLManager(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, crlPath string) (*CRLManager, error) {
	if caCert == nil {
		return nil, errors.New("CA certificate is required")
	}
	mgr := &CRLManager{
		caCert:    caCert,
		caKey:     caKey,
		crlPath:   crlPath,
		entries:   make(map[string]x509.RevocationListEntry),
		crlNumber: big.NewInt(1),
	}

	applyLoaded := func(raw []byte, info os.FileInfo, digest [32]byte) error {
		entries, nextNum, err := parseSignedCRL(raw, caCert)
		if err != nil {
			return err
		}
		mgr.entries = entries
		if nextNum != nil {
			mgr.crlNumber = nextNum
		}
		mgr.lastDigest = digest
		mgr.hasDigest = true
		if info != nil {
			mgr.lastModTime = info.ModTime()
			mgr.lastSize = info.Size()
		}
		return nil
	}

	if caKey == nil {
		var raw []byte
		var info os.FileInfo
		var digest [32]byte
		err := flock.WithShared(crlPath, 0644, true, func() error {
			var rErr error
			raw, info, digest, rErr = readCRLFile(crlPath)
			return rErr
		})
		if err != nil {
			if os.IsNotExist(err) {
				return nil, contract.NewError(contract.ExitMissing, "MISSING", "CRL file not found", err)
			}
			return nil, fmt.Errorf("read CRL: %w", err)
		}
		if err := applyLoaded(raw, info, digest); err != nil {
			return nil, err
		}
		return mgr, nil
	}

	err := flock.WithExclusive(crlPath, 0644, func() error {
		raw, info, digest, rErr := readCRLFile(crlPath)
		if rErr != nil {
			if os.IsNotExist(rErr) {
				return mgr.writeLocked()
			}
			return fmt.Errorf("read CRL: %w", rErr)
		}
		return applyLoaded(raw, info, digest)
	})
	if err != nil {
		return nil, err
	}
	return mgr, nil
}

// ReloadIfChanged reloads and verifies ca.crl from disk if its SHA-256 digest changed.
func (m *CRLManager) ReloadIfChanged() error {
	if m == nil || m.crlPath == "" {
		return nil
	}

	m.mu.RLock()
	var raw []byte
	var info os.FileInfo
	var digest [32]byte
	err := flock.WithShared(m.crlPath, 0644, true, func() error {
		var rErr error
		raw, info, digest, rErr = readCRLFile(m.crlPath)
		return rErr
	})
	unchanged := err == nil && m.hasDigest && digest == m.lastDigest
	m.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("read CRL: %w", err)
	}
	if unchanged {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	err = flock.WithShared(m.crlPath, 0644, true, func() error {
		var rErr error
		raw, info, digest, rErr = readCRLFile(m.crlPath)
		return rErr
	})
	if err != nil {
		return fmt.Errorf("read CRL: %w", err)
	}
	if m.hasDigest && digest == m.lastDigest {
		return nil
	}

	entries, nextNum, err := parseSignedCRL(raw, m.caCert)
	if err != nil {
		return err
	}
	m.entries = entries
	if nextNum != nil {
		m.crlNumber = nextNum
	}
	m.lastDigest = digest
	m.hasDigest = true
	if info != nil {
		m.lastModTime = info.ModTime()
		m.lastSize = info.Size()
	}
	return nil
}

// Revoke adds serialHex to the CRL, re-signs ca.crl atomically, and updates the live lookup set.
func (m *CRLManager) Revoke(serialHex string, reason int) (string, error) {
	serial, canonical, err := ParseSerial(serialHex)
	if err != nil {
		return "", err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.caKey == nil {
		return "", errors.New("CA private key required to sign CRL")
	}

	err = flock.WithExclusive(m.crlPath, 0644, func() error {
		if m.crlPath != "" {
			raw, info, digest, rErr := readCRLFile(m.crlPath)
			if rErr == nil {
				if !m.hasDigest || digest != m.lastDigest {
					entries, nextNum, pErr := parseSignedCRL(raw, m.caCert)
					if pErr != nil {
						return pErr
					}
					m.entries = entries
					if nextNum != nil {
						m.crlNumber = nextNum
					}
					m.lastDigest = digest
					m.hasDigest = true
					if info != nil {
						m.lastModTime = info.ModTime()
						m.lastSize = info.Size()
					}
				}
			} else if !os.IsNotExist(rErr) {
				return fmt.Errorf("read CRL: %w", rErr)
			}
		}

		prev, existed := m.entries[canonical]
		m.entries[canonical] = x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().UTC(),
			ReasonCode:     reason,
		}
		if wErr := m.writeLocked(); wErr != nil {
			if existed {
				m.entries[canonical] = prev
			} else {
				delete(m.entries, canonical)
			}
			return wErr
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return canonical, nil
}

// IsRevoked performs an O(1) thread-safe check for serial.
func (m *CRLManager) IsRevoked(serial *big.Int) bool {
	if m == nil || serial == nil {
		return false
	}
	canonical := FormatSerial(serial)
	m.mu.RLock()
	_, ok := m.entries[canonical]
	m.mu.RUnlock()
	return ok
}

// IsRevokedHex checks revocation by hex serial string.
func (m *CRLManager) IsRevokedHex(serialHex string) bool {
	if m == nil {
		return false
	}
	_, canonical, err := ParseSerial(serialHex)
	if err != nil {
		return false
	}
	m.mu.RLock()
	_, ok := m.entries[canonical]
	m.mu.RUnlock()
	return ok
}

// RevokedSerials returns a sorted slice of canonical hex serials currently in the CRL.
func (m *CRLManager) RevokedSerials() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.entries))
	for k := range m.entries {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (m *CRLManager) writeLocked() error {
	now := time.Now().UTC()
	list := make([]x509.RevocationListEntry, 0, len(m.entries))
	keys := make([]string, 0, len(m.entries))
	for k := range m.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		list = append(list, m.entries[k])
	}

	num := new(big.Int).Set(m.crlNumber)
	tmpl := &x509.RevocationList{
		Number:                    num,
		ThisUpdate:                now.Add(-1 * time.Minute),
		NextUpdate:                now.Add(DefaultCRLValidity),
		RevokedCertificateEntries: list,
	}

	der, err := x509.CreateRevocationList(rand.Reader, tmpl, m.caCert, m.caKey)
	if err != nil {
		return fmt.Errorf("create CRL: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})

	dir := filepath.Dir(m.crlPath)
	tmp, err := os.CreateTemp(dir, ".ca.crl.tmp-*")
	if err != nil {
		return fmt.Errorf("create temp CRL: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(pemBytes); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write temp CRL: %w", err)
	}
	if err := tmp.Chmod(0644); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("chmod temp CRL: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp CRL: %w", err)
	}
	if err := os.Rename(tmpName, m.crlPath); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename CRL: %w", err)
	}

	m.lastDigest = sha256.Sum256(pemBytes)
	m.hasDigest = true
	if info, statErr := os.Stat(m.crlPath); statErr == nil {
		m.lastModTime = info.ModTime()
		m.lastSize = info.Size()
	}
	m.crlNumber = new(big.Int).Add(m.crlNumber, big.NewInt(1))
	return nil
}
