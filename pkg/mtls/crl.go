package mtls

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

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
	mu        sync.RWMutex
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	crlPath   string
	entries   map[string]x509.RevocationListEntry
	crlNumber *big.Int
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

	raw, err := os.ReadFile(crlPath)
	if err != nil {
		if os.IsNotExist(err) {
			if caKey == nil {
				return nil, contract.NewError(contract.ExitMissing, "MISSING", "CRL file not found", err)
			}
			if err := mgr.writeLocked(); err != nil {
				return nil, err
			}
			return mgr, nil
		}
		return nil, fmt.Errorf("read CRL: %w", err)
	}

	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "X509 CRL" {
		return nil, ErrInvalidCRL
	}
	rl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "parse CRL failed", err)
	}
	if err := rl.CheckSignatureFrom(caCert); err != nil {
		return nil, contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "CRL signature verification failed", err)
	}

	for _, e := range rl.RevokedCertificateEntries {
		mgr.entries[FormatSerial(e.SerialNumber)] = e
	}
	if rl.Number != nil {
		mgr.crlNumber = new(big.Int).Add(rl.Number, big.NewInt(1))
	}
	return mgr, nil
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

	m.entries[canonical] = x509.RevocationListEntry{
		SerialNumber:   serial,
		RevocationTime: time.Now().UTC(),
		ReasonCode:     reason,
	}
	if err := m.writeLocked(); err != nil {
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

	m.crlNumber = new(big.Int).Add(m.crlNumber, big.NewInt(1))
	return nil
}
