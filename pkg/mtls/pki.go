package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mafifrizi/shuna/pkg/contract"
)

type Role string

const (
	RoleClient   Role = "client"
	RoleServer   Role = "server"
	RolePostgres Role = "postgres"

	DefaultClientTTL = 24 * time.Hour
	DefaultServerTTL = 7 * 24 * time.Hour
	DefaultCATTL     = 365 * 24 * time.Hour
)

// ParseRole validates and returns a Role.
func ParseRole(s string) (Role, error) {
	switch Role(strings.ToLower(strings.TrimSpace(s))) {
	case RoleClient:
		return RoleClient, nil
	case RoleServer:
		return RoleServer, nil
	case RolePostgres:
		return RolePostgres, nil
	default:
		return "", contract.NewError(contract.ExitUsage, "USAGE", fmt.Sprintf("invalid cert role %q (want client|server|postgres)", s), nil)
	}
}

// IssuedCert summarizes a newly generated certificate and keypair on disk.
type IssuedCert struct {
	CommonName   string    `json:"common_name"`
	Role         Role      `json:"role"`
	SerialHex    string    `json:"serial_hex"`
	Fingerprint  string    `json:"fingerprint_sha256"`
	CertPath     string    `json:"cert_path"`
	KeyPath      string    `json:"key_path"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	DNSNames     []string  `json:"dns_names,omitempty"`
	IPAddresses  []string  `json:"ip_addresses,omitempty"`
}

// PKIInitResult summarizes artifacts produced by InitPKI.
type PKIInitResult struct {
	PKIDir       string      `json:"pki_dir"`
	CACertPath   string      `json:"ca_cert_path"`
	CAKeyPath    string      `json:"ca_key_path"`
	CRLPath      string      `json:"crl_path"`
	ServerCert   *IssuedCert `json:"server_cert"`
	PostgresCert *IssuedCert `json:"postgres_cert"`
}

// TLSOptions controls PQC key exchange and optional live revocation hooks.
type TLSOptions struct {
	AllowClassicalFallback bool
	ServerName             string
	ExtraRevokedCheck      func(serialHex string) bool
}

// CertVerifyStatus records verification details for a single leaf certificate.
type CertVerifyStatus struct {
	Path         string `json:"path"`
	CommonName   string `json:"common_name"`
	SerialHex    string `json:"serial_hex"`
	Valid        bool   `json:"valid"`
	Revoked      bool   `json:"revoked"`
	NeedsRenewal bool   `json:"needs_renewal"`
	Error        string `json:"error,omitempty"`
}

// VerifyReport summarizes PKI health, CRL signature validity, and leaf certificates.
type VerifyReport struct {
	PKIDir         string             `json:"pki_dir"`
	CASubject      string             `json:"ca_subject"`
	CRLSigned      bool               `json:"crl_signed"`
	RevokedCount   int                `json:"revoked_count"`
	RevokedSerials []string           `json:"revoked_serials,omitempty"`
	Certificates   []CertVerifyStatus `json:"certificates"`
}

// InitPKI initializes an ECDSA P-384 CA, signed empty CRL, server cert, and postgres server cert.
func InitPKI(outDir string, hosts, pgHosts []string, leafTTL time.Duration) (*PKIInitResult, error) {
	if outDir == "" {
		return nil, contract.NewError(contract.ExitUsage, "USAGE", "pki output directory required", nil)
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, fmt.Errorf("create pki dir: %w", err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	caSerial, err := newRandomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	caTmpl := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			Organization: []string{"Shuna PKI"},
			CommonName:   "Shuna Root CA",
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(DefaultCATTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign CA cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	caCertPath := filepath.Join(outDir, "ca.crt")
	caKeyPath := filepath.Join(outDir, "ca.key")
	crlPath := filepath.Join(outDir, "ca.crl")

	if err := writeCertPEM(caCertPath, caDER); err != nil {
		return nil, err
	}
	if err := writeECKeyPEM(caKeyPath, caKey); err != nil {
		return nil, err
	}

	if _, err := OpenCRLManager(caCert, caKey, crlPath); err != nil {
		return nil, err
	}

	serverTTL := leafTTL
	if serverTTL <= 0 {
		serverTTL = DefaultServerTTL
	}
	if len(hosts) == 0 {
		hosts = []string{"127.0.0.1", "localhost"}
	}
	if len(pgHosts) == 0 {
		pgHosts = []string{"postgres", "127.0.0.1"}
	}

	serverCert, err := issueCert(outDir, "server", RoleServer, hosts, serverTTL)
	if err != nil {
		return nil, err
	}
	pgCert, err := issueCert(outDir, "pg-server", RolePostgres, pgHosts, serverTTL)
	if err != nil {
		return nil, err
	}

	return &PKIInitResult{
		PKIDir:       outDir,
		CACertPath:   caCertPath,
		CAKeyPath:    caKeyPath,
		CRLPath:      crlPath,
		ServerCert:   serverCert,
		PostgresCert: pgCert,
	}, nil
}

// IssueCert signs a short-lived ECDSA P-384 certificate using the CA in pkiDir.
func IssueCert(pkiDir, cn string, role Role, hosts []string, ttl time.Duration) (*IssuedCert, error) {
	if pkiDir == "" || strings.TrimSpace(cn) == "" {
		return nil, contract.NewError(contract.ExitUsage, "USAGE", "pki-dir and cn are required", nil)
	}
	safeName, err := sanitizeFileBase(cn)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(safeName, "server") {
		if role != RoleServer || cn != "server" {
			return nil, contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", fmt.Sprintf("reserved PKI certificate name %q cannot be issued", cn), nil)
		}
		srvPath := filepath.Join(pkiDir, "server.crt")
		if existing, loadErr := LoadCertificate(srvPath); loadErr == nil && !NeedsRenewal(existing, time.Now().UTC()) {
			return nil, contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "reserved PKI certificate \"server\" already exists and does not need renewal", nil)
		}
	}
	return issueCert(pkiDir, safeName, role, hosts, ttl)
}

func issueCert(pkiDir, cn string, role Role, hosts []string, ttl time.Duration) (*IssuedCert, error) {
	cn = strings.TrimSpace(cn)
	if pkiDir == "" || cn == "" {
		return nil, contract.NewError(contract.ExitUsage, "USAGE", "pki-dir and cn are required", nil)
	}
	safeName := cn

	caCert, caKey, err := LoadCA(pkiDir)
	if err != nil {
		return nil, err
	}

	if ttl <= 0 {
		if role == RoleClient {
			ttl = DefaultClientTTL
		} else {
			ttl = DefaultServerTTL
		}
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := newRandomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Shuna PKI"},
			CommonName:   cn,
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
	}

	var dnsNames []string
	var ipStrs []string
	switch role {
	case RoleClient:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case RoleServer, RolePostgres:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		candidates := append([]string(nil), hosts...)
		if len(candidates) == 0 {
			candidates = []string{cn}
		}
		for _, h := range candidates {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			if ip := net.ParseIP(h); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
				ipStrs = append(ipStrs, ip.String())
			} else {
				tmpl.DNSNames = append(tmpl.DNSNames, h)
				dnsNames = append(dnsNames, h)
			}
		}
	default:
		return nil, contract.NewError(contract.ExitUsage, "USAGE", fmt.Sprintf("unsupported role %q", role), nil)
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf cert: %w", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("parse leaf cert: %w", err)
	}

	certPath := filepath.Join(pkiDir, safeName+".crt")
	keyPath := filepath.Join(pkiDir, safeName+".key")
	if err := writeCertPEM(certPath, leafDER); err != nil {
		return nil, err
	}
	if err := writeECKeyPEM(keyPath, leafKey); err != nil {
		return nil, err
	}

	return &IssuedCert{
		CommonName:  cn,
		Role:        role,
		SerialHex:   FormatSerial(leafCert.SerialNumber),
		Fingerprint: CertFingerprintSHA256(leafCert),
		CertPath:    certPath,
		KeyPath:     keyPath,
		NotBefore:   leafCert.NotBefore,
		NotAfter:    leafCert.NotAfter,
		DNSNames:    dnsNames,
		IPAddresses: ipStrs,
	}, nil
}

// NeedsRenewal returns true when >= 50% of cert's total validity lifetime has elapsed.
func NeedsRenewal(cert *x509.Certificate, now time.Time) bool {
	if cert == nil {
		return true
	}
	halfLife := cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2)
	return !now.Before(halfLife)
}

// CertFingerprintSHA256 returns the lowercase hex SHA-256 digest of cert.Raw.
func CertFingerprintSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// LoadCA loads ca.crt and ca.key from pkiDir.
func LoadCA(pkiDir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	caCert, err := LoadCertificate(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		return nil, nil, err
	}
	caKey, err := loadECPrivateKey(filepath.Join(pkiDir, "ca.key"))
	if err != nil {
		return nil, nil, err
	}
	return caCert, caKey, nil
}

// LoadCertificate reads and parses a PEM-encoded X.509 certificate.
func LoadCertificate(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, contract.NewError(contract.ExitMissing, "MISSING", fmt.Sprintf("certificate not found: %s", path), err)
		}
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM: %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func loadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, contract.NewError(contract.ExitMissing, "MISSING", fmt.Sprintf("private key not found: %s", path), err)
		}
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("invalid private key PEM: %s", path)
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	anyKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key %s: %w", path, err)
	}
	ecKey, ok := anyKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected ECDSA private key in %s", path)
	}
	return ecKey, nil
}

// ServerTLSConfig builds a strict TLS 1.3 mutual-TLS server config enforcing X25519MLKEM768 and CRL revocation checks.
func ServerTLSConfig(certPath, keyPath, caCertPath string, crl *CRLManager, opts TLSOptions) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, mapMissingErr(err, "server keypair")
	}
	caCert, err := LoadCertificate(caCertPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	curves := []tls.CurveID{tls.X25519MLKEM768}
	if opts.AllowClassicalFallback {
		curves = append(curves, tls.X25519)
	}

	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: curves,
		Certificates:     []tls.Certificate{cert},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        pool,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return checkPeerRevocation(rawCerts, verifiedChains, crl, opts.ExtraRevokedCheck)
		},
	}, nil
}

// ClientTLSConfig builds a strict TLS 1.3 client config enforcing X25519MLKEM768 and CA/CRL verification.
func ClientTLSConfig(certPath, keyPath, caCertPath string, crl *CRLManager, opts TLSOptions) (*tls.Config, error) {
	caCert, err := LoadCertificate(caCertPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	var certs []tls.Certificate
	if certPath != "" && keyPath != "" {
		c, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, mapMissingErr(err, "client keypair")
		}
		certs = []tls.Certificate{c}
	}

	curves := []tls.CurveID{tls.X25519MLKEM768}
	if opts.AllowClassicalFallback {
		curves = append(curves, tls.X25519)
	}

	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: curves,
		Certificates:     certs,
		RootCAs:          pool,
		ServerName:       opts.ServerName,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return checkPeerRevocation(rawCerts, verifiedChains, crl, opts.ExtraRevokedCheck)
		},
	}, nil
}

func checkPeerRevocation(rawCerts [][]byte, verifiedChains [][]*x509.Certificate, crl *CRLManager, extra func(string) bool) error {
	var leaf *x509.Certificate
	if len(verifiedChains) > 0 && len(verifiedChains[0]) > 0 {
		leaf = verifiedChains[0][0]
	} else if len(rawCerts) > 0 {
		parsed, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		leaf = parsed
	}
	if leaf == nil {
		return errors.New("missing peer leaf certificate")
	}
	if crl != nil {
		if err := crl.ReloadIfChanged(); err != nil {
			return err
		}
		if crl.IsRevoked(leaf.SerialNumber) {
			return fmt.Errorf("%w: serial %s", ErrCertRevoked, FormatSerial(leaf.SerialNumber))
		}
	}
	if extra != nil && extra(FormatSerial(leaf.SerialNumber)) {
		return fmt.Errorf("%w: serial %s", ErrCertRevoked, FormatSerial(leaf.SerialNumber))
	}
	return nil
}

// VerifyPKI validates CA integrity, CRL signature, and leaf certificates in pkiDir (or a single certPath).
func VerifyPKI(pkiDir, certPath string) (*VerifyReport, error) {
	if pkiDir == "" {
		return nil, contract.NewError(contract.ExitUsage, "USAGE", "pki-dir is required", nil)
	}
	caCert, err := LoadCertificate(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	if !caCert.IsCA {
		return nil, contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "ca.crt is not a CA certificate", nil)
	}

	now := time.Now().UTC()
	if now.Before(caCert.NotBefore) || now.After(caCert.NotAfter) {
		return nil, contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "CA certificate expired or not yet valid", nil)
	}

	crl, err := LoadCRL(filepath.Join(pkiDir, "ca.crl"), caCert)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	var targets []string
	if certPath != "" {
		if _, err := os.Stat(certPath); err != nil {
			return nil, mapMissingErr(err, "target certificate")
		}
		targets = []string{certPath}
	} else {
		matches, err := filepath.Glob(filepath.Join(pkiDir, "*.crt"))
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			if filepath.Base(m) == "ca.crt" {
				continue
			}
			targets = append(targets, m)
		}
	}

	revokedSerials := crl.RevokedSerials()
	report := &VerifyReport{
		PKIDir:         pkiDir,
		CASubject:      caCert.Subject.String(),
		CRLSigned:      true,
		RevokedCount:   len(revokedSerials),
		RevokedSerials: revokedSerials,
		Certificates:   make([]CertVerifyStatus, 0, len(targets)),
	}

	var policyErr error
	for _, p := range targets {
		leaf, err := LoadCertificate(p)
		if err != nil {
			return nil, err
		}
		st := CertVerifyStatus{
			Path:         p,
			CommonName:   leaf.Subject.CommonName,
			SerialHex:    FormatSerial(leaf.SerialNumber),
			NeedsRenewal: NeedsRenewal(leaf, now),
		}
		if crl.IsRevoked(leaf.SerialNumber) {
			st.Revoked = true
			st.Valid = false
			st.Error = "certificate revoked in ca.crl"
			if policyErr == nil {
				policyErr = contract.NewError(contract.ExitPolicyStop, "REVOKED", fmt.Sprintf("certificate %s is revoked", st.SerialHex), ErrCertRevoked)
			}
		} else {
			_, verifyErr := leaf.Verify(x509.VerifyOptions{
				Roots:       pool,
				CurrentTime: now,
				KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})
			if verifyErr != nil {
				st.Valid = false
				st.Error = verifyErr.Error()
				if policyErr == nil {
					policyErr = contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", fmt.Sprintf("certificate %s verification failed", st.SerialHex), verifyErr)
				}
			} else {
				st.Valid = true
			}
		}
		report.Certificates = append(report.Certificates, st)
	}

	return report, policyErr
}

func newRandomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	if n.Sign() == 0 {
		n.SetInt64(1)
	}
	return n, nil
}

func writeCertPEM(path string, der []byte) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return os.WriteFile(path, pemBytes, 0644)
}

func writeECKeyPEM(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal EC private key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return os.WriteFile(path, pemBytes, 0600)
}

func sanitizeFileBase(name string) (string, error) {
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", contract.NewError(contract.ExitUsage, "USAGE", fmt.Sprintf("unsafe certificate common name %q", name), nil)
		}
	}
	base := strings.TrimSpace(name)
	if base == "" ||
		strings.ContainsAny(base, "/\\:\x00*?\"<>|") ||
		strings.Contains(base, "..") ||
		strings.HasPrefix(base, ".") ||
		strings.HasSuffix(base, ".") {
		return "", contract.NewError(contract.ExitUsage, "USAGE", fmt.Sprintf("unsafe certificate common name %q", name), nil)
	}

	lower := strings.ToLower(base)
	stem := lower
	for _, ext := range []string{".crt", ".key", ".crl", ".pem"} {
		if strings.HasSuffix(lower, ext) {
			stem = strings.TrimSuffix(lower, ext)
			break
		}
	}
	switch stem {
	case "ca", "ca.crl", "pg-server", "server":
		if lower == "server" {
			return base, nil
		}
		return "", contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", fmt.Sprintf("reserved PKI certificate name %q cannot be issued", name), nil)
	}
	if stem != lower {
		return "", contract.NewError(contract.ExitUsage, "USAGE", fmt.Sprintf("certificate common name %q must not include key/cert extension", name), nil)
	}
	return base, nil
}

func mapMissingErr(err error, label string) error {
	if os.IsNotExist(err) {
		return contract.NewError(contract.ExitMissing, "MISSING", fmt.Sprintf("%s not found", label), err)
	}
	return err
}
