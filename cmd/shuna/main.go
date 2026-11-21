package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mafifrizi/shuna/pkg/contract"
	"github.com/Mafifrizi/shuna/pkg/envelope"
	"github.com/Mafifrizi/shuna/pkg/kdf"
	"github.com/Mafifrizi/shuna/pkg/mtls"
	"github.com/Mafifrizi/shuna/pkg/pqc"
	"github.com/Mafifrizi/shuna/pkg/vault"
)

var version = "1.0.0"

type cmdResult struct {
	Message string
	Data    any
	RawOut  []byte
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return contract.ExitUsage
	}

	sub := args[0]
	if sub == "-h" || sub == "--help" || sub == "help" {
		printUsage(stdout)
		return contract.ExitOK
	}

	jsonOut := hasJSONFlag(args[1:])

	var res cmdResult
	var err error
	switch sub {
	case "keygen":
		res, err = cmdKeygen(args[1:])
	case "init-pki":
		res, err = cmdInitPKI(args[1:])
	case "issue-cert":
		res, err = cmdIssueCert(args[1:])
	case "revoke":
		res, err = cmdRevoke(args[1:])
	case "seal":
		res, err = cmdSeal(args[1:], stdin, stdout)
	case "unseal":
		res, err = cmdUnseal(args[1:], stdin, stdout)
	case "rotate":
		res, err = cmdRotate(args[1:])
	case "verify":
		res, err = cmdVerify(args[1:])
	case "unlock-reset":
		res, err = cmdUnlockReset(args[1:])
	case "-V", "--version", "version":
		res, err = cmdVersion(args[1:])
	default:
		err = contract.NewError(contract.ExitUsage, "USAGE", fmt.Sprintf("unknown subcommand %q", sub), nil)
	}

	code := contract.CodeOf(err)
	status := contract.StatusOf(err)

	if jsonOut {
		if jErr := contract.WriteJSON(stdout, code, status, res.Message, res.Data, err); jErr != nil {
			fmt.Fprintf(stderr, "json encode error: %v\n", jErr)
			return contract.ExitUsage
		}
		return code
	}

	if err != nil {
		fmt.Fprintf(stderr, "error [%s]: %v\n", status, err)
		return code
	}
	if len(res.RawOut) > 0 {
		if _, wErr := stdout.Write(res.RawOut); wErr != nil {
			fmt.Fprintf(stderr, "write stdout error: %v\n", wErr)
			return contract.ExitUsage
		}
		return contract.ExitOK
	}
	if res.Message != "" {
		fmt.Fprintln(stdout, res.Message)
	}
	return contract.ExitOK
}

func hasJSONFlag(args []string) bool {
	for _, a := range args {
		if a == "--" {
			break
		}
		if a == "--json" || a == "-json" || a == "--json=true" || a == "-json=true" {
			return true
		}
	}
	return false
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return contract.NewError(contract.ExitUsage, "USAGE", err.Error(), err)
	}
	if fs.NArg() > 0 {
		return contract.NewError(contract.ExitUsage, "USAGE", fmt.Sprintf("unexpected positional arguments: %v", fs.Args()), nil)
	}
	return nil
}

func cmdVersion(args []string) (cmdResult, error) {
	fs := newFlagSet("version")
	_ = fs.Bool("json", false, "emit JSON output")
	if err := parseFlags(fs, args); err != nil {
		return cmdResult{}, err
	}
	return cmdResult{
		Message: fmt.Sprintf("shuna %s", version),
		Data:    map[string]any{"version": version},
	}, nil
}

func resolvePassphrase(envName string, required bool) ([]byte, error) {
	if envName != "" {
		val := os.Getenv(envName)
		if val == "" && required {
			return nil, contract.NewError(contract.ExitUsage, "USAGE", fmt.Sprintf("environment variable %s is empty or unset", envName), nil)
		}
		return []byte(val), nil
	}
	val := os.Getenv("SHUNA_PASSPHRASE")
	if val == "" && required {
		return nil, contract.NewError(contract.ExitUsage, "USAGE", "passphrase required via --passphrase-env or SHUNA_PASSPHRASE", nil)
	}
	return []byte(val), nil
}

func cmdKeygen(args []string) (cmdResult, error) {
	fs := newFlagSet("keygen")
	outDir := fs.String("out", "", "output vault directory")
	passEnv := fs.String("passphrase-env", "", "env var holding vault passphrase")
	strictMlock := fs.Bool("strict-mlock", false, "fail closed if mlock fails")
	strictWipe := fs.Bool("strict-lockout-wipe", false, "zeroize keys on 5th failed unlock")
	algName := fs.String("alg", "xchacha20", "AEAD algorithm (xchacha20|aes256gcm)")
	_ = fs.Bool("json", false, "emit JSON output")
	if err := parseFlags(fs, args); err != nil {
		return cmdResult{}, err
	}
	if *outDir == "" {
		return cmdResult{}, contract.NewError(contract.ExitUsage, "USAGE", "--out is required", nil)
	}
	alg, err := envelope.ParseAlg(*algName)
	if err != nil {
		return cmdResult{}, contract.NewError(contract.ExitUsage, "USAGE", err.Error(), err)
	}
	pass, err := resolvePassphrase(*passEnv, true)
	if err != nil {
		return cmdResult{}, err
	}
	defer kdf.WipeBytes(pass)

	v, initRes, err := vault.InitVault(*outDir, pass, vault.Options{
		Algorithm:         alg,
		StrictMlock:       *strictMlock,
		StrictLockoutWipe: *strictWipe,
	})
	if err != nil {
		return cmdResult{}, err
	}
	defer v.Zeroize()

	return cmdResult{
		Message: fmt.Sprintf("initialized vault at %s (active_version=%d, recovery_fp=%s)", initRes.VaultDir, initRes.ActiveVersion, initRes.RecoveryFingerprnt),
		Data:    initRes,
	}, nil
}

func cmdInitPKI(args []string) (cmdResult, error) {
	fs := newFlagSet("init-pki")
	outDir := fs.String("out", "", "output PKI directory")
	hosts := fs.String("hosts", "127.0.0.1,localhost", "comma-separated server SANs")
	pgHosts := fs.String("pg-hosts", "postgres,127.0.0.1", "comma-separated PostgreSQL server SANs")
	leafTTL := fs.Duration("leaf-ttl", 0, "leaf certificate TTL (default 7d for server/postgres)")
	_ = fs.Bool("json", false, "emit JSON output")
	if err := parseFlags(fs, args); err != nil {
		return cmdResult{}, err
	}
	if *outDir == "" {
		return cmdResult{}, contract.NewError(contract.ExitUsage, "USAGE", "--out is required", nil)
	}

	res, err := mtls.InitPKI(*outDir, splitCSV(*hosts), splitCSV(*pgHosts), *leafTTL)
	if err != nil {
		return cmdResult{}, err
	}
	return cmdResult{
		Message: fmt.Sprintf("initialized PKI in %s (server=%s, postgres=%s)", res.PKIDir, res.ServerCert.SerialHex, res.PostgresCert.SerialHex),
		Data:    res,
	}, nil
}

func cmdIssueCert(args []string) (cmdResult, error) {
	fs := newFlagSet("issue-cert")
	pkiDir := fs.String("pki-dir", "", "PKI directory")
	cn := fs.String("cn", "", "certificate common name")
	roleStr := fs.String("role", "client", "certificate role (client|server|postgres)")
	hosts := fs.String("hosts", "", "comma-separated SANs for server/postgres certs")
	ttl := fs.Duration("ttl", 0, "certificate TTL (default 24h client, 7d server/postgres)")
	_ = fs.Bool("json", false, "emit JSON output")
	if err := parseFlags(fs, args); err != nil {
		return cmdResult{}, err
	}
	if *pkiDir == "" || *cn == "" {
		return cmdResult{}, contract.NewError(contract.ExitUsage, "USAGE", "--pki-dir and --cn are required", nil)
	}
	role, err := mtls.ParseRole(*roleStr)
	if err != nil {
		return cmdResult{}, err
	}
	issued, err := mtls.IssueCert(*pkiDir, *cn, role, splitCSV(*hosts), *ttl)
	if err != nil {
		return cmdResult{}, err
	}
	return cmdResult{
		Message: fmt.Sprintf("issued %s certificate for %s (serial=%s)", issued.Role, issued.CommonName, issued.SerialHex),
		Data:    issued,
	}, nil
}

func cmdRevoke(args []string) (cmdResult, error) {
	fs := newFlagSet("revoke")
	pkiDir := fs.String("pki-dir", "", "PKI directory")
	serial := fs.String("serial", "", "hex serial number to revoke")
	reasonStr := fs.String("reason", "key_compromise", "revocation reason")
	_ = fs.Bool("json", false, "emit JSON output")
	if err := parseFlags(fs, args); err != nil {
		return cmdResult{}, err
	}
	if *pkiDir == "" || *serial == "" {
		return cmdResult{}, contract.NewError(contract.ExitUsage, "USAGE", "--pki-dir and --serial are required", nil)
	}
	reasonCode, err := mtls.ParseReason(*reasonStr)
	if err != nil {
		return cmdResult{}, err
	}

	caCert, caKey, err := mtls.LoadCA(*pkiDir)
	if err != nil {
		return cmdResult{}, err
	}
	crl, err := mtls.OpenCRLManager(caCert, caKey, filepath.Join(*pkiDir, "ca.crl"))
	if err != nil {
		return cmdResult{}, err
	}
	canonical, err := crl.Revoke(*serial, reasonCode)
	if err != nil {
		return cmdResult{}, err
	}
	data := map[string]any{
		"serial_hex": canonical,
		"reason":     *reasonStr,
		"crl_path":   filepath.Join(*pkiDir, "ca.crl"),
	}
	return cmdResult{
		Message: fmt.Sprintf("revoked serial %s (%s)", canonical, *reasonStr),
		Data:    data,
	}, nil
}

func cmdSeal(args []string, stdin io.Reader, stdout io.Writer) (cmdResult, error) {
	fs := newFlagSet("seal")
	keyPath := fs.String("key", "", "vault directory or 32-byte key file")
	aad := fs.String("aad", "", "associated authenticated data context")
	inPath := fs.String("in", "", "input file path or '-' for stdin")
	outPath := fs.String("out", "", "optional output file path")
	algName := fs.String("alg", "xchacha20", "AEAD algorithm (xchacha20|aes256gcm)")
	streamMode := fs.Bool("stream", false, "use SHUNAS1 chunked streaming AEAD")
	passEnv := fs.String("passphrase-env", "", "env var holding vault passphrase (when --key is a vault dir)")
	strictMlock := fs.Bool("strict-mlock", false, "fail closed if mlock fails")
	jsonFlag := fs.Bool("json", false, "emit JSON output")
	if err := parseFlags(fs, args); err != nil {
		return cmdResult{}, err
	}
	if *keyPath == "" || *inPath == "" {
		return cmdResult{}, contract.NewError(contract.ExitUsage, "USAGE", "--key and --in are required", nil)
	}
	algExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "alg" {
			algExplicit = true
		}
	})
	alg, err := envelope.ParseAlg(*algName)
	if err != nil {
		return cmdResult{}, contract.NewError(contract.ExitUsage, "USAGE", err.Error(), err)
	}
	if *streamMode && algExplicit && alg != envelope.AlgXChaCha20Poly1305 {
		return cmdResult{}, contract.NewError(contract.ExitUsage, "USAGE", "SHUNAS1 streaming mode requires xchacha20", nil)
	}
	if *streamMode && *jsonFlag && *outPath == "" {
		return cmdResult{}, contract.NewError(contract.ExitUsage, "USAGE", "--stream with --json requires --out <file>", nil)
	}

	vaultAlg := byte(0)
	if algExplicit {
		vaultAlg = alg
	}
	v, rawKey, err := loadKeyOrVault(*keyPath, *passEnv, *strictMlock, vaultAlg)
	if err != nil {
		return cmdResult{}, err
	}
	if v != nil {
		defer v.Zeroize()
	}
	if rawKey != nil {
		defer func() {
			kdf.WipeBytes(rawKey)
			_ = kdf.UnlockSensitiveMemory(rawKey)
		}()
	}

	inReader, closeIn, err := openInput(*inPath, stdin)
	if err != nil {
		return cmdResult{}, err
	}
	defer closeIn()

	if *streamMode {
		if *outPath != "" {
			if err := writeStreamToFile(*outPath, 0644, func(w io.Writer) error {
				if v != nil {
					return v.SealStream(inReader, w, []byte(*aad))
				}
				return envelope.SealStream(inReader, w, rawKey, []byte(*aad))
			}); err != nil {
				return cmdResult{}, err
			}
			return cmdResult{
				Message: fmt.Sprintf("sealed stream to %s", *outPath),
				Data:    map[string]any{"mode": "stream", "format": envelope.StreamMagic, "out": *outPath},
			}, nil
		}
		if v != nil {
			err = v.SealStream(inReader, stdout, []byte(*aad))
		} else {
			err = envelope.SealStream(inReader, stdout, rawKey, []byte(*aad))
		}
		return cmdResult{}, err
	}

	plaintext, err := io.ReadAll(inReader)
	if err != nil {
		return cmdResult{}, fmt.Errorf("read input: %w", err)
	}
	defer kdf.WipeBytes(plaintext)

	var blob []byte
	usedAlg := alg
	if v != nil {
		usedAlg = v.Algorithm()
		blob, err = v.Encrypt([]byte(*aad), plaintext)
	} else {
		blob, err = envelope.Seal(alg, 1, rawKey, []byte(*aad), plaintext)
	}
	if err != nil {
		return cmdResult{}, err
	}
	if len(blob) > 6 {
		usedAlg = blob[6]
	}

	if *outPath != "" {
		if err := os.WriteFile(*outPath, blob, 0644); err != nil {
			return cmdResult{}, fmt.Errorf("write output: %w", err)
		}
		return cmdResult{
			Message: fmt.Sprintf("sealed %d bytes to %s", len(blob), *outPath),
			Data: map[string]any{
				"format":    envelope.Magic,
				"algorithm": envelope.AlgName(usedAlg),
				"bytes":     len(blob),
				"out":       *outPath,
			},
		}, nil
	}

	if *jsonFlag {
		return cmdResult{
			Message: "sealed envelope",
			Data: map[string]any{
				"format":         envelope.Magic,
				"algorithm":      envelope.AlgName(usedAlg),
				"bytes":          len(blob),
				"ciphertext_b64": base64.StdEncoding.EncodeToString(blob),
			},
		}, nil
	}

	return cmdResult{RawOut: blob}, nil
}

func cmdUnseal(args []string, stdin io.Reader, stdout io.Writer) (cmdResult, error) {
	fs := newFlagSet("unseal")
	keyPath := fs.String("key", "", "vault directory or 32-byte key file")
	aad := fs.String("aad", "", "associated authenticated data context")
	inPath := fs.String("in", "", "input file path or '-' for stdin")
	outPath := fs.String("out", "", "optional output file path")
	streamMode := fs.Bool("stream", false, "use SHUNAS1 chunked streaming AEAD")
	passEnv := fs.String("passphrase-env", "", "env var holding vault passphrase (when --key is a vault dir)")
	strictMlock := fs.Bool("strict-mlock", false, "fail closed if mlock fails")
	jsonFlag := fs.Bool("json", false, "emit JSON output")
	if err := parseFlags(fs, args); err != nil {
		return cmdResult{}, err
	}
	if *keyPath == "" || *inPath == "" {
		return cmdResult{}, contract.NewError(contract.ExitUsage, "USAGE", "--key and --in are required", nil)
	}
	if *streamMode && *jsonFlag && *outPath == "" {
		return cmdResult{}, contract.NewError(contract.ExitUsage, "USAGE", "--stream with --json requires --out <file>", nil)
	}

	v, rawKey, err := loadKeyOrVault(*keyPath, *passEnv, *strictMlock, 0)
	if err != nil {
		return cmdResult{}, err
	}
	if v != nil {
		defer v.Zeroize()
	}
	if rawKey != nil {
		defer func() {
			kdf.WipeBytes(rawKey)
			_ = kdf.UnlockSensitiveMemory(rawKey)
		}()
	}

	inReader, closeIn, err := openInput(*inPath, stdin)
	if err != nil {
		return cmdResult{}, err
	}
	defer closeIn()

	if *streamMode {
		if *outPath != "" {
			if err := writeStreamToFile(*outPath, 0600, func(w io.Writer) error {
				if v != nil {
					return v.UnsealStream(inReader, w, []byte(*aad))
				}
				return envelope.UnsealStream(inReader, w, rawKey, []byte(*aad))
			}); err != nil {
				return cmdResult{}, err
			}
			return cmdResult{
				Message: fmt.Sprintf("unsealed stream to %s", *outPath),
				Data:    map[string]any{"mode": "stream", "format": envelope.StreamMagic, "out": *outPath},
			}, nil
		}
		if v != nil {
			err = v.UnsealStream(inReader, stdout, []byte(*aad))
		} else {
			err = envelope.UnsealStream(inReader, stdout, rawKey, []byte(*aad))
		}
		return cmdResult{}, err
	}

	blob, err := io.ReadAll(inReader)
	if err != nil {
		return cmdResult{}, fmt.Errorf("read ciphertext: %w", err)
	}

	var plaintext []byte
	var keyVer uint32 = 1
	if v != nil {
		hdr, hdrErr := envelope.InspectHeader(blob)
		if hdrErr != nil {
			return cmdResult{}, hdrErr
		}
		keyVer = hdr.KeyVersion
		plaintext, err = v.Decrypt([]byte(*aad), blob)
	} else {
		plaintext, keyVer, err = envelope.Open(rawKey, []byte(*aad), blob)
	}
	if err != nil {
		return cmdResult{}, err
	}
	defer kdf.WipeBytes(plaintext)

	if *outPath != "" {
		if err := os.WriteFile(*outPath, plaintext, 0600); err != nil {
			return cmdResult{}, fmt.Errorf("write output: %w", err)
		}
		return cmdResult{
			Message: fmt.Sprintf("unsealed %d bytes to %s", len(plaintext), *outPath),
			Data:    map[string]any{"key_version": keyVer, "bytes": len(plaintext), "out": *outPath},
		}, nil
	}

	if *jsonFlag {
		return cmdResult{
			Message: "unsealed envelope",
			Data: map[string]any{
				"key_version":   keyVer,
				"bytes":         len(plaintext),
				"plaintext_b64": base64.StdEncoding.EncodeToString(plaintext),
			},
		}, nil
	}

	outCopy := append([]byte(nil), plaintext...)
	return cmdResult{RawOut: outCopy}, nil
}

func cmdRotate(args []string) (cmdResult, error) {
	fs := newFlagSet("rotate")
	vaultDir := fs.String("vault", "", "vault directory")
	passEnv := fs.String("passphrase-env", "", "env var holding current vault passphrase")
	newPassEnv := fs.String("new-passphrase-env", "", "optional env var holding new passphrase")
	retireOld := fs.Bool("retire-old", false, "immediately retire previous active key version")
	strictMlock := fs.Bool("strict-mlock", false, "fail closed if mlock fails")
	_ = fs.Bool("json", false, "emit JSON output")
	if err := parseFlags(fs, args); err != nil {
		return cmdResult{}, err
	}
	if *vaultDir == "" {
		return cmdResult{}, contract.NewError(contract.ExitUsage, "USAGE", "--vault is required", nil)
	}

	pass, err := resolvePassphrase(*passEnv, true)
	if err != nil {
		return cmdResult{}, err
	}
	defer kdf.WipeBytes(pass)

	newPass := append([]byte(nil), pass...)
	if *newPassEnv != "" {
		np, err := resolvePassphrase(*newPassEnv, true)
		if err != nil {
			kdf.WipeBytes(newPass)
			return cmdResult{}, err
		}
		kdf.WipeBytes(newPass)
		newPass = np
	}
	defer kdf.WipeBytes(newPass)

	v, err := vault.OpenVault(*vaultDir, vault.Options{StrictMlock: *strictMlock})
	if err != nil {
		return cmdResult{}, err
	}
	defer v.Zeroize()

	if err := v.Unlock(pass); err != nil {
		return cmdResult{}, err
	}

	oldVer := v.ActiveKeyVersion()
	newVer, err := v.RotatePrepare(newPass)
	if err != nil {
		return cmdResult{}, err
	}
	if *retireOld {
		if err := v.RetireKey(oldVer); err != nil {
			return cmdResult{}, err
		}
	}

	return cmdResult{
		Message: fmt.Sprintf("rotated vault key %d -> %d (retired_old=%v)", oldVer, newVer, *retireOld),
		Data: map[string]any{
			"previous_version": oldVer,
			"active_version":   newVer,
			"retired_old":      *retireOld,
		},
	}, nil
}

func cmdVerify(args []string) (cmdResult, error) {
	fs := newFlagSet("verify")
	pkiDir := fs.String("pki-dir", "", "PKI directory")
	certPath := fs.String("cert", "", "optional specific certificate path to verify")
	_ = fs.Bool("json", false, "emit JSON output")
	if err := parseFlags(fs, args); err != nil {
		return cmdResult{}, err
	}
	if *pkiDir == "" {
		return cmdResult{}, contract.NewError(contract.ExitUsage, "USAGE", "--pki-dir is required", nil)
	}

	report, err := mtls.VerifyPKI(*pkiDir, *certPath)
	msg := ""
	if report != nil {
		msg = fmt.Sprintf("verified PKI in %s (%d cert(s), %d revoked)", *pkiDir, len(report.Certificates), report.RevokedCount)
	}
	return cmdResult{
		Message: msg,
		Data:    report,
	}, err
}

func cmdUnlockReset(args []string) (cmdResult, error) {
	fs := newFlagSet("unlock-reset")
	vaultDir := fs.String("vault", "", "vault directory")
	recKeyPath := fs.String("recovery-key", "", "path to offline ML-KEM-1024+X25519 recovery.key")
	newPassEnv := fs.String("new-passphrase-env", "", "optional env var to set a new vault passphrase")
	strictMlock := fs.Bool("strict-mlock", false, "fail closed if mlock fails")
	_ = fs.Bool("json", false, "emit JSON output")
	if err := parseFlags(fs, args); err != nil {
		return cmdResult{}, err
	}
	if *vaultDir == "" || *recKeyPath == "" {
		return cmdResult{}, contract.NewError(contract.ExitUsage, "USAGE", "--vault and --recovery-key are required", nil)
	}

	var newPass []byte
	if *newPassEnv != "" {
		var err error
		newPass, err = resolvePassphrase(*newPassEnv, true)
		if err != nil {
			return cmdResult{}, err
		}
		defer kdf.WipeBytes(newPass)
	}

	recPriv, err := pqc.LoadRecoveryPrivateKey(*recKeyPath)
	if err != nil {
		return cmdResult{}, err
	}
	defer recPriv.Zeroize()

	v, err := vault.OpenVault(*vaultDir, vault.Options{StrictMlock: *strictMlock})
	if err != nil {
		return cmdResult{}, err
	}
	defer v.Zeroize()

	if err := v.UnlockWithRecoveryKey(recPriv, newPass); err != nil {
		return cmdResult{}, err
	}

	return cmdResult{
		Message: fmt.Sprintf("lockout reset and vault unlocked (active_version=%d)", v.ActiveKeyVersion()),
		Data: map[string]any{
			"vault_dir":      *vaultDir,
			"active_version": v.ActiveKeyVersion(),
			"lockout_reset":  true,
		},
	}, nil
}

func loadKeyOrVault(path, passEnv string, strictMlock bool, alg byte) (*vault.Vault, []byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, contract.NewError(contract.ExitMissing, "MISSING", fmt.Sprintf("key path not found: %s", path), err)
		}
		return nil, nil, err
	}

	if info.IsDir() || filepath.Base(path) == vault.VaultFileName {
		dir := path
		if !info.IsDir() {
			dir = filepath.Dir(path)
		}
		v, err := vault.OpenVault(dir, vault.Options{Algorithm: alg, StrictMlock: strictMlock})
		if err != nil {
			return nil, nil, err
		}
		pass, err := resolvePassphrase(passEnv, true)
		if err != nil {
			return nil, nil, err
		}
		defer kdf.WipeBytes(pass)

		if err := v.Unlock(pass); err != nil {
			v.Zeroize()
			return nil, nil, err
		}
		return v, nil, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	key, err := parseRawKeyBytes(raw)
	kdf.WipeBytes(raw)
	if err != nil {
		return nil, nil, err
	}
	if _, err := kdf.LockSensitiveMemory(key, strictMlock); err != nil {
		kdf.WipeBytes(key)
		return nil, nil, contract.NewError(contract.ExitPolicyStop, "POLICY_STOP", "strict mlock failed", err)
	}
	return nil, key, nil
}

func parseRawKeyBytes(raw []byte) ([]byte, error) {
	if len(raw) == envelope.KeySize {
		out := make([]byte, envelope.KeySize)
		copy(out, raw)
		return out, nil
	}
	trimmed := string(bytes.TrimSpace(raw))
	if decoded, err := hex.DecodeString(trimmed); err == nil && len(decoded) == envelope.KeySize {
		return decoded, nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(decoded) == envelope.KeySize {
		return decoded, nil
	}
	return nil, contract.NewError(contract.ExitUsage, "USAGE", "key file must be 32 raw bytes, 64 hex chars, or base64-encoded 32 bytes", nil)
}

func openInput(inPath string, stdin io.Reader) (io.Reader, func(), error) {
	if inPath == "-" {
		return stdin, func() {}, nil
	}
	f, err := os.Open(inPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, func() {}, contract.NewError(contract.ExitMissing, "MISSING", fmt.Sprintf("input file not found: %s", inPath), err)
		}
		return nil, func() {}, err
	}
	return f, func() { _ = f.Close() }, nil
}

func writeStreamToFile(outPath string, perm os.FileMode, fn func(io.Writer) error) error {
	dir := filepath.Dir(outPath)
	tmp, err := os.CreateTemp(dir, ".shuna-stream-*")
	if err != nil {
		return fmt.Errorf("create temp output: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if err := fn(tmp); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, outPath); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `shuna - post-quantum hybrid cryptography, envelope encryption, and mTLS 1.3 PKI

Usage:
  shuna keygen       --out <dir> [--passphrase-env VAR] [--strict-mlock] [--strict-lockout-wipe] [--alg xchacha20|aes256gcm] [--json]
  shuna init-pki     --out <dir> [--hosts 127.0.0.1,localhost] [--pg-hosts postgres,127.0.0.1] [--leaf-ttl 24h] [--json]
  shuna issue-cert   --pki-dir <dir> --cn <name> --role client|server|postgres [--hosts ...] [--ttl 24h] [--json]
  shuna revoke       --pki-dir <dir> --serial <hex> [--reason key_compromise] [--json]
  shuna seal         --key <path> --aad <context> --in <file|-> [--out <file>] [--alg xchacha20|aes256gcm] [--stream] [--passphrase-env VAR] [--strict-mlock] [--json]
  shuna unseal       --key <path> --aad <context> --in <file|-> [--out <file>] [--stream] [--passphrase-env VAR] [--strict-mlock] [--json]
  shuna rotate       --vault <dir> [--passphrase-env VAR] [--new-passphrase-env VAR] [--retire-old] [--strict-mlock] [--json]
  shuna verify       --pki-dir <dir> [--cert <path>] [--json]
  shuna unlock-reset --vault <dir> --recovery-key <path> [--new-passphrase-env VAR] [--strict-mlock] [--json]
  shuna version      [--json]  (aliases: --version, -V)

Exit codes:
  0  OK
  1  USAGE
  2  POLICY_STOP / LOCKED / REVOKED
  3  MISSING
  4  CORRUPT_CIPHERTEXT`)
}
