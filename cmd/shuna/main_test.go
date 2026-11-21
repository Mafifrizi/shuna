package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mafifrizi/shuna/pkg/contract"
)

func runInProc(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, bytes.NewReader(nil), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestVersionFlagsAndJSON(t *testing.T) {
	for _, flagArg := range []string{"--version", "-V", "version"} {
		code, out, errOut := runInProc(flagArg)
		if code != contract.ExitOK {
			t.Fatalf("%s exit = %d, want 0 (stderr=%s)", flagArg, code, errOut)
		}
		if out != "shuna "+version+"\n" {
			t.Fatalf("%s stdout = %q, want %q", flagArg, out, "shuna "+version+"\n")
		}

		code, out, errOut = runInProc(flagArg, "--json")
		if code != contract.ExitOK {
			t.Fatalf("%s --json exit = %d, want 0 (stderr=%s)", flagArg, code, errOut)
		}
		var env struct {
			OK      bool   `json:"ok"`
			Code    int    `json:"code"`
			Status  string `json:"status"`
			Message string `json:"message"`
			Data    struct {
				Version string `json:"version"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(out), &env); err != nil {
			t.Fatalf("%s --json unmarshal: %v (%s)", flagArg, err, out)
		}
		if !env.OK || env.Code != 0 || env.Status != "OK" || env.Data.Version != version {
			t.Fatalf("%s --json unexpected envelope: %+v", flagArg, env)
		}
	}

	if code, _, _ := runInProc("--version", "--bogus"); code != contract.ExitUsage {
		t.Fatalf("--version --bogus exit = %d, want 1", code)
	}
	if code, _, _ := runInProc("version", "extra"); code != contract.ExitUsage {
		t.Fatalf("version extra exit = %d, want 1", code)
	}
	code, out, _ := runInProc("--version", "--bogus", "--json")
	if code != contract.ExitUsage {
		t.Fatalf("--version --bogus --json exit = %d, want 1", code)
	}
	var errEnv contract.Envelope
	if err := json.Unmarshal([]byte(out), &errEnv); err != nil || errEnv.OK || errEnv.Code != contract.ExitUsage {
		t.Fatalf("unexpected error JSON envelope: %s (%v)", out, err)
	}
}

func TestHelpAndUnknownSubcommands(t *testing.T) {
	if code, _, errOut := runInProc(); code != contract.ExitUsage || !strings.Contains(errOut, "Usage:") {
		t.Fatalf("empty args: code=%d stderr=%q", code, errOut)
	}
	for _, h := range []string{"--help", "-h", "help"} {
		code, out, _ := runInProc(h)
		if code != contract.ExitOK || !strings.Contains(out, "Usage:") {
			t.Fatalf("%s: code=%d stdout=%q", h, code, out)
		}
	}
	code, _, errOut := runInProc("nope")
	if code != contract.ExitUsage || !strings.Contains(errOut, "unknown subcommand") {
		t.Fatalf("unknown cmd: code=%d stderr=%q", code, errOut)
	}
	code, out, _ := runInProc("nope", "--json")
	if code != contract.ExitUsage {
		t.Fatalf("unknown cmd --json code=%d, want 1", code)
	}
	var env contract.Envelope
	if err := json.Unmarshal([]byte(out), &env); err != nil || env.OK || env.Status != "USAGE" {
		t.Fatalf("unknown cmd --json envelope=%s err=%v", out, err)
	}
}

func TestRequiredFlagsAndStreamValidation(t *testing.T) {
	cases := [][]string{
		{"keygen"},
		{"init-pki"},
		{"issue-cert"},
		{"issue-cert", "--pki-dir", "/tmp/pki"},
		{"revoke"},
		{"seal"},
		{"unseal"},
		{"rotate"},
		{"verify"},
		{"unlock-reset"},
		{"seal", "--key", "k", "--in", "-", "--stream", "--alg", "aes256gcm"},
		{"seal", "--key", "k", "--in", "-", "--stream", "--json"},
		{"unseal", "--key", "k", "--in", "-", "--stream", "--json"},
	}
	for _, args := range cases {
		if code, _, _ := runInProc(args...); code != contract.ExitUsage {
			t.Fatalf("%v exit = %d, want %d", args, code, contract.ExitUsage)
		}
	}
}

func TestParseRawKeyBytes(t *testing.T) {
	raw := bytes.Repeat([]byte{0xab}, 32)
	got, err := parseRawKeyBytes(raw)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("raw parse failed: %v", err)
	}

	hexIn := []byte("  " + hex.EncodeToString(raw) + "\n")
	got, err = parseRawKeyBytes(hexIn)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("hex parse failed: %v", err)
	}

	b64In := []byte(base64.StdEncoding.EncodeToString(raw) + "\r\n")
	got, err = parseRawKeyBytes(b64In)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("base64 parse failed: %v", err)
	}

	if _, err := parseRawKeyBytes([]byte("too-short")); contract.CodeOf(err) != contract.ExitUsage {
		t.Fatalf("invalid key code = %d, want 1", contract.CodeOf(err))
	}
}

func TestCLIReservedPKINamesExitCodes(t *testing.T) {
	pkiDir := filepath.Join(t.TempDir(), "pki")
	if code, _, errOut := runInProc("init-pki", "--out", pkiDir, "--json"); code != contract.ExitOK {
		t.Fatalf("init-pki exit=%d stderr=%s", code, errOut)
	}

	for _, cn := range []string{"ca", "CA", "server", "SERVER", "pg-server", "ca.crl", "server.crt"} {
		code, out, _ := runInProc("issue-cert", "--pki-dir", pkiDir, "--cn", cn, "--role", "client", "--json")
		if code != contract.ExitPolicyStop {
			t.Fatalf("issue-cert --cn %q exit = %d, want %d (out=%s)", cn, code, contract.ExitPolicyStop, out)
		}
	}
	for _, cn := range []string{"../evil", ".", "alice.crt"} {
		code, out, _ := runInProc("issue-cert", "--pki-dir", pkiDir, "--cn", cn, "--role", "client", "--json")
		if code != contract.ExitUsage {
			t.Fatalf("issue-cert unsafe --cn %q exit = %d, want %d (out=%s)", cn, code, contract.ExitUsage, out)
		}
	}
}
