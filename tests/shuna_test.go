package tests

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mafifrizi/shuna/pkg/contract"
	"github.com/Mafifrizi/shuna/pkg/envelope"
	"github.com/Mafifrizi/shuna/pkg/kdf"
	"github.com/Mafifrizi/shuna/pkg/mtls"
	"github.com/Mafifrizi/shuna/pkg/pqc"
	"github.com/Mafifrizi/shuna/pkg/vault"
)

func TestArgon2idHKDFWipeAndMlock(t *testing.T) {
	salt, err := kdf.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	if len(salt) != kdf.SaltLen {
		t.Fatalf("unexpected salt len %d", len(salt))
	}

	if _, err := kdf.DeriveMasterKey(nil, salt); !errors.Is(err, kdf.ErrInvalidPassphrase) {
		t.Fatalf("expected ErrInvalidPassphrase, got %v", err)
	}
	if _, err := kdf.DeriveMasterKey([]byte("pass"), []byte("short")); !errors.Is(err, kdf.ErrInvalidSalt) {
		t.Fatalf("expected ErrInvalidSalt, got %v", err)
	}

	mk1, err := kdf.DeriveMasterKey([]byte("correct-horse-battery-staple"), salt)
	if err != nil {
		t.Fatalf("DeriveMasterKey 1: %v", err)
	}
	mk2, err := kdf.DeriveMasterKey([]byte("correct-horse-battery-staple"), salt)
	if err != nil {
		t.Fatalf("DeriveMasterKey 2: %v", err)
	}
	if !bytes.Equal(mk1, mk2) {
		t.Fatal("Argon2id output not deterministic for identical passphrase and salt")
	}

	infos := []string{kdf.InfoKEK, kdf.InfoDEK, kdf.InfoBlindIndex, kdf.InfoStream, kdf.InfoHybridKEK}
	seen := make(map[string]bool)
	for _, info := range infos {
		sub, err := kdf.DeriveSubkey(mk1, salt, info, 32)
		if err != nil {
			t.Fatalf("DeriveSubkey(%s): %v", info, err)
		}
		if len(sub) != 32 {
			t.Fatalf("subkey len = %d, want 32", len(sub))
		}
		if seen[string(sub)] {
			t.Fatalf("HKDF domain collision for %s", info)
		}
		seen[string(sub)] = true
		kdf.WipeBytes(sub)
		for _, b := range sub {
			if b != 0 {
				t.Fatalf("WipeBytes failed to zero subkey for %s", info)
			}
		}
	}

	if runtime.GOOS == "linux" {
		warn, err := kdf.LockSensitiveMemory(mk1, true)
		if err != nil {
			t.Fatalf("strict LockSensitiveMemory failed on Linux: %v", err)
		}
		if warn != "" {
			t.Fatalf("expected empty warning on strict LockSensitiveMemory success, got %q", warn)
		}
	} else {
		if _, err := kdf.LockSensitiveMemory(mk1, false); err != nil {
			t.Fatalf("non-strict LockSensitiveMemory failed: %v", err)
		}
	}
	kdf.WipeBytes(mk1)
	if err := kdf.UnlockSensitiveMemory(mk1); err != nil {
		t.Fatalf("UnlockSensitiveMemory failed: %v", err)
	}
	kdf.WipeBytes(mk2)
}

func TestSHUNA1RoundTripAndStrictNonceInvariant(t *testing.T) {
	key := make([]byte, envelope.KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}
	aad := []byte("hosts|host_01|1|1")
	plaintexts := [][]byte{
		{},
		[]byte("short"),
		bytes.Repeat([]byte("shuna-pqc-aead-"), 100),
	}

	for _, alg := range []byte{envelope.AlgXChaCha20Poly1305, envelope.AlgAES256GCM} {
		for _, pt := range plaintexts {
			blob, err := envelope.Seal(alg, 7, key, aad, pt)
			if err != nil {
				t.Fatalf("Seal(alg=0x%02x): %v", alg, err)
			}
			if string(blob[:6]) != envelope.Magic || blob[6] != alg {
				t.Fatalf("unexpected header: magic=%q alg=0x%02x", blob[:6], blob[6])
			}
			if kv := binary.BigEndian.Uint32(blob[7:11]); kv != 7 {
				t.Fatalf("keyVersion = %d, want 7", kv)
			}

			got, gotKV, err := envelope.Open(key, aad, blob)
			if err != nil {
				t.Fatalf("Open(alg=0x%02x): %v", alg, err)
			}
			if gotKV != 7 || !bytes.Equal(got, pt) {
				t.Fatalf("roundtrip mismatch: kv=%d len=%d", gotKV, len(got))
			}

			// Wrong AAD -> exit 4
			if _, _, err := envelope.Open(key, []byte("wrong-aad"), blob); contract.CodeOf(err) != contract.ExitCorruptCiphertext {
				t.Fatalf("wrong AAD code = %d, want 4 (%v)", contract.CodeOf(err), err)
			}

			// Tampered KeyVersion -> exit 4
			badKV := append([]byte(nil), blob...)
			badKV[10] ^= 0x01
			if _, _, err := envelope.Open(key, aad, badKV); contract.CodeOf(err) != contract.ExitCorruptCiphertext {
				t.Fatalf("tampered KeyVersion code = %d, want 4", contract.CodeOf(err))
			}

			// Tampered ciphertext -> exit 4
			badCT := append([]byte(nil), blob...)
			badCT[len(badCT)-1] ^= 0x80
			if _, _, err := envelope.Open(key, aad, badCT); contract.CodeOf(err) != contract.ExitCorruptCiphertext {
				t.Fatalf("tampered CT code = %d, want 4", contract.CodeOf(err))
			}
		}
	}

	// Strict AlgID-First Nonce Parsing Invariant for AES-256-GCM:
	// Any non-zero byte in blob[23:35] MUST fail with CORRUPT_CIPHERTEXT (exit 4).
	gcmBlob, err := envelope.Seal(envelope.AlgAES256GCM, 1, key, aad, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 23; i < 35; i++ {
		if gcmBlob[i] != 0 {
			t.Fatalf("expected 0x00 at pad offset %d, got 0x%02x", i, gcmBlob[i])
		}
		tampered := append([]byte(nil), gcmBlob...)
		tampered[i] = 0x01
		if _, _, err := envelope.Open(key, aad, tampered); contract.CodeOf(err) != contract.ExitCorruptCiphertext {
			t.Fatalf("non-zero GCM pad at %d returned exit %d, want 4", i, contract.CodeOf(err))
		}
	}

	// Unknown AlgID -> exit 4
	badAlg := append([]byte(nil), gcmBlob...)
	badAlg[6] = 0x7f
	if _, _, err := envelope.Open(key, aad, badAlg); contract.CodeOf(err) != contract.ExitCorruptCiphertext {
		t.Fatalf("unknown AlgID returned exit %d, want 4", contract.CodeOf(err))
	}
}

func TestSHUNAS1StreamingRoundTripAndTampering(t *testing.T) {
	key := make([]byte, envelope.KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}
	aad := []byte("pg_dump|cluster-alpha")

	// Empty stream, exact chunk size, and multi-chunk non-aligned streams.
	cases := []struct {
		name      string
		size      int
		chunkSize uint32
	}{
		{"empty", 0, 4096},
		{"exact_one_chunk", 4096, 4096},
		{"multi_chunk_exact", 4096 * 3, 4096},
		{"multi_chunk_unaligned", 4096*3 + 313, 4096},
		{"default_64k_multi", 65536*2 + 777, envelope.DefaultStreamChunkSize},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pt := make([]byte, tc.size)
			if tc.size > 0 {
				if _, err := io.ReadFull(rand.Reader, pt); err != nil {
					t.Fatal(err)
				}
			}

			var sealed bytes.Buffer
			if err := envelope.SealStreamWithOptions(bytes.NewReader(pt), &sealed, key, 2, tc.chunkSize, aad); err != nil {
				t.Fatalf("SealStream: %v", err)
			}

			var unsealed bytes.Buffer
			if err := envelope.UnsealStream(bytes.NewReader(sealed.Bytes()), &unsealed, key, aad); err != nil {
				t.Fatalf("UnsealStream: %v", err)
			}
			if !bytes.Equal(unsealed.Bytes(), pt) {
				t.Fatalf("plaintext mismatch: got %d bytes, want %d", unsealed.Len(), len(pt))
			}

			// Wrong AAD must fail with exit 4.
			unsealed.Reset()
			if err := envelope.UnsealStream(bytes.NewReader(sealed.Bytes()), &unsealed, key, []byte("wrong")); contract.CodeOf(err) != contract.ExitCorruptCiphertext {
				t.Fatalf("wrong AAD code = %d, want 4", contract.CodeOf(err))
			}
		})
	}

	// Build a 3-chunk stream (chunkSize=4096, len=9000 -> chunks: 4096, 4096, 808) to test reordering, truncation, and trailing bytes.
	pt := bytes.Repeat([]byte("A"), 9000)
	var sealedBuf bytes.Buffer
	if err := envelope.SealStreamWithOptions(bytes.NewReader(pt), &sealedBuf, key, 1, 4096, aad); err != nil {
		t.Fatal(err)
	}
	raw := sealedBuf.Bytes()

	// Chunk 0 frame size = 5 + 4096 + 16 = 4117
	// Chunk 1 frame size = 5 + 4096 + 16 = 4117
	// Chunk 2 frame size = 5 + 808 + 16 = 829
	c0Start := envelope.StreamHeaderSize
	c1Start := c0Start + 5 + 4096 + 16
	c2Start := c1Start + 5 + 4096 + 16

	// 1. Reordering chunk 0 and chunk 1 must fail.
	reordered := make([]byte, 0, len(raw))
	reordered = append(reordered, raw[:c0Start]...)
	reordered = append(reordered, raw[c1Start:c2Start]...)
	reordered = append(reordered, raw[c0Start:c1Start]...)
	reordered = append(reordered, raw[c2Start:]...)
	if err := envelope.UnsealStream(bytes.NewReader(reordered), io.Discard, key, aad); contract.CodeOf(err) != contract.ExitCorruptCiphertext {
		t.Fatalf("reordered stream code = %d, want 4", contract.CodeOf(err))
	}

	// 2. Truncating before final chunk (premature EOF) must fail.
	if err := envelope.UnsealStream(bytes.NewReader(raw[:c2Start]), io.Discard, key, aad); contract.CodeOf(err) != contract.ExitCorruptCiphertext {
		t.Fatalf("truncated stream code = %d, want 4", contract.CodeOf(err))
	}

	// 3. Trailing bytes after final chunk must fail.
	withTrailing := append(append([]byte(nil), raw...), 0x00)
	if err := envelope.UnsealStream(bytes.NewReader(withTrailing), io.Discard, key, aad); contract.CodeOf(err) != contract.ExitCorruptCiphertext {
		t.Fatalf("trailing bytes code = %d, want 4", contract.CodeOf(err))
	}

	// 4. Bit-flip in chunk 1 ciphertext must fail.
	tampered := append([]byte(nil), raw...)
	tampered[c1Start+20] ^= 0xff
	if err := envelope.UnsealStream(bytes.NewReader(tampered), io.Discard, key, aad); contract.CodeOf(err) != contract.ExitCorruptCiphertext {
		t.Fatalf("tampered chunk code = %d, want 4", contract.CodeOf(err))
	}

	// 5. Duplicating chunk 0 in place of chunk 1 must fail.
	duplicated := make([]byte, 0, len(raw))
	duplicated = append(duplicated, raw[:c0Start]...)
	duplicated = append(duplicated, raw[c0Start:c1Start]...)
	duplicated = append(duplicated, raw[c0Start:c1Start]...)
	duplicated = append(duplicated, raw[c2Start:]...)
	if err := envelope.UnsealStream(bytes.NewReader(duplicated), io.Discard, key, aad); contract.CodeOf(err) != contract.ExitCorruptCiphertext {
		t.Fatalf("duplicated chunk code = %d, want 4", contract.CodeOf(err))
	}
}

func TestHybridMLKEM1024X25519WrapAndRecovery(t *testing.T) {
	priv, pub, err := pqc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	defer priv.Zeroize()

	ss1, kemCT, err := pqc.Encapsulate(pub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if len(kemCT) != pqc.HybridCiphertextSize {
		t.Fatalf("kemCT len = %d, want %d", len(kemCT), pqc.HybridCiphertextSize)
	}
	ss2, err := pqc.Decapsulate(priv, kemCT)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("hybrid shared secrets do not match")
	}

	dek := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, dek)
	aad := []byte("shuna:v1:admin-recovery|1")

	wrapped, ct, err := pqc.WrapKey(pub, dek, aad)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	unwrapped, err := pqc.UnwrapKey(priv, wrapped, ct, aad)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if !bytes.Equal(unwrapped, dek) {
		t.Fatal("unwrapped DEK mismatch")
	}

	// Wrong private key must fail.
	otherPriv, _, err := pqc.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer otherPriv.Zeroize()
	if _, err := pqc.UnwrapKey(otherPriv, wrapped, ct, aad); err == nil {
		t.Fatal("expected UnwrapKey with wrong private key to fail")
	}

	// Save & reload recovery keypair.
	dir := t.TempDir()
	pubPath, privPath, err := pqc.SaveRecoveryKeyPair(dir, priv, pub)
	if err != nil {
		t.Fatalf("SaveRecoveryKeyPair: %v", err)
	}
	loadedPub, err := pqc.LoadRecoveryPublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadRecoveryPublicKey: %v", err)
	}
	loadedPriv, err := pqc.LoadRecoveryPrivateKey(privPath)
	if err != nil {
		t.Fatalf("LoadRecoveryPrivateKey: %v", err)
	}
	defer loadedPriv.Zeroize()

	if loadedPub.Fingerprint != pub.Fingerprint || loadedPriv.Fingerprint != priv.Fingerprint {
		t.Fatal("fingerprint mismatch after reload")
	}
	unwrapped2, err := pqc.UnwrapKey(loadedPriv, wrapped, ct, aad)
	if err != nil || !bytes.Equal(unwrapped2, dek) {
		t.Fatalf("UnwrapKey after reload failed: %v", err)
	}
}

func TestMTLSHandshakeX25519MLKEM768AndCRLRevocation(t *testing.T) {
	pkiDir := filepath.Join(t.TempDir(), "pki")
	res, err := mtls.InitPKI(pkiDir, []string{"127.0.0.1", "localhost"}, []string{"postgres", "127.0.0.1"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("InitPKI: %v", err)
	}

	clientCert, err := mtls.IssueCert(pkiDir, "operator-1", mtls.RoleClient, nil, 24*time.Hour)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// Verify 50% TTL renewal boundary.
	x509Client, err := mtls.LoadCertificate(clientCert.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	if mtls.NeedsRenewal(x509Client, x509Client.NotBefore.Add(time.Hour)) {
		t.Fatal("cert should not need renewal before 50% TTL")
	}
	if !mtls.NeedsRenewal(x509Client, x509Client.NotBefore.Add(13*time.Hour)) {
		t.Fatal("cert should need renewal after 50% TTL")
	}

	caCert, caKey, err := mtls.LoadCA(pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	crlMgr, err := mtls.OpenCRLManager(caCert, caKey, res.CRLPath)
	if err != nil {
		t.Fatal(err)
	}

	// Reload CRL from disk via an independent CRLManager instance (simulating separate server/CLI processes).
	serverSideCRL, err := mtls.LoadCRL(res.CRLPath, caCert)
	if err != nil {
		t.Fatalf("LoadCRL initial: %v", err)
	}

	srvTLS, err := mtls.ServerTLSConfig(res.ServerCert.CertPath, res.ServerCert.KeyPath, res.CACertPath, serverSideCRL, mtls.TLSOptions{})
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	cliTLS, err := mtls.ClientTLSConfig(clientCert.CertPath, clientCert.KeyPath, res.CACertPath, crlMgr, mtls.TLSOptions{ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvTLS)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc := c.(*tls.Conn)
				if err := tc.Handshake(); err == nil {
					_, _ = tc.Write([]byte("pong"))
				}
			}(conn)
		}
	}()

	// 1. Classical-only client (X25519 without X25519MLKEM768) MUST be rejected by strict PQC server.
	classicalOnlyTLS := cliTLS.Clone()
	classicalOnlyTLS.CurvePreferences = []tls.CurveID{tls.X25519}
	if badConn, err := tls.Dial("tcp", ln.Addr().String(), classicalOnlyTLS); err == nil {
		_ = badConn.Close()
		t.Fatal("expected strict X25519MLKEM768 server to reject classical-only X25519 client")
	}

	// 2. Valid X25519MLKEM768 mTLS handshake must negotiate TLS 1.3 and transfer data.
	conn, err := tls.Dial("tcp", ln.Addr().String(), cliTLS)
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	st := conn.ConnectionState()
	if st.Version != tls.VersionTLS13 {
		t.Fatalf("TLS version = 0x%04x, want TLS 1.3", st.Version)
	}
	if len(st.PeerCertificates) == 0 || st.PeerCertificates[0].Subject.CommonName != "server" {
		t.Fatalf("unexpected peer cert: %+v", st.PeerCertificates)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "pong" {
		t.Fatalf("mTLS read failed: %q err=%v", buf, err)
	}
	_ = conn.Close()

	// 3. Revoke client serial and verify immediate handshake rejection.
	if _, err := crlMgr.Revoke(clientCert.SerialHex, 1); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	conn2, err := tls.Dial("tcp", ln.Addr().String(), cliTLS)
	if err == nil {
		// Under TLS 1.3 server sends post-handshake alert or rejects during server handshake; reading triggers alert error.
		_, readErr := io.ReadFull(conn2, buf)
		_ = conn2.Close()
		if readErr == nil {
			t.Fatal("expected revoked client certificate connection to fail")
		}
	}

	// 3. Reload CRL from disk and verify VerifyPKI reports POLICY_STOP (exit 2).
	reloadedCRL, err := mtls.LoadCRL(res.CRLPath, caCert)
	if err != nil {
		t.Fatalf("LoadCRL: %v", err)
	}
	if !reloadedCRL.IsRevokedHex(clientCert.SerialHex) {
		t.Fatal("revoked serial missing after CRL reload")
	}

	report, verErr := mtls.VerifyPKI(pkiDir, clientCert.CertPath)
	if contract.CodeOf(verErr) != contract.ExitPolicyStop {
		t.Fatalf("VerifyPKI revoked code = %d, want 2 (%v)", contract.CodeOf(verErr), verErr)
	}
	if !report.CRLSigned || report.RevokedCount != 1 {
		t.Fatalf("unexpected VerifyReport: %+v", report)
	}

	_ = ln.Close()
	wg.Wait()

	// 4. Verify AllowClassicalFallback + ExtraRevokedCheck callback behavior.
	extraRevoked := false
	fbSrvTLS, err := mtls.ServerTLSConfig(res.ServerCert.CertPath, res.ServerCert.KeyPath, res.CACertPath, nil, mtls.TLSOptions{
		AllowClassicalFallback: true,
		ExtraRevokedCheck: func(serialHex string) bool {
			return extraRevoked && serialHex == clientCert.SerialHex
		},
	})
	if err != nil {
		t.Fatalf("fallback ServerTLSConfig: %v", err)
	}
	fbLn, err := tls.Listen("tcp", "127.0.0.1:0", fbSrvTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer fbLn.Close()
	go func() {
		for {
			c, err := fbLn.Accept()
			if err != nil {
				return
			}
			go func(nc net.Conn) {
				defer nc.Close()
				tc := nc.(*tls.Conn)
				if err := tc.Handshake(); err == nil {
					_, _ = tc.Write([]byte("ok"))
				}
			}(c)
		}
	}()

	if c, err := tls.Dial("tcp", fbLn.Addr().String(), classicalOnlyTLS); err != nil {
		t.Fatalf("classical fallback dial failed: %v", err)
	} else {
		var b [2]byte
		_, _ = io.ReadFull(c, b[:])
		_ = c.Close()
	}
	extraRevoked = true
	if c, err := tls.Dial("tcp", fbLn.Addr().String(), classicalOnlyTLS); err == nil {
		var b [2]byte
		_, rErr := io.ReadFull(c, b[:])
		_ = c.Close()
		if rErr == nil {
			t.Fatal("expected ExtraRevokedCheck to reject client")
		}
	}
}

func TestVaultDualReadRotationAndZeroize(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	v, _, err := vault.InitVault(dir, []byte("initial-pass"), vault.Options{})
	if err != nil {
		t.Fatalf("InitVault: %v", err)
	}

	if v.ActiveKeyVersion() != 1 {
		t.Fatalf("ActiveKeyVersion = %d, want 1", v.ActiveKeyVersion())
	}
	blindKey, err := v.DeriveBlindIndexKey()
	if err != nil || len(blindKey) != 32 {
		t.Fatalf("DeriveBlindIndexKey failed: len=%d err=%v", len(blindKey), err)
	}
	kdf.WipeBytes(blindKey)

	aad1 := []byte("hosts|h1|1|1")
	ct1, err := v.Encrypt(aad1, []byte("payload-v1"))
	if err != nil {
		t.Fatalf("Encrypt v1: %v", err)
	}

	// Re-initializing an existing vault directory must fail closed (preventing key destruction).
	if _, _, err := vault.InitVault(dir, []byte("overwrite-attempt"), vault.Options{}); contract.CodeOf(err) != contract.ExitPolicyStop {
		t.Fatalf("InitVault overwrite code = %d, want 2", contract.CodeOf(err))
	}

	newVer, err := v.RotatePrepare([]byte("rotated-pass"))
	if err != nil {
		t.Fatalf("RotatePrepare: %v", err)
	}
	if newVer != 2 || v.ActiveKeyVersion() != 2 {
		t.Fatalf("unexpected version after rotate: %d", newVer)
	}

	aad2 := []byte("hosts|h1|1|2")
	ct2, err := v.Encrypt(aad2, []byte("payload-v2"))
	if err != nil {
		t.Fatalf("Encrypt v2: %v", err)
	}

	// Dual-read across process restart (OpenVault + Unlock with rotated passphrase) before RetireKey.
	v.Zeroize()
	vReloaded, err := vault.OpenVault(dir, vault.Options{})
	if err != nil {
		t.Fatalf("OpenVault mid-rotation: %v", err)
	}
	if err := vReloaded.Unlock([]byte("rotated-pass")); err != nil {
		t.Fatalf("Unlock mid-rotation with rotated-pass: %v", err)
	}
	v = vReloaded

	// Dual-read: both v1 and v2 ciphertexts decrypt cleanly.
	pt1, err := v.Decrypt(aad1, ct1)
	if err != nil || string(pt1) != "payload-v1" {
		t.Fatalf("dual-read v1 failed: %q err=%v", pt1, err)
	}
	pt2, err := v.Decrypt(aad2, ct2)
	if err != nil || string(pt2) != "payload-v2" {
		t.Fatalf("dual-read v2 failed: %q err=%v", pt2, err)
	}

	// Non-zero AES-256-GCM nonce pad with unknown KeyVersion must still fail with CORRUPT_CIPHERTEXT (exit 4).
	badGCM := make([]byte, envelope.HeaderSize+envelope.TagSize)
	copy(badGCM[:6], envelope.Magic)
	badGCM[6] = envelope.AlgAES256GCM
	binary.BigEndian.PutUint32(badGCM[7:11], 999)
	badGCM[30] = 0x55
	if _, err := v.Decrypt(aad1, badGCM); contract.CodeOf(err) != contract.ExitCorruptCiphertext {
		t.Fatalf("malformed GCM unknown kv code = %d, want 4", contract.CodeOf(err))
	}

	// Retiring active key must fail closed.
	if err := v.RetireKey(2); contract.CodeOf(err) != contract.ExitPolicyStop {
		t.Fatalf("RetireKey(active) code = %d, want 2", contract.CodeOf(err))
	}

	// Retire old v1 key: v2 continues, v1 fails with MISSING.
	if err := v.RetireKey(1); err != nil {
		t.Fatalf("RetireKey(1): %v", err)
	}
	if _, err := v.Decrypt(aad1, ct1); contract.CodeOf(err) != contract.ExitMissing {
		t.Fatalf("Decrypt retired v1 code = %d, want 3", contract.CodeOf(err))
	}
	if pt2b, err := v.Decrypt(aad2, ct2); err != nil || string(pt2b) != "payload-v2" {
		t.Fatalf("v2 decrypt after retiring v1 failed: %v", err)
	}

	// Zeroize wipes RAM DEKs.
	v.Zeroize()
	if _, err := v.Encrypt(aad2, []byte("x")); !errors.Is(err, vault.ErrVaultLocked) {
		t.Fatalf("Encrypt after Zeroize = %v, want ErrVaultLocked", err)
	}
	if _, err := v.Decrypt(aad2, ct2); !errors.Is(err, vault.ErrVaultLocked) {
		t.Fatalf("Decrypt after Zeroize = %v, want ErrVaultLocked", err)
	}
}

func TestVaultBruteForceLockoutPersistenceAndStrictWipe(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	var sleeps []time.Duration

	opts := vault.Options{
		Now: func() time.Time { return now },
		Sleep: func(d time.Duration) {
			sleeps = append(sleeps, d)
			now = now.Add(d)
		},
	}

	dir := filepath.Join(t.TempDir(), "vault-lockout")
	v, _, err := vault.InitVault(dir, []byte("valid-pass"), opts)
	if err != nil {
		t.Fatalf("InitVault: %v", err)
	}
	v.Zeroize()

	// 4 wrong attempts -> backoff sequence [1s, 2s, 4s, 8s] enforced before attempts 2, 3, 4, 5.
	for i := 0; i < 4; i++ {
		err := v.Unlock([]byte("wrong-pass"))
		if contract.CodeOf(err) != contract.ExitPolicyStop {
			t.Fatalf("attempt %d exit code = %d, want 2", i+1, contract.CodeOf(err))
		}
	}

	// Reload vault from disk (simulates server restart) -> failure count MUST persist.
	vReloaded, err := vault.OpenVault(dir, opts)
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	st, err := vReloaded.LockoutStatus()
	if err != nil || st.FailedAttempts != 4 {
		t.Fatalf("persisted FailedAttempts = %d, want 4 (err=%v)", st.FailedAttempts, err)
	}

	// 5th wrong attempt triggers 15-minute hard lockout.
	err = vReloaded.Unlock([]byte("wrong-pass"))
	if !errors.Is(err, vault.ErrVaultLocked) {
		t.Fatalf("5th failure = %v, want ErrVaultLocked", err)
	}

	wantSleeps := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
	if len(sleeps) != len(wantSleeps) {
		t.Fatalf("sleeps = %v, want %v", sleeps, wantSleeps)
	}
	for i := range wantSleeps {
		if sleeps[i] != wantSleeps[i] {
			t.Fatalf("sleep[%d] = %v, want %v", i, sleeps[i], wantSleeps[i])
		}
	}

	// Even with the VALID passphrase, another reload during the 15m lockout fails closed.
	vReloaded2, err := vault.OpenVault(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := vReloaded2.Unlock([]byte("valid-pass")); !errors.Is(err, vault.ErrVaultLocked) {
		t.Fatalf("Unlock during 15m lockout = %v, want ErrVaultLocked", err)
	}

	// After 15m elapses, valid passphrase succeeds and resets lockout state.
	now = now.Add(15*time.Minute + time.Second)
	if err := vReloaded2.Unlock([]byte("valid-pass")); err != nil {
		t.Fatalf("Unlock after 15m failed: %v", err)
	}
	st, err = vReloaded2.LockoutStatus()
	if err != nil || st.FailedAttempts != 0 {
		t.Fatalf("expected FailedAttempts reset to 0, got %+v (err=%v)", st, err)
	}
	vReloaded2.Zeroize()

	// StrictLockoutWipe mode + offline hybrid ML-KEM-1024+X25519 Admin Recovery Key reset.
	strictDir := filepath.Join(t.TempDir(), "vault-strict")
	strictNow := now
	strictOpts := vault.Options{
		StrictLockoutWipe: true,
		Now:               func() time.Time { return strictNow },
		Sleep:             func(d time.Duration) { strictNow = strictNow.Add(d) },
	}
	sv, initRes, err := vault.InitVault(strictDir, []byte("strict-pass"), strictOpts)
	if err != nil {
		t.Fatalf("InitVault strict: %v", err)
	}
	ct, err := sv.Encrypt([]byte("ctx"), []byte("top-secret"))
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		_ = sv.Unlock([]byte("bad"))
	}
	// Active DEK must be zeroized in RAM immediately.
	if _, err := sv.Encrypt([]byte("ctx"), []byte("x")); !errors.Is(err, vault.ErrVaultLocked) {
		t.Fatalf("expected Encrypt wiped after 5th strict failure, got %v", err)
	}
	// Even 1 hour later, valid passphrase remains blocked until admin recovery reset.
	strictNow = strictNow.Add(1 * time.Hour)
	if err := sv.Unlock([]byte("strict-pass")); !errors.Is(err, vault.ErrVaultLocked) {
		t.Fatalf("expected strict wiped vault locked after 1h, got %v", err)
	}

	recPriv, err := pqc.LoadRecoveryPrivateKey(initRes.RecoveryKeyPath)
	if err != nil {
		t.Fatalf("LoadRecoveryPrivateKey: %v", err)
	}
	defer recPriv.Zeroize()

	if err := sv.UnlockWithRecoveryKey(recPriv, []byte("new-strict-pass")); err != nil {
		t.Fatalf("UnlockWithRecoveryKey: %v", err)
	}
	pt, err := sv.Decrypt([]byte("ctx"), ct)
	if err != nil || string(pt) != "top-secret" {
		t.Fatalf("Decrypt after recovery unlock failed: %q err=%v", pt, err)
	}
	sv.Zeroize()
	if err := sv.Unlock([]byte("new-strict-pass")); err != nil {
		t.Fatalf("Unlock with rotated recovery passphrase failed: %v", err)
	}
	sv.Zeroize()
}

func TestCLIExitCodesAndWorkflows(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "shuna")
	buildCmd := exec.Command("go", "build", "-o", binPath, "../cmd/shuna")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, out)
	}

	runCLI := func(env map[string]string, args ...string) (int, string, string) {
		t.Helper()
		cmd := exec.Command(binPath, args...)
		cmd.Env = os.Environ()
		for k, v := range env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		code := 0
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				code = exitErr.ExitCode()
			} else {
				t.Fatalf("exec error: %v", err)
			}
		}
		return code, stdout.String(), stderr.String()
	}

	work := t.TempDir()
	vaultDir := filepath.Join(work, "vault")
	pkiDir := filepath.Join(work, "pki")
	env := map[string]string{"SHUNA_TEST_PASS": "cli-vault-pass"}

	// Exit 1: USAGE
	if code, _, _ := runCLI(nil, "unknown-cmd"); code != contract.ExitUsage {
		t.Fatalf("unknown-cmd exit = %d, want 1", code)
	}
	if code, _, _ := runCLI(nil, "seal", "--key", "x"); code != contract.ExitUsage {
		t.Fatalf("incomplete seal exit = %d, want 1", code)
	}

	// Exit 3: MISSING (both unseal and verify on missing dirs)
	if code, _, _ := runCLI(env, "unseal", "--key", filepath.Join(work, "nope.key"), "--aad", "a", "--in", "b"); code != contract.ExitMissing {
		t.Fatalf("missing key exit = %d, want 3", code)
	}
	if code, out, stderr := runCLI(nil, "verify", "--pki-dir", filepath.Join(work, "missing-pki"), "--json"); code != contract.ExitMissing {
		t.Fatalf("verify missing pki exit = %d, want 3 (out=%s stderr=%s)", code, out, stderr)
	}

	// Exit 0: keygen --strict-mlock --json (and exit 2 under prlimit --memlock=0 on Linux)
	if runtime.GOOS == "linux" {
		strictVault := filepath.Join(work, "vault-strict-ok")
		if code, out, stderr := runCLI(env, "keygen", "--out", strictVault, "--passphrase-env", "SHUNA_TEST_PASS", "--strict-mlock", "--json"); code != 0 {
			t.Fatalf("keygen --strict-mlock failed (%d): %s %s", code, out, stderr)
		}
		if _, err := exec.LookPath("prlimit"); err == nil {
			prOutDir := filepath.Join(work, "vault-strict-prlimit")
			cmd := exec.Command("prlimit", "--memlock=0", binPath, "keygen", "--out", prOutDir, "--passphrase-env", "SHUNA_TEST_PASS", "--strict-mlock", "--json")
			cmd.Env = append(os.Environ(), "SHUNA_TEST_PASS=cli-vault-pass")
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != contract.ExitPolicyStop {
				t.Fatalf("prlimit --memlock=0 keygen --strict-mlock err=%v out=%s stderr=%s, want exit 2", err, stdout.String(), stderr.String())
			}
		}
	}

	// Exit 0: keygen --json
	code, out, stderr := runCLI(env, "keygen", "--out", vaultDir, "--passphrase-env", "SHUNA_TEST_PASS", "--json")
	if code != 0 {
		t.Fatalf("keygen failed (%d): %s %s", code, out, stderr)
	}
	var envJSON contract.Envelope
	if err := json.Unmarshal([]byte(out), &envJSON); err != nil || !envJSON.OK {
		t.Fatalf("invalid keygen JSON: %s (%v)", out, err)
	}

	// Exit 0: init-pki + issue-cert + verify
	if code, _, stderr := runCLI(nil, "init-pki", "--out", pkiDir, "--hosts", "127.0.0.1,localhost", "--pg-hosts", "postgres,127.0.0.1", "--json"); code != 0 {
		t.Fatalf("init-pki failed (%d): %s", code, stderr)
	}
	code, out, stderr = runCLI(nil, "issue-cert", "--pki-dir", pkiDir, "--cn", "alice", "--role", "client", "--ttl", "24h", "--json")
	if code != 0 {
		t.Fatalf("issue-cert failed (%d): %s", code, stderr)
	}
	var issuedWrap struct {
		Data mtls.IssuedCert `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &issuedWrap); err != nil {
		t.Fatalf("parse issue-cert JSON: %v", err)
	}
	if code, _, stderr := runCLI(nil, "verify", "--pki-dir", pkiDir, "--json"); code != 0 {
		t.Fatalf("verify failed (%d): %s", code, stderr)
	}

	// Revoke -> verify returns exit 2 (POLICY_STOP / REVOKED)
	if code, _, stderr := runCLI(nil, "revoke", "--pki-dir", pkiDir, "--serial", issuedWrap.Data.SerialHex, "--reason", "key_compromise", "--json"); code != 0 {
		t.Fatalf("revoke failed (%d): %s", code, stderr)
	}
	if code, _, _ := runCLI(nil, "verify", "--pki-dir", pkiDir, "--cert", issuedWrap.Data.CertPath, "--json"); code != contract.ExitPolicyStop {
		t.Fatalf("verify revoked cert exit = %d, want 2", code)
	}

	// Seal & unseal with AES-256-GCM raw key file + non-zero pad rejection (exit 4)
	rawKeyPath := filepath.Join(work, "raw.key")
	rawKey := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, rawKey)
	if err := os.WriteFile(rawKeyPath, rawKey, 0600); err != nil {
		t.Fatal(err)
	}
	plainPath := filepath.Join(work, "plain.txt")
	sealedPath := filepath.Join(work, "sealed.shuna1")
	unsealedPath := filepath.Join(work, "unsealed.txt")
	if err := os.WriteFile(plainPath, []byte("hello-shuna-cli"), 0600); err != nil {
		t.Fatal(err)
	}

	if code, _, stderr := runCLI(nil, "seal", "--key", rawKeyPath, "--aad", "cli-ctx", "--in", plainPath, "--out", sealedPath, "--alg", "aes256gcm", "--json"); code != 0 {
		t.Fatalf("seal aes256gcm failed (%d): %s", code, stderr)
	}
	if code, _, stderr := runCLI(nil, "unseal", "--key", rawKeyPath, "--aad", "cli-ctx", "--in", sealedPath, "--out", unsealedPath, "--json"); code != 0 {
		t.Fatalf("unseal aes256gcm failed (%d): %s", code, stderr)
	}
	gotPT, err := os.ReadFile(unsealedPath)
	if err != nil || string(gotPT) != "hello-shuna-cli" {
		t.Fatalf("unsealed content = %q, err=%v", gotPT, err)
	}

	// Wrong AAD -> exit 4
	if code, _, _ := runCLI(nil, "unseal", "--key", rawKeyPath, "--aad", "wrong", "--in", sealedPath, "--json"); code != contract.ExitCorruptCiphertext {
		t.Fatalf("unseal wrong AAD exit = %d, want 4", code)
	}

	// Non-zero byte in AES-256-GCM nonce pad [23:35] -> exit 4
	badPadBytes, err := os.ReadFile(sealedPath)
	if err != nil {
		t.Fatal(err)
	}
	badPadBytes[25] = 0x42
	badPadPath := filepath.Join(work, "badpad.shuna1")
	if err := os.WriteFile(badPadPath, badPadBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI(nil, "unseal", "--key", rawKeyPath, "--aad", "cli-ctx", "--in", badPadPath, "--json"); code != contract.ExitCorruptCiphertext {
		t.Fatalf("unseal non-zero GCM pad exit = %d, want 4", code)
	}

	// Stream seal/unseal via Vault + rotate
	streamIn := filepath.Join(work, "backup.sql")
	streamEnc := filepath.Join(work, "backup.shunas1")
	streamDec := filepath.Join(work, "backup.dec.sql")
	bigData := strings.Repeat("INSERT INTO audit_events VALUES (1,'ok');\n", 2500)
	if err := os.WriteFile(streamIn, []byte(bigData), 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI(env, "seal", "--key", vaultDir, "--passphrase-env", "SHUNA_TEST_PASS", "--aad", "pg_dump", "--in", streamIn, "--out", streamEnc, "--stream", "--json"); code != 0 {
		t.Fatalf("seal --stream failed (%d): %s", code, stderr)
	}
	if code, _, stderr := runCLI(env, "unseal", "--key", vaultDir, "--passphrase-env", "SHUNA_TEST_PASS", "--aad", "pg_dump", "--in", streamEnc, "--out", streamDec, "--stream", "--json"); code != 0 {
		t.Fatalf("unseal --stream failed (%d): %s", code, stderr)
	}
	gotBig, err := os.ReadFile(streamDec)
	if err != nil || string(gotBig) != bigData {
		t.Fatalf("stream unseal mismatch (len=%d vs %d, err=%v)", len(gotBig), len(bigData), err)
	}

	// Truncated stream -> exit 4 and no partial output file left behind
	encBytes, _ := os.ReadFile(streamEnc)
	truncEnc := filepath.Join(work, "trunc.shunas1")
	_ = os.WriteFile(truncEnc, encBytes[:len(encBytes)-10], 0600)
	truncOut := filepath.Join(work, "trunc.out")
	if code, _, _ := runCLI(env, "unseal", "--key", vaultDir, "--passphrase-env", "SHUNA_TEST_PASS", "--aad", "pg_dump", "--in", truncEnc, "--out", truncOut, "--stream", "--json"); code != contract.ExitCorruptCiphertext {
		t.Fatalf("unseal truncated stream exit = %d, want 4", code)
	}
	if _, err := os.Stat(truncOut); !os.IsNotExist(err) {
		t.Fatal("partial unsealed stream file should not exist after failure")
	}

	// Seal with Vault + explicit --alg aes256gcm must produce AES-256-GCM ciphertext AND report aes-256-gcm in JSON.
	vaultGCMOut := filepath.Join(work, "vault-gcm.shuna1")
	code, out, stderr = runCLI(env, "seal", "--key", vaultDir, "--passphrase-env", "SHUNA_TEST_PASS", "--aad", "vault-gcm", "--in", plainPath, "--out", vaultGCMOut, "--alg", "aes256gcm", "--json")
	if code != 0 {
		t.Fatalf("vault seal aes256gcm failed (%d): %s %s", code, out, stderr)
	}
	var sealWrap struct {
		Data struct {
			Algorithm string `json:"algorithm"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &sealWrap); err != nil || sealWrap.Data.Algorithm != "aes-256-gcm" {
		t.Fatalf("unexpected seal JSON algorithm: %s (%v)", out, err)
	}
	vaultGCMBytes, err := os.ReadFile(vaultGCMOut)
	if err != nil || len(vaultGCMBytes) < envelope.HeaderSize || vaultGCMBytes[6] != envelope.AlgAES256GCM {
		t.Fatalf("vault seal --alg aes256gcm wrote alg 0x%02x, want 0x02", vaultGCMBytes[6])
	}

	// Rotate to a NEW passphrase + unseal pre-rotation v1 ciphertext with new passphrase + unlock-reset
	env2 := map[string]string{
		"SHUNA_TEST_PASS":     "cli-vault-pass",
		"SHUNA_TEST_NEW_PASS": "cli-vault-pass-v2",
	}
	if code, _, stderr := runCLI(env2, "rotate", "--vault", vaultDir, "--passphrase-env", "SHUNA_TEST_PASS", "--new-passphrase-env", "SHUNA_TEST_NEW_PASS", "--json"); code != 0 {
		t.Fatalf("rotate failed (%d): %s", code, stderr)
	}
	envOnlyNew := map[string]string{"SHUNA_TEST_NEW_PASS": "cli-vault-pass-v2"}
	vaultGCMDec := filepath.Join(work, "vault-gcm.dec.txt")
	if code, _, stderr := runCLI(envOnlyNew, "unseal", "--key", vaultDir, "--passphrase-env", "SHUNA_TEST_NEW_PASS", "--aad", "vault-gcm", "--in", vaultGCMOut, "--out", vaultGCMDec, "--json"); code != 0 {
		t.Fatalf("dual-read unseal after passphrase rotate failed (%d): %s", code, stderr)
	}
	if got, err := os.ReadFile(vaultGCMDec); err != nil || string(got) != "hello-shuna-cli" {
		t.Fatalf("dual-read unseal content = %q, err=%v", got, err)
	}
	if code, _, stderr := runCLI(env, "unlock-reset", "--vault", vaultDir, "--recovery-key", filepath.Join(vaultDir, "recovery.key"), "--new-passphrase-env", "SHUNA_TEST_PASS", "--json"); code != 0 {
		t.Fatalf("unlock-reset failed (%d): %s", code, stderr)
	}

	// Stdin (--in -) seal -> unseal round-trip using hex-encoded key file.
	hexKeyPath := filepath.Join(work, "raw.hex.key")
	if err := os.WriteFile(hexKeyPath, []byte(fmt.Sprintf("%x\n", rawKey)), 0600); err != nil {
		t.Fatal(err)
	}
	sealStdin := exec.Command(binPath, "seal", "--key", hexKeyPath, "--aad", "stdin-ctx", "--in", "-")
	sealStdin.Stdin = strings.NewReader("stdin-secret-payload")
	sealedOut, err := sealStdin.Output()
	if err != nil {
		t.Fatalf("seal stdin failed: %v", err)
	}
	unsealStdin := exec.Command(binPath, "unseal", "--key", hexKeyPath, "--aad", "stdin-ctx", "--in", "-")
	unsealStdin.Stdin = bytes.NewReader(sealedOut)
	unsealedOut, err := unsealStdin.Output()
	if err != nil || string(unsealedOut) != "stdin-secret-payload" {
		t.Fatalf("unseal stdin mismatch: %q err=%v", unsealedOut, err)
	}
}

func snapshotDirHashes(t *testing.T, dir string, names []string) map[string][32]byte {
	t.Helper()
	out := make(map[string][32]byte, len(names))
	for _, n := range names {
		raw, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		out[n] = sha256.Sum256(raw)
	}
	return out
}

func TestIssueCertRejectsReservedNamesAndUnsafePaths(t *testing.T) {
	pkiDir := filepath.Join(t.TempDir(), "pki")
	if _, err := mtls.InitPKI(pkiDir, []string{"127.0.0.1", "localhost"}, []string{"postgres", "127.0.0.1"}, 24*time.Hour); err != nil {
		t.Fatalf("InitPKI: %v", err)
	}

	reservedFiles := []string{"ca.crt", "ca.key", "ca.crl", "server.crt", "server.key", "pg-server.crt", "pg-server.key"}
	before := snapshotDirHashes(t, pkiDir, reservedFiles)

	policyDenied := []struct {
		cn   string
		role mtls.Role
	}{
		{"ca", mtls.RoleClient},
		{"CA", mtls.RoleServer},
		{" ca ", mtls.RoleClient},
		{"ca.crt", mtls.RoleClient},
		{"ca.key", mtls.RoleClient},
		{"ca.crl", mtls.RoleClient},
		{"CA.CRL", mtls.RoleServer},
		{"ca.pem", mtls.RoleClient},
		{"ca.crl.crt", mtls.RoleClient},
		{"pg-server", mtls.RoleClient},
		{"PG-SERVER", mtls.RolePostgres},
		{"pg-server.crt", mtls.RolePostgres},
		{"pg-server.key", mtls.RoleClient},
		{"server", mtls.RoleClient},
		{"server", mtls.RolePostgres},
		{"SERVER", mtls.RoleServer},
		{"Server", mtls.RoleServer},
		{" server ", mtls.RoleServer},
		{"server.crt", mtls.RoleServer},
		{"server.key", mtls.RoleClient},
		{"server", mtls.RoleServer},
	}
	for _, tc := range policyDenied {
		_, err := mtls.IssueCert(pkiDir, tc.cn, tc.role, []string{"127.0.0.1"}, time.Hour)
		if contract.CodeOf(err) != contract.ExitPolicyStop {
			t.Fatalf("IssueCert(%q, %q) code = %d, want %d (err=%v)", tc.cn, tc.role, contract.CodeOf(err), contract.ExitPolicyStop, err)
		}
	}

	usageDenied := []string{
		"", "   ", ".", "..", ".hidden", "foo.", "a/b", "a\\b", "C:foo",
		"bad\x00cn", "bad\ncn", "foo*bar", "foo?bar", "foo\"bar", "foo<bar", "foo>bar", "foo|bar",
		"alice.crt", "alice.key", "alice.crl", "alice.pem",
	}
	for _, cn := range usageDenied {
		_, err := mtls.IssueCert(pkiDir, cn, mtls.RoleClient, nil, time.Hour)
		if contract.CodeOf(err) != contract.ExitUsage {
			t.Fatalf("IssueCert(%q) code = %d, want %d (err=%v)", cn, contract.CodeOf(err), contract.ExitUsage, err)
		}
	}

	after := snapshotDirHashes(t, pkiDir, reservedFiles)
	for _, name := range reservedFiles {
		if before[name] != after[name] {
			t.Fatalf("reserved PKI file %s was modified", name)
		}
	}

	issued, err := mtls.IssueCert(pkiDir, " operator-1 ", mtls.RoleClient, nil, time.Hour)
	if err != nil {
		t.Fatalf("IssueCert valid trimmed CN: %v", err)
	}
	if issued.CommonName != "operator-1" {
		t.Fatalf("CommonName = %q, want operator-1", issued.CommonName)
	}
	cert, err := mtls.LoadCertificate(issued.CertPath)
	if err != nil {
		t.Fatalf("LoadCertificate: %v", err)
	}
	if cert.Subject.CommonName != "operator-1" {
		t.Fatalf("Subject.CommonName = %q, want operator-1", cert.Subject.CommonName)
	}
}

func TestIssueCertAllowsServerRenewalWhenNeeded(t *testing.T) {
	pkiDir := filepath.Join(t.TempDir(), "pki")
	res, err := mtls.InitPKI(pkiDir, []string{"127.0.0.1", "localhost"}, []string{"postgres", "127.0.0.1"}, 2*time.Second)
	if err != nil {
		t.Fatalf("InitPKI: %v", err)
	}

	// Simulate ciel/teamserver/main.go:2510-2514 renewal once >= 50% TTL has elapsed.
	origCert, err := mtls.LoadCertificate(res.ServerCert.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !mtls.NeedsRenewal(origCert, time.Now().UTC()) {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for NeedsRenewal")
		}
		time.Sleep(100 * time.Millisecond)
	}

	renewed, err := mtls.IssueCert(pkiDir, "server", mtls.RoleServer, []string{"127.0.0.1", "localhost"}, mtls.DefaultServerTTL)
	if err != nil {
		t.Fatalf("IssueCert server renewal failed: %v", err)
	}
	if renewed.SerialHex == res.ServerCert.SerialHex {
		t.Fatal("expected renewed server certificate to have a new serial")
	}

	// Simulate missing server.crt while ca.key exists (ciel/teamserver/main.go:2510).
	if err := os.Remove(res.ServerCert.CertPath); err != nil {
		t.Fatal(err)
	}
	recreated, err := mtls.IssueCert(pkiDir, "server", mtls.RoleServer, []string{"127.0.0.1", "localhost"}, mtls.DefaultServerTTL)
	if err != nil {
		t.Fatalf("IssueCert missing server.crt failed: %v", err)
	}
	if recreated.Role != mtls.RoleServer {
		t.Fatalf("role = %q, want server", recreated.Role)
	}

	// Verify client issuance and renewal remains intact (ciel/teamserver/main.go:2529,2533).
	if _, err := mtls.IssueCert(pkiDir, "client", mtls.RoleClient, nil, mtls.DefaultClientTTL); err != nil {
		t.Fatalf("IssueCert client 1: %v", err)
	}
	if _, err := mtls.IssueCert(pkiDir, "client", mtls.RoleClient, nil, mtls.DefaultClientTTL); err != nil {
		t.Fatalf("IssueCert client 2 (renewal): %v", err)
	}
}

func TestLockoutHelperProcess(t *testing.T) {
	dir := os.Getenv("SHUNA_LOCKOUT_HELPER_DIR")
	if dir == "" {
		return
	}
	v, err := vault.OpenVault(dir, vault.Options{
		StrictLockoutWipe: true,
		Sleep:             func(time.Duration) {},
	})
	if err != nil {
		t.Fatalf("helper OpenVault: %v", err)
	}
	defer v.Zeroize()
	_ = v.Unlock([]byte("wrong-pass"))
}

func TestFileLockoutStoreConcurrentRMW(t *testing.T) {
	// 1. Direct concurrent FileLockoutStore.Update + Load.
	storePath := filepath.Join(t.TempDir(), "lockout.json")
	store := vault.NewFileLockoutStore(storePath)

	var wg sync.WaitGroup
	errCh := make(chan error, 64)
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := store.Update(func(st vault.LockoutState) (vault.LockoutState, error) {
				st.FailedAttempts++
				return st, nil
			}); err != nil {
				errCh <- err
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := store.Load(); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent FileLockoutStore error: %v", err)
	}
	st, err := store.Load()
	if err != nil || st.FailedAttempts != 16 {
		t.Fatalf("FailedAttempts = %d, want 16 (err=%v)", st.FailedAttempts, err)
	}

	// 2. Concurrent distinct *Vault instances failing Unlock concurrently.
	vaultDir := filepath.Join(t.TempDir(), "vault-concurrent")
	vInit, _, err := vault.InitVault(vaultDir, []byte("valid-pass"), vault.Options{
		StrictLockoutWipe: true,
		Sleep:             func(time.Duration) {},
	})
	if err != nil {
		t.Fatalf("InitVault: %v", err)
	}
	vInit.Zeroize()

	const workers = 8
	var unlockWG sync.WaitGroup
	var lockedCount atomic.Int32
	for i := 0; i < workers; i++ {
		unlockWG.Add(1)
		go func() {
			defer unlockWG.Done()
			vi, oErr := vault.OpenVault(vaultDir, vault.Options{
				StrictLockoutWipe: true,
				Sleep:             func(time.Duration) {},
			})
			if oErr != nil {
				t.Errorf("OpenVault: %v", oErr)
				return
			}
			defer vi.Zeroize()
			uErr := vi.Unlock([]byte("wrong-pass"))
			if errors.Is(uErr, vault.ErrVaultLocked) {
				lockedCount.Add(1)
			}
		}()
	}
	unlockWG.Wait()

	finalState, err := vInit.LockoutStatus()
	if err != nil {
		t.Fatalf("LockoutStatus: %v", err)
	}
	if finalState.FailedAttempts != vault.MaxFailedAttempts || !finalState.WipedLocked {
		t.Fatalf("unexpected lockout state: %+v", finalState)
	}
	if lockedCount.Load() != workers-4 {
		t.Fatalf("lockedCount = %d, want %d", lockedCount.Load(), workers-4)
	}
	vCheck, err := vault.OpenVault(vaultDir, vault.Options{StrictLockoutWipe: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := vCheck.Unlock([]byte("valid-pass")); !errors.Is(err, vault.ErrVaultLocked) {
		t.Fatalf("Unlock with valid pass after strict lockout = %v, want ErrVaultLocked", err)
	}

	// 3. Multi-process concurrent Vault.Unlock via helper subprocesses.
	procVaultDir := filepath.Join(t.TempDir(), "vault-multiproc")
	vp, _, err := vault.InitVault(procVaultDir, []byte("valid-pass"), vault.Options{
		StrictLockoutWipe: true,
		Sleep:             func(time.Duration) {},
	})
	if err != nil {
		t.Fatalf("InitVault multiproc: %v", err)
	}
	vp.Zeroize()

	var procWG sync.WaitGroup
	procErrs := make(chan error, 5)
	for i := 0; i < 5; i++ {
		procWG.Add(1)
		go func() {
			defer procWG.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestLockoutHelperProcess$")
			cmd.Env = append(os.Environ(), "SHUNA_LOCKOUT_HELPER_DIR="+procVaultDir)
			if out, err := cmd.CombinedOutput(); err != nil {
				procErrs <- fmt.Errorf("helper failed: %v\n%s", err, out)
			}
		}()
	}
	procWG.Wait()
	close(procErrs)
	for err := range procErrs {
		t.Fatal(err)
	}
	procState, err := vp.LockoutStatus()
	if err != nil {
		t.Fatalf("multiproc LockoutStatus: %v", err)
	}
	if procState.FailedAttempts != vault.MaxFailedAttempts || !procState.WipedLocked {
		t.Fatalf("multiproc lockout state = %+v, want FailedAttempts=5 WipedLocked=true", procState)
	}
}

func TestCRLManagerConcurrentRevokeAndReload(t *testing.T) {
	pkiDir := filepath.Join(t.TempDir(), "pki")
	res, err := mtls.InitPKI(pkiDir, []string{"127.0.0.1"}, []string{"postgres"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("InitPKI: %v", err)
	}
	caCert, caKey, err := mtls.LoadCA(pkiDir)
	if err != nil {
		t.Fatal(err)
	}

	const n = 6
	serials := make([]string, n)
	managers := make([]*mtls.CRLManager, n)
	for i := 0; i < n; i++ {
		serials[i] = mtls.FormatSerial(big.NewInt(int64(1000 + i)))
		m, err := mtls.OpenCRLManager(caCert, caKey, res.CRLPath)
		if err != nil {
			t.Fatalf("OpenCRLManager %d: %v", i, err)
		}
		managers[i] = m
	}

	var wg sync.WaitGroup
	stopReaders := make(chan struct{})
	readerErrs := make(chan error, 32)
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reader, err := mtls.LoadCRL(res.CRLPath, caCert)
			if err != nil {
				readerErrs <- err
				return
			}
			for {
				select {
				case <-stopReaders:
					return
				default:
					if err := reader.ReloadIfChanged(); err != nil {
						readerErrs <- err
						return
					}
					_ = reader.IsRevokedHex(serials[0])
				}
			}
		}()
	}

	revokeErrs := make(chan error, n)
	var revokeWG sync.WaitGroup
	for i := 0; i < n; i++ {
		revokeWG.Add(1)
		go func(idx int) {
			defer revokeWG.Done()
			if _, err := managers[idx].Revoke(serials[idx], 1); err != nil {
				revokeErrs <- err
			}
		}(i)
	}
	revokeWG.Wait()
	close(stopReaders)
	wg.Wait()
	close(readerErrs)
	close(revokeErrs)

	for err := range revokeErrs {
		t.Fatalf("concurrent Revoke failed: %v", err)
	}
	for err := range readerErrs {
		t.Fatalf("concurrent ReloadIfChanged failed: %v", err)
	}

	diskCRL, err := mtls.LoadCRL(res.CRLPath, caCert)
	if err != nil {
		t.Fatalf("LoadCRL: %v", err)
	}
	for _, s := range serials {
		if !diskCRL.IsRevokedHex(s) {
			t.Fatalf("serial %s lost after concurrent Revoke", s)
		}
	}
	for i, m := range managers {
		if err := m.ReloadIfChanged(); err != nil {
			t.Fatalf("manager[%d].ReloadIfChanged: %v", i, err)
		}
		for _, s := range serials {
			if !m.IsRevokedHex(s) {
				t.Fatalf("manager[%d] missing serial %s after ReloadIfChanged", i, s)
			}
		}
	}

	// Multi-process CLI shuna revoke test.
	binPath := filepath.Join(t.TempDir(), "shuna")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	buildCmd := exec.Command("go", "build", "-o", binPath, "../cmd/shuna")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, out)
	}

	cliSerials := []string{
		mtls.FormatSerial(big.NewInt(2001)),
		mtls.FormatSerial(big.NewInt(2002)),
		mtls.FormatSerial(big.NewInt(2003)),
		mtls.FormatSerial(big.NewInt(2004)),
	}
	var cliWG sync.WaitGroup
	cliErrs := make(chan error, len(cliSerials))
	for _, s := range cliSerials {
		cliWG.Add(1)
		go func(ser string) {
			defer cliWG.Done()
			cmd := exec.Command(binPath, "revoke", "--pki-dir", pkiDir, "--serial", ser, "--reason", "key_compromise", "--json")
			if out, err := cmd.CombinedOutput(); err != nil {
				cliErrs <- fmt.Errorf("cli revoke %s: %v\n%s", ser, err, out)
			}
		}(s)
	}
	cliWG.Wait()
	close(cliErrs)
	for err := range cliErrs {
		t.Fatal(err)
	}

	afterCLI, err := mtls.LoadCRL(res.CRLPath, caCert)
	if err != nil {
		t.Fatalf("LoadCRL after CLI revokes: %v", err)
	}
	for _, s := range append(serials, cliSerials...) {
		if !afterCLI.IsRevokedHex(s) {
			t.Fatalf("serial %s missing after multi-process CLI revokes", s)
		}
	}
}

func TestCRLReloadIfChangedSubSecondSameSizeAndMtime(t *testing.T) {
	pkiDir := filepath.Join(t.TempDir(), "pki")
	res, err := mtls.InitPKI(pkiDir, []string{"127.0.0.1"}, []string{"postgres"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("InitPKI: %v", err)
	}
	caCert, caKey, err := mtls.LoadCA(pkiDir)
	if err != nil {
		t.Fatal(err)
	}

	signCRL := func(num int64, ser *big.Int) []byte {
		now := time.Now().UTC()
		tmpl := &x509.RevocationList{
			Number:     big.NewInt(num),
			ThisUpdate: now.Add(-1 * time.Minute),
			NextUpdate: now.Add(mtls.DefaultCRLValidity),
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber:   ser,
					RevocationTime: now,
					ReasonCode:     1,
				},
			},
		}
		der, err := x509.CreateRevocationList(rand.Reader, tmpl, caCert, caKey)
		if err != nil {
			t.Fatalf("CreateRevocationList: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	}

	serA := big.NewInt(0x1111)
	serB := big.NewInt(0x2222)
	hexA := mtls.FormatSerial(serA)
	hexB := mtls.FormatSerial(serB)

	pem1 := signCRL(10, serA)
	if err := os.WriteFile(res.CRLPath, pem1, 0644); err != nil {
		t.Fatal(err)
	}
	info1, err := os.Stat(res.CRLPath)
	if err != nil {
		t.Fatal(err)
	}

	reader, err := mtls.LoadCRL(res.CRLPath, caCert)
	if err != nil {
		t.Fatalf("LoadCRL: %v", err)
	}
	if !reader.IsRevokedHex(hexA) || reader.IsRevokedHex(hexB) {
		t.Fatal("unexpected initial revocation state")
	}

	var pem2 []byte
	for i := 0; i < 64; i++ {
		cand := signCRL(11, serB)
		if len(cand) == len(pem1) {
			pem2 = cand
			break
		}
	}
	if pem2 == nil {
		t.Fatal("failed to generate same-length ECDSA CRL PEM within 64 attempts")
	}
	if err := os.WriteFile(res.CRLPath, pem2, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(res.CRLPath, info1.ModTime(), info1.ModTime()); err != nil {
		t.Fatal(err)
	}
	info2, err := os.Stat(res.CRLPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info2.ModTime().Equal(info1.ModTime()) || info2.Size() != info1.Size() {
		t.Fatalf("expected identical mtime and size, got (%v,%d) vs (%v,%d)", info2.ModTime(), info2.Size(), info1.ModTime(), info1.Size())
	}

	if err := reader.ReloadIfChanged(); err != nil {
		t.Fatalf("ReloadIfChanged: %v", err)
	}
	if !reader.IsRevokedHex(hexB) || reader.IsRevokedHex(hexA) {
		t.Fatalf("ReloadIfChanged missed identical-mtime/identical-size CRL replacement (hexA=%v hexB=%v)", reader.IsRevokedHex(hexA), reader.IsRevokedHex(hexB))
	}

	// Verify rapid back-to-back Revoke calls without sleep are immediately visible via ReloadIfChanged.
	writer, err := mtls.OpenCRLManager(caCert, caKey, res.CRLPath)
	if err != nil {
		t.Fatal(err)
	}
	rapid1 := hex.EncodeToString([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x33, 0x33})
	rapid2 := hex.EncodeToString([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x44, 0x44})
	if _, err := writer.Revoke(rapid1, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Revoke(rapid2, 1); err != nil {
		t.Fatal(err)
	}
	if err := reader.ReloadIfChanged(); err != nil {
		t.Fatal(err)
	}
	if !reader.IsRevokedHex(rapid1) || !reader.IsRevokedHex(rapid2) {
		t.Fatal("rapid consecutive Revoke calls not visible after ReloadIfChanged")
	}
}
