package tests

import (
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mafifrizi/shuna/pkg/mtls"
	"github.com/Mafifrizi/shuna/pkg/pqc"
)

func assertNoShunaTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".shuna.tmp-") {
			t.Fatalf("leftover temp file %s in %s", e.Name(), dir)
		}
	}
}

func TestAtomicPKIAndPQCKeyWritesRejectSymlinksAndPreservePerms(t *testing.T) {
	base := t.TempDir()
	victim := filepath.Join(base, "victim.txt")
	if err := os.WriteFile(victim, []byte("preserve-me"), 0o600); err != nil {
		t.Fatal(err)
	}

	makeSymlink := func(linkPath string) {
		t.Helper()
		if err := os.Symlink(victim, linkPath); err != nil {
			if runtime.GOOS == "windows" && errors.Is(err, os.ErrPermission) {
				t.Skip("symlink creation requires elevated privilege on Windows")
			}
			t.Fatalf("Symlink(%s -> %s): %v", linkPath, victim, err)
		}
	}

	// 1. Pre-planted file symlinks in InitPKI (ca.crt and ca.key)
	for _, target := range []string{"ca.crt", "ca.key"} {
		pkiDir := filepath.Join(base, "init-"+target)
		if err := os.MkdirAll(pkiDir, 0o755); err != nil {
			t.Fatal(err)
		}
		makeSymlink(filepath.Join(pkiDir, target))
		if _, err := mtls.InitPKI(pkiDir, []string{"127.0.0.1"}, []string{"127.0.0.1"}, time.Hour); err == nil {
			t.Fatalf("expected InitPKI to reject pre-planted symlink %s", target)
		}
		assertNoShunaTempFiles(t, pkiDir)
	}

	// 2. Clean InitPKI + permissions check + pre-planted leaf symlinks in IssueCert
	pkiClean := filepath.Join(base, "pki-clean")
	res, err := mtls.InitPKI(pkiClean, []string{"127.0.0.1"}, []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("InitPKI clean: %v", err)
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{res.CACertPath, res.ServerCert.CertPath, res.PostgresCert.CertPath} {
			info, err := os.Stat(p)
			if err != nil || info.Mode().Perm() != 0o644 {
				t.Fatalf("expected 0644 on %s, got %v (err=%v)", p, info.Mode().Perm(), err)
			}
		}
		for _, p := range []string{res.CAKeyPath, res.ServerCert.KeyPath, res.PostgresCert.KeyPath} {
			info, err := os.Stat(p)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("expected 0600 on %s, got %v (err=%v)", p, info.Mode().Perm(), err)
			}
		}
	}

	for _, name := range []string{"alice.crt", "alice.key"} {
		link := filepath.Join(pkiClean, name)
		_ = os.Remove(link)
		makeSymlink(link)
		if _, err := mtls.IssueCert(pkiClean, "alice", mtls.RoleClient, nil, time.Hour); err == nil {
			t.Fatalf("expected IssueCert to reject pre-planted symlink %s", name)
		}
		_ = os.Remove(link)
		assertNoShunaTempFiles(t, pkiClean)
	}

	// 3. Symlinked output directory
	realOut := filepath.Join(base, "real-out")
	if err := os.MkdirAll(realOut, 0o755); err != nil {
		t.Fatal(err)
	}
	symDir := filepath.Join(base, "sym-dir")
	if err := os.Symlink(realOut, symDir); err != nil {
		if runtime.GOOS == "windows" && errors.Is(err, os.ErrPermission) {
			t.Skip("symlink creation requires elevated privilege on Windows")
		}
		t.Fatalf("Symlink dir: %v", err)
	}
	if _, err := mtls.InitPKI(symDir, []string{"127.0.0.1"}, []string{"127.0.0.1"}, time.Hour); err == nil {
		t.Fatal("expected InitPKI to reject symlinked output directory")
	}

	// 4. PQC SaveRecoveryKeyPair symlink rejection + permissions
	priv, pub, err := pqc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	defer priv.Zeroize()

	for _, name := range []string{"recovery.pub", "recovery.key"} {
		recDir := filepath.Join(base, "rec-"+name)
		if err := os.MkdirAll(recDir, 0o700); err != nil {
			t.Fatal(err)
		}
		makeSymlink(filepath.Join(recDir, name))
		if _, _, err := pqc.SaveRecoveryKeyPair(recDir, priv, pub); err == nil {
			t.Fatalf("expected SaveRecoveryKeyPair to reject pre-planted symlink %s", name)
		}
		assertNoShunaTempFiles(t, recDir)
	}
	if _, _, err := pqc.SaveRecoveryKeyPair(symDir, priv, pub); err == nil {
		t.Fatal("expected SaveRecoveryKeyPair to reject symlinked output directory")
	}

	recClean := filepath.Join(base, "rec-clean")
	pubPath, privPath, err := pqc.SaveRecoveryKeyPair(recClean, priv, pub)
	if err != nil {
		t.Fatalf("SaveRecoveryKeyPair clean: %v", err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(pubPath); err != nil || info.Mode().Perm() != 0o644 {
			t.Fatalf("expected 0644 on recovery.pub, got %v (err=%v)", info.Mode().Perm(), err)
		}
		if info, err := os.Stat(privPath); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("expected 0600 on recovery.key, got %v (err=%v)", info.Mode().Perm(), err)
		}
	}

	gotVictim, err := os.ReadFile(victim)
	if err != nil || string(gotVictim) != "preserve-me" {
		t.Fatalf("victim file was modified: %q err=%v", string(gotVictim), err)
	}
}

func TestAtomicPKIAndPQCConcurrentOverwriteRead(t *testing.T) {
	base := t.TempDir()
	pkiDir := filepath.Join(base, "pki")
	if _, err := mtls.InitPKI(pkiDir, []string{"127.0.0.1"}, []string{"127.0.0.1"}, time.Hour); err != nil {
		t.Fatalf("InitPKI: %v", err)
	}
	issued, err := mtls.IssueCert(pkiDir, "client", mtls.RoleClient, nil, time.Hour)
	if err != nil {
		t.Fatalf("initial IssueCert: %v", err)
	}

	recDir := filepath.Join(base, "rec")
	priv, pub, err := pqc.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Zeroize()
	pubPath, privPath, err := pqc.SaveRecoveryKeyPair(recDir, priv, pub)
	if err != nil {
		t.Fatalf("initial SaveRecoveryKeyPair: %v", err)
	}

	const writers = 4
	const readers = 4
	const iters = 20

	var wg sync.WaitGroup
	errCh := make(chan error, 64)

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				if _, err := mtls.IssueCert(pkiDir, "client", mtls.RoleClient, nil, time.Hour); err != nil {
					errCh <- err
					return
				}
				if _, _, err := pqc.SaveRecoveryKeyPair(recDir, priv, pub); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}

	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters*2; i++ {
				if _, err := mtls.LoadCertificate(issued.CertPath); err != nil {
					errCh <- err
					return
				}
				if _, err := tls.LoadX509KeyPair(issued.CertPath, issued.KeyPath); err != nil {
					// On concurrent cert+key pair update, cert and key could briefly come from consecutive generations;
					// verify at least LoadCertificate succeeds and key file parses cleanly if keypair mismatches.
					if !strings.Contains(err.Error(), "does not match") {
						errCh <- err
						return
					}
				}
				if _, err := pqc.LoadRecoveryPublicKey(pubPath); err != nil {
					errCh <- err
					return
				}
				loadedPriv, err := pqc.LoadRecoveryPrivateKey(privPath)
				if err != nil {
					errCh <- err
					return
				}
				loadedPriv.Zeroize()
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent atomic overwrite/read error: %v", err)
	}
	assertNoShunaTempFiles(t, pkiDir)
	assertNoShunaTempFiles(t, recDir)
}
