package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	root   *x509.Certificate
	signer crypto.Signer
	roots  *x509.CertPool
	now    time.Time
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return fixture{root, key, roots, now}
}
func (f fixture) leaf(t *testing.T, kind, host string, after time.Time, curve elliptic.Curve) (tls.Certificate, []byte) {
	t.Helper()
	var key crypto.Signer
	var err error
	if kind == "RSA" {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		key, err = ecdsa.GenerateKey(curve, rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, DNSNames: []string{host}, NotBefore: f.now.Add(-72 * time.Hour), NotAfter: after, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, f.root, key.Public(), f.signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, f.root.Raw}, PrivateKey: key, Leaf: cert}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
func successfulOutput(cert []byte) commandOutput {
	return commandOutput{stdout: append(append([]byte{}, cert...), []byte("\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nVerify return code: 0 (ok)\n")...)}
}
func TestIndependentChecks(t *testing.T) {
	f := newFixture(t)
	_, rsaOK := f.leaf(t, "RSA", "example.test", f.now.Add(72*time.Hour), nil)
	_, ecOK := f.leaf(t, "ECDSA", "example.test", f.now.Add(72*time.Hour), elliptic.P384())
	_, rsaExpired := f.leaf(t, "RSA", "example.test", f.now.Add(-time.Second), nil)
	_, ecExpired := f.leaf(t, "ECDSA", "example.test", f.now.Add(-time.Second), elliptic.P256())
	for _, tc := range []struct {
		name          string
		rsa, ec       []byte
		badRSA, badEC bool
	}{
		{"both healthy", rsaOK, ecOK, false, false},
		{"RSA expired", rsaExpired, ecOK, true, false},
		{"ECDSA expired", rsaOK, ecExpired, false, true},
		{"RSA missing", nil, ecOK, true, false},
		{"ECDSA missing", rsaOK, nil, false, true},
		{"wrong public key", ecOK, ecOK, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			m := Monitor{Timeout: time.Second, Roots: f.roots, Now: func() time.Time { return f.now }, Run: func(_ context.Context, _ string, args []string) (commandOutput, error) {
				calls++
				if strings.Contains(strings.Join(args, " "), "rsa_pss") {
					return successfulOutput(tc.rsa), nil
				}
				return successfulOutput(tc.ec), nil
			}}
			results := m.CheckAll(context.Background(), []Target{{"example.test", 443, []string{"RSA", "ECDSA"}}})
			if calls != 2 || len(results) != 2 {
				t.Fatalf("did not run both checks: %d %+v", calls, results)
			}
			for i, want := range []bool{tc.badRSA, tc.badEC} {
				if (len(results[i].Problems) > 0) != want {
					t.Fatalf("result %d: %s", i, results[i])
				}
			}
			if tc.rsa != nil && results[0].Certificate == nil {
				t.Fatal("certificate information lost")
			}
		})
	}
}
func TestValidationAndBoundaries(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name, host, status, problem string
		remaining                   time.Duration
		untrusted, future           bool
	}{
		{name: "48h", remaining: 48 * time.Hour, status: "正常"},
		{name: "below48", remaining: 48*time.Hour - time.Nanosecond, status: "警告"},
		{name: "24h", remaining: 24 * time.Hour, status: "警告"},
		{name: "below24", remaining: 24*time.Hour - time.Nanosecond, status: "緊急"},
		{name: "zero", remaining: 0, status: "異常", problem: "期限切れ"},
		{name: "expired", remaining: -time.Second, status: "異常", problem: "期限切れ"},
		{name: "hostname mismatch", host: "wrong.test", remaining: 72 * time.Hour, status: "異常", problem: "ホスト名"},
		{name: "untrusted chain", remaining: 72 * time.Hour, status: "異常", problem: "チェーン", untrusted: true},
		{name: "not yet valid", remaining: 72 * time.Hour, status: "異常", problem: "まだ有効", future: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := tc.host
			if host == "" {
				host = "example.test"
			}
			// DER validity has second precision. Shift the clock to test nanosecond boundaries.
			expiry := f.now.Add(tc.remaining).Truncate(time.Second)
			now := expiry.Add(-tc.remaining)
			source := f
			if tc.future {
				source.now = f.now.Add(100 * time.Hour)
			}
			_, data := source.leaf(t, "ECDSA", host, expiry, elliptic.P256())
			roots := f.roots
			if tc.untrusted {
				roots = x509.NewCertPool()
			}
			m := Monitor{Timeout: time.Second, Roots: roots, Now: func() time.Time { return now }, Run: func(context.Context, string, []string) (commandOutput, error) { return successfulOutput(data), nil }}
			r := m.check(context.Background(), Target{"example.test", 443, nil}, "ECDSA")
			if r.Status != tc.status || !strings.Contains(strings.Join(r.Problems, " "), tc.problem) {
				t.Fatalf("%s", r)
			}
			if r.Certificate == nil || r.Remaining != tc.remaining {
				t.Fatalf("lost certificate/time: %s", r)
			}
		})
	}
}
func TestOpenSSLFailures(t *testing.T) {
	f := newFixture(t)
	_, data := f.leaf(t, "RSA", "example.test", f.now.Add(72*time.Hour), nil)
	for _, tc := range []struct {
		name string
		out  commandOutput
		err  error
	}{
		{"exit failure with valid PEM", successfulOutput(data), errors.New("exit status 1")},
		{"connection failure", commandOutput{}, errors.New("connection refused")},
		{"timeout", commandOutput{}, context.DeadlineExceeded},
		{"verification failure", commandOutput{stdout: bytes.Replace(successfulOutput(data).stdout, []byte("code: 0"), []byte("code: 20"), 1)}, nil},
		{"missing verification", commandOutput{stdout: data}, nil},
		{"missing handshake", commandOutput{stdout: append(data, []byte("Verify return code: 0 (ok)\n")...)}, nil},
		{"malformed certificate", successfulOutput(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad")})), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Monitor{Timeout: time.Second, Roots: f.roots, Now: func() time.Time { return f.now }, Run: func(context.Context, string, []string) (commandOutput, error) { return tc.out, tc.err }}
			r := m.check(context.Background(), Target{"example.test", 443, nil}, "RSA")
			if len(r.Problems) == 0 {
				t.Fatalf("accepted: %s", r)
			}
		})
	}
	out, err := runCommand(context.Background(), filepath.Join(t.TempDir(), "missing-openssl"), nil)
	if err == nil || len(out.stdout) != 0 {
		t.Fatal("missing executable accepted")
	}
}
func TestMultipleHostsAndNotification(t *testing.T) {
	f := newFixture(t)
	_, data := f.leaf(t, "ECDSA", "good.test", f.now.Add(72*time.Hour), elliptic.P256())
	m := Monitor{Timeout: time.Second, Roots: f.roots, Now: func() time.Time { return f.now }, Run: func(context.Context, string, []string) (commandOutput, error) { return successfulOutput(data), nil }}
	results := m.CheckAll(context.Background(), []Target{{"bad.test", 443, []string{"RSA", "ECDSA"}}, {"good.test", 443, []string{"ECDSA"}}})
	var log bytes.Buffer
	calls := 0
	notify := func(_ context.Context, message string) error {
		calls++
		for _, s := range []string{"bad.test", "RSA", "ECDSA", "有効期限:", "残り時間:"} {
			if !strings.Contains(message, s) {
				t.Errorf("missing %s", s)
			}
		}
		if strings.Contains(message, " — good.test:") {
			t.Error("healthy host notified")
		}
		return nil
	}
	if report(context.Background(), results, &log, notify) == nil || calls != 1 {
		t.Fatal("failures not aggregated")
	}
	calls = 0
	if report(context.Background(), results[2:], &log, notify) != nil || calls != 0 {
		t.Fatal("healthy result notified")
	}
	failure := errors.New("Slack unavailable")
	if err := report(context.Background(), results, &log, func(context.Context, string) error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("notification failure lost: %v", err)
	}
	if !strings.Contains(log.String(), "host=good.test") {
		t.Fatal("healthy certificate not logged")
	}
}

func opensslForTest(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("TEST_OPENSSL"); path != "" {
		return path
	}
	candidates := []string{"openssl"}
	if runtime.GOOS == "darwin" {
		candidates = append(candidates, "/opt/homebrew/opt/openssl@3/bin/openssl", "/usr/local/opt/openssl@3/bin/openssl")
	}
	for _, candidate := range candidates {
		path, err := exec.LookPath(candidate)
		if err != nil {
			continue
		}
		version, err := exec.Command(path, "version").Output()
		if err == nil && strings.HasPrefix(string(version), "OpenSSL ") {
			return path
		}
	}

	t.Skip("compatible OpenSSL is not installed (LibreSSL does not support -sigalgs); set TEST_OPENSSL")
	return ""
}
func TestLocalTLSCertificateSelection(t *testing.T) {
	binary := opensslForTest(t)
	f := newFixture(t)
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			rsaCert, _ := f.leaf(t, "RSA", "localhost", f.now.Add(72*time.Hour), nil)
			ecCert, _ := f.leaf(t, "ECDSA", "localhost", f.now.Add(72*time.Hour), curve)
			var mu sync.Mutex
			var selected []string
			config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if hello.ServerName != "localhost" {
					return nil, errors.New("missing SNI")
				}
				for _, entry := range []struct {
					key  string
					cert *tls.Certificate
				}{{"RSA", &rsaCert}, {"ECDSA", &ecCert}} {
					if err := hello.SupportsCertificate(entry.cert); err == nil {
						mu.Lock()
						selected = append(selected, entry.key)
						mu.Unlock()
						return entry.cert, nil
					}
				}
				return nil, errors.New("no compatible signature algorithm")
			}}
			listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					conn, e := listener.Accept()
					if e != nil {
						return
					}
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					_ = conn.(*tls.Conn).Handshake()
					_ = conn.Close()
				}
			}()
			defer func() { listener.Close(); <-done }()
			caFile := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			m := Monitor{OpenSSL: binary, Timeout: 5 * time.Second, CAFile: caFile, Roots: f.roots, Run: runCommand, Now: time.Now}
			results := m.CheckAll(context.Background(), []Target{{"localhost", listener.Addr().(*net.TCPAddr).Port, []string{"RSA", "ECDSA"}}})
			for _, r := range results {
				if len(r.Problems) > 0 {
					t.Fatalf("%s", r)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if fmt.Sprint(selected) != "[RSA ECDSA]" {
				t.Fatalf("unexpected selection: %v", selected)
			}
		})
	}
}
func TestRealConnectionFailureAndTimeout(t *testing.T) {
	binary := opensslForTest(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	// A real TCP peer that never speaks TLS must be killed by CommandContext.
	done := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(done)
		c, e := listener.Accept()
		if e == nil {
			defer c.Close()
			<-stop
		}
	}()
	m := Monitor{OpenSSL: binary, Timeout: 200 * time.Millisecond, Run: runCommand, Now: time.Now}
	start := time.Now()
	r := m.check(context.Background(), Target{"127.0.0.1", port, nil}, "RSA")
	close(stop)
	listener.Close()
	<-done
	if !strings.Contains(strings.Join(r.Problems, " "), "deadline exceeded") || time.Since(start) > 3*time.Second {
		t.Fatalf("timeout failed: %s", r)
	}
	r = m.check(context.Background(), Target{"127.0.0.1", port, nil}, "ECDSA")
	if len(r.Problems) == 0 {
		t.Fatal("connection failure accepted")
	}
}
