package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const outputLimit = 1024 * 1024

// Keep untrusted command output bounded, while continuing to drain both pipes.
type limitedBuffer struct {
	buffer   bytes.Buffer
	overflow bool
}

func (b *limitedBuffer) Len() int      { return b.buffer.Len() }
func (b *limitedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	available := outputLimit - b.Len()
	if len(p) > available {
		b.overflow = true
		p = p[:available]
	}
	_, _ = b.buffer.Write(p)
	return n, nil
}

type commandOutput struct{ stdout, stderr []byte }
type commandRunner func(context.Context, string, []string) (commandOutput, error)

func runCommand(ctx context.Context, name string, args []string) (commandOutput, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errout limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &errout
	// nil stdin supplies EOF; do not use -ign_eof, which would wait for application data.
	err := cmd.Run()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if out.overflow || errout.overflow {
		err = fmt.Errorf("command output exceeded %d bytes", outputLimit)
	}
	return commandOutput{out.Bytes(), errout.Bytes()}, err
}

func sigalgs(key string) string {
	if key == "RSA" {
		return "rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512"
	}
	return "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512"
}

func opensslArgs(t Target, key, caFile string) []string {
	args := []string{"s_client", "-connect", net.JoinHostPort(t.Host, strconv.Itoa(t.Port)), "-servername", t.Host, "-tls1_3", "-sigalgs", sigalgs(key), "-showcerts", "-no_ign_eof"}
	if net.ParseIP(t.Host) != nil {
		args = append(args, "-verify_ip", t.Host)
	} else {
		args = append(args, "-verify_hostname", t.Host)
	}
	if caFile != "" {
		args = append(args, "-CAfile", caFile)
	}
	return args
}

type Result struct {
	Host        string
	Port        int
	KeyType     string
	Status      string
	Certificate *x509.Certificate
	Remaining   time.Duration
	Problems    []string
}

func (r *Result) fail(message string) { r.Problems = append(r.Problems, message); r.Status = "異常" }
func (r Result) String() string {
	expiry, remaining, notBefore, actual := "不明", "不明", "不明", "不明"
	if r.Certificate != nil {
		expiry = r.Certificate.NotAfter.UTC().Format(time.RFC3339)
		notBefore = r.Certificate.NotBefore.UTC().Format(time.RFC3339)
		remaining = r.Remaining.String()
		actual = r.Certificate.PublicKeyAlgorithm.String()
	}
	detail := "OK"
	if len(r.Problems) > 0 {
		detail = strings.Join(r.Problems, "; ")
	}
	return fmt.Sprintf("host=%s port=%d key=%s status=%s public_key=%s not_before=%s expires=%s remaining=%s detail=%s", r.Host, r.Port, r.KeyType, r.Status, actual, notBefore, expiry, remaining, detail)
}

type Monitor struct {
	OpenSSL string
	Timeout time.Duration
	CAFile  string
	Roots   *x509.CertPool
	Run     commandRunner
	Now     func() time.Time
}

var handshakePattern = regexp.MustCompile(`(?m)^New, TLSv1\.3, Cipher is ([A-Za-z0-9_]+)\s*$`)
var verifyPattern = regexp.MustCompile(`(?m)^\s*Verify return code: (\d+) \([^\r\n]*\)`)

func (m Monitor) check(ctx context.Context, t Target, key string) Result {
	r := Result{Host: t.Host, Port: t.Port, KeyType: key, Status: "正常"}
	child, cancel := context.WithTimeout(ctx, m.Timeout)
	defer cancel()
	out, err := m.Run(child, m.OpenSSL, opensslArgs(t, key, m.CAFile))
	now := m.Now()
	if err != nil {
		r.fail("OpenSSL実行/TLS接続失敗: " + err.Error())
	}
	handshake := handshakePattern.FindSubmatch(out.stdout)
	if len(handshake) == 0 || string(handshake[1]) == "NONE" {
		r.fail("TLS 1.3ハンドシェイク成功を確認できない")
	}
	codes := verifyPattern.FindAllSubmatch(out.stdout, -1)
	if len(codes) == 0 {
		r.fail("OpenSSL検証結果が存在しない")
	}
	for _, code := range codes {
		if string(code[1]) != "0" {
			r.fail("OpenSSL証明書検証失敗: code=" + string(code[1]))
		}
	}
	// s_client deliberately continues after verification errors to retain the peer's
	// certificate. Neither its exit code nor a PEM block alone establishes success.
	var certs []*x509.Certificate
	rest := out.stdout
	for {
		block, tail := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = tail
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			r.fail("証明書解析失敗: " + e.Error())
			continue
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		r.fail("証明書が取得できない")
	} else {
		cert := certs[0]
		r.Certificate = cert
		r.Remaining = cert.NotAfter.Sub(now)
		expected := x509.RSA
		if key == "ECDSA" {
			expected = x509.ECDSA
		}
		if cert.PublicKeyAlgorithm != expected {
			r.fail("公開鍵種別不一致: got=" + cert.PublicKeyAlgorithm.String() + " want=" + key)
		}
		if e := cert.VerifyHostname(t.Host); e != nil {
			r.fail("ホスト名検証失敗: " + e.Error())
		}
		intermediates := x509.NewCertPool()
		for _, c := range certs[1:] {
			intermediates.AddCert(c)
		}
		if _, e := cert.Verify(x509.VerifyOptions{Roots: m.Roots, Intermediates: intermediates, CurrentTime: now, DNSName: t.Host, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
			r.fail("証明書チェーン/有効期間検証失敗: " + e.Error())
		}
		if !cert.NotAfter.After(cert.NotBefore) {
			r.fail("NotBefore/NotAfterの順序が不正")
		}
		if now.Before(cert.NotBefore) {
			r.fail("証明書はまだ有効でない")
		}
		switch {
		case r.Remaining <= 0:
			r.fail("証明書の有効期限切れ")
		case r.Remaining < 24*time.Hour:
			if r.Status == "正常" {
				r.Status = "緊急"
			}
			r.Problems = append(r.Problems, "有効期限まで24時間未満")
		case r.Remaining < 48*time.Hour:
			if r.Status == "正常" {
				r.Status = "警告"
			}
			r.Problems = append(r.Problems, "有効期限まで48時間未満")
		}
	}
	if len(r.Problems) > 0 && len(out.stderr) > 0 {
		// Quote diagnostics onto one log line. Do not log stdout (contains session data).
		diagnostic := out.stderr
		if len(diagnostic) > 4096 {
			diagnostic = diagnostic[:4096]
		}
		r.Problems = append(r.Problems, "openssl_stderr="+strconv.Quote(string(diagnostic)))
	}
	return r
}

func (m Monitor) CheckAll(ctx context.Context, targets []Target) []Result {
	var results []Result
	for _, t := range targets {
		for _, key := range t.KeyTypes {
			results = append(results, m.check(ctx, t, key))
		}
	}
	return results
}
