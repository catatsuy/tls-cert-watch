package main

import (
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestReadableAlert(t *testing.T) {
	expiry := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	results := []Result{
		{Host: "catatsuy.org", Port: 443, KeyType: "RSA", Status: "警告", Certificate: &x509.Certificate{NotAfter: expiry}, Remaining: 36*time.Hour + 20*time.Minute, Problems: []string{"有効期限まで48時間未満"}},
		{Host: "blog.catatsuy.org", Port: 443, KeyType: "ECDSA", Status: "異常", Problems: []string{"TLS接続失敗: <bad&peer>", "openssl_stderr=raw noise"}},
		{Host: "matw.co", Port: 443, KeyType: "RSA", Status: "異常", Certificate: &x509.Certificate{NotAfter: expiry}, Remaining: -time.Hour, Problems: []string{"証明書の有効期限切れ"}},
	}
	message := formatAlert(results, 8)
	for _, want := range []string{"検査 8件中 3件", "警告 — catatsuy.org:443 / RSA", "36時間20分0秒", "2026-11-04 12:00:00 UTC", "blog.catatsuy.org:443 / ECDSA", "不明（証明書を取得できませんでした）", "期限切れ（1時間0分0秒経過）", "&lt;bad&amp;peer&gt;"} {
		if !strings.Contains(message, want) {
			t.Errorf("missing %q: %s", want, message)
		}
	}
	if strings.Contains(message, "raw noise") {
		t.Fatal("raw diagnostics in alert")
	}
	// Notifications are summaries; log output retains complete command diagnostics.
	if !strings.Contains(results[1].String(), "raw noise") {
		t.Fatal("diagnostics lost from log")
	}
	if readableRemaining(time.Nanosecond) != "1秒未満" {
		t.Fatal("subsecond duration rounded incorrectly")
	}
}
func TestAlertLengthLimit(t *testing.T) {
	var results []Result
	for i := 0; i < 1000; i++ {
		results = append(results, Result{Host: fmt.Sprintf("host%d.test", i), Port: 443, KeyType: "RSA", Status: "異常", Problems: []string{strings.Repeat("失敗", 1000)}})
	}
	message := formatAlert(results, len(results))
	if len([]rune(message)) >= 40000 || !strings.Contains(message, "全件の詳細は実行ログ") {
		t.Fatal("long alert must explicitly summarize omitted checks")
	}
}
