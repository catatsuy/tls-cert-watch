package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "command")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestSlackCLI(t *testing.T) {
	t.Setenv("NOTIFY_SLACK_TOKEN", "test-secret")
	t.Setenv("NOTIFY_SLACK_CHANNEL_ID", "C123")
	output := filepath.Join(t.TempDir(), "message")
	t.Setenv("TEST_MESSAGE_FILE", output)
	binary := writeScript(t, `[ "$1" = '-c' ] && [ "$2" = '/dev/null' ] && [ "$3" = '-snippet' ] && [ "$4" = '-snippet-type' ] && [ "$5" = 'text' ] && [ "$6" = '-filename' ] && [ "$7" = 'tls-cert-watch.txt' ] || exit 1
cat > "$TEST_MESSAGE_FILE"`)
	notify := slackNotifier(binary, time.Second)
	if err := notify(context.Background(), "host=test RSA expires=... remaining=1h"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil || string(data) != "host=test RSA expires=... remaining=1h" {
		t.Fatalf("%q %v", data, err)
	}
	for _, tc := range []struct {
		name, binary string
		timeout      time.Duration
	}{
		{"failure", writeScript(t, "echo test-secret >&2; exit 1"), time.Second},
		{"missing", filepath.Join(t.TempDir(), "missing"), time.Second},
		{"timeout", writeScript(t, "exec sleep 10"), 50 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := slackNotifier(tc.binary, tc.timeout)(context.Background(), "bad")
			if err == nil || strings.Contains(err.Error(), "test-secret") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
	t.Setenv("NOTIFY_SLACK_TOKEN", "")
	if err := notify(context.Background(), "bad"); err == nil {
		t.Fatal("missing credentials accepted")
	}
}
func TestRunSetupAndCheckFailure(t *testing.T) {
	t.Setenv("NOTIFY_SLACK_TOKEN", "test-token")
	t.Setenv("NOTIFY_SLACK_CHANNEL_ID", "C123")
	dir := t.TempDir()
	message := filepath.Join(dir, "message")
	t.Setenv("TEST_MESSAGE_FILE", message)
	notify := writeScript(t, `cat >> "$TEST_MESSAGE_FILE"`)
	config := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(config, []byte(`[{"host":"example.test","key_types":["RSA","ECDSA"]}]`), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	err := run(context.Background(), []string{"-config", config, "-openssl", filepath.Join(dir, "missing"), "-notify-slack", notify}, &out, &errout)
	if err == nil {
		t.Fatal("checks should fail")
	}
	data, e := os.ReadFile(message)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Count(string(data), "tls-cert-watch: TLS証明書監視で異常を検出") != 1 || !strings.Contains(string(data), "key=RSA") || !strings.Contains(string(data), "key=ECDSA") {
		t.Fatalf("bad notification: %s", data)
	}
	err = run(context.Background(), []string{"-config", filepath.Join(dir, "missing-config"), "-notify-slack", notify}, &out, &errout)
	if err == nil {
		t.Fatal("setup should fail")
	}
	data, _ = os.ReadFile(message)
	if !strings.Contains(string(data), "監視開始失敗") {
		t.Fatal("setup failure not notified")
	}
	err = run(context.Background(), []string{"-config", config, "-openssl", filepath.Join(dir, "missing"), "-no-slack"}, &out, &errout)
	if err == nil || !strings.Contains(errout.String(), "無効化") {
		t.Fatal("no-slack should preserve check failure")
	}
}
func TestLimitedOutput(t *testing.T) {
	var b limitedBuffer
	data := bytes.Repeat([]byte("a"), outputLimit+1)
	if n, err := b.Write(data); err != nil || n != len(data) || !b.overflow || b.Len() != outputLimit {
		t.Fatal("output limit failed")
	}
	if n, err := b.Write([]byte("more")); n != 4 || err != nil || b.Len() != outputLimit {
		t.Fatal("cannot drain excess output")
	}
}
