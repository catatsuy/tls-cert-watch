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

func TestSlackNotifier(t *testing.T) {
	messages := mockSlack(t)
	t.Setenv("NOTIFY_SLACK_TOKEN", "test-secret")
	t.Setenv("NOTIFY_SLACK_CHANNEL_ID", "C123")
	notify := slackNotifier(time.Second)
	if err := notify(context.Background(), "certificate report"); err != nil {
		t.Fatal(err)
	}
	if len(*messages) != 1 || (*messages)[0] != "<!channel>\ncertificate report" {
		t.Fatalf("unexpected notification: %v", *messages)
	}
	t.Setenv("NOTIFY_SLACK_TOKEN", "")
	if err := notify(context.Background(), "bad"); err == nil {
		t.Fatal("missing credentials accepted")
	}
	if len(*messages) != 1 {
		t.Fatal("sent without credentials")
	}
}
func TestRunSetupAndCheckFailure(t *testing.T) {
	messages := mockSlack(t)
	t.Setenv("NOTIFY_SLACK_TOKEN", "test-token")
	t.Setenv("NOTIFY_SLACK_CHANNEL_ID", "C123")
	dir := t.TempDir()
	config := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(config, []byte(`[{"host":"example.test","key_types":["RSA","ECDSA"]}]`), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	err := run(context.Background(), []string{"-config", config, "-openssl", filepath.Join(dir, "missing")}, &out, &errout)
	if err == nil {
		t.Fatal("checks should fail")
	}
	if len(*messages) != 1 {
		t.Fatalf("expected single notification, got %v", *messages)
	}
	data := (*messages)[0]
	if !strings.Contains(data, "TLS証明書の監視") || !strings.Contains(data, "RSA") || !strings.Contains(data, "ECDSA") {
		t.Fatalf("bad notification: %s", data)
	}
	err = run(context.Background(), []string{"-config", filepath.Join(dir, "missing-config")}, &out, &errout)
	if err == nil {
		t.Fatal("setup should fail")
	}
	data = (*messages)[len(*messages)-1]
	if !strings.Contains(data, "監視を開始できませんでした") {
		t.Fatal("setup failure not notified")
	}
	err = run(context.Background(), []string{"-config", config, "-openssl", filepath.Join(dir, "missing"), "-no-slack"}, &out, &errout)
	if len(*messages) != 2 {
		t.Fatal("no-slack sent a message")
	}
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
