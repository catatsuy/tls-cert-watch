package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

type notifier func(context.Context, string) error

func slackNotifier(binary string, timeout time.Duration) notifier {
	return func(ctx context.Context, message string) error {
		if os.Getenv("NOTIFY_SLACK_TOKEN") == "" || os.Getenv("NOTIFY_SLACK_CHANNEL_ID") == "" {
			return errors.New("NOTIFY_SLACK_TOKEN and NOTIFY_SLACK_CHANNEL_ID are required")
		}
		child, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd := exec.CommandContext(child, binary, "-c", "/dev/null", "-snippet", "-snippet-type", "text", "-filename", "tls-cert-watch.txt")
		cmd.Stdin = strings.NewReader(message)
		// Do not expose third-party CLI output, which might contain credentials.
		if err := cmd.Run(); err != nil {
			if child.Err() != nil {
				return fmt.Errorf("notify_slack: %w", child.Err())
			}
			return fmt.Errorf("notify_slack failed: %w", err)
		}
		return nil
	}
}

func report(ctx context.Context, results []Result, log io.Writer, notify notifier) error {
	var failures []string
	for _, r := range results {
		fmt.Fprintln(log, r.String())
		if len(r.Problems) > 0 {
			failures = append(failures, r.String())
		}
	}
	if len(failures) == 0 {
		return nil
	}
	message := "tls-cert-watch: TLS証明書監視で異常を検出\n\n" + strings.Join(failures, "\n\n")
	err := notify(ctx, message)
	if err != nil {
		return fmt.Errorf("%d checks failed; Slack通知失敗: %w", len(failures), err)
	}
	return fmt.Errorf("%d checks failed", len(failures))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("tls-cert-watch", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := flags.String("config", "targets.json", "JSON configuration file")
	openssl := flags.String("openssl", "openssl", "OpenSSL executable (OpenSSL 3 recommended)")
	timeout := flags.Duration("timeout", 20*time.Second, "timeout per TLS connection")
	notifyTimeout := flags.Duration("notify-timeout", 60*time.Second, "Slack notification timeout")
	notifyBinary := flags.String("notify-slack", "notify_slack", "notify_slack executable")
	caFile := flags.String("ca-file", "", "optional PEM CA bundle (OpenSSL and Go)")
	noSlack := flags.Bool("no-slack", false, "local checks only; failures still exit nonzero")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *timeout <= 0 || *notifyTimeout <= 0 {
		return errors.New("timeouts must be positive")
	}
	notify := slackNotifier(*notifyBinary, *notifyTimeout)
	if *noSlack {
		notify = func(context.Context, string) error {
			fmt.Fprintln(stderr, "Slack通知を無効化しています (-no-slack)")
			return nil
		}
	}
	// Setup errors also attempt notification: an invalid config must not silently
	// disable monitoring. Keep this separate from report to avoid double posting.
	setupError := func(err error) error {
		if e := notify(ctx, "tls-cert-watch: 監視開始失敗: "+err.Error()); e != nil {
			return errors.Join(err, e)
		}
		return err
	}
	file, err := os.Open(*config)
	if err != nil {
		return setupError(err)
	}
	targets, err := loadConfig(file)
	file.Close()
	if err != nil {
		return setupError(err)
	}
	var roots *x509.CertPool
	if *caFile != "" {
		data, e := os.ReadFile(*caFile)
		if e != nil {
			return setupError(e)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return setupError(errors.New("CA file contains no certificates"))
		}
	}
	m := Monitor{OpenSSL: *openssl, Timeout: *timeout, CAFile: *caFile, Roots: roots, Run: runCommand, Now: time.Now}
	return report(ctx, m.CheckAll(ctx, targets), stdout, notify)
}
func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
