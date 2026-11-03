package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/catatsuy/tls-cert-watch/internal/ctwatch"
	"net/http"
	"os"
	"time"
)

func run() error {
	config := flag.String("config", "ct-targets.json", "CT targets")
	state := flag.String("state", "ct-state.json", "state file")
	runtimePath := flag.String("runtime", "ct-runtime.json", "request budget and Retry-After metadata")
	init := flag.Bool("initialize", false, "explicit baseline (no notifications)")
	flag.Parse()
	key := os.Getenv("CERTSPOTTER_API_KEY")
	if key == "" {
		return fmt.Errorf("CERTSPOTTER_API_KEY required")
	}
	var targets []ctwatch.Target
	if e := ctwatch.Load(*config, &targets); e != nil {
		return e
	}
	var s ctwatch.State
	if e := ctwatch.Load(*state, &s); e != nil {
		if !*init || !errors.Is(e, os.ErrNotExist) {
			return fmt.Errorf("state required; restore or explicitly initialize: %w", e)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	c := &ctwatch.Client{HTTP: &http.Client{Timeout: 30 * time.Second}, Endpoint: "https://api.certspotter.com/v1/issuances", Key: key, Wait: ctwatch.Sleep, Log: os.Stderr}
	var runtime ctwatch.Runtime
	if e := ctwatch.Load(*runtimePath, &runtime); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	c.Runtime = &runtime
	c.SaveRuntime = func(r *ctwatch.Runtime) error { return ctwatch.Save(*runtimePath, r) }
	next, changed, processErr := ctwatch.Process(ctx, c, targets, s, *init, ctwatch.Notify)
	// Persist partial acquisition even on API/Slack failure. Acknowledged cursors
	// are advanced by Process only after the complete batch was notified.
	if e := ctwatch.Save(*state, next); e != nil {
		return errors.Join(processErr, e)
	}
	if processErr != nil {
		return processErr
	}
	if changed {
		fmt.Println("CT: complete; acknowledged cursors saved")
	} else {
		fmt.Println("CT: complete; no new issuances")
	}
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
