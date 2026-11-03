package main

import (
	"context"
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
	if !*init {
		if e := ctwatch.Load(*state, &s); e != nil {
			return fmt.Errorf("state required; restore or explicitly initialize: %w", e)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Hour)
	defer cancel()
	c := &ctwatch.Client{HTTP: &http.Client{Timeout: 30 * time.Second}, Endpoint: "https://api.certspotter.com/v1/issuances", Key: key, Wait: ctwatch.Sleep}
	next, changed, e := ctwatch.Process(ctx, c, targets, s, *init, ctwatch.Notify)
	if e != nil {
		return e
	}
	if changed {
		return ctwatch.Save(*state, next)
	}
	fmt.Println("CT: no new issuances; no state update")
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
