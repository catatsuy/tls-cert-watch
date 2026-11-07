package ctwatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/catatsuy/tls-cert-watch/internal/slack"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type Target struct {
	Domain     string `json:"domain"`
	Subdomains bool   `json:"include_subdomains"`
}
type Cursor struct {
	After      string   `json:"after"`
	Issuers    []string `json:"issuers"`
	Subdomains bool     `json:"include_subdomains"`
}
type State struct {
	Version int               `json:"version"`
	Domains map[string]Cursor `json:"domains"`
	Pending *Batch            `json:"pending,omitempty"`
}
type Issuance struct {
	ID       string   `json:"id"`
	DNSNames []string `json:"dns_names"`
	Issuer   struct {
		Name string `json:"friendly_name"`
	} `json:"issuer"`
	Pubkey struct {
		Type  string `json:"type"`
		Bits  int    `json:"bit_length"`
		Curve string `json:"curve"`
	} `json:"pubkey"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
	Fingerprint string `json:"cert_sha256"`
}
type Client struct {
	HTTP          *http.Client
	Endpoint, Key string
	Wait          func(context.Context, time.Duration) error
	Runtime       *Runtime
	SaveRuntime   func(*Runtime) error
	Now           func() time.Time
	Log           io.Writer
}

func Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
func retryDelay(h string) time.Duration {
	if n, e := strconv.Atoi(h); e == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if t, e := http.ParseTime(h); e == nil {
		return max(time.Until(t), 0)
	}
	return 0
}
func (c *Client) page(ctx context.Context, t Target, after string) ([]Issuance, error) {
	u, e := url.Parse(c.Endpoint)
	if e != nil {
		return nil, e
	}
	q := u.Query()
	q.Set("domain", t.Domain)
	q.Set("include_subdomains", strconv.FormatBool(t.Subdomains))
	q.Set("match_wildcards", "true")
	if after != "" {
		q.Set("after", after)
	}
	for _, v := range []string{"dns_names", "issuer", "pubkey"} {
		q.Add("expand", v)
	}
	u.RawQuery = q.Encode()
	for attempt := 0; attempt < 4; attempt++ {
		if e := c.beforeRequest(ctx, t); e != nil {
			return nil, e
		}
		req, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("Authorization", "Bearer "+c.Key)
		safe := *c.HTTP
		safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		c.logf("domain=%s requesting page attempt=%d", t.Domain, attempt+1)
		res, e := safe.Do(req)
		if e != nil {
			if attempt == 3 {
				return nil, errors.New("CT HTTP request failed")
			}
			if e = c.Wait(ctx, time.Second<<attempt); e != nil {
				return nil, e
			}
			continue
		}
		delay := retryDelay(res.Header.Get("Retry-After"))
		data, readErr := io.ReadAll(io.LimitReader(res.Body, 8*1024*1024+1))
		res.Body.Close()
		c.logf("domain=%s HTTP=%d", t.Domain, res.StatusCode)
		if res.StatusCode == 429 || res.StatusCode >= 500 {
			delay = max(delay, time.Second<<attempt)
			if e = c.deferRequest(t, delay, res.StatusCode == 429); e != nil {
				return nil, e
			}
			if res.StatusCode == 429 {
				return nil, fmt.Errorf("CT HTTP 429: %w", ErrDeferred)
			}
			if attempt == 3 || delay > 5*time.Second {
				return nil, fmt.Errorf("CT HTTP %d; resume next run", res.StatusCode)
			}
			continue
		}
		if res.StatusCode != 200 {
			return nil, fmt.Errorf("CT HTTP %d; no cursor saved", res.StatusCode)
		}
		if readErr != nil || len(data) > 8*1024*1024 {
			return nil, errors.New("CT response read failed or oversized")
		}
		var page []Issuance
		if e = json.Unmarshal(data, &page); e != nil || page == nil {
			return nil, errors.New("CT invalid JSON array")
		}
		if len(page) == 0 {
			if e = c.deferRequest(t, delay, false); e != nil {
				return nil, e
			}
		}
		c.logf("domain=%s received=%d", t.Domain, len(page))
		return page, nil
	}
	return nil, errors.New("CT retries exhausted")
}
func (c *Client) Fetch(ctx context.Context, t Target, after string) ([]Issuance, error) {
	p := &Progress{After: after}
	if e := c.fetchProgress(ctx, t, p); e != nil {
		return nil, e
	}
	return p.Items, nil
}
func (c *Client) fetchProgress(ctx context.Context, t Target, progress *Progress) error {
	seen := map[string]bool{}
	if progress.After != "" {
		seen[progress.After] = true
	}
	for _, v := range progress.Items {
		seen[v.ID] = true
	}
	for !progress.Complete {
		if progress.Pages >= 1000 {
			return errors.New("CT pagination limit reached")
		}
		p, e := c.page(ctx, t, progress.After)
		if e != nil {
			return e
		}
		if len(p) == 0 {
			progress.Complete = true
			c.logf("domain=%s complete issuances=%d", t.Domain, len(progress.Items))
			return nil
		}
		// Validate the entire page before adding it to the durable checkpoint.
		pageSeen := map[string]bool{}
		for _, v := range p {
			if v.ID == "" || seen[v.ID] || pageSeen[v.ID] {
				return errors.New("CT missing/repeated issuance id")
			}
			pageSeen[v.ID] = true
			if len(v.DNSNames) == 0 || v.Issuer.Name == "" || v.Pubkey.Type == "" || v.Fingerprint == "" {
				return errors.New("CT missing certificate information")
			}
			if _, e = time.Parse(time.RFC3339, v.NotBefore); e != nil {
				return errors.New("CT invalid not_before")
			}
			if _, e = time.Parse(time.RFC3339, v.NotAfter); e != nil {
				return errors.New("CT invalid not_after")
			}
		}
		for _, v := range p {
			seen[v.ID] = true
		}
		progress.Items = append(progress.Items, p...)
		progress.After = p[len(p)-1].ID
		progress.Pages++
	}
	return nil
}

func Load(path string, v any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func Validate(ts []Target, s State, init bool) error {
	if len(ts) == 0 {
		return errors.New("empty CT targets")
	}
	seen := map[string]bool{}
	for _, t := range ts {
		if t.Domain == "" || strings.ContainsAny(t.Domain, " /:*?@&<>\n\r") || !strings.Contains(t.Domain, ".") || seen[t.Domain] {
			return errors.New("invalid/duplicate CT domain")
		}
		seen[t.Domain] = true
		if !init {
			v, ok := s.Domains[t.Domain]
			if !ok || v.Subdomains != t.Subdomains {
				return fmt.Errorf("missing or changed baseline for %s: explicit initialization required", t.Domain)
			}
		}
	}
	if !init && ((s.Version != 1 && s.Version != 2) || s.Domains == nil) {
		return errors.New("invalid CT state")
	}
	return nil
}
func Escape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
func Message(t Target, v Issuance) string {
	key := strings.ToUpper(v.Pubkey.Type)
	if key == "RSA" {
		key += fmt.Sprintf(" %d bits", v.Pubkey.Bits)
	}
	if key == "ECDSA" {
		key += " " + v.Pubkey.Curve
	}
	return fmt.Sprintf("\n\n対象: %s\n発行ID: %s\nSAN/CN: %s\nCA: %s\n公開鍵: %s\n発行日時 (NotBefore): %s\n期限: %s\nSHA-256: %s", Escape(t.Domain), Escape(v.ID), Escape(strings.Join(v.DNSNames, ", ")), Escape(v.Issuer.Name), Escape(key), Escape(v.NotBefore), Escape(v.NotAfter), Escape(v.Fingerprint))
}

// Process preserves partial acquisition separately from acknowledged cursors.
// Only a complete, successfully notified batch advances those cursors.
func Process(ctx context.Context, c *Client, ts []Target, s State, init bool, notify func(context.Context, string) error) (State, bool, error) {
	if e := Validate(ts, State{}, true); e != nil {
		return s, false, e
	}
	if s.Version != 0 && s.Version != 1 && s.Version != 2 {
		return s, false, errors.New("unsupported CT state version")
	}

	// Version 1 stored only cursors. Rebuild issuer history from all available
	// certificates without treating historical issuers as new alerts.
	if s.Version == 1 {
		if e := Validate(ts, s, init || s.Pending != nil && s.Pending.Initialize); e != nil {
			return s, false, e
		}
		if s.Pending != nil && !reflect.DeepEqual(ts, s.Pending.Targets) {
			return s, false, errors.New("CT targets changed during pending acquisition; restore matching config")
		}
		s.Version = 2
		if s.Pending != nil && !s.Pending.Initialize {
			s.Pending = nil
		}
		init = true
		c.logf("building issuer history from existing certificates")
	}

	if s.Pending != nil {
		if s.Pending.Domains == nil {
			return s, false, errors.New("invalid CT pending domains")
		}
		known := map[string]bool{}
		for _, t := range ts {
			known[t.Domain] = true
		}
		for domain, p := range s.Pending.Domains {
			if !known[domain] || p == nil || p.Pages < 0 || p.Pages > 1000 {
				return s, false, errors.New("invalid CT progress")
			}
			seen := map[string]bool{}
			for _, v := range p.Items {
				if v.ID == "" || seen[v.ID] {
					return s, false, errors.New("invalid CT pending issuance")
				}
				seen[v.ID] = true
			}
			if len(p.Items) > 0 && p.After != p.Items[len(p.Items)-1].ID {
				return s, false, errors.New("invalid CT pending cursor")
			}
		}
		if !reflect.DeepEqual(ts, s.Pending.Targets) {
			return s, false, errors.New("CT targets changed during pending acquisition; restore matching config or explicitly recover state")
		}
		if init && !s.Pending.Initialize {
			return s, false, errors.New("finish pending monitoring before reinitializing")
		}
		if !s.Pending.Initialize {
			if e := Validate(ts, s, false); e != nil {
				return s, false, e
			}
		}
	} else {
		if e := Validate(ts, s, init); e != nil {
			return s, false, e
		}
	}
	// Work on a copy: the acknowledged cursors stay unchanged on every failure.
	data, _ := json.Marshal(s)
	var working State
	if e := json.Unmarshal(data, &working); e != nil {
		return s, false, e
	}
	if working.Pending == nil {
		working.Pending = &Batch{Initialize: init, Targets: ts, Domains: map[string]*Progress{}}
	}
	batch := working.Pending
	for _, t := range ts {
		p := batch.Domains[t.Domain]
		if p == nil {
			after := ""
			if !batch.Initialize {
				after = s.Domains[t.Domain].After
			}
			p = &Progress{After: after}
			batch.Domains[t.Domain] = p
		}
		if e := c.fetchProgress(ctx, t, p); e != nil {
			return working, false, fmt.Errorf("%s: %w", t.Domain, e)
		}
	}
	next := State{Version: 2, Domains: map[string]Cursor{}}
	for k, v := range s.Domains {
		next.Domains[k] = v
	}
	changed := batch.Initialize
	message := "*CTログで未確認の発行元による証明書発行を検出しました*"
	alert := false
	for _, t := range ts {
		p := batch.Domains[t.Domain]
		issuers := append([]string{}, s.Domains[t.Domain].Issuers...)
		known := map[string]bool{}
		for _, issuer := range issuers {
			known[issuer] = true
		}
		for _, v := range p.Items {
			if !batch.Initialize && !known[v.Issuer.Name] {
				message += Message(t, v)
				alert = true
			}
		}
		for _, v := range p.Items {
			if !known[v.Issuer.Name] {
				issuers = append(issuers, v.Issuer.Name)
				known[v.Issuer.Name] = true
			}
		}
		next.Domains[t.Domain] = Cursor{After: p.After, Subdomains: t.Subdomains, Issuers: issuers}
		if len(p.Items) > 0 {
			changed = true
		}
	}
	if alert {
		if len([]rune(message)) > 35000 {
			return working, false, errors.New("CT Slack message exceeds safe size; no cursor saved")
		}
		if e := notify(ctx, message); e != nil {
			return working, false, e
		}
	}
	return next, changed, nil
}

func Notify(ctx context.Context, message string) error {
	token, channel := os.Getenv("NOTIFY_SLACK_TOKEN"), os.Getenv("NOTIFY_SLACK_CHANNEL_ID")
	if token == "" || channel == "" {
		return errors.New("Slack secrets missing")
	}
	child, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return slack.PostMessage(child, &http.Client{Timeout: time.Minute}, token, channel, message)
}
func Save(path string, s any) error {
	b, e := json.MarshalIndent(s, "", "  ")
	if e != nil {
		return e
	}
	tmp := path + ".tmp"
	if e = os.WriteFile(tmp, append(b, '\n'), 0600); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}
