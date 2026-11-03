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
	"strconv"
	"strings"
	"time"
)

type Target struct {
	Domain     string `json:"domain"`
	Subdomains bool   `json:"include_subdomains"`
}
type Cursor struct {
	After      string `json:"after"`
	Subdomains bool   `json:"include_subdomains"`
}
type State struct {
	Version int               `json:"version"`
	Domains map[string]Cursor `json:"domains"`
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
	Log           io.Writer
	PollUntil     map[string]time.Time
	SavePoll      func(map[string]time.Time) error
	Now           func() time.Time
}

// Poll deadlines are operational metadata, independent of issuance cursors.
func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
func (c *Client) cooldown(t Target, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	if c.PollUntil == nil {
		c.PollUntil = map[string]time.Time{}
	}
	c.PollUntil[t.Domain] = c.now().Add(d)
	c.logf("domain=%s next request not before %s", t.Domain, c.PollUntil[t.Domain].UTC().Format(time.RFC3339))
	if c.SavePoll != nil {
		return c.SavePoll(c.PollUntil)
	}
	return nil
}

func (c *Client) logf(format string, args ...any) {
	if c.Log != nil {
		fmt.Fprintf(c.Log, "CT: "+format+"\n", args...)
	}
}

func (c *Client) wait(ctx context.Context, t Target, d time.Duration, reason string) error {
	c.logf("domain=%s waiting=%s reason=%s", t.Domain, d, reason)
	return c.Wait(ctx, d)
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
		// Waiting before EVERY request also bounds usage across serialized workflow runs.
		pace := 41 * time.Second
		if t.Subdomains {
			pace = 361 * time.Second
		}
		if e := c.wait(ctx, t, pace, "Small plan request pacing"); e != nil {
			return nil, e
		}
		if until := c.PollUntil[t.Domain]; until.After(c.now()) {
			if e := c.wait(ctx, t, until.Sub(c.now()), "previous response Retry-After"); e != nil {
				return nil, e
			}
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
			if e = c.wait(ctx, t, time.Second<<attempt, "network retry backoff"); e != nil {
				return nil, e
			}
			continue
		}
		c.logf("domain=%s HTTP status=%d", t.Domain, res.StatusCode)
		delay := retryDelay(res.Header.Get("Retry-After"))
		data, readErr := io.ReadAll(io.LimitReader(res.Body, 8*1024*1024+1))
		res.Body.Close()
		if res.StatusCode == 429 || res.StatusCode >= 500 {
			if e = c.cooldown(t, max(delay, time.Second<<attempt)); e != nil {
				return nil, e
			}
			if attempt == 3 {
				return nil, fmt.Errorf("CT HTTP %d (retry exhausted)", res.StatusCode)
			}
			if e = c.wait(ctx, t, max(delay, time.Second<<attempt), "HTTP retry backoff / Retry-After"); e != nil {
				return nil, e
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
		c.logf("domain=%s page issuances=%d", t.Domain, len(page))
		// Completion does not require sleeping. The next run honors this deadline.
		if len(page) == 0 {
			if e = c.cooldown(t, delay); e != nil {
				return nil, e
			}
		}
		return page, nil
	}
	return nil, errors.New("CT retries exhausted")
}
func (c *Client) Fetch(ctx context.Context, t Target, after string) ([]Issuance, error) {
	c.logf("domain=%s fetching all pages", t.Domain)
	var all []Issuance
	seen := map[string]bool{}
	if after != "" {
		seen[after] = true
	}
	for pages := 0; pages < 1000; pages++ {
		p, e := c.page(ctx, t, after)
		if e != nil {
			return nil, e
		}
		if len(p) == 0 {
			c.logf("domain=%s pagination complete pages=%d issuances=%d", t.Domain, pages+1, len(all))
			return all, nil
		}
		for _, v := range p {
			if v.ID == "" || seen[v.ID] {
				return nil, errors.New("CT missing/repeated issuance id")
			}
			if len(v.DNSNames) == 0 || v.Issuer.Name == "" || v.Pubkey.Type == "" || v.Fingerprint == "" {
				return nil, errors.New("CT missing certificate information")
			}
			if _, e := time.Parse(time.RFC3339, v.NotBefore); e != nil {
				return nil, errors.New("CT invalid not_before")
			}
			if _, e := time.Parse(time.RFC3339, v.NotAfter); e != nil {
				return nil, errors.New("CT invalid not_after")
			}
			seen[v.ID] = true
			all = append(all, v)
		}
		after = p[len(p)-1].ID
	}
	return nil, errors.New("CT pagination limit reached; no cursor saved")
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
	if !init && (s.Version != 1 || s.Domains == nil) {
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

// Process collects all domains before notifying and mutates state only after notification succeeds.
func Process(ctx context.Context, c *Client, ts []Target, s State, init bool, notify func(context.Context, string) error) (State, bool, error) {
	if e := Validate(ts, s, init); e != nil {
		return s, false, e
	}
	next := State{Version: 1, Domains: map[string]Cursor{}}
	for k, v := range s.Domains {
		next.Domains[k] = v
	}
	changed := init
	message := "*CTログで新規証明書発行を検出しました*"
	for _, t := range ts {
		cur := s.Domains[t.Domain]
		if init {
			cur = Cursor{Subdomains: t.Subdomains}
		}
		items, e := c.Fetch(ctx, t, cur.After)
		if e != nil {
			return s, false, fmt.Errorf("%s: %w", t.Domain, e)
		}
		for _, v := range items {
			cur.After = v.ID
			if !init {
				message += Message(t, v)
			}
		}
		next.Domains[t.Domain] = cur
		if len(items) > 0 {
			changed = true
		}
	}
	if !init && changed {
		if len([]rune(message)) > 35000 {
			return s, false, errors.New("CT Slack message exceeds safe size; no cursor saved")
		}
		if e := notify(ctx, message); e != nil {
			return s, false, e
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
