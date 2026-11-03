package ctwatch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, handler http.HandlerFunc) (*Client, *[]time.Duration) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	var waits []time.Duration
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	return &Client{Now: func() time.Time { return now }, HTTP: server.Client(), Endpoint: server.URL, Key: "secret", Wait: func(_ context.Context, d time.Duration) error { waits = append(waits, d); now = now.Add(d); return nil }}, &waits
}
func event(id string) string {
	return fmt.Sprintf(`{"id":%q,"dns_names":["<@evil>&"],"issuer":{"friendly_name":"CA"},"pubkey":{"type":"ecdsa","curve":"P-384"},"not_before":"2020-01-01T00:00:00Z","not_after":"2020-02-01T00:00:00Z","cert_sha256":"abcd"}`, id)
}
func baseline() State {
	return State{Version: 1, Domains: map[string]Cursor{"example.com": {After: "old", Subdomains: true}}}
}

var target = []Target{{Domain: "example.com", Subdomains: true}}

func TestPaginationAndNotification(t *testing.T) {
	calls := 0
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("auth")
		}
		if r.URL.Query().Get("include_subdomains") != "true" || len(r.URL.Query()["expand"]) != 3 {
			t.Error("expansions")
		}
		switch r.URL.Query().Get("after") {
		case "old":
			fmt.Fprint(w, "["+event("a")+"]")
		case "a":
			fmt.Fprint(w, "["+event("b")+"]")
		case "b":
			fmt.Fprint(w, "[]")
		default:
			t.Error("cursor")
		}
	})
	notifications := 0
	s, changed, e := Process(context.Background(), c, target, baseline(), false, func(_ context.Context, m string) error {
		notifications++
		if calls != 3 || !strings.Contains(m, "&lt;@evil&gt;&amp;") || !strings.Contains(m, "ECDSA P-384") || !strings.Contains(m, "発行ID: b") {
			t.Error(m)
		}
		return nil
	})
	if e != nil || !changed || s.Domains["example.com"].After != "b" || notifications != 1 {
		t.Fatalf("%+v %v", s, e)
	}
}
func TestInitialization(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("after") == "" {
					fmt.Fprint(w, "["+event("a")+"]")
				} else if fail {
					w.WriteHeader(403)
				} else {
					fmt.Fprint(w, "[]")
				}
			})
			s, changed, e := Process(context.Background(), c, target, State{}, true, func(context.Context, string) error { t.Fatal("baseline notified"); return nil })
			if fail {
				if e == nil || changed || s.Domains != nil {
					t.Fatal("partial baseline accepted")
				}
			} else if e != nil || !changed || s.Domains["example.com"].After != "a" {
				t.Fatal(s, e)
			}
		})
	}
}
func TestFailuresDoNotAdvance(t *testing.T) {
	for _, response := range []string{"bad", "null", "{}", "[] trailing", "[{\"id\":\"old\"}]"} {
		t.Run(response, func(t *testing.T) {
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, response) })
			s, changed, e := Process(context.Background(), c, target, baseline(), false, func(context.Context, string) error { t.Fatal("notified"); return nil })
			if e == nil || changed || s.Domains["example.com"].After != "old" {
				t.Fatal(s, e)
			}
		})
	}
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") == "old" {
			fmt.Fprint(w, "["+event("new")+"]")
		} else {
			fmt.Fprint(w, "[]")
		}
	})
	s, changed, e := Process(context.Background(), c, target, baseline(), false, func(context.Context, string) error { return errors.New("Slack failed") })
	if e == nil || changed || s.Domains["example.com"].After != "old" {
		t.Fatal(s, e)
	}
}
func TestNoNewAndMissingState(t *testing.T) {
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "[]") })
	_, changed, e := Process(context.Background(), c, target, baseline(), false, func(context.Context, string) error { t.Fatal("notified"); return nil })
	if e != nil || changed {
		t.Fatal(e)
	}
	if Validate(target, State{}, false) == nil {
		t.Fatal("missing state accepted")
	}
	s := baseline()
	s.Domains["example.com"] = Cursor{After: "old"}
	if Validate(target, s, false) == nil {
		t.Fatal("query changed")
	}
}
func TestRetryAfter(t *testing.T) {
	n := 0
	c, waits := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		n++
		w.Header().Set("Retry-After", "600")
		w.WriteHeader(429)
	})
	_, e := c.Fetch(context.Background(), target[0], "old")
	if e == nil || n != 4 {
		t.Fatal(n, e)
	}
	found := false
	for _, d := range *waits {
		if d == 600*time.Second {
			found = true
		}
	}
	if !found {
		t.Fatal(*waits)
	}
}
func TestTimeoutAndSaveFailure(t *testing.T) {
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, e := c.Fetch(ctx, target[0], "old"); e == nil {
		t.Fatal("timeout accepted")
	}
	if Save(t.TempDir()+"/missing/state", baseline()) == nil {
		t.Fatal("save accepted")
	}
}
func TestRSA(t *testing.T) {
	v := Issuance{}
	v.Pubkey.Type = "rsa"
	v.Pubkey.Bits = 2048
	if !strings.Contains(Message(target[0], v), "RSA 2048 bits") {
		t.Fatal("RSA missing")
	}
}

func TestAllDomainsBeforeNotification(t *testing.T) {
	ts := append(append([]Target{}, target...), Target{Domain: "other.example.com"})
	s := baseline()
	s.Domains["other.example.com"] = Cursor{After: "old"}
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("domain") == "other.example.com" {
			w.WriteHeader(403)
			return
		}
		if r.URL.Query().Get("after") == "old" {
			fmt.Fprint(w, "["+event("new")+"]")
		} else {
			fmt.Fprint(w, "[]")
		}
	})
	next, changed, e := Process(context.Background(), c, ts, s, false, func(context.Context, string) error { t.Fatal("partial result notified"); return nil })
	if e == nil || changed || next.Domains["example.com"].After != "old" {
		t.Fatal(next, e)
	}
}
func TestEmptyBaselineAndRecovery(t *testing.T) {
	n := 0
	c, waits := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.Header().Set("Retry-After", "700")
			w.WriteHeader(503)
		} else {
			w.Header().Set("Retry-After", "10")
			fmt.Fprint(w, "[]")
		}
	})
	s, changed, e := Process(context.Background(), c, target, State{}, true, func(context.Context, string) error { t.Fatal("notified"); return nil })
	if e != nil || !changed || s.Domains["example.com"].After != "" || !s.Domains["example.com"].Subdomains {
		t.Fatal(s, e)
	}
	if len(*waits) != 3 || (*waits)[1] != 700*time.Second {
		t.Fatal(*waits)
	}
	if c.PollUntil["example.com"].Sub(c.now()) != 10*time.Second {
		t.Fatal(c.PollUntil)
	}
	path := t.TempDir() + "/state.json"
	if e = Save(path, s); e != nil {
		t.Fatal(e)
	}
	var restored State
	if e = Load(path, &restored); e != nil {
		t.Fatal(e)
	}
	if e = Validate(target, restored, false); e != nil {
		t.Fatal(e)
	}
}
func TestMessageTooLarge(t *testing.T) {
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") == "old" {
			fmt.Fprint(w, "["+strings.ReplaceAll(event("new"), "CA", strings.Repeat("x", 36000))+"]")
		} else {
			fmt.Fprint(w, "[]")
		}
	})
	_, changed, e := Process(context.Background(), c, target, baseline(), false, func(context.Context, string) error { t.Fatal("oversize notified"); return nil })
	if e == nil || changed {
		t.Fatal(e)
	}
}

func TestEmptyPageEndsImmediatelyAndNextRunWaits(t *testing.T) {
	c, waits := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3600")
		fmt.Fprint(w, "[]")
	})
	path := t.TempDir() + "/poll.json"
	c.SavePoll = func(p map[string]time.Time) error { return Save(path, p) }
	if _, e := c.Fetch(context.Background(), target[0], "old"); e != nil {
		t.Fatal(e)
	}
	if len(*waits) != 1 || (*waits)[0] != 361*time.Second {
		t.Fatalf("completion slept: %v", *waits)
	}
	var poll map[string]time.Time
	if e := Load(path, &poll); e != nil {
		t.Fatal(e)
	}
	next, nextWaits := fixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "[]") })
	next.PollUntil = poll
	start := c.now()
	next.Now = func() time.Time { return start }
	next.Wait = func(_ context.Context, d time.Duration) error {
		*nextWaits = append(*nextWaits, d)
		start = start.Add(d)
		return nil
	}
	if _, e := next.Fetch(context.Background(), target[0], "old"); e != nil {
		t.Fatal(e)
	}
	var total time.Duration
	for _, d := range *nextWaits {
		total += d
	}
	if total != time.Hour {
		t.Fatalf("next run waited %s", total)
	}
}
func TestPollSaveFailureDoesNotAdvance(t *testing.T) {
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") == "old" {
			fmt.Fprint(w, "["+event("new")+"]")
		} else {
			w.Header().Set("Retry-After", "3600")
			fmt.Fprint(w, "[]")
		}
	})
	c.SavePoll = func(map[string]time.Time) error { return errors.New("disk full") }
	s, changed, e := Process(context.Background(), c, target, baseline(), false, func(context.Context, string) error { t.Fatal("notified before metadata saved"); return nil })
	if e == nil || changed || s.Domains["example.com"].After != "old" {
		t.Fatal(s, e)
	}
}
