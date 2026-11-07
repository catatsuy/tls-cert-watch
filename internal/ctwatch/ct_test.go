package ctwatch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	return &Client{HTTP: server.Client(), Endpoint: server.URL, Key: "secret", Now: func() time.Time { return now }, Wait: func(_ context.Context, d time.Duration) error { waits = append(waits, d); now = now.Add(d); return nil }}, &waits
}
func event(id string) string {
	return fmt.Sprintf(`{"id":%q,"dns_names":["<@evil>&"],"issuer":{"friendly_name":"CA"},"pubkey":{"type":"ecdsa","curve":"P-384"},"not_before":"2020-01-01T00:00:00Z","not_after":"2020-02-01T00:00:00Z","cert_sha256":"abcd"}`, id)
}
func baseline() State {
	return State{Version: 2, Domains: map[string]Cursor{"example.com": {After: "old", Subdomains: true}}}
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
	if _, e := c.Fetch(context.Background(), target[0], "old"); !errors.Is(e, ErrDeferred) || n != 1 {
		t.Fatal(n, e)
	}
	if _, e := c.Fetch(context.Background(), target[0], "old"); !errors.Is(e, ErrDeferred) || n != 1 {
		t.Fatal(n, e)
	}
	for _, d := range *waits {
		if d > 5*time.Second {
			t.Fatal("long wait", d)
		}
	}
	if c.Runtime.GlobalUntil.Sub(c.now()) != 600*time.Second {
		t.Fatal(c.Runtime)
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
	if e == nil || changed || s.Version == 2 || s.Pending == nil {
		t.Fatal(s, e)
	}
	now := c.now().Add(701 * time.Second)
	c.Now = func() time.Time { return now }
	s, changed, e = Process(context.Background(), c, target, s, false, func(context.Context, string) error { t.Fatal("notified"); return nil })
	if e != nil || !changed || s.Domains["example.com"].After != "" || !s.Domains["example.com"].Subdomains || s.Pending != nil {
		t.Fatal(s, e)
	}
	for _, d := range *waits {
		if d > 5*time.Second {
			t.Fatal("long wait", d)
		}
	}
	if c.Runtime.PollUntil["example.com"].Sub(c.now()) != 10*time.Second {
		t.Fatal(c.Runtime.PollUntil)
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

func TestBudgetCheckpointResume(t *testing.T) {
	for _, initialize := range []bool{false, true} {
		t.Run(fmt.Sprint(initialize), func(t *testing.T) {
			calls := []string{}
			c, waits := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				after := r.URL.Query().Get("after")
				calls = append(calls, after)
				n := 0
				if after != "" && after != "old" {
					var e error
					n, e = strconv.Atoi(after)
					if e != nil {
						t.Error(e)
					}
				}
				if n == 12 {
					fmt.Fprint(w, "[]")
				} else {
					fmt.Fprint(w, "["+event(strconv.Itoa(n+1))+"]")
				}
			})
			s := baseline()
			if initialize {
				s = State{}
			}
			notified := 0
			notify := func(_ context.Context, m string) error {
				notified++
				for i := 1; i <= 12; i++ {
					if !strings.Contains(m, "発行ID: "+strconv.Itoa(i)+"\n") {
						t.Error("missing issuance", i)
					}
				}
				return nil
			}
			pending, changed, e := Process(context.Background(), c, target, s, initialize, notify)
			if !errors.Is(e, ErrDeferred) || changed || notified != 0 || len(calls) != 9 || pending.Pending == nil {
				t.Fatal(pending, changed, len(calls), e)
			}
			if !initialize && pending.Domains["example.com"].After != "old" {
				t.Fatal("acknowledged cursor advanced")
			}
			if pending.Pending.Domains["example.com"].After != "9" || len(pending.Pending.Domains["example.com"].Items) != 9 {
				t.Fatal(pending.Pending)
			}
			// Serialize both files and create a new client, as the next Actions run does.
			dir := t.TempDir()
			if e = Save(dir+"/state", pending); e != nil {
				t.Fatal(e)
			}
			if e = Save(dir+"/runtime", c.Runtime); e != nil {
				t.Fatal(e)
			}
			var restored State
			var runtime Runtime
			if e = Load(dir+"/state", &restored); e != nil {
				t.Fatal(e)
			}
			if e = Load(dir+"/runtime", &runtime); e != nil {
				t.Fatal(e)
			}
			next := *c
			next.Runtime = &runtime
			now := c.now().Add(time.Hour + time.Second)
			next.Now = func() time.Time { return now }
			complete, changed, e := Process(context.Background(), &next, target, restored, false, notify)
			if e != nil || !changed || complete.Pending != nil || complete.Domains["example.com"].After != "12" || len(calls) != 13 || calls[9] != "9" {
				t.Fatal(complete, calls, e)
			}
			if initialize && notified != 0 || !initialize && notified != 1 {
				t.Fatal(notified)
			}
			for _, d := range *waits {
				if d > 5*time.Second {
					t.Fatal(d)
				}
			}
		})
	}
}
func TestSlackRetryUsesCompleteCheckpoint(t *testing.T) {
	calls := 0
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("after") == "old" {
			fmt.Fprint(w, "["+event("new")+"]")
		} else {
			fmt.Fprint(w, "[]")
		}
	})
	pending, _, e := Process(context.Background(), c, target, baseline(), false, func(context.Context, string) error { return errors.New("Slack down") })
	if e == nil || pending.Pending == nil || pending.Domains["example.com"].After != "old" {
		t.Fatal(pending, e)
	}
	complete, changed, e := Process(context.Background(), c, target, pending, false, func(context.Context, string) error { return nil })
	if e != nil || !changed || calls != 2 || complete.Pending != nil || complete.Domains["example.com"].After != "new" {
		t.Fatal(complete, calls, e)
	}
}
func TestEmptyPageDoesNotWait(t *testing.T) {
	c, waits := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3600")
		fmt.Fprint(w, "[]")
	})
	s, changed, e := Process(context.Background(), c, target, baseline(), false, func(context.Context, string) error { t.Fatal("notified"); return nil })
	if e != nil || changed || s.Pending != nil || len(*waits) != 1 || (*waits)[0] != time.Second {
		t.Fatal(s, *waits, e)
	}
	if _, _, e = Process(context.Background(), c, target, s, false, func(context.Context, string) error { return nil }); !errors.Is(e, ErrDeferred) {
		t.Fatal(e)
	}
}
func TestRuntimeSaveFailurePreventsRequest(t *testing.T) {
	c, _ := fixture(t, func(http.ResponseWriter, *http.Request) { t.Fatal("request without saved accounting") })
	c.SaveRuntime = func(*Runtime) error { return errors.New("disk full") }
	if _, _, e := Process(context.Background(), c, target, baseline(), false, func(context.Context, string) error { return nil }); e == nil {
		t.Fatal("success")
	}
}

func Test429ResumesLastSuccessfulPage(t *testing.T) {
	calls := []string{}
	limited := false
	c, waits := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		after := r.URL.Query().Get("after")
		calls = append(calls, after)
		switch {
		case after == "old":
			fmt.Fprint(w, "["+event("new")+"]")
		case !limited:
			limited = true
			w.Header().Set("Retry-After", "600")
			w.WriteHeader(429)
		default:
			fmt.Fprint(w, "[]")
		}
	})
	notifications := 0
	notify := func(context.Context, string) error { notifications++; return nil }
	pending, changed, e := Process(context.Background(), c, target, baseline(), false, notify)
	if !errors.Is(e, ErrDeferred) || changed || pending.Domains["example.com"].After != "old" || notifications != 0 {
		t.Fatal(pending, e)
	}
	if pending.Pending.Domains["example.com"].After != "new" {
		t.Fatal("lost page")
	}
	now := c.now().Add(601 * time.Second)
	c.Now = func() time.Time { return now }
	complete, changed, e := Process(context.Background(), c, target, pending, false, notify)
	if e != nil || !changed || notifications != 1 || complete.Domains["example.com"].After != "new" || strings.Join(calls, ",") != "old,new,new" {
		t.Fatal(complete, calls, e)
	}
	for _, d := range *waits {
		if d > 5*time.Second {
			t.Fatal("long wait", d)
		}
	}
}

func TestIssuerHistory(t *testing.T) {
	s := baseline()
	s.Domains["example.com"] = Cursor{After: "old", Subdomains: true, Issuers: []string{"CA"}}
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("after") {
		case "old":
			fmt.Fprint(w, "["+event("known")+","+strings.ReplaceAll(event("new"), `"CA"`, `"New CA"`)+"]")
		default:
			fmt.Fprint(w, "[]")
		}
	})
	notifications := 0
	pending, _, err := Process(context.Background(), c, target, s, false, func(_ context.Context, message string) error {
		notifications++
		if strings.Contains(message, "発行ID: known") || !strings.Contains(message, "発行ID: new") {
			t.Fatal(message)
		}
		return errors.New("Slack failed")
	})
	if err == nil || len(pending.Domains["example.com"].Issuers) != 1 || len(s.Domains["example.com"].Issuers) != 1 {
		t.Fatal(pending, err)
	}
	next, changed, err := Process(context.Background(), c, target, pending, false, func(context.Context, string) error { notifications++; return nil })
	if err != nil || !changed || notifications != 2 || len(next.Domains["example.com"].Issuers) != 2 {
		t.Fatal(next, err)
	}
	// A later issuance from the newly learned CA advances the cursor silently.
	c, _ = fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") == "new" {
			fmt.Fprint(w, "["+strings.ReplaceAll(event("renewal"), `"CA"`, `"New CA"`)+"]")
		} else {
			fmt.Fprint(w, "[]")
		}
	})
	next, changed, err = Process(context.Background(), c, target, next, false, func(context.Context, string) error { t.Fatal("known issuer notified"); return nil })
	if err != nil || !changed || next.Domains["example.com"].After != "renewal" {
		t.Fatal(next, err)
	}
	path := t.TempDir() + "/state.json"
	if err = Save(path, next); err != nil {
		t.Fatal(err)
	}
	var restored State
	if err = Load(path, &restored); err != nil || len(restored.Domains["example.com"].Issuers) != 2 {
		t.Fatal(restored, err)
	}
}

func TestIssuerHistoryMigration(t *testing.T) {
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("after") {
		case "":
			fmt.Fprint(w, "["+event("existing")+"]")
		case "existing":
			fmt.Fprint(w, "[]")
		default:
			t.Error("migration must fetch historical issuers")
			fmt.Fprint(w, "[]")
		}
	})
	s := baseline()
	s.Version = 1
	next, changed, err := Process(context.Background(), c, target, s, false, func(context.Context, string) error { t.Fatal("migration notified"); return nil })
	if err != nil || !changed || next.Version != 2 || len(next.Domains["example.com"].Issuers) != 1 || next.Domains["example.com"].Issuers[0] != "CA" {
		t.Fatal(next, err)
	}
}
