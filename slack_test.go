package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mockSlack(t *testing.T) *[]string {
	var messages []string
	t.Helper()
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://slack.com/api/chat.postMessage" || req.Method != "POST" {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL)
		}
		if req.Header.Get("Authorization") == "" {
			t.Error("missing token")
		}
		var payload struct{ Channel, Text string }
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.Channel != "C123" || strings.Count(payload.Text, "<!channel>") != 1 {
			t.Fatalf("unexpected mention: %+v", payload)
		}
		messages = append(messages, payload.Text)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
	})}
	return &messages
}

func TestSlackFailures(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"API failure", `{"ok":false,"error":"missing_scope"}`, 200},
		{"HTTP failure", `secret body`, 429},
		{"invalid JSON", `secret body`, 200},
		{"missing result", `{}`, 200},
		{"truncation", `{"ok":true,"response_metadata":{"warnings":["message_truncated"]}}`, 200},
		{"untrusted error text", `{"ok":false,"error":"secret body"}`, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}
			err := postSlackMessage(context.Background(), client, "secret-token", "C123", "report")
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe/missing error: %v", err)
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}
	if err := postSlackMessage(ctx, client, "secret-token", "C123", "report"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout lost: %v", err)
	}
}

func TestAPIFailureFailsNotification(t *testing.T) {
	mockSlack(t)
	t.Setenv("NOTIFY_SLACK_TOKEN", "test-token")
	t.Setenv("NOTIFY_SLACK_CHANNEL_ID", "C123")
	http.DefaultClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":false,"error":"missing_scope"}`))}, nil
	})
	err := slackNotifier(time.Second)(context.Background(), "report")
	if err == nil || !strings.Contains(err.Error(), "missing_scope") {
		t.Fatalf("mention failure lost: %v", err)
	}
}

func TestSlackDoesNotFollowRedirect(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://other.test/"}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	})}
	if err := postSlackMessage(context.Background(), client, "secret-token", "C123", "report"); err == nil || calls != 1 {
		t.Fatalf("redirect followed: calls=%d error=%v", calls, err)
	}
}
