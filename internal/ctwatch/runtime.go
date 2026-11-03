package ctwatch

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type Progress struct {
	After    string     `json:"after"`
	Items    []Issuance `json:"items,omitempty"`
	Pages    int        `json:"pages"`
	Complete bool       `json:"complete"`
}
type Batch struct {
	Initialize bool                 `json:"initialize"`
	Targets    []Target             `json:"targets"`
	Domains    map[string]*Progress `json:"domains"`
}
type Request struct {
	At         time.Time `json:"at"`
	Subdomains bool      `json:"include_subdomains"`
}
type Runtime struct {
	Requests    []Request            `json:"requests,omitempty"`
	GlobalUntil time.Time            `json:"global_until"`
	PollUntil   map[string]time.Time `json:"poll_until,omitempty"`
}

var ErrDeferred = errors.New("CT request deferred until a later run")

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
func (c *Client) logf(format string, args ...any) {
	if c.Log != nil {
		fmt.Fprintf(c.Log, "CT: "+format+"\n", args...)
	}
}
func (c *Client) runtime() *Runtime {
	if c.Runtime == nil {
		c.Runtime = &Runtime{}
	}
	return c.Runtime
}
func (c *Client) saveRuntime() error {
	if c.SaveRuntime != nil {
		return c.SaveRuntime(c.Runtime)
	}
	return nil
}
func (c *Client) deferRequest(t Target, delay time.Duration, global bool) error {
	r := c.runtime()
	until := c.now().Add(delay)
	if r.PollUntil == nil {
		r.PollUntil = map[string]time.Time{}
	}
	if until.After(r.PollUntil[t.Domain]) {
		r.PollUntil[t.Domain] = until
	}
	if global && until.After(r.GlobalUntil) {
		r.GlobalUntil = until
	}
	return c.saveRuntime()
}
func (c *Client) beforeRequest(ctx context.Context, t Target) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r := c.runtime()
	now := c.now()
	delay := max(r.GlobalUntil.Sub(now), r.PollUntil[t.Domain].Sub(now))
	if delay > 5*time.Second {
		return ErrDeferred
	}
	kept := make([]Request, 0, len(r.Requests))
	subdomains := 0
	for _, request := range r.Requests {
		if request.At.After(now.Add(-time.Hour)) {
			kept = append(kept, request)
			if request.Subdomains {
				subdomains++
			}
		}
	}
	r.Requests = kept
	if len(kept) >= 90 || t.Subdomains && subdomains >= 9 {
		return ErrDeferred
	}
	wait := c.Wait
	if wait == nil {
		wait = Sleep
	}
	if err := wait(ctx, max(time.Second, delay)); err != nil {
		return err
	}
	r.Requests = append(r.Requests, Request{At: c.now(), Subdomains: t.Subdomains})
	return c.saveRuntime()
}
