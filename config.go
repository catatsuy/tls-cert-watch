package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
)

type Target struct {
	Host     string   `json:"host"`
	Port     int      `json:"port,omitempty"`
	KeyTypes []string `json:"key_types"`
}

func loadConfig(r io.Reader) ([]Target, error) {
	var targets []Target
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&targets); err != nil {
		return nil, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("config must contain exactly one JSON array")
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets configured")
	}
	for i := range targets {
		t := &targets[i]
		if !validHost(t.Host) {
			return nil, fmt.Errorf("target %d: invalid host %q (use a hostname or IP, without scheme or port)", i+1, t.Host)
		}
		if t.Port == 0 {
			t.Port = 443
		}
		if t.Port < 1 || t.Port > 65535 {
			return nil, fmt.Errorf("%s: invalid port", t.Host)
		}
		if len(t.KeyTypes) == 0 {
			return nil, fmt.Errorf("%s: key_types is required", t.Host)
		}
		seen := map[string]bool{}
		for _, k := range t.KeyTypes {
			if (k != "RSA" && k != "ECDSA") || seen[k] {
				return nil, fmt.Errorf("%s: key_types must contain unique RSA/ECDSA values", t.Host)
			}
			seen[k] = true
		}
	}
	return targets, nil
}

func validHost(h string) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for label := range strings.SplitSeq(strings.TrimSuffix(h, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
