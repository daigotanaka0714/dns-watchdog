package main

import (
	"testing"
)

func TestReverseIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"1.2.3.4", "4.3.2.1"},
		{"192.168.1.1", "1.1.168.192"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := reverseIP(tt.input)
			if result != tt.expected {
				t.Errorf("reverseIP(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCheckBlocklist_NotListed(t *testing.T) {
	lookupFn := func(host string) ([]string, error) {
		return nil, nil
	}
	listed, err := checkBlocklistWith("1.2.3.4", "zen.spamhaus.org", lookupFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if listed {
		t.Error("expected not listed, got listed")
	}
}

func TestCheckBlocklist_Listed(t *testing.T) {
	lookupFn := func(host string) ([]string, error) {
		return []string{"127.0.0.2"}, nil
	}
	listed, err := checkBlocklistWith("1.2.3.4", "zen.spamhaus.org", lookupFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !listed {
		t.Error("expected listed, got not listed")
	}
}

func TestRunBlocklistCheck_AllClear(t *testing.T) {
	origLookup := dnsLookupHost
	defer func() { dnsLookupHost = origLookup }()
	dnsLookupHost = func(host string) ([]string, error) {
		return nil, nil
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "BLOCKLIST", Name: "@", Expected: []string{"1.2.3.4"}}
	result := RunBlocklistCheck(cfg, check)
	if !result.OK {
		t.Errorf("expected OK=true, got false. Error: %s", result.Error)
	}
}

func TestRunBlocklistCheck_Listed(t *testing.T) {
	origLookup := dnsLookupHost
	defer func() { dnsLookupHost = origLookup }()
	dnsLookupHost = func(host string) ([]string, error) {
		return []string{"127.0.0.2"}, nil
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "BLOCKLIST", Name: "@", Expected: []string{"1.2.3.4"}}
	result := RunBlocklistCheck(cfg, check)
	if result.OK {
		t.Error("expected OK=false for listed IP")
	}
	if len(result.Actual) == 0 {
		t.Error("expected actual to contain blocklist names")
	}
}
