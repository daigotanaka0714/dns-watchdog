package main

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestIsBlocklistListing_ValidCodes(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want bool
	}{
		{"valid listing 127.0.0.2", "127.0.0.2", true},
		{"valid listing 127.0.0.3", "127.0.0.3", true},
		{"valid listing 127.0.0.10", "127.0.0.10", true},
		{"valid listing 127.0.0.255", "127.0.0.255", true},
		{"not listed 127.0.0.0", "127.0.0.0", false},
		{"not listed 127.0.0.1 (localhost)", "127.0.0.1", false},
		{"spamhaus error 127.255.255.254", "127.255.255.254", false},
		{"spamhaus rate limit 127.255.255.255", "127.255.255.255", false},
		{"non-loopback 192.168.1.1", "192.168.1.1", false},
		{"invalid IP", "not-an-ip", false},
		{"empty string", "", false},
		{"IPv6 address", "::1", false},
		{"127.0.1.2 wrong subnet", "127.0.1.2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBlocklistListing(tt.addr)
			if got != tt.want {
				t.Errorf("isBlocklistListing(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestReverseIP(t *testing.T) {
	rev, err := reverseIP("1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rev != "4.3.2.1" {
		t.Errorf("expected 4.3.2.1, got %s", rev)
	}

	_, err = reverseIP("invalid")
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

// mockLookup creates a lookup function that returns predefined results per query.
func mockLookup(responses map[string][]string, errors map[string]error) func(string) ([]string, error) {
	return func(host string) ([]string, error) {
		if err, ok := errors[host]; ok {
			return nil, err
		}
		if addrs, ok := responses[host]; ok {
			return addrs, nil
		}
		// Default: NXDOMAIN (not found)
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
}

func TestRunBlocklistCheck_PartialDNSBLFailure(t *testing.T) {
	origLookup := lookupHostFunc
	defer func() { lookupHostFunc = origLookup }()

	lookupHostFunc = mockLookup(
		map[string][]string{
			"1.4.3.2.bl-listed.example": {"127.0.0.2"},
		},
		map[string]error{
			"1.4.3.2.bl-error.example": fmt.Errorf("temporary DNS failure"),
		},
	)

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{
		Type:       "BLOCKLIST",
		Name:       "@",
		Host:       "2.3.4.1",
		Blocklists: []string{"bl-error.example", "bl-ok.example", "bl-listed.example"},
	}

	result := RunBlocklistCheck(cfg, check)

	if result.OK {
		t.Error("expected OK=false because IP is listed on bl-listed.example")
	}
	if len(result.Actual) != 1 || !strings.Contains(result.Actual[0], "bl-listed.example") {
		t.Errorf("expected listed on [bl-listed.example], got %v", result.Actual)
	}
	if !strings.Contains(result.Error, "bl-error.example") {
		t.Errorf("expected warning about bl-error.example, got: %s", result.Error)
	}
}

func TestRunBlocklistCheck_SpamhausErrorCode(t *testing.T) {
	origLookup := lookupHostFunc
	defer func() { lookupHostFunc = origLookup }()

	lookupHostFunc = mockLookup(
		map[string][]string{
			"1.4.3.2.zen.spamhaus.org": {"127.255.255.254"},
		},
		nil,
	)

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{
		Type:       "BLOCKLIST",
		Name:       "@",
		Host:       "2.3.4.1",
		Blocklists: []string{"zen.spamhaus.org"},
	}

	result := RunBlocklistCheck(cfg, check)

	if !result.OK {
		t.Errorf("expected OK=true (127.255.255.254 is not a listing), got false. Error: %s", result.Error)
	}
}

func TestRunBlocklistCheck_CustomBlocklists(t *testing.T) {
	origLookup := lookupHostFunc
	defer func() { lookupHostFunc = origLookup }()

	queriedHosts := make(map[string]bool)
	lookupHostFunc = func(host string) ([]string, error) {
		queriedHosts[host] = true
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{
		Type:       "BLOCKLIST",
		Name:       "@",
		Host:       "10.20.30.40",
		Blocklists: []string{"custom1.example.com", "custom2.example.com"},
	}

	result := RunBlocklistCheck(cfg, check)

	if !result.OK {
		t.Errorf("expected OK=true, got false. Error: %s", result.Error)
	}

	if !queriedHosts["40.30.20.10.custom1.example.com"] {
		t.Error("expected query to custom1.example.com")
	}
	if !queriedHosts["40.30.20.10.custom2.example.com"] {
		t.Error("expected query to custom2.example.com")
	}

	for _, def := range defaultBlocklists {
		defQuery := "40.30.20.10." + def
		if queriedHosts[defQuery] {
			t.Errorf("default blocklist %s should not have been queried when custom blocklists are set", def)
		}
	}
}

func TestRunBlocklistCheck_DefaultBlocklists(t *testing.T) {
	origLookup := lookupHostFunc
	defer func() { lookupHostFunc = origLookup }()

	queriedHosts := make(map[string]bool)
	lookupHostFunc = func(host string) ([]string, error) {
		queriedHosts[host] = true
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{
		Type: "BLOCKLIST",
		Name: "@",
		Host: "10.20.30.40",
	}

	result := RunBlocklistCheck(cfg, check)

	if !result.OK {
		t.Errorf("expected OK=true, got false. Error: %s", result.Error)
	}

	for _, def := range defaultBlocklists {
		defQuery := "40.30.20.10." + def
		if !queriedHosts[defQuery] {
			t.Errorf("expected default blocklist %s to be queried", def)
		}
	}
}

func TestRunBlocklistCheck_AllClear(t *testing.T) {
	origLookup := lookupHostFunc
	defer func() { lookupHostFunc = origLookup }()
	lookupHostFunc = func(host string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "BLOCKLIST", Name: "@", Host: "1.2.3.4"}
	result := RunBlocklistCheck(cfg, check)
	if !result.OK {
		t.Errorf("expected OK=true, got false. Error: %s", result.Error)
	}
}

func TestRunBlocklistCheck_Listed(t *testing.T) {
	origLookup := lookupHostFunc
	defer func() { lookupHostFunc = origLookup }()
	lookupHostFunc = mockLookup(
		map[string][]string{
			"4.3.2.1.zen.spamhaus.org": {"127.0.0.2"},
		},
		nil,
	)

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "BLOCKLIST", Name: "@", Host: "1.2.3.4"}
	result := RunBlocklistCheck(cfg, check)
	if result.OK {
		t.Error("expected OK=false for listed IP")
	}
	if len(result.Actual) == 0 {
		t.Error("expected actual to contain blocklist names")
	}
}

func TestRunBlocklistCheck_MultipleIPs(t *testing.T) {
	origLookup := lookupHostFunc
	defer func() { lookupHostFunc = origLookup }()

	// Domain resolves to two IPs; second one is listed
	lookupHostFunc = mockLookup(
		map[string][]string{
			"example.com":                       {"1.2.3.4", "5.6.7.8"},
			"8.7.6.5.zen.spamhaus.org":          {"127.0.0.2"},
		},
		nil,
	)

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "BLOCKLIST", Name: "@"}

	result := RunBlocklistCheck(cfg, check)

	if result.OK {
		t.Error("expected OK=false because 5.6.7.8 is listed")
	}
	if len(result.Actual) == 0 {
		t.Error("expected actual to contain listing for 5.6.7.8")
	}
	found := false
	for _, a := range result.Actual {
		if strings.Contains(a, "5.6.7.8") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected listing for 5.6.7.8, got: %v", result.Actual)
	}
}
