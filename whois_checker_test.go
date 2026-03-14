package main

import (
	"strings"
	"testing"
	"time"
)

func TestRunWhoisCheck_NotExpiringSoon(t *testing.T) {
	origFn := whoisQueryFn
	defer func() { whoisQueryFn = origFn }()

	futureDate := time.Now().Add(365 * 24 * time.Hour)
	whoisQueryFn = func(domain string) (time.Time, error) {
		return futureDate, nil
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "WHOIS_EXPIRY", Name: "@", WarnDays: 60}
	result := RunWhoisCheck(cfg, check)
	if !result.OK {
		t.Errorf("expected OK=true, got false. Error: %s", result.Error)
	}
}

func TestRunWhoisCheck_ExpiringSoon(t *testing.T) {
	origFn := whoisQueryFn
	defer func() { whoisQueryFn = origFn }()

	soonDate := time.Now().Add(30 * 24 * time.Hour)
	whoisQueryFn = func(domain string) (time.Time, error) {
		return soonDate, nil
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "WHOIS_EXPIRY", Name: "@", WarnDays: 60}
	result := RunWhoisCheck(cfg, check)
	if result.OK {
		t.Error("expected OK=false for expiring domain")
	}
}

func TestRunWhoisCheck_AlreadyExpired(t *testing.T) {
	origFn := whoisQueryFn
	defer func() { whoisQueryFn = origFn }()

	pastDate := time.Now().Add(-10 * 24 * time.Hour)
	whoisQueryFn = func(domain string) (time.Time, error) {
		return pastDate, nil
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "WHOIS_EXPIRY", Name: "@", WarnDays: 60}
	result := RunWhoisCheck(cfg, check)
	if result.OK {
		t.Error("expected OK=false for expired domain")
	}
	if len(result.Actual) == 0 || !strings.Contains(result.Actual[0], "期限切れ") {
		t.Errorf("expected 期限切れ message, got: %v", result.Actual)
	}
}
