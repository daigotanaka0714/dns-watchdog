package main

import (
	"testing"
	"time"
)

func TestParseWhoisExpiry(t *testing.T) {
	tests := []struct {
		name     string
		response string
		wantErr  bool
	}{
		{
			"standard format",
			"Registry Expiry Date: 2027-08-13T04:00:00Z\n",
			false,
		},
		{
			"paid-till format",
			"paid-till: 2027-08-13T04:00:00Z\n",
			false,
		},
		{
			"no expiry found",
			"Some random whois data\n",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expiry, err := parseWhoisExpiry(tt.response)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if expiry.Year() != 2027 || expiry.Month() != 8 || expiry.Day() != 13 {
				t.Errorf("unexpected expiry date: %v", expiry)
			}
		})
	}
}

func TestRunWhoisCheck_NotExpiringSoon(t *testing.T) {
	origFn := whoisQueryFn
	defer func() { whoisQueryFn = origFn }()

	futureDate := time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02T15:04:05Z")
	whoisQueryFn = func(domain string) (string, error) {
		return "Registry Expiry Date: " + futureDate + "\n", nil
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

	soonDate := time.Now().Add(30 * 24 * time.Hour).Format("2006-01-02T15:04:05Z")
	whoisQueryFn = func(domain string) (string, error) {
		return "Registry Expiry Date: " + soonDate + "\n", nil
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "WHOIS_EXPIRY", Name: "@", WarnDays: 60}
	result := RunWhoisCheck(cfg, check)
	if result.OK {
		t.Error("expected OK=false for expiring domain")
	}
}
