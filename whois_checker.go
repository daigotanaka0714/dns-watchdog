package main

import (
	"fmt"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

// whoisQueryFn is injectable for testing. Returns parsed expiry time.
var whoisQueryFn = func(domain string) (time.Time, error) {
	raw, err := whois.Whois(domain)
	if err != nil {
		return time.Time{}, fmt.Errorf("WHOIS query failed for %s: %w", domain, err)
	}

	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse WHOIS response for %s: %w", domain, err)
	}

	if parsed.Domain.ExpirationDateInTime != nil {
		return *parsed.Domain.ExpirationDateInTime, nil
	}

	if parsed.Domain.ExpirationDate != "" {
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02"} {
			if t, err := time.Parse(layout, parsed.Domain.ExpirationDate); err == nil {
				return t, nil
			}
		}
		return time.Time{}, fmt.Errorf("could not parse expiry date: %s", parsed.Domain.ExpirationDate)
	}

	return time.Time{}, fmt.Errorf("no expiry date found for %s", domain)
}

// RunWhoisCheck queries WHOIS for the domain and checks if it expires within WarnDays.
func RunWhoisCheck(cfg *Config, check CheckEntry) CheckResult {
	result := CheckResult{Check: check, OK: true}

	warnDays := check.WarnDays
	if warnDays == 0 {
		warnDays = 60
	}

	expiry, err := whoisQueryFn(cfg.Domain)
	if err != nil {
		result.OK = false
		result.Error = err.Error()
		return result
	}

	daysUntilExpiry := int(time.Until(expiry).Hours() / 24)

	if daysUntilExpiry < 0 {
		result.OK = false
		result.Actual = []string{
			fmt.Sprintf("期限切れ（%d日前に失効, %s）", -daysUntilExpiry, expiry.Format("2006-01-02")),
		}
	} else if daysUntilExpiry < warnDays {
		result.OK = false
		result.Actual = []string{
			fmt.Sprintf("domain expires in %d days (%s)", daysUntilExpiry, expiry.Format("2006-01-02")),
		}
	}

	return result
}
