package main

import (
	"fmt"
	"log"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

// WHOIS servers rate-limit and drop connections, so a single failed query says
// nothing about the domain. Retry the query a few times with a growing gap
// before calling it a failure. How hard to try is not something a user of this
// action decides, so these stay constants rather than config keys.
const whoisMaxAttempts = 3

// whoisRetryDelays holds the wait before each retry; it has
// whoisMaxAttempts-1 entries. A var so tests do not have to sit through it.
var whoisRetryDelays = []time.Duration{2 * time.Second, 5 * time.Second}

// whoisSleepFn is injectable for testing.
var whoisSleepFn = time.Sleep

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

// whoisRetryDelay returns the wait between attempt n and attempt n+1.
func whoisRetryDelay(n int) time.Duration {
	if len(whoisRetryDelays) == 0 {
		return 0
	}
	if n > len(whoisRetryDelays) {
		n = len(whoisRetryDelays)
	}
	return whoisRetryDelays[n-1]
}

// queryWhoisWithRetry retries the WHOIS query itself, and only that: a
// response saying the domain is expiring is a result, not a failure, so the
// expiry is judged by the caller and never retried. On exhaustion the last
// error is returned unwrapped, so the notification text stays as it was.
func queryWhoisWithRetry(domain string) (time.Time, error) {
	var lastErr error

	for attempt := 1; attempt <= whoisMaxAttempts; attempt++ {
		expiry, err := whoisQueryFn(domain)
		if err == nil {
			if attempt > 1 {
				log.Printf("WHOIS query for %s succeeded on attempt %d/%d", domain, attempt, whoisMaxAttempts)
			}
			return expiry, nil
		}

		lastErr = err
		log.Printf("WHOIS query for %s failed on attempt %d/%d: %v", domain, attempt, whoisMaxAttempts, err)

		if attempt < whoisMaxAttempts {
			whoisSleepFn(whoisRetryDelay(attempt))
		}
	}

	log.Printf("WHOIS query for %s failed on all %d attempts, giving up", domain, whoisMaxAttempts)
	return time.Time{}, lastErr
}

// RunWhoisCheck queries WHOIS for the domain and checks if it expires within WarnDays.
func RunWhoisCheck(cfg *Config, check CheckEntry) CheckResult {
	result := CheckResult{Check: check, OK: true}

	warnDays := check.WarnDays
	if warnDays == 0 {
		warnDays = 60
	}

	expiry, err := queryWhoisWithRetry(cfg.Domain)
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
