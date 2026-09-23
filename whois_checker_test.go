package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// stubWhoisRetry makes the retry loop instant and records what it waited for,
// so a test never sits through the real 2s/5s delays.
func stubWhoisRetry(t *testing.T) *[]time.Duration {
	t.Helper()

	origSleep := whoisSleepFn
	origDelays := whoisRetryDelays
	t.Cleanup(func() {
		whoisSleepFn = origSleep
		whoisRetryDelays = origDelays
	})

	var slept []time.Duration
	whoisRetryDelays = []time.Duration{time.Millisecond, 2 * time.Millisecond}
	whoisSleepFn = func(d time.Duration) { slept = append(slept, d) }

	return &slept
}

// The incident this retry exists for: JPRS reset the connection on one run out
// of the last hundred, which made WHOIS_EXPIRY red while the domain itself was
// fine. The next attempt answers, so the check must come back green.
func TestRunWhoisCheck_RetriesTransientQueryFailure(t *testing.T) {
	origFn := whoisQueryFn
	defer func() { whoisQueryFn = origFn }()
	slept := stubWhoisRetry(t)

	calls := 0
	whoisQueryFn = func(domain string) (time.Time, error) {
		calls++
		if calls == 1 {
			return time.Time{}, errors.New("WHOIS query failed for jinushi-ballet.com: " +
				"whois: read from whois server failed: " +
				"read tcp 172.17.0.2:39008->117.104.133.169:43: read: connection reset by peer")
		}
		return time.Now().Add(400 * 24 * time.Hour), nil
	}

	cfg := &Config{Domain: "jinushi-ballet.com"}
	check := CheckEntry{Type: "WHOIS_EXPIRY", Name: "@", WarnDays: 60}
	result := RunWhoisCheck(cfg, check)

	if !result.OK {
		t.Fatalf("expected OK=true after a transient failure, got false. Error: %s", result.Error)
	}
	if calls != 2 {
		t.Errorf("expected 2 queries, got %d", calls)
	}
	if len(*slept) != 1 {
		t.Errorf("expected 1 wait between the two attempts, got %v", *slept)
	}
}

func TestRunWhoisCheck_GivesUpAfterMaxAttempts(t *testing.T) {
	origFn := whoisQueryFn
	defer func() { whoisQueryFn = origFn }()
	slept := stubWhoisRetry(t)

	calls := 0
	whoisQueryFn = func(domain string) (time.Time, error) {
		calls++
		return time.Time{}, fmt.Errorf("connection reset by peer (attempt %d)", calls)
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "WHOIS_EXPIRY", Name: "@", WarnDays: 60}
	result := RunWhoisCheck(cfg, check)

	if result.OK {
		t.Error("expected OK=false when every attempt fails")
	}
	if calls != whoisMaxAttempts {
		t.Errorf("expected %d queries, got %d", whoisMaxAttempts, calls)
	}
	// The last failure is what the operator needs to see in the notification.
	if !strings.Contains(result.Error, "attempt 3") {
		t.Errorf("expected the last failure reason in the error, got: %s", result.Error)
	}
	if len(*slept) != whoisMaxAttempts-1 {
		t.Errorf("expected %d waits, got %v", whoisMaxAttempts-1, *slept)
	}
}

// Waits must grow: an immediate retry against a rate-limiting server just
// earns the same refusal.
func TestWhoisRetryDelaysIncrease(t *testing.T) {
	if len(whoisRetryDelays) != whoisMaxAttempts-1 {
		t.Fatalf("expected %d delays for %d attempts, got %d",
			whoisMaxAttempts-1, whoisMaxAttempts, len(whoisRetryDelays))
	}
	for i := 1; i < len(whoisRetryDelays); i++ {
		if whoisRetryDelays[i] <= whoisRetryDelays[i-1] {
			t.Errorf("delay %d (%s) does not grow past delay %d (%s)",
				i, whoisRetryDelays[i], i-1, whoisRetryDelays[i-1])
		}
	}
}

func TestRunWhoisCheck_NotExpiringSoon(t *testing.T) {
	origFn := whoisQueryFn
	defer func() { whoisQueryFn = origFn }()
	slept := stubWhoisRetry(t)

	calls := 0
	futureDate := time.Now().Add(365 * 24 * time.Hour)
	whoisQueryFn = func(domain string) (time.Time, error) {
		calls++
		return futureDate, nil
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "WHOIS_EXPIRY", Name: "@", WarnDays: 60}
	result := RunWhoisCheck(cfg, check)
	if !result.OK {
		t.Errorf("expected OK=true, got false. Error: %s", result.Error)
	}
	// A query that answers first time must cost exactly one query and no wait.
	if calls != 1 {
		t.Errorf("expected 1 query, got %d", calls)
	}
	if len(*slept) != 0 {
		t.Errorf("expected no waiting, got %v", *slept)
	}
}

func TestRunWhoisCheck_ExpiringSoon(t *testing.T) {
	origFn := whoisQueryFn
	defer func() { whoisQueryFn = origFn }()
	stubWhoisRetry(t)

	calls := 0
	soonDate := time.Now().Add(30 * 24 * time.Hour)
	whoisQueryFn = func(domain string) (time.Time, error) {
		calls++
		return soonDate, nil
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "WHOIS_EXPIRY", Name: "@", WarnDays: 60}
	result := RunWhoisCheck(cfg, check)
	if result.OK {
		t.Error("expected OK=false for expiring domain")
	}
	// A near expiry is a detection, not a query failure: never retried.
	if calls != 1 {
		t.Errorf("expected 1 query, got %d", calls)
	}
}

func TestRunWhoisCheck_AlreadyExpired(t *testing.T) {
	origFn := whoisQueryFn
	defer func() { whoisQueryFn = origFn }()
	stubWhoisRetry(t)

	calls := 0
	pastDate := time.Now().Add(-10 * 24 * time.Hour)
	whoisQueryFn = func(domain string) (time.Time, error) {
		calls++
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
	// An expired domain is a detection, not a query failure: never retried.
	if calls != 1 {
		t.Errorf("expected 1 query, got %d", calls)
	}
}
