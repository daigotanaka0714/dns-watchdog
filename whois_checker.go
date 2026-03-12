package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

var whoisQueryFn = func(domain string) (string, error) {
	conn, err := net.DialTimeout("tcp", "whois.verisign-grs.com:43", 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to WHOIS server: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return "", fmt.Errorf("failed to set deadline: %w", err)
	}

	if _, err := fmt.Fprintf(conn, "%s\r\n", domain); err != nil {
		return "", fmt.Errorf("failed to send WHOIS query: %w", err)
	}

	var sb strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteString("\n")
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to read WHOIS response: %w", err)
	}

	return sb.String(), nil
}

var expiryKeywords = []string{
	"Registry Expiry Date:",
	"Registrar Registration Expiration Date:",
	"paid-till:",
	"Expiry Date:",
	"Expiration Date:",
}

func parseWhoisExpiry(response string) (time.Time, error) {
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		for _, keyword := range expiryKeywords {
			if strings.HasPrefix(trimmed, keyword) {
				dateStr := strings.TrimSpace(strings.TrimPrefix(trimmed, keyword))
				for _, layout := range []string{
					time.RFC3339,
					"2006-01-02T15:04:05Z",
					"2006-01-02",
					"02-Jan-2006",
				} {
					if t, err := time.Parse(layout, dateStr); err == nil {
						return t, nil
					}
				}
				return time.Time{}, fmt.Errorf("could not parse date: %s", dateStr)
			}
		}
	}
	return time.Time{}, fmt.Errorf("no expiry date found in WHOIS response")
}

// RunWhoisCheck queries WHOIS for the domain and checks if it expires within WarnDays.
func RunWhoisCheck(cfg *Config, check CheckEntry) CheckResult {
	result := CheckResult{Check: check, OK: true}

	warnDays := check.WarnDays
	if warnDays == 0 {
		warnDays = 60
	}

	response, err := whoisQueryFn(cfg.Domain)
	if err != nil {
		result.OK = false
		result.Error = err.Error()
		return result
	}

	expiry, err := parseWhoisExpiry(response)
	if err != nil {
		result.OK = false
		result.Error = fmt.Sprintf("failed to parse WHOIS expiry for %s: %v", cfg.Domain, err)
		return result
	}

	daysUntilExpiry := int(time.Until(expiry).Hours() / 24)
	if daysUntilExpiry < warnDays {
		result.OK = false
		result.Actual = []string{
			fmt.Sprintf("domain expires in %d days (%s)", daysUntilExpiry, expiry.Format("2006-01-02")),
		}
	}

	return result
}
