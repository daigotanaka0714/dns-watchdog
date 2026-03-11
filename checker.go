package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// DoH API response types
type DoHResponse struct {
	Status int         `json:"Status"`
	Answer []DoHAnswer `json:"Answer"`
}

type DoHAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

// DNS type map
var dnsTypeMap = map[string]int{
	"A":     1,
	"NS":    2,
	"CNAME": 5,
	"MX":    15,
	"TXT":   16,
}

// CheckResult holds the outcome of a single DNS check
type CheckResult struct {
	Check  CheckEntry
	Actual []string
	OK     bool
	Error  string
}

const defaultDoHBaseURL = "https://dns.google/resolve"

// QueryDNS queries DNS over HTTPS for the given domain and record type.
// baseURL allows injecting a mock server URL for testing; if empty, defaults to dns.google.
func QueryDNS(domain, recordType string, client *http.Client, baseURL string) ([]string, error) {
	typeNum, ok := dnsTypeMap[recordType]
	if !ok {
		return nil, fmt.Errorf("unsupported DNS record type: %s", recordType)
	}

	if baseURL == "" {
		baseURL = defaultDoHBaseURL
	}

	url := fmt.Sprintf("%s?name=%s&type=%d", baseURL, domain, typeNum)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DNS query returned HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var dohResp DoHResponse
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return nil, fmt.Errorf("failed to parse DoH response: %w", err)
	}

	var results []string
	for _, ans := range dohResp.Answer {
		if ans.Type == typeNum {
			results = append(results, ans.Data)
		}
	}

	return results, nil
}

// ResolveName returns the full DNS name for a check entry.
// If name is "@", returns the domain itself. Otherwise returns name.domain.
func ResolveName(domain, name string) string {
	if name == "@" {
		return domain
	}
	return name + "." + domain
}

// RunCheck executes a single DNS check and returns the result.
func RunCheck(cfg *Config, check CheckEntry, client *http.Client, baseURL string) CheckResult {
	fqdn := ResolveName(cfg.Domain, check.Name)

	actual, err := QueryDNS(fqdn, check.Type, client, baseURL)
	if err != nil {
		return CheckResult{
			Check: check,
			OK:    false,
			Error: err.Error(),
		}
	}

	result := CheckResult{
		Check:  check,
		Actual: actual,
	}

	if check.Contains != "" {
		// Partial match: any actual value contains the string
		for _, val := range actual {
			if strings.Contains(val, check.Contains) {
				result.OK = true
				return result
			}
		}
		result.OK = false
	} else {
		// Exact match: sorted comparison, order-independent
		expected := make([]string, len(check.Expected))
		copy(expected, check.Expected)
		sort.Strings(expected)

		actualSorted := make([]string, len(actual))
		copy(actualSorted, actual)
		sort.Strings(actualSorted)

		if len(expected) != len(actualSorted) {
			result.OK = false
		} else {
			result.OK = true
			for i := range expected {
				if expected[i] != actualSorted[i] {
					result.OK = false
					break
				}
			}
		}
	}

	return result
}

// RunAllChecks executes all checks in the config and returns only failures.
func RunAllChecks(cfg *Config, baseURL string) []CheckResult {
	client := &http.Client{Timeout: 10 * time.Second}

	var failures []CheckResult
	for _, check := range cfg.Checks {
		result := RunCheck(cfg, check, client, baseURL)
		if !result.OK {
			failures = append(failures, result)
		}
	}

	return failures
}
