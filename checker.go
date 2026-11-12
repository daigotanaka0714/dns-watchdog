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
	// Query is what the resolver reported about the lookup. It is set only by
	// the DoH-based record checks (A, NS, CNAME, MX, TXT).
	Query *QueryInfo
}

// QueryInfo holds what a DoH resolver said about a query besides the answers.
type QueryInfo struct {
	RCode      int // DNS response code from the DoH "Status" field
	TTL        int // smallest TTL among the matching answers; 0 when there are none
	HTTPStatus int // non-200 status returned by the DoH endpoint; 0 otherwise
}

// HTTPStatusError is returned when the DoH endpoint answers with a non-200 status.
type HTTPStatusError struct {
	Code int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("DNS query returned HTTP status %d", e.Code)
}

const defaultDoHBaseURL = "https://dns.google/resolve"

// QueryDNS queries DNS over HTTPS for the given domain and record type.
// baseURL allows injecting a mock server URL for testing; if empty, defaults to dns.google.
func QueryDNS(domain, recordType string, client *http.Client, baseURL string) ([]string, error) {
	results, _, err := queryDNSDetail(domain, recordType, client, baseURL)
	return results, err
}

// queryDNSDetail is QueryDNS plus the resolver's response code, TTL and any
// non-200 HTTP status.
func queryDNSDetail(domain, recordType string, client *http.Client, baseURL string) ([]string, QueryInfo, error) {
	var info QueryInfo

	typeNum, ok := dnsTypeMap[recordType]
	if !ok {
		return nil, info, fmt.Errorf("unsupported DNS record type: %s", recordType)
	}

	if baseURL == "" {
		baseURL = defaultDoHBaseURL
	}

	url := fmt.Sprintf("%s?name=%s&type=%d", baseURL, domain, typeNum)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, info, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, info, fmt.Errorf("DNS query failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		info.HTTPStatus = resp.StatusCode
		return nil, info, &HTTPStatusError{Code: resp.StatusCode}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, info, fmt.Errorf("failed to read response: %w", err)
	}

	var dohResp DoHResponse
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return nil, info, fmt.Errorf("failed to parse DoH response: %w", err)
	}
	info.RCode = dohResp.Status

	var results []string
	for _, ans := range dohResp.Answer {
		if ans.Type == typeNum {
			results = append(results, ans.Data)
			if info.TTL == 0 || ans.TTL < info.TTL {
				info.TTL = ans.TTL
			}
		}
	}

	return results, info, nil
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

	actual, info, err := queryDNSDetail(fqdn, check.Type, client, baseURL)
	if err != nil {
		return CheckResult{
			Check: check,
			OK:    false,
			Error: err.Error(),
			Query: &info,
		}
	}

	result := CheckResult{
		Check:  check,
		Actual: actual,
		Query:  &info,
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
		var result CheckResult
		switch check.Type {
		case "BLOCKLIST":
			result = RunBlocklistCheck(cfg, check)
		case "CERT_EXPIRY":
			result = RunCertCheck(cfg, check)
		case "WHOIS_EXPIRY":
			result = RunWhoisCheck(cfg, check)
		case "NS_CONSISTENCY":
			result = RunNSConsistencyCheck(cfg, check)
		case "PROPAGATION":
			result = RunPropagationCheck(cfg, check)
		case "A", "NS", "CNAME", "MX", "TXT":
			result = RunCheck(cfg, check, client, baseURL)
		default:
			result = CheckResult{
				Check: check,
				OK:    false,
				Error: fmt.Sprintf("unknown check type: %s", check.Type),
			}
		}
		if !result.OK {
			failures = append(failures, result)
		}
	}

	return failures
}
