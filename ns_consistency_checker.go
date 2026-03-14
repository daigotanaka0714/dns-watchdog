package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

var defaultNSCheckTypes = []string{"A", "MX", "TXT", "NS"}

var nsLookupFn = func(domain string) ([]string, error) {
	nss, err := net.LookupNS(domain)
	if err != nil {
		return nil, err
	}
	var hosts []string
	for _, ns := range nss {
		hosts = append(hosts, ns.Host)
	}
	return hosts, nil
}

var queryNSFn = func(domain, ns, qtype string) ([]string, error) {
	if !strings.Contains(ns, ":") {
		ns = ns + ":53"
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", ns)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	switch qtype {
	case "A":
		return resolver.LookupHost(ctx, domain)
	case "MX":
		mxs, err := resolver.LookupMX(ctx, domain)
		if err != nil {
			return nil, err
		}
		var results []string
		for _, mx := range mxs {
			results = append(results, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
		}
		return results, nil
	case "TXT":
		return resolver.LookupTXT(ctx, domain)
	case "NS":
		nss, err := resolver.LookupNS(ctx, domain)
		if err != nil {
			return nil, err
		}
		var results []string
		for _, ns := range nss {
			results = append(results, ns.Host)
		}
		return results, nil
	default:
		return nil, fmt.Errorf("unsupported query type for NS consistency: %s", qtype)
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// RunNSConsistencyCheck queries all authoritative NS for the domain and verifies consistent results.
// Expected field contains the record types to check (e.g., ["A"]).
func RunNSConsistencyCheck(cfg *Config, check CheckEntry) CheckResult {
	result := CheckResult{Check: check, OK: true}
	domain := ResolveName(cfg.Domain, check.Name)

	nameservers, err := nsLookupFn(cfg.Domain)
	if err != nil {
		result.OK = false
		result.Error = fmt.Sprintf("failed to lookup NS for %s: %v", cfg.Domain, err)
		return result
	}
	if len(nameservers) == 0 {
		result.OK = false
		result.Error = fmt.Sprintf("no nameservers found for %s", cfg.Domain)
		return result
	}

	checkTypes := check.Expected
	if len(checkTypes) == 0 {
		checkTypes = defaultNSCheckTypes
	}

	for _, qtype := range checkTypes {
		var referenceResult []string
		var referenceNS string

		for _, ns := range nameservers {
			records, err := queryNSFn(domain, ns, qtype)
			if err != nil {
				result.OK = false
				result.Error = fmt.Sprintf("query to %s failed for %s %s: %v", ns, domain, qtype, err)
				return result
			}

			sorted := make([]string, len(records))
			copy(sorted, records)
			sort.Strings(sorted)

			if referenceNS == "" {
				referenceResult = sorted
				referenceNS = ns
			} else {
				if !slicesEqual(referenceResult, sorted) {
					result.OK = false
					result.Actual = append(result.Actual,
						fmt.Sprintf("%s %s: %s returned [%s], %s returned [%s]",
							domain, qtype,
							referenceNS, strings.Join(referenceResult, ", "),
							ns, strings.Join(sorted, ", ")))
				}
			}
		}
	}

	return result
}
