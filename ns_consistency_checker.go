package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
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

var queryNSFn = queryNameserver

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

	var queryErrors []string
	for _, qtype := range checkTypes {
		var referenceResult []string
		var referenceNS string

		for _, ns := range nameservers {
			records, err := queryNSFn(domain, ns, qtype)
			if err != nil {
				queryErrors = append(queryErrors,
					fmt.Sprintf("%s %s query to %s: %v", domain, qtype, ns, err))
				continue
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

	if len(queryErrors) > 0 {
		result.OK = false
		result.Error = strings.Join(queryErrors, "; ")
	}

	return result
}
