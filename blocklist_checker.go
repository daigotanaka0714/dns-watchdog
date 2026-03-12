package main

import (
	"fmt"
	"net"
	"strings"
)

var defaultBlocklists = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"b.barracudacentral.org",
}

// dnsLookupHost is a package-level variable for testability
var dnsLookupHost = func(host string) ([]string, error) {
	addrs, err := net.LookupHost(host)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return nil, nil
		}
		return nil, err
	}
	return addrs, nil
}

func reverseIP(ip string) string {
	parts := strings.Split(ip, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}

func checkBlocklistWith(ip, blocklist string, lookupFn func(string) ([]string, error)) (bool, error) {
	query := reverseIP(ip) + "." + blocklist
	addrs, err := lookupFn(query)
	if err != nil {
		return false, fmt.Errorf("DNSBL lookup failed for %s on %s: %w", ip, blocklist, err)
	}
	return len(addrs) > 0, nil
}

// RunBlocklistCheck checks if IPs in Expected are listed on any DNSBL
func RunBlocklistCheck(cfg *Config, check CheckEntry) CheckResult {
	result := CheckResult{Check: check, OK: true}

	var listedOn []string
	for _, ip := range check.Expected {
		for _, bl := range defaultBlocklists {
			listed, err := checkBlocklistWith(ip, bl, dnsLookupHost)
			if err != nil {
				result.OK = false
				result.Error = err.Error()
				return result
			}
			if listed {
				listedOn = append(listedOn, fmt.Sprintf("%s listed on %s", ip, bl))
			}
		}
	}

	if len(listedOn) > 0 {
		result.OK = false
		result.Actual = listedOn
	}

	return result
}
