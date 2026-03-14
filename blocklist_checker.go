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

// lookupHostFunc is the function used for DNS lookups. It can be overridden in tests.
var lookupHostFunc = net.LookupHost

// isBlocklistListing validates whether a DNSBL response address represents a
// real listing. Only 127.0.0.x where x >= 2 is a genuine listing. Addresses
// like 127.255.255.254 (public resolver error) and 127.255.255.255 (rate
// limit) are NOT listings.
func isBlocklistListing(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 127 && ip4[1] == 0 && ip4[2] == 0 && ip4[3] >= 2
}

// checkBlocklistWith queries a single DNSBL for the given reversed IP.
func checkBlocklistWith(reversedIP, blocklist string) (bool, error) {
	query := reversedIP + "." + blocklist
	addrs, err := lookupHostFunc(query)
	if err != nil {
		// NXDOMAIN means not listed — this is the normal "not found" case
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return false, nil
		}
		return false, fmt.Errorf("DNSBL lookup %s: %w", blocklist, err)
	}

	for _, addr := range addrs {
		if isBlocklistListing(addr) {
			return true, nil
		}
	}
	return false, nil
}

// reverseIP reverses the octets of an IPv4 address for DNSBL queries.
func reverseIP(ip string) (string, error) {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid IPv4 address: %s", ip)
	}
	return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0], nil
}

// RunBlocklistCheck checks if the IP (from check.Host or resolved from domain)
// is listed on any DNSBL. It uses check.Blocklists if provided, otherwise
// defaultBlocklists. One DNSBL failure does NOT abort remaining checks.
func RunBlocklistCheck(cfg *Config, check CheckEntry) CheckResult {
	result := CheckResult{Check: check, OK: true}

	host := check.Host
	if host == "" {
		// Use first IP from Expected if available
		if len(check.Expected) > 0 {
			host = check.Expected[0]
		} else {
			// Resolve the domain's A record to get an IP
			addrs, err := lookupHostFunc(cfg.Domain)
			if err != nil {
				result.OK = false
				result.Error = fmt.Sprintf("failed to resolve domain %s: %v", cfg.Domain, err)
				return result
			}
			if len(addrs) == 0 {
				result.OK = false
				result.Error = fmt.Sprintf("no A record found for %s", cfg.Domain)
				return result
			}
			host = addrs[0]
		}
	}

	reversedIP, err := reverseIP(host)
	if err != nil {
		result.OK = false
		result.Error = err.Error()
		return result
	}

	blocklists := check.Blocklists
	if len(blocklists) == 0 {
		blocklists = defaultBlocklists
	}

	var listedOn []string
	var warnings []string
	for _, bl := range blocklists {
		listed, err := checkBlocklistWith(reversedIP, bl)
		if err != nil {
			warnings = append(warnings, err.Error())
			continue // Don't abort — check remaining blocklists
		}
		if listed {
			listedOn = append(listedOn, fmt.Sprintf("%s listed on %s", host, bl))
		}
	}

	if len(listedOn) > 0 {
		result.OK = false
		result.Actual = listedOn
	}

	if len(warnings) > 0 && result.Error == "" {
		result.Error = strings.Join(warnings, "; ")
	}

	return result
}
