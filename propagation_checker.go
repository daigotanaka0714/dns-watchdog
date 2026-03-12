package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

var publicResolvers = map[string]string{
	"Google":     "8.8.8.8:53",
	"Cloudflare": "1.1.1.1:53",
	"OpenDNS":    "208.67.222.222:53",
	"Quad9":      "9.9.9.9:53",
}

var propagationQueryFn = func(domain, resolver, qtype string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", resolver)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch qtype {
	case "A":
		return r.LookupHost(ctx, domain)
	default:
		return nil, fmt.Errorf("unsupported type for propagation check: %s", qtype)
	}
}

// RunPropagationCheck queries multiple public DNS resolvers and compares results against expected.
func RunPropagationCheck(cfg *Config, check CheckEntry) CheckResult {
	result := CheckResult{Check: check, OK: true}
	domain := ResolveName(cfg.Domain, check.Name)

	expectedSorted := make([]string, len(check.Expected))
	copy(expectedSorted, check.Expected)
	sort.Strings(expectedSorted)

	var mismatches []string
	for name, resolver := range publicResolvers {
		records, err := propagationQueryFn(domain, resolver, "A")
		if err != nil {
			mismatches = append(mismatches, fmt.Sprintf("%s (%s): error - %v", name, resolver, err))
			continue
		}

		sorted := make([]string, len(records))
		copy(sorted, records)
		sort.Strings(sorted)

		if !slicesEqual(expectedSorted, sorted) {
			mismatches = append(mismatches,
				fmt.Sprintf("%s (%s): [%s]", name, resolver, strings.Join(sorted, ", ")))
		}
	}

	if len(mismatches) > 0 {
		result.OK = false
		result.Actual = mismatches
	}

	return result
}
