package main

import (
	"testing"
)

func TestRunNSConsistencyCheck_Consistent(t *testing.T) {
	origNSLookup := nsLookupFn
	origQueryNS := queryNSFn
	defer func() {
		nsLookupFn = origNSLookup
		queryNSFn = origQueryNS
	}()

	nsLookupFn = func(domain string) ([]string, error) {
		return []string{"ns1.example.com.", "ns2.example.com."}, nil
	}
	queryNSFn = func(domain, ns, qtype string) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "NS_CONSISTENCY", Name: "@", Expected: []string{"A"}}
	result := RunNSConsistencyCheck(cfg, check)
	if !result.OK {
		t.Errorf("expected OK=true, got false. Error: %s, Actual: %v", result.Error, result.Actual)
	}
}

func TestRunNSConsistencyCheck_Inconsistent(t *testing.T) {
	origNSLookup := nsLookupFn
	origQueryNS := queryNSFn
	defer func() {
		nsLookupFn = origNSLookup
		queryNSFn = origQueryNS
	}()

	nsLookupFn = func(domain string) ([]string, error) {
		return []string{"ns1.example.com.", "ns2.example.com."}, nil
	}
	callCount := 0
	queryNSFn = func(domain, ns, qtype string) ([]string, error) {
		callCount++
		if callCount <= 1 {
			return []string{"1.2.3.4"}, nil
		}
		return []string{"5.6.7.8"}, nil
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "NS_CONSISTENCY", Name: "@", Expected: []string{"A"}}
	result := RunNSConsistencyCheck(cfg, check)
	if result.OK {
		t.Error("expected OK=false for inconsistent NS results")
	}
}

func TestRunNSConsistencyCheck_DefaultRecordTypes(t *testing.T) {
	origNSLookup := nsLookupFn
	origQueryNS := queryNSFn
	defer func() {
		nsLookupFn = origNSLookup
		queryNSFn = origQueryNS
	}()

	nsLookupFn = func(domain string) ([]string, error) {
		return []string{"ns1.example.com.", "ns2.example.com."}, nil
	}
	var queriedTypes []string
	queryNSFn = func(domain, ns, qtype string) ([]string, error) {
		queriedTypes = append(queriedTypes, qtype)
		return []string{"1.2.3.4"}, nil
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "NS_CONSISTENCY", Name: "@"} // Empty Expected
	result := RunNSConsistencyCheck(cfg, check)
	if !result.OK {
		t.Errorf("expected OK=true, got false. Error: %s", result.Error)
	}
	if len(queriedTypes) == 0 {
		t.Error("expected default record types to be queried, but none were")
	}
}

func TestRunNSConsistencyCheck_MXConsistency(t *testing.T) {
	origNSLookup := nsLookupFn
	origQueryNS := queryNSFn
	defer func() {
		nsLookupFn = origNSLookup
		queryNSFn = origQueryNS
	}()

	nsLookupFn = func(domain string) ([]string, error) {
		return []string{"ns1.example.com.", "ns2.example.com."}, nil
	}
	queryNSFn = func(domain, ns, qtype string) ([]string, error) {
		return []string{"10 mail.example.com."}, nil
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "NS_CONSISTENCY", Name: "@", Expected: []string{"MX"}}
	result := RunNSConsistencyCheck(cfg, check)
	if !result.OK {
		t.Errorf("expected OK=true for consistent MX, got false. Error: %s", result.Error)
	}
}

func TestRunNSConsistencyCheck_NoNSFound(t *testing.T) {
	origNSLookup := nsLookupFn
	defer func() { nsLookupFn = origNSLookup }()

	nsLookupFn = func(domain string) ([]string, error) {
		return nil, nil
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "NS_CONSISTENCY", Name: "@", Expected: []string{"A"}}
	result := RunNSConsistencyCheck(cfg, check)
	if result.OK {
		t.Error("expected OK=false when no NS found")
	}
}
