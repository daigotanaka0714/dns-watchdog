package main

import (
	"testing"
)

func TestRunPropagationCheck_AllMatch(t *testing.T) {
	origFn := propagationQueryFn
	defer func() { propagationQueryFn = origFn }()

	propagationQueryFn = func(domain, resolver, qtype string) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "PROPAGATION", Name: "@", Expected: []string{"1.2.3.4"}}
	result := RunPropagationCheck(cfg, check)
	if !result.OK {
		t.Errorf("expected OK=true, got false. Error: %s, Actual: %v", result.Error, result.Actual)
	}
}

func TestRunPropagationCheck_Mismatch(t *testing.T) {
	origFn := propagationQueryFn
	defer func() { propagationQueryFn = origFn }()

	callCount := 0
	propagationQueryFn = func(domain, resolver, qtype string) ([]string, error) {
		callCount++
		if callCount == 2 {
			return []string{"5.6.7.8"}, nil
		}
		return []string{"1.2.3.4"}, nil
	}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "PROPAGATION", Name: "@", Expected: []string{"1.2.3.4"}}
	result := RunPropagationCheck(cfg, check)
	if result.OK {
		t.Error("expected OK=false for mismatched propagation")
	}
	if len(result.Actual) == 0 {
		t.Error("expected actual to contain mismatch details")
	}
}
