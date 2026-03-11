package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		domain   string
		expected string
	}{
		{"@ returns domain", "@", "example.com", "example.com"},
		{"mail returns mail.domain", "mail", "example.com", "mail.example.com"},
		{"sub returns sub.domain", "sub", "example.com", "sub.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ResolveName(tt.domain, tt.input)
			if result != tt.expected {
				t.Errorf("ResolveName(%q, %q) = %q, want %q", tt.domain, tt.input, result, tt.expected)
			}
		})
	}
}

func TestQueryDNS_UnsupportedType(t *testing.T) {
	client := &http.Client{}
	_, err := QueryDNS("example.com", "AAAA", client, "")
	if err == nil {
		t.Fatal("expected error for unsupported type AAAA, got nil")
	}
}

func newMockDoHServer(response DoHResponse) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
	}))
}

func TestRunCheck_ExactMatch(t *testing.T) {
	server := newMockDoHServer(DoHResponse{
		Status: 0,
		Answer: []DoHAnswer{
			{Name: "example.com.", Type: 1, TTL: 300, Data: "1.2.3.4"},
		},
	})
	defer server.Close()

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{
		Type:     "A",
		Name:     "@",
		Expected: []string{"1.2.3.4"},
	}

	result := RunCheck(cfg, check, server.Client(), server.URL)
	if !result.OK {
		t.Errorf("expected OK=true, got false. Error: %s, Actual: %v", result.Error, result.Actual)
	}
}

func TestRunCheck_ExactMatch_Fail(t *testing.T) {
	server := newMockDoHServer(DoHResponse{
		Status: 0,
		Answer: []DoHAnswer{
			{Name: "example.com.", Type: 1, TTL: 300, Data: "5.6.7.8"},
		},
	})
	defer server.Close()

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{
		Type:     "A",
		Name:     "@",
		Expected: []string{"1.2.3.4"},
	}

	result := RunCheck(cfg, check, server.Client(), server.URL)
	if result.OK {
		t.Errorf("expected OK=false, got true. Actual: %v", result.Actual)
	}
}

func TestRunCheck_Contains(t *testing.T) {
	server := newMockDoHServer(DoHResponse{
		Status: 0,
		Answer: []DoHAnswer{
			{Name: "example.com.", Type: 16, TTL: 300, Data: "v=spf1 a:mail.example.com ~all"},
		},
	})
	defer server.Close()

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{
		Type:     "TXT",
		Name:     "@",
		Contains: "v=spf1",
	}

	result := RunCheck(cfg, check, server.Client(), server.URL)
	if !result.OK {
		t.Errorf("expected OK=true, got false. Error: %s, Actual: %v", result.Error, result.Actual)
	}
}

func TestRunCheck_Contains_Fail(t *testing.T) {
	server := newMockDoHServer(DoHResponse{
		Status: 0,
		Answer: []DoHAnswer{
			{Name: "example.com.", Type: 16, TTL: 300, Data: "v=dkim something"},
		},
	})
	defer server.Close()

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{
		Type:     "TXT",
		Name:     "@",
		Contains: "v=spf1",
	}

	result := RunCheck(cfg, check, server.Client(), server.URL)
	if result.OK {
		t.Errorf("expected OK=false, got true. Actual: %v", result.Actual)
	}
}

func TestExactMatchLogic(t *testing.T) {
	tests := []struct {
		name     string
		expected []string
		actual   []string
		wantOK   bool
	}{
		{"match order independent", []string{"a", "b"}, []string{"b", "a"}, true},
		{"mismatch", []string{"a", "b"}, []string{"a", "c"}, false},
		{"different length", []string{"a"}, []string{"a", "b"}, false},
		{"empty both", []string{}, []string{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a mock server that returns the "actual" values as A records
			answers := make([]DoHAnswer, len(tt.actual))
			for i, val := range tt.actual {
				answers[i] = DoHAnswer{Name: "example.com.", Type: 1, TTL: 300, Data: val}
			}
			server := newMockDoHServer(DoHResponse{Status: 0, Answer: answers})
			defer server.Close()

			cfg := &Config{Domain: "example.com"}
			check := CheckEntry{
				Type:     "A",
				Name:     "@",
				Expected: tt.expected,
			}

			result := RunCheck(cfg, check, server.Client(), server.URL)
			if result.OK != tt.wantOK {
				t.Errorf("expected OK=%v, got %v. Expected: %v, Actual: %v",
					tt.wantOK, result.OK, tt.expected, result.Actual)
			}
		})
	}
}
