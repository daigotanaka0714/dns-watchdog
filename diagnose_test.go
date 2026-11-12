package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiagnose(t *testing.T) {
	tests := []struct {
		name       string
		result     CheckResult
		wantOK     bool
		wantCause  string
		wantAction string
		wantArg    int
	}{
		{
			name:   "no query info",
			result: CheckResult{Check: CheckEntry{Type: "CERT_EXPIRY"}},
			wantOK: false,
		},
		{
			name:       "NXDOMAIN",
			result:     CheckResult{Query: &QueryInfo{RCode: rcodeNXDomain}},
			wantOK:     true,
			wantCause:  "cause_nxdomain",
			wantAction: "action_check_name_and_expiry",
		},
		{
			name:       "SERVFAIL",
			result:     CheckResult{Query: &QueryInfo{RCode: rcodeServFail}},
			wantOK:     true,
			wantCause:  "cause_servfail",
			wantAction: "action_check_dnssec_ns",
		},
		{
			name:       "REFUSED",
			result:     CheckResult{Query: &QueryInfo{RCode: rcodeRefused}},
			wantOK:     true,
			wantCause:  "cause_refused",
			wantAction: "action_check_ns",
		},
		{
			name:       "NOERROR with no records",
			result:     CheckResult{Query: &QueryInfo{RCode: rcodeNoError}},
			wantOK:     true,
			wantCause:  "cause_no_records",
			wantAction: "action_add_record",
		},
		{
			name:       "NOERROR mismatch with TTL",
			result:     CheckResult{Actual: []string{"5.6.7.8"}, Query: &QueryInfo{TTL: 300}},
			wantOK:     true,
			wantCause:  "cause_ttl_stale",
			wantAction: "action_wait_propagation",
			wantArg:    300,
		},
		{
			name:   "NOERROR mismatch without TTL",
			result: CheckResult{Actual: []string{"5.6.7.8"}, Query: &QueryInfo{}},
			wantOK: false,
		},
		{
			name:       "HTTP 429",
			result:     CheckResult{Error: "x", Query: &QueryInfo{HTTPStatus: 429}},
			wantOK:     true,
			wantCause:  "cause_http_rate_limited",
			wantAction: "action_retry",
		},
		{
			name:       "HTTP 400",
			result:     CheckResult{Error: "x", Query: &QueryInfo{HTTPStatus: 400}},
			wantOK:     true,
			wantCause:  "cause_http_client_error",
			wantAction: "action_check_config",
			wantArg:    400,
		},
		{
			name:       "HTTP 503",
			result:     CheckResult{Error: "x", Query: &QueryInfo{HTTPStatus: 503}},
			wantOK:     true,
			wantCause:  "cause_http_server_error",
			wantAction: "action_retry",
			wantArg:    503,
		},
		{
			name:   "HTTP 3xx has no suggestion",
			result: CheckResult{Error: "x", Query: &QueryInfo{HTTPStatus: 302}},
			wantOK: false,
		},
		{
			name:   "transport error has no suggestion",
			result: CheckResult{Error: "DNS query failed: timeout", Query: &QueryInfo{}},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Diagnose(tt.result)
			if ok != tt.wantOK {
				t.Fatalf("Diagnose ok = %v, want %v (got %+v)", ok, tt.wantOK, got)
			}
			if !ok {
				return
			}
			if got.Cause != tt.wantCause || got.Action != tt.wantAction || got.CauseArg != tt.wantArg {
				t.Errorf("Diagnose = %+v, want cause=%s action=%s arg=%d",
					got, tt.wantCause, tt.wantAction, tt.wantArg)
			}
		})
	}
}

func TestDiagnose_LabelsExistInBothLocales(t *testing.T) {
	keys := []string{
		"cause",
		"cause_http_rate_limited", "cause_http_client_error", "cause_http_server_error",
		"cause_nxdomain", "cause_servfail", "cause_refused", "cause_no_records", "cause_ttl_stale",
		"action_check_config", "action_check_name_and_expiry", "action_check_dnssec_ns", "action_add_record",
	}
	for lang, labels := range builtinLabels {
		for _, k := range keys {
			if labels[k] == "" {
				t.Errorf("locale %s is missing label %q", lang, k)
			}
		}
	}
}

func TestQueryDNSDetail_RCodeAndTTL(t *testing.T) {
	server := newMockDoHServer(DoHResponse{
		Status: rcodeNXDomain,
	})
	defer server.Close()

	got, info, err := queryDNSDetail("missing.example.com", "A", server.Client(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no answers, got %v", got)
	}
	if info.RCode != rcodeNXDomain {
		t.Errorf("RCode = %d, want %d", info.RCode, rcodeNXDomain)
	}

	server2 := newMockDoHServer(DoHResponse{
		Answer: []DoHAnswer{
			{Name: "example.com.", Type: 1, TTL: 300, Data: "1.2.3.4"},
			{Name: "example.com.", Type: 1, TTL: 60, Data: "1.2.3.5"},
		},
	})
	defer server2.Close()

	_, info, err = queryDNSDetail("example.com", "A", server2.Client(), server2.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.TTL != 60 {
		t.Errorf("TTL = %d, want the smallest (60)", info.TTL)
	}
}

func TestRunCheck_HTTPStatusIsRecorded(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer server.Close()

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "A", Name: "@", Expected: []string{"1.2.3.4"}}

	result := RunCheck(cfg, check, server.Client(), server.URL)
	if result.OK {
		t.Fatal("expected failure")
	}
	if result.Query == nil || result.Query.HTTPStatus != http.StatusTooManyRequests {
		t.Fatalf("Query = %+v, want HTTPStatus 429", result.Query)
	}
	if !strings.Contains(result.Error, "429") {
		t.Errorf("error text changed: %q", result.Error)
	}
}

func TestFormatSlackAttachment_IncludesDiagnosis(t *testing.T) {
	labels := ResolveLabels("en", nil)
	failures := []CheckResult{{
		Check: CheckEntry{Type: "A", Name: "www", Expected: []string{"1.2.3.4"}},
		Query: &QueryInfo{RCode: rcodeNXDomain},
	}}

	payload := FormatSlackAttachment("example.com", failures, labels)
	att := payload.Attachments[0]

	if !strings.Contains(att.Text, "NXDOMAIN") {
		t.Errorf("summary should include the cause, got %q", att.Text)
	}
	var action string
	for _, f := range att.Fields {
		if f.Title == labels["action"] {
			action = f.Value
		}
	}
	if action != labels["action_check_name_and_expiry"] {
		t.Errorf("action = %q, want %q", action, labels["action_check_name_and_expiry"])
	}
}

func TestFormatSlackAttachment_NoDiagnosisKeepsGenericAction(t *testing.T) {
	labels := ResolveLabels("en", nil)
	failures := []CheckResult{{
		Check:  CheckEntry{Type: "CERT_EXPIRY", Name: "@"},
		Actual: []string{"5 days"},
	}}

	payload := FormatSlackAttachment("example.com", failures, labels)
	att := payload.Attachments[0]

	if strings.Contains(att.Text, labels["cause"]) {
		t.Errorf("no cause expected, got %q", att.Text)
	}
}
