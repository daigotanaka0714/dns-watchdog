package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFormatSlackAttachment_Error(t *testing.T) {
	labels := ResolveLabels("en", nil)
	failures := []CheckResult{
		{
			Check: CheckEntry{Type: "WHOIS_EXPIRY", Name: "@"},
			OK:    false,
			Error: "WHOIS query failed: i/o timeout",
		},
	}

	payload := FormatSlackAttachment("example.com", failures, labels)

	if len(payload.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(payload.Attachments))
	}

	att := payload.Attachments[0]
	if att.Color != colorError {
		t.Errorf("expected color %s, got %s", colorError, att.Color)
	}
	if !strings.Contains(att.Title, "ERROR") {
		t.Errorf("expected title to contain ERROR, got %s", att.Title)
	}
	if !strings.Contains(att.Text, "i/o timeout") {
		t.Errorf("expected text to contain error message, got %s", att.Text)
	}
	if !strings.Contains(att.Pretext, "example.com") {
		t.Errorf("expected pretext to contain domain, got %s", att.Pretext)
	}
	if att.Fallback == "" {
		t.Error("expected fallback to be set")
	}
	if att.Footer != "dns-watchdog" {
		t.Errorf("expected footer dns-watchdog, got %s", att.Footer)
	}

	// Check action field
	actionFound := false
	for _, f := range att.Fields {
		if f.Title == "Action" && f.Value == "Retry in next cycle" {
			actionFound = true
		}
	}
	if !actionFound {
		t.Error("expected action field 'Retry in next cycle'")
	}
}

func TestFormatSlackAttachment_Warning_DNSMismatch(t *testing.T) {
	labels := ResolveLabels("en", nil)
	failures := []CheckResult{
		{
			Check: CheckEntry{
				Type:     "MX",
				Name:     "@",
				Expected: []string{"10 mail.example.com."},
			},
			Actual: []string{"20 other.example.com."},
			OK:     false,
		},
	}

	payload := FormatSlackAttachment("example.com", failures, labels)
	att := payload.Attachments[0]

	if att.Color != colorWarning {
		t.Errorf("expected color %s, got %s", colorWarning, att.Color)
	}
	if !strings.Contains(att.Title, "WARNING") {
		t.Errorf("expected title to contain WARNING, got %s", att.Title)
	}
	if !strings.Contains(att.Text, "MX record mismatch") {
		t.Errorf("expected summary to contain 'MX record mismatch', got %s", att.Text)
	}
	if !strings.Contains(att.Text, "10 mail.example.com.") {
		t.Errorf("expected text to contain expected value, got %s", att.Text)
	}
	if !strings.Contains(att.Text, "20 other.example.com.") {
		t.Errorf("expected text to contain actual value, got %s", att.Text)
	}
}

func TestFormatSlackAttachment_Warning_ContainsMatch(t *testing.T) {
	labels := ResolveLabels("en", nil)
	failures := []CheckResult{
		{
			Check: CheckEntry{
				Type:     "TXT",
				Name:     "@",
				Contains: "v=spf1",
			},
			Actual: []string{"\"v=DKIM1; k=rsa\""},
			OK:     false,
		},
	}

	payload := FormatSlackAttachment("example.com", failures, labels)
	att := payload.Attachments[0]

	if !strings.Contains(att.Text, "missing expected content") {
		t.Errorf("expected summary for contains mismatch, got %s", att.Text)
	}
	if !strings.Contains(att.Text, "v=spf1") {
		t.Errorf("expected text to contain expected substring, got %s", att.Text)
	}
}

func TestFormatSlackAttachment_CertExpiry(t *testing.T) {
	labels := ResolveLabels("en", nil)
	failures := []CheckResult{
		{
			Check:  CheckEntry{Type: "CERT_EXPIRY", Name: "@", Host: "example.com:443", WarnDays: 30},
			Actual: []string{"expires in 10 days (2026-03-30)"},
			OK:     false,
		},
	}

	payload := FormatSlackAttachment("example.com", failures, labels)
	att := payload.Attachments[0]

	if !strings.Contains(att.Text, "Certificate expires in") {
		t.Errorf("expected cert expiry summary, got %s", att.Text)
	}
	// Check action
	for _, f := range att.Fields {
		if f.Title == "Action" && f.Value != "Renew SSL certificate" {
			t.Errorf("expected action 'Renew SSL certificate', got %s", f.Value)
		}
	}
}

func TestFormatSlackAttachment_WhoisExpiry(t *testing.T) {
	labels := ResolveLabels("en", nil)
	failures := []CheckResult{
		{
			Check:  CheckEntry{Type: "WHOIS_EXPIRY", Name: "@", WarnDays: 60},
			Actual: []string{"domain expires in 30 days (2026-04-19)"},
			OK:     false,
		},
	}

	payload := FormatSlackAttachment("example.com", failures, labels)
	att := payload.Attachments[0]

	if !strings.Contains(att.Text, "Domain expires in") {
		t.Errorf("expected whois expiry summary, got %s", att.Text)
	}
}

func TestFormatSlackAttachment_Blocklist(t *testing.T) {
	labels := ResolveLabels("en", nil)
	failures := []CheckResult{
		{
			Check:  CheckEntry{Type: "BLOCKLIST", Name: "@"},
			Actual: []string{"1.2.3.4 listed on zen.spamhaus.org"},
			OK:     false,
		},
	}

	payload := FormatSlackAttachment("example.com", failures, labels)
	att := payload.Attachments[0]

	if !strings.Contains(att.Text, "IP listed on blocklist") {
		t.Errorf("expected blocklist summary, got %s", att.Text)
	}
	if !strings.Contains(att.Text, "zen.spamhaus.org") {
		t.Errorf("expected blocklist details, got %s", att.Text)
	}
}

func TestFormatSlackAttachment_NSConsistency(t *testing.T) {
	labels := ResolveLabels("en", nil)
	failures := []CheckResult{
		{
			Check:  CheckEntry{Type: "NS_CONSISTENCY", Name: "@"},
			Actual: []string{"ns1: [1.2.3.4], ns2: [5.6.7.8]"},
			OK:     false,
		},
	}

	payload := FormatSlackAttachment("example.com", failures, labels)
	att := payload.Attachments[0]

	if !strings.Contains(att.Text, "NS records inconsistent") {
		t.Errorf("expected NS inconsistency summary, got %s", att.Text)
	}
}

func TestFormatSlackAttachment_Propagation(t *testing.T) {
	labels := ResolveLabels("en", nil)
	failures := []CheckResult{
		{
			Check:  CheckEntry{Type: "PROPAGATION", Name: "@", Expected: []string{"1.2.3.4"}},
			Actual: []string{"Cloudflare (1.1.1.1:53): [5.6.7.8]"},
			OK:     false,
		},
	}

	payload := FormatSlackAttachment("example.com", failures, labels)
	att := payload.Attachments[0]

	if !strings.Contains(att.Text, "DNS propagation mismatch") {
		t.Errorf("expected propagation summary, got %s", att.Text)
	}
	if !strings.Contains(att.Text, "Cloudflare") {
		t.Errorf("expected propagation details, got %s", att.Text)
	}
}

func TestFormatSlackAttachment_MultipleFailures_PretextOnlyFirst(t *testing.T) {
	labels := ResolveLabels("en", nil)
	failures := []CheckResult{
		{
			Check:  CheckEntry{Type: "A", Name: "@", Expected: []string{"1.2.3.4"}},
			Actual: []string{"5.6.7.8"},
			OK:     false,
		},
		{
			Check:  CheckEntry{Type: "MX", Name: "@", Expected: []string{"10 mail.example.com."}},
			Actual: []string{"20 other.example.com."},
			OK:     false,
		},
	}

	payload := FormatSlackAttachment("example.com", failures, labels)

	if len(payload.Attachments) != 2 {
		t.Fatalf("expected 2 attachments, got %d", len(payload.Attachments))
	}
	if payload.Attachments[0].Pretext == "" {
		t.Error("expected pretext on first attachment")
	}
	if payload.Attachments[1].Pretext != "" {
		t.Error("expected no pretext on second attachment")
	}
}

func TestFormatSlackAttachment_JapaneseLabels(t *testing.T) {
	labels := ResolveLabels("ja", nil)
	failures := []CheckResult{
		{
			Check:  CheckEntry{Type: "A", Name: "@", Expected: []string{"1.2.3.4"}},
			Actual: []string{"5.6.7.8"},
			OK:     false,
		},
	}

	payload := FormatSlackAttachment("example.com", failures, labels)
	att := payload.Attachments[0]

	if !strings.Contains(att.Title, "警告") {
		t.Errorf("expected Japanese warning label, got %s", att.Title)
	}
	if !strings.Contains(att.Pretext, "DNS異常検知") {
		t.Errorf("expected Japanese title in pretext, got %s", att.Pretext)
	}

	// Check field labels
	for _, f := range att.Fields {
		if f.Title == "Record" {
			t.Error("expected Japanese label for Record field")
		}
	}
}

func TestFormatSlackAttachment_CustomLabels(t *testing.T) {
	custom := map[string]string{
		"error": "CRITICAL",
		"title": "DNS Monitor: %s",
	}
	labels := ResolveLabels("en", custom)
	failures := []CheckResult{
		{
			Check: CheckEntry{Type: "A", Name: "@"},
			OK:    false,
			Error: "DNS query failed: timeout",
		},
	}

	payload := FormatSlackAttachment("example.com", failures, labels)
	att := payload.Attachments[0]

	if !strings.Contains(att.Title, "CRITICAL") {
		t.Errorf("expected custom severity label CRITICAL, got %s", att.Title)
	}
	if !strings.Contains(att.Pretext, "DNS Monitor:") {
		t.Errorf("expected custom title in pretext, got %s", att.Pretext)
	}
}

func TestFormatFailures(t *testing.T) {
	failures := []CheckResult{
		{
			Check: CheckEntry{
				Type:     "MX",
				Name:     "@",
				Expected: []string{"10 mail.example.com."},
			},
			Actual: []string{"20 other.example.com."},
			OK:     false,
		},
		{
			Check: CheckEntry{
				Type: "A",
				Name: "www",
			},
			OK:    false,
			Error: "DNS query failed: timeout",
		},
	}

	msg := FormatFailures("example.com", failures)

	checks := []string{
		"example.com",
		"MX (@)",
		"10 mail.example.com.",
		"20 other.example.com.",
		"DNS query failed: timeout",
	}

	for _, check := range checks {
		if !strings.Contains(msg, check) {
			t.Errorf("expected message to contain %q, got:\n%s", check, msg)
		}
	}
}

func TestFormatFailures_Contains(t *testing.T) {
	failures := []CheckResult{
		{
			Check: CheckEntry{
				Type:     "TXT",
				Name:     "@",
				Contains: "v=spf1",
			},
			Actual: []string{"\"v=DKIM1; k=rsa\""},
			OK:     false,
		},
	}

	msg := FormatFailures("example.com", failures)

	if !strings.Contains(msg, "Expected (contains)") {
		t.Errorf("expected message to contain 'Expected (contains)', got:\n%s", msg)
	}
	if !strings.Contains(msg, "v=spf1") {
		t.Errorf("expected message to contain 'v=spf1', got:\n%s", msg)
	}
}

func TestFormatFailures_Blocklist(t *testing.T) {
	failures := []CheckResult{
		{
			Check:  CheckEntry{Type: "BLOCKLIST", Name: "@"},
			Actual: []string{"1.2.3.4 listed on zen.spamhaus.org"},
			OK:     false,
		},
	}
	msg := FormatFailures("example.com", failures)
	if !strings.Contains(msg, "BLOCKLIST") {
		t.Errorf("expected BLOCKLIST, got:\n%s", msg)
	}
	if !strings.Contains(msg, "Blocklist detected") {
		t.Errorf("expected Blocklist detected, got:\n%s", msg)
	}
}

func TestFormatFailures_CertExpiry(t *testing.T) {
	failures := []CheckResult{
		{
			Check:  CheckEntry{Type: "CERT_EXPIRY", Name: "@", Host: "example.com:443", WarnDays: 30},
			Actual: []string{"expires in 10 days (2026-03-21)"},
			OK:     false,
		},
	}
	msg := FormatFailures("example.com", failures)
	if !strings.Contains(msg, "Certificate expiry") {
		t.Errorf("expected Certificate expiry, got:\n%s", msg)
	}
	if !strings.Contains(msg, "Warning threshold: 30 days") {
		t.Errorf("expected Warning threshold: 30 days, got:\n%s", msg)
	}
}

func TestFormatFailures_WhoisExpiry(t *testing.T) {
	failures := []CheckResult{
		{
			Check:  CheckEntry{Type: "WHOIS_EXPIRY", Name: "@", WarnDays: 60},
			Actual: []string{"domain expires in 30 days (2026-04-10)"},
			OK:     false,
		},
	}
	msg := FormatFailures("example.com", failures)
	if !strings.Contains(msg, "Domain expiry") {
		t.Errorf("expected Domain expiry, got:\n%s", msg)
	}
	if !strings.Contains(msg, "Warning threshold: 60 days") {
		t.Errorf("expected Warning threshold: 60 days, got:\n%s", msg)
	}
}

func TestFormatFailures_NSConsistency(t *testing.T) {
	failures := []CheckResult{
		{
			Check:  CheckEntry{Type: "NS_CONSISTENCY", Name: "@"},
			Actual: []string{"ns1: [1.2.3.4], ns2: [5.6.7.8]"},
			OK:     false,
		},
	}
	msg := FormatFailures("example.com", failures)
	if !strings.Contains(msg, "NS inconsistency") {
		t.Errorf("expected NS inconsistency, got:\n%s", msg)
	}
}

func TestFormatFailures_Propagation(t *testing.T) {
	failures := []CheckResult{
		{
			Check:  CheckEntry{Type: "PROPAGATION", Name: "@", Expected: []string{"1.2.3.4"}},
			Actual: []string{"Cloudflare (1.1.1.1:53): [5.6.7.8]"},
			OK:     false,
		},
	}
	msg := FormatFailures("example.com", failures)
	if !strings.Contains(msg, "Propagation mismatch") {
		t.Errorf("expected Propagation mismatch, got:\n%s", msg)
	}
	if !strings.Contains(msg, "Cloudflare") {
		t.Errorf("expected Cloudflare, got:\n%s", msg)
	}
}

func TestSendSlack(t *testing.T) {
	var received SlackPayload

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		if err := json.Unmarshal(body, &received); err != nil {
			t.Fatalf("failed to unmarshal request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	payload := SlackPayload{
		Attachments: []SlackAttachment{
			{
				Color:    colorError,
				Fallback: "ERROR: A (@) - example.com",
				Title:    "ERROR — A (@)",
				Text:     "DNS query failed",
				Footer:   "dns-watchdog",
				Ts:       1710783670,
			},
		},
	}

	err := SendSlack(server.URL, payload)
	if err != nil {
		t.Fatalf("SendSlack returned error: %v", err)
	}

	if len(received.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(received.Attachments))
	}
	if received.Attachments[0].Title != "ERROR — A (@)" {
		t.Errorf("expected title 'ERROR — A (@)', got %q", received.Attachments[0].Title)
	}
}

func TestSendSlack_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	payload := SlackPayload{
		Attachments: []SlackAttachment{
			{Color: colorError, Fallback: "test", Title: "test", Text: "test"},
		},
	}

	err := SendSlack(server.URL, payload)
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected error to mention status 500, got: %v", err)
	}
}

func TestSendSlack_PayloadIsValidJSON(t *testing.T) {
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	labels := ResolveLabels("en", nil)
	failures := []CheckResult{
		{
			Check:  CheckEntry{Type: "A", Name: "@", Expected: []string{"1.2.3.4"}},
			Actual: []string{"5.6.7.8"},
			OK:     false,
		},
	}
	payload := FormatSlackAttachment("example.com", failures, labels)

	if err := SendSlack(server.URL, payload); err != nil {
		t.Fatalf("SendSlack error: %v", err)
	}

	var parsed SlackPayload
	if err := json.Unmarshal(receivedBody, &parsed); err != nil {
		t.Fatalf("sent payload is not valid JSON: %v", err)
	}
	if len(parsed.Attachments) != 1 {
		t.Errorf("expected 1 attachment in parsed payload, got %d", len(parsed.Attachments))
	}
	if parsed.Attachments[0].Color != colorWarning {
		t.Errorf("expected warning color, got %s", parsed.Attachments[0].Color)
	}
}
