package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

	if !strings.Contains(msg, "期待値（部分一致）") {
		t.Errorf("expected message to contain '期待値（部分一致）', got:\n%s", msg)
	}
	if !strings.Contains(msg, "v=spf1") {
		t.Errorf("expected message to contain 'v=spf1', got:\n%s", msg)
	}
}

func TestSendSlack(t *testing.T) {
	var received SlackMessage

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

	message := "test notification"
	err := SendSlack(server.URL, message)
	if err != nil {
		t.Fatalf("SendSlack returned error: %v", err)
	}

	if received.Text != message {
		t.Errorf("expected text %q, got %q", message, received.Text)
	}
}

func TestSendSlack_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	err := SendSlack(server.URL, "test")
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected error to mention status 500, got: %v", err)
	}
}
