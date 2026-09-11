package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// SlackPayload represents a Slack webhook payload with attachments
type SlackPayload struct {
	Attachments []SlackAttachment `json:"attachments"`
}

// SlackAttachment represents a single Slack attachment
type SlackAttachment struct {
	Color    string       `json:"color"`
	Pretext  string       `json:"pretext,omitempty"`
	Fallback string       `json:"fallback"`
	Title    string       `json:"title"`
	Text     string       `json:"text"`
	Fields   []SlackField `json:"fields,omitempty"`
	Footer   string       `json:"footer,omitempty"`
	Ts       int64        `json:"ts"`
}

// SlackField represents a field in a Slack attachment
type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

const (
	colorError               = "#e01e5a"
	colorWarning             = "#ecb22e"
	maxAttachmentsPerMessage = 20
)

// classifySeverity returns severity label key and color for a check result.
func classifySeverity(result CheckResult) (string, string) {
	if result.Error != "" {
		return "error", colorError
	}
	return "warning", colorWarning
}

// generateSummary returns a human-readable summary and action label key for a check result.
func generateSummary(result CheckResult, labels map[string]string) (string, string) {
	if result.Error != "" {
		return result.Error, labels["action_retry"]
	}

	switch result.Check.Type {
	case "CERT_EXPIRY":
		info := strings.Join(result.Actual, ", ")
		return fmt.Sprintf(labels["summary_cert_expiry"], info), labels["action_renew_cert"]
	case "WHOIS_EXPIRY":
		info := strings.Join(result.Actual, ", ")
		return fmt.Sprintf(labels["summary_whois_expiry"], info), labels["action_renew_domain"]
	case "BLOCKLIST":
		detail := labels["summary_blocklist"]
		if len(result.Actual) > 0 {
			detail += "\n" + strings.Join(result.Actual, "\n")
		}
		return detail, labels["action_request_delist"]
	case "NS_CONSISTENCY":
		detail := labels["summary_ns_inconsistency"]
		if len(result.Actual) > 0 {
			detail += "\n" + strings.Join(result.Actual, "\n")
		}
		return detail, labels["action_check_ns"]
	case "PROPAGATION":
		detail := labels["summary_propagation"]
		if len(result.Check.Expected) > 0 {
			detail += fmt.Sprintf("\nExpected: %s", strings.Join(result.Check.Expected, ", "))
		}
		if len(result.Actual) > 0 {
			detail += "\n" + strings.Join(result.Actual, "\n")
		}
		return detail, labels["action_wait_propagation"]
	default:
		// DNS record checks: A, NS, MX, CNAME, TXT
		if result.Check.Contains != "" {
			summary := fmt.Sprintf(labels["summary_dns_contains_mismatch"], result.Check.Type)
			summary += fmt.Sprintf("\nExpected (contains): %s", result.Check.Contains)
			summary += fmt.Sprintf("\nActual: %s", strings.Join(result.Actual, ", "))
			return summary, labels["action_verify_dns"]
		}
		summary := fmt.Sprintf(labels["summary_dns_mismatch"], result.Check.Type)
		summary += fmt.Sprintf("\nExpected: %s", strings.Join(result.Check.Expected, ", "))
		summary += fmt.Sprintf("\nActual: %s", strings.Join(result.Actual, ", "))
		return summary, labels["action_verify_dns"]
	}
}

// FormatSlackAttachment builds a SlackPayload with one attachment per failure.
func FormatSlackAttachment(domain string, failures []CheckResult, labels map[string]string) SlackPayload {
	now := time.Now().Unix()
	pretext := fmt.Sprintf(":rotating_light: "+labels["title"], domain)

	attachments := make([]SlackAttachment, 0, len(failures))
	for i, f := range failures {
		sevKey, color := classifySeverity(f)
		sevLabel := labels[sevKey]
		summary, action := generateSummary(f, labels)
		recordLabel := fmt.Sprintf("%s (%s)", f.Check.Type, f.Check.Name)

		att := SlackAttachment{
			Color:    color,
			Fallback: fmt.Sprintf("%s: %s - %s", sevLabel, recordLabel, domain),
			Title:    fmt.Sprintf("%s — %s", sevLabel, recordLabel),
			Text:     summary,
			Fields: []SlackField{
				{Title: labels["record"], Value: recordLabel, Short: true},
				{Title: labels["domain"], Value: domain, Short: true},
				{Title: labels["action"], Value: action, Short: true},
			},
			Footer: labels["footer"],
			Ts:     now,
		}

		if i == 0 {
			att.Pretext = pretext
		}

		attachments = append(attachments, att)
	}

	return SlackPayload{Attachments: attachments}
}

// FormatFailures formats DNS check failures into a human-readable message for CLI output.
func FormatFailures(domain string, failures []CheckResult) string {
	var b strings.Builder

	fmt.Fprintf(&b, "DNS Alert: %s\n", domain)
	fmt.Fprintf(&b, "Detected at: %s\n\n", time.Now().UTC().Format(time.RFC3339))

	for i, f := range failures {
		fmt.Fprintf(&b, "Record: %s (%s)\n", f.Check.Type, f.Check.Name)

		if f.Error != "" {
			fmt.Fprintf(&b, "Error: %s\n", f.Error)
		} else {
			switch f.Check.Type {
			case "BLOCKLIST":
				b.WriteString("Blocklist detected:\n")
				for _, entry := range f.Actual {
					fmt.Fprintf(&b, "  - %s\n", entry)
				}
			case "CERT_EXPIRY":
				fmt.Fprintf(&b, "Certificate expiry: %s\n", strings.Join(f.Actual, ", "))
				certWarn := f.Check.WarnDays
				if certWarn == 0 {
					certWarn = 30
				}
				fmt.Fprintf(&b, "Warning threshold: %d days\n", certWarn)
			case "WHOIS_EXPIRY":
				fmt.Fprintf(&b, "Domain expiry: %s\n", strings.Join(f.Actual, ", "))
				whoisWarn := f.Check.WarnDays
				if whoisWarn == 0 {
					whoisWarn = 60
				}
				fmt.Fprintf(&b, "Warning threshold: %d days\n", whoisWarn)
			case "NS_CONSISTENCY":
				b.WriteString("NS inconsistency:\n")
				for _, entry := range f.Actual {
					fmt.Fprintf(&b, "  - %s\n", entry)
				}
			case "PROPAGATION":
				fmt.Fprintf(&b, "Expected: %s\n", strings.Join(f.Check.Expected, ", "))
				b.WriteString("Propagation mismatch:\n")
				for _, entry := range f.Actual {
					fmt.Fprintf(&b, "  - %s\n", entry)
				}
			default:
				if f.Check.Contains != "" {
					fmt.Fprintf(&b, "Expected (contains): %s\n", f.Check.Contains)
					fmt.Fprintf(&b, "Actual: %s\n", strings.Join(f.Actual, ", "))
				} else {
					fmt.Fprintf(&b, "Expected: %s\n", strings.Join(f.Check.Expected, ", "))
					fmt.Fprintf(&b, "Actual: %s\n", strings.Join(f.Actual, ", "))
				}
			}
		}

		if i < len(failures)-1 {
			b.WriteString("\n")
		}
	}

	return b.String()
}

// SendSlack posts a SlackPayload to a Slack webhook URL.
func SendSlack(webhookURL string, payload SlackPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack payload: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to send Slack message: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// Notify sends Slack notifications for DNS check failures.
// Splits into multiple calls if there are more than 20 failures (Slack attachment limit).
func Notify(cfg *Config, failures []CheckResult) error {
	webhookURL := os.Getenv(cfg.Notify.SlackWebhookEnv)
	if webhookURL == "" {
		return fmt.Errorf("environment variable %s is not set", cfg.Notify.SlackWebhookEnv)
	}

	labels := ResolveLabels(cfg.Notify.Language, cfg.Notify.CustomLabels)

	for i := 0; i < len(failures); i += maxAttachmentsPerMessage {
		end := i + maxAttachmentsPerMessage
		if end > len(failures) {
			end = len(failures)
		}
		batch := failures[i:end]
		payload := FormatSlackAttachment(cfg.Domain, batch, labels)
		if err := SendSlack(webhookURL, payload); err != nil {
			return err
		}
	}

	return nil
}
