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

// SlackMessage represents a Slack webhook payload
type SlackMessage struct {
	Text string `json:"text"`
}

// FormatFailures formats DNS check failures into a human-readable message
func FormatFailures(domain string, failures []CheckResult) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("🚨 DNS異常検知: %s\n", domain))
	b.WriteString(fmt.Sprintf("検知時刻: %s\n\n", time.Now().UTC().Format(time.RFC3339)))

	for i, f := range failures {
		b.WriteString(fmt.Sprintf("レコード: %s (%s)\n", f.Check.Type, f.Check.Name))

		if f.Error != "" {
			b.WriteString(fmt.Sprintf("エラー: %s\n", f.Error))
		} else {
			switch f.Check.Type {
			case "BLOCKLIST":
				b.WriteString("ブロックリスト検知:\n")
				for _, entry := range f.Actual {
					b.WriteString(fmt.Sprintf("  - %s\n", entry))
				}
			case "CERT_EXPIRY":
				b.WriteString(fmt.Sprintf("証明書期限: %s\n", strings.Join(f.Actual, ", ")))
				b.WriteString(fmt.Sprintf("警告閾値: %d日前\n", f.Check.WarnDays))
			case "WHOIS_EXPIRY":
				b.WriteString(fmt.Sprintf("ドメイン期限: %s\n", strings.Join(f.Actual, ", ")))
				b.WriteString(fmt.Sprintf("警告閾値: %d日前\n", f.Check.WarnDays))
			case "NS_CONSISTENCY":
				b.WriteString("ネームサーバー不整合:\n")
				for _, entry := range f.Actual {
					b.WriteString(fmt.Sprintf("  - %s\n", entry))
				}
			case "PROPAGATION":
				b.WriteString(fmt.Sprintf("期待値: %s\n", strings.Join(f.Check.Expected, ", ")))
				b.WriteString("伝播不一致:\n")
				for _, entry := range f.Actual {
					b.WriteString(fmt.Sprintf("  - %s\n", entry))
				}
			default:
				if f.Check.Contains != "" {
					b.WriteString(fmt.Sprintf("期待値（部分一致）: %s\n", f.Check.Contains))
					b.WriteString(fmt.Sprintf("実際値: %s\n", strings.Join(f.Actual, ", ")))
				} else {
					b.WriteString(fmt.Sprintf("期待値: %s\n", strings.Join(f.Check.Expected, ", ")))
					b.WriteString(fmt.Sprintf("実際値: %s\n", strings.Join(f.Actual, ", ")))
				}
			}
		}

		if i < len(failures)-1 {
			b.WriteString("\n")
		}
	}

	return b.String()
}

// SendSlack posts a message to a Slack webhook URL
func SendSlack(webhookURL string, message string) error {
	payload := SlackMessage{Text: message}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack message: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to send Slack message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// Notify sends a Slack notification for DNS check failures
func Notify(cfg *Config, failures []CheckResult) error {
	webhookURL := os.Getenv(cfg.Notify.SlackWebhookEnv)
	if webhookURL == "" {
		return fmt.Errorf("environment variable %s is not set", cfg.Notify.SlackWebhookEnv)
	}

	message := FormatFailures(cfg.Domain, failures)
	return SendSlack(webhookURL, message)
}
