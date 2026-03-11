package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	content := `
domain: example.com
checks:
  - type: A
    name: "@"
    expected:
      - "1.2.3.4"
  - type: TXT
    name: "@"
    contains: "v=spf1"
notify:
  slack_webhook_env: "SLACK_URL"
  template: "default"
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", cfg.Domain)
	}
	if len(cfg.Checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(cfg.Checks))
	}
	if cfg.Checks[0].Type != "A" {
		t.Errorf("expected type A, got %s", cfg.Checks[0].Type)
	}
	if cfg.Checks[0].Expected[0] != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", cfg.Checks[0].Expected[0])
	}
	if cfg.Checks[1].Contains != "v=spf1" {
		t.Errorf("expected contains v=spf1, got %s", cfg.Checks[1].Contains)
	}
	if cfg.Notify.SlackWebhookEnv != "SLACK_URL" {
		t.Errorf("expected SLACK_URL, got %s", cfg.Notify.SlackWebhookEnv)
	}
}

func TestLoadConfig_MissingDomain(t *testing.T) {
	content := `
checks:
  - type: A
    name: "@"
    expected:
      - "1.2.3.4"
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for missing domain")
	}
}

func TestLoadConfig_NoChecks(t *testing.T) {
	content := `
domain: example.com
checks: []
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for empty checks")
	}
}

func TestLoadConfig_EmptyCheckType(t *testing.T) {
	content := `
domain: example.com
checks:
  - type: ""
    name: "@"
    expected:
      - "1.2.3.4"
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for empty check type")
	}
}

func TestLoadConfig_NoExpectedOrContains(t *testing.T) {
	content := `
domain: example.com
checks:
  - type: A
    name: "@"
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for check with no expected or contains")
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path.yml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
