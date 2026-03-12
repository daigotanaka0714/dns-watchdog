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

func TestLoadConfig_Blocklist(t *testing.T) {
	content := `
domain: example.com
checks:
  - type: BLOCKLIST
    name: "@"
    expected:
      - "clean"
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
	if cfg.Checks[0].Type != "BLOCKLIST" {
		t.Errorf("expected type BLOCKLIST, got %s", cfg.Checks[0].Type)
	}
}

func TestLoadConfig_CertExpiry(t *testing.T) {
	content := `
domain: example.com
checks:
  - type: CERT_EXPIRY
    name: "example.com"
    host: "example.com:443"
    warn_days: 30
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
	if cfg.Checks[0].Type != "CERT_EXPIRY" {
		t.Errorf("expected type CERT_EXPIRY, got %s", cfg.Checks[0].Type)
	}
	if cfg.Checks[0].Host != "example.com:443" {
		t.Errorf("expected host example.com:443, got %s", cfg.Checks[0].Host)
	}
	if cfg.Checks[0].WarnDays != 30 {
		t.Errorf("expected warn_days 30, got %d", cfg.Checks[0].WarnDays)
	}
}

func TestLoadConfig_WhoisExpiry(t *testing.T) {
	content := `
domain: example.com
checks:
  - type: WHOIS_EXPIRY
    name: "example.com"
    warn_days: 60
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
	if cfg.Checks[0].Type != "WHOIS_EXPIRY" {
		t.Errorf("expected type WHOIS_EXPIRY, got %s", cfg.Checks[0].Type)
	}
	if cfg.Checks[0].WarnDays != 60 {
		t.Errorf("expected warn_days 60, got %d", cfg.Checks[0].WarnDays)
	}
}

func TestLoadConfig_Propagation(t *testing.T) {
	content := `
domain: example.com
checks:
  - type: PROPAGATION
    name: "@"
    expected:
      - "1.2.3.4"
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
	if cfg.Checks[0].Type != "PROPAGATION" {
		t.Errorf("expected type PROPAGATION, got %s", cfg.Checks[0].Type)
	}
}

func TestLoadConfig_NSConsistency(t *testing.T) {
	content := `
domain: example.com
checks:
  - type: NS_CONSISTENCY
    name: "@"
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
	if cfg.Checks[0].Type != "NS_CONSISTENCY" {
		t.Errorf("expected type NS_CONSISTENCY, got %s", cfg.Checks[0].Type)
	}
}

func TestLoadConfig_SelfContainedTypeNoExpected(t *testing.T) {
	// Self-contained types should not require expected or contains
	for _, typ := range []string{"CERT_EXPIRY", "WHOIS_EXPIRY", "NS_CONSISTENCY"} {
		content := `
domain: example.com
checks:
  - type: ` + typ + `
    name: "test"
`
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "config.yml")
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		_, err := LoadConfig(path)
		if err != nil {
			t.Errorf("type %s should not require expected/contains, got error: %v", typ, err)
		}
	}
}

func TestLoadConfig_NonSelfContainedStillRequiresExpected(t *testing.T) {
	// Non-self-contained types like BLOCKLIST and PROPAGATION still need expected/contains
	for _, typ := range []string{"BLOCKLIST", "PROPAGATION"} {
		content := `
domain: example.com
checks:
  - type: ` + typ + `
    name: "test"
`
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "config.yml")
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		_, err := LoadConfig(path)
		if err == nil {
			t.Errorf("type %s should require expected/contains but no error returned", typ)
		}
	}
}
