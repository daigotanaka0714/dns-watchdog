package main

import "testing"

func TestResolveLabels_English(t *testing.T) {
	labels := ResolveLabels("en", nil)
	if labels["error"] != "ERROR" {
		t.Errorf("expected ERROR, got %s", labels["error"])
	}
	if labels["warning"] != "WARNING" {
		t.Errorf("expected WARNING, got %s", labels["warning"])
	}
}

func TestResolveLabels_Japanese(t *testing.T) {
	labels := ResolveLabels("ja", nil)
	if labels["error"] != "エラー" {
		t.Errorf("expected エラー, got %s", labels["error"])
	}
	if labels["warning"] != "警告" {
		t.Errorf("expected 警告, got %s", labels["warning"])
	}
}

func TestResolveLabels_UnsupportedFallsBackToEN(t *testing.T) {
	labels := ResolveLabels("fr", nil)
	if labels["error"] != "ERROR" {
		t.Errorf("unsupported language should fall back to en, got %s", labels["error"])
	}
}

func TestResolveLabels_EmptyFallsBackToEN(t *testing.T) {
	labels := ResolveLabels("", nil)
	if labels["error"] != "ERROR" {
		t.Errorf("empty language should fall back to en, got %s", labels["error"])
	}
}

func TestResolveLabels_CustomOverride(t *testing.T) {
	custom := map[string]string{
		"error": "CRITICAL",
		"title": "DNS Monitor: %s",
	}
	labels := ResolveLabels("en", custom)
	if labels["error"] != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", labels["error"])
	}
	if labels["title"] != "DNS Monitor: %s" {
		t.Errorf("expected DNS Monitor: %%s, got %s", labels["title"])
	}
	// Non-overridden keys should remain
	if labels["warning"] != "WARNING" {
		t.Errorf("expected WARNING, got %s", labels["warning"])
	}
}

func TestResolveLabels_UnknownKeysIgnored(t *testing.T) {
	custom := map[string]string{
		"unknown_key": "value",
	}
	labels := ResolveLabels("en", custom)
	if _, exists := labels["unknown_key"]; exists {
		t.Error("unknown keys should be ignored")
	}
}

func TestResolveLabels_CustomOverrideOnJapanese(t *testing.T) {
	custom := map[string]string{
		"error": "重大",
	}
	labels := ResolveLabels("ja", custom)
	if labels["error"] != "重大" {
		t.Errorf("expected 重大, got %s", labels["error"])
	}
	if labels["warning"] != "警告" {
		t.Errorf("expected 警告, got %s", labels["warning"])
	}
}

func TestResolveLabels_DoesNotMutateBuiltin(t *testing.T) {
	custom := map[string]string{
		"error": "CRITICAL",
	}
	ResolveLabels("en", custom)

	// Verify built-in map was not modified
	if labelsEN["error"] != "ERROR" {
		t.Errorf("built-in labelsEN was mutated: error = %s", labelsEN["error"])
	}
}
