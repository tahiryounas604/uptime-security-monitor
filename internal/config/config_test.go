package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("missing file must not error: %v", err)
	}
	if cfg.Listen != ":8080" || cfg.DBPath != "uptime.db" || cfg.CheckInterval != 60 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
		"listen": ":9090",
		"db_path": "test.db",
		"webhook_url": "https://hooks.example.com/x",
		"monitors": [
			{"name": "Site", "url": "https://example.com", "keyword": "welcome"},
			{"name": "NoInterval", "url": "https://example.org"}
		]
	}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":9090" || cfg.DBPath != "test.db" || cfg.WebhookURL != "https://hooks.example.com/x" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if len(cfg.Monitors) != 2 {
		t.Fatalf("expected 2 monitors, got %d", len(cfg.Monitors))
	}
	if cfg.Monitors[0].Keyword != "welcome" {
		t.Fatalf("expected keyword 'welcome', got %q", cfg.Monitors[0].Keyword)
	}
	if cfg.Monitors[1].IntervalSeconds != 60 {
		t.Fatalf("missing interval must default to 60, got %d", cfg.Monitors[1].IntervalSeconds)
	}
}

func TestLoadInvalidJSONErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("invalid JSON must error")
	}
}
