// Package config loads the monitor's JSON configuration file.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Monitor is one target declared in the config file.
type Monitor struct {
	Name            string `json:"name"`
	URL             string `json:"url"`
	IntervalSeconds int    `json:"interval_seconds"`
	Keyword         string `json:"keyword"`
	ExpectedStatus  int    `json:"expected_status"`
	CheckPort       string `json:"check_port"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	SSLWarnDays     int    `json:"ssl_warn_days"`
}

// Config is the whole configuration file.
type Config struct {
	Listen        string    `json:"listen"`                 // e.g. ":8080"
	DBPath        string    `json:"db_path"`                // e.g. "uptime.db"
	WebhookURL    string    `json:"webhook_url"`            // optional
	StaticDir     string    `json:"static_dir"`             // optional: dashboard build output
	CheckInterval int       `json:"check_interval_seconds"` // fallback interval, default 60
	Monitors      []Monitor `json:"monitors"`
}

// Defaults returns a Config with sane defaults.
func Defaults() Config {
	return Config{
		Listen:        ":8080",
		DBPath:        "uptime.db",
		CheckInterval: 60,
	}
}

// Load reads path (JSON) and fills in defaults for missing fields.
// A missing file is not an error — defaults are used.
func Load(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing %s: %w", path, err)
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.DBPath == "" {
		cfg.DBPath = "uptime.db"
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 60
	}
	for i, m := range cfg.Monitors {
		if m.IntervalSeconds <= 0 {
			cfg.Monitors[i].IntervalSeconds = cfg.CheckInterval
		}
	}
	return cfg, nil
}
