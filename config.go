package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Domain string       `yaml:"domain"`
	Checks []CheckEntry `yaml:"checks"`
	Notify NotifyConfig `yaml:"notify"`
}

type CheckEntry struct {
	Type     string   `yaml:"type"`
	Name     string   `yaml:"name"`
	Expected []string `yaml:"expected,omitempty"`
	Contains string   `yaml:"contains,omitempty"`
}

type NotifyConfig struct {
	SlackWebhookEnv string `yaml:"slack_webhook_env"`
	Template        string `yaml:"template"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if cfg.Domain == "" {
		return nil, fmt.Errorf("domain is required in config")
	}
	if len(cfg.Checks) == 0 {
		return nil, fmt.Errorf("at least one check is required")
	}

	for i, check := range cfg.Checks {
		if check.Type == "" {
			return nil, fmt.Errorf("check[%d]: type is required", i)
		}
		if len(check.Expected) == 0 && check.Contains == "" {
			return nil, fmt.Errorf("check[%d]: either expected or contains is required", i)
		}
	}

	return &cfg, nil
}
