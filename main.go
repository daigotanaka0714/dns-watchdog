package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	// 1. Config path: CLI arg > DNS_WATCHDOG_CONFIG env > ./config.yml
	configPath := ""
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}
	if configPath == "" {
		configPath = os.Getenv("DNS_WATCHDOG_CONFIG")
	}
	if configPath == "" {
		exe, err := os.Executable()
		if err != nil {
			log.Fatalf("Failed to get executable path: %v", err)
		}
		configPath = filepath.Join(filepath.Dir(exe), "config.yml")
	}

	// 2. Load config
	cfg, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	fmt.Printf("DNS Watchdog: checking %s (%d checks)\n", cfg.Domain, len(cfg.Checks))

	// 3. Run all checks (baseURL="" means use default dns.google)
	failures := RunAllChecks(cfg, "")

	// 4. All OK -> exit 0
	if len(failures) == 0 {
		fmt.Println("\u2705 All DNS records OK")
		os.Exit(0)
	}

	// 5. Print failures
	fmt.Printf("\u274c %d check(s) failed:\n", len(failures))
	for _, f := range failures {
		if f.Error != "" {
			fmt.Printf("  %s (%s): ERROR - %s\n", f.Check.Type, f.Check.Name, f.Error)
		} else {
			fmt.Printf("  %s (%s): expected %s, got %s\n",
				f.Check.Type, f.Check.Name,
				strings.Join(f.Check.Expected, ", "),
				strings.Join(f.Actual, ", "))
		}
	}

	// 6. Send Slack notification
	if err := Notify(cfg, failures); err != nil {
		log.Printf("Warning: failed to send notification: %v", err)
	} else {
		fmt.Println("\U0001f4e4 Slack notification sent")
	}

	// 7. Exit 1 (failure)
	os.Exit(1)
}
