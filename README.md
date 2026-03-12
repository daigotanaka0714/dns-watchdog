# dns-watchdog

DNS record monitoring tool with Slack notifications.

## Features

- **DNS record checks**: A, MX, TXT, NS, CNAME with exact or substring matching
- **DNS blocklist monitoring**: checks if your IPs are listed on DNSBL (Spamhaus, SpamCop, Barracuda)
- **Nameserver consistency**: verifies all authoritative NS return identical results
- **SSL certificate expiry**: warns before certificates expire
- **DNS propagation**: verifies records are consistent across major public resolvers (Google, Cloudflare, OpenDNS, Quad9)
- **Domain expiry**: WHOIS-based domain registration expiry warnings
- **Slack notifications**: sends alerts on failures via incoming webhook
- **DNS-over-HTTPS**: queries Google Public DNS (dns.google) -- no local resolver dependency
- **Single binary**: zero runtime dependencies, easy to deploy
- **CLI + GitHub Action**: run locally or on a schedule in CI

## Installation

### go install

```bash
go install github.com/daigotanaka0714/dns-watchdog@latest
```

### GitHub Releases

Download a prebuilt binary from the
[Releases](https://github.com/daigotanaka0714/dns-watchdog/releases) page.

### GitHub Action

```yaml
- uses: daigotanaka0714/dns-watchdog@v1
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

## Usage

### CLI

```bash
# Use default config path (config.yml next to the binary)
dns-watchdog

# Specify a config file
DNS_WATCHDOG_CONFIG=./my-config.yml dns-watchdog
```

#### Environment variables

| Variable | Description |
|---|---|
| `DNS_WATCHDOG_CONFIG` | Path to the YAML config file (default: `config.yml` next to the executable) |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL for failure notifications (env var name is configurable in the config) |

#### Exit codes

| Code | Meaning |
|---|---|
| `0` | All DNS checks passed |
| `1` | One or more checks failed |

### Configuration

dns-watchdog uses a YAML config file. See [`config.example.yml`](config.example.yml) for a full example.

```yaml
domain: example.com
checks:
  # DNS record checks
  - type: A
    name: "@"
    expected:
      - "93.184.216.34"
  - type: TXT
    name: "@"
    contains: "v=spf1"

  # Extended monitoring
  - type: BLOCKLIST
    name: "@"
    expected:
      - "93.184.216.34"
  - type: NS_CONSISTENCY
    name: "@"
    expected:
      - "A"
  - type: CERT_EXPIRY
    name: "@"
    host: "example.com:443"
    warn_days: 30
  - type: PROPAGATION
    name: "@"
    expected:
      - "93.184.216.34"
  - type: WHOIS_EXPIRY
    name: "@"
    warn_days: 60
notify:
  slack_webhook_env: "SLACK_WEBHOOK_URL"
  template: "default"
```

#### Check types

##### DNS record checks

| Type | Description | Match mode |
|---|---|---|
| `A` | IPv4 address records | `expected` (exact) |
| `MX` | Mail exchange records | `expected` (exact, include priority e.g. `"10 mail.example.com."`) |
| `TXT` | Text records | `expected` (exact) or `contains` (substring) |
| `NS` | Name server records | `expected` (exact) |
| `CNAME` | Canonical name records | `expected` (exact) |

Each check requires either `expected` (a list of exact values) or `contains` (a substring to search for in any returned record).

##### Extended monitoring

| Type | Description | Fields |
|---|---|---|
| `BLOCKLIST` | Check if IPs are listed on DNS blocklists (Spamhaus, SpamCop, Barracuda) | `expected`: list of IPs to check |
| `NS_CONSISTENCY` | Verify all authoritative nameservers return identical results | `expected`: record types to check (e.g. `["A"]`) |
| `CERT_EXPIRY` | Warn before SSL/TLS certificate expires | `host`: address to connect to (default: `domain:443`), `warn_days`: threshold (default: 30) |
| `PROPAGATION` | Verify DNS records are consistent across public resolvers | `expected`: expected record values |
| `WHOIS_EXPIRY` | Warn before domain registration expires | `warn_days`: threshold (default: 60) |

### GitHub Action workflow example

```yaml
name: DNS Watchdog
on:
  schedule:
    - cron: "0 */6 * * *"   # every 6 hours
  workflow_dispatch:

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: daigotanaka0714/dns-watchdog@v1
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
          DNS_WATCHDOG_CONFIG: ./config.yml
```

## License

[MIT](LICENSE)
