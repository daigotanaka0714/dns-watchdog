# dns-watchdog

DNS record monitoring tool with Slack notifications.

## Features

- **Record types**: A, MX, TXT, NS, CNAME
- **Match modes**: exact match (`expected`) and substring match (`contains`)
- **Slack notifications**: sends alerts on mismatches via incoming webhook
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
  - type: A
    name: "@"
    expected:
      - "93.184.216.34"
  - type: TXT
    name: "@"
    contains: "v=spf1"
notify:
  slack_webhook_env: "SLACK_WEBHOOK_URL"
  template: "default"
```

#### Check types

| Type | Description | Match mode |
|---|---|---|
| `A` | IPv4 address records | `expected` (exact) |
| `MX` | Mail exchange records | `expected` (exact, include priority e.g. `"10 mail.example.com."`) |
| `TXT` | Text records | `expected` (exact) or `contains` (substring) |
| `NS` | Name server records | `expected` (exact) |
| `CNAME` | Canonical name records | `expected` (exact) |

Each check requires either `expected` (a list of exact values) or `contains` (a substring to search for in any returned record).

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
