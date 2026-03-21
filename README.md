# CrowdSec CTI Feed

Public threat feed built from alerts collected by my self-hosted CrowdSec instance.

It publishes a rolling 7-day list of source IPs seen triggering CrowdSec scenarios, updated every 12 hours.

> This is a best-effort feed derived from a single self-hosted sensor. It may contain false positives, stale entries, or shared infrastructure IPs — review it before enforcing it blindly.

---

## Feed URLs

Consume the feed directly from GitHub raw URLs:

| Feed | Format | URL |
|---|---|---|
| All IPs (v4 + v6) | Plain text | `https://raw.githubusercontent.com/RedBlue232/crowdsec-alerts-feed/main/feeds/crowdsec_7d.txt` |
| IPv4 only | Plain text | `https://raw.githubusercontent.com/RedBlue232/crowdsec-alerts-feed/main/feeds/crowdsec_7d_v4.txt` |
| IPv6 only | Plain text | `https://raw.githubusercontent.com/RedBlue232/crowdsec-alerts-feed/main/feeds/crowdsec_7d_v6.txt` |
| Enriched JSON | JSON | `https://raw.githubusercontent.com/RedBlue232/crowdsec-alerts-feed/main/feeds/crowdsec_7d.json` |

Use the plain text feeds for direct firewall blocking. Use the JSON feed when you need scenario metadata and observation timestamps.

### Feed format

Plain text feeds follow the **one IP per line** format, directly consumable by firewalls and blocklist tools:
```
1.2.3.4
5.6.7.8
2001:db8::1
```

The enriched JSON feed includes scenarios and timestamps rounded to the hour:
```json
{
  "generated_at": "2026-03-21T12:00:00Z",
  "ttl_days": 7,
  "counts": { "total": 42, "v4": 38, "v6": 4 },
  "items": [
    {
      "ip": "1.2.3.4",
      "family": "v4",
      "first_seen": "2026-03-15T08:00:00Z",
      "last_seen":  "2026-03-21T11:00:00Z",
      "scenarios":  ["crowdsecurity/ssh-bf", "crowdsecurity/http-probing"]
    }
  ]
}
```

### Feed status

Current feed health and IP counts are available in [`state/status.json`](./state/status.json).

---

## What is this?

[CrowdSec](https://crowdsec.net) is an open-source security engine that detects malicious behaviors by analyzing logs. When an IP triggers a detection scenario (brute force, port scan, HTTP probing, etc.), CrowdSec records an alert with context: scenario name, timestamps, and source IP.

This project pulls those alerts, deduplicates them by IP, keeps entries for 7 days after their last observation (sliding TTL on `last_seen`), and republishes the result as text and JSON feeds.

**This feed is:**
- A rolling list of IPs seen triggering CrowdSec scenarios
- Enriched with scenario names and observation window (timestamps rounded to the hour)
- Published in plain text and JSON

**This feed is not:**
- A global reputation feed — it reflects a single sensor's view
- A guarantee that every listed IP is still malicious at time of consumption
- A substitute for your own filtering logic

---

## Architecture

```
CrowdSec LAPI  ──(JWT auth)──▶  feed.py (Python)
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
              GitHub repo         MISP         other outputs
          feeds/*.txt          Event
          feeds/*.json     ip-src attributes
          state/
```

The pipeline runs in Docker, scheduled with [supercronic](https://github.com/aptible/supercronic):

1. Authenticates to the CrowdSec LAPI as a watcher (JWT)
2. Fetches recent alerts (`/v1/alerts`)
3. Normalizes and deduplicates by IP
4. Merges with the existing state, applies 7-day TTL purge based on `last_seen`
5. Publishes feeds to GitHub via the Contents API
6. Optionally pushes IOCs to MISP via PyMISP

---

## Self-hosting

### Prerequisites

- Docker + Docker Compose
- A running [CrowdSec](https://docs.crowdsec.net) instance (LAPI accessible)
- A GitHub repository, preferably public if the feeds are meant to be consumed directly by firewalls or third-party systems
- A GitHub fine-grained token with **Contents: read/write** scoped to this repo
- *(Optional)* A MISP instance

### 1. Register a CrowdSec watcher machine

On your CrowdSec host:
```bash
sudo cscli machines add feed-publisher --password 'YOUR_STRONG_PASSWORD'
sudo cscli machines list  # verify: status should be "validated"
```

### 2. Configure the environment

```bash
cp .env.example .env
# Edit .env with your values
```

See [Configuration](#configuration) below for all available variables.

### 3. Build and test

```bash
# Build the image
docker build -t crowdsec-feed:latest ./script

# Run a one-shot test before enabling the schedule
docker run --rm --env-file .env crowdsec-feed:latest python /app/feed.py
```

Expected output:
```
... [INFO] Token JWT obtained ✓
... [INFO] 12 alerts received
... [INFO] DB after merge: 5 IPs (0 purged)
... [INFO] GitHub ✓ feeds/crowdsec_7d.txt
... [INFO] Done — 5 IPs published
```

### 4. Deploy

```bash
docker compose up -d
```

The container runs silently and executes the script at **01:00 and 13:00 UTC** daily.

---

## Configuration

Copy `.env.example` to `.env` and fill in your values. **Never commit `.env`** — it is listed in `.gitignore`.

| Variable | Required | Description |
|---|---|---|
| `LAPI_BASE` | ✅ | CrowdSec LAPI base URL, e.g. `http://crowdsec:8080/v1` |
| `CS_MACHINE_ID` | ✅ | Machine ID registered with `cscli machines add` |
| `CS_PASSWORD` | ✅ | Password for the machine |
| `LOOKBACK` | — | Alert fetch window, default `13h` (covers 12h cadence + margin) |
| `GH_TOKEN` | ✅ | GitHub fine-grained token (Contents: read/write) |
| `GH_OWNER` | ✅ | GitHub username or organization |
| `GH_REPO` | ✅ | Target repository name |
| `GH_BRANCH` | — | Target branch, default `main` |
| `TTL_DAYS` | — | Sliding TTL in days, default `7` |
| `MISP_URL` | — | MISP instance URL (leave empty to disable) |
| `MISP_KEY` | — | MISP auth key |
| `MISP_VERIFY_SSL` | — | `true` / `false`, default `false` |

---

## MISP Integration

When `MISP_URL` and `MISP_KEY` are set, the script maintains a **single rolling MISP event** tagged `crowdsec-feed`:

- On first run: creates the event with all current IPs as `ip-src` attributes
- On subsequent runs: replaces attributes with the current TTL-filtered IP set

To disable MISP integration, leave `MISP_URL` empty in your `.env`.

---

## pfBlocker-NG Integration

In pfSense → **pfBlockerNG → IP → IP Lists → Add**:

- URL: `https://raw.githubusercontent.com/RedBlue232/crowdsec-alerts-feed/main/feeds/crowdsec_7d_v4.txt`
- Format: `IP`
- Action: `Deny Inbound` (or `Alias Only` for custom rules)
- Update frequency: `Every 12 hours`

Add a second entry for the IPv6 feed (`crowdsec_7d_v6.txt`) if needed.

---

## CI / Monitoring

A GitHub Actions workflow ([`monitor.yml`](.github/workflows/monitor.yml)) runs every 13 hours — slightly offset from the 12-hour publish cycle to avoid checking the feed at the exact moment it is being updated. It opens an issue if the feed has not been refreshed within the expected window.

A validation workflow ([`ci.yml`](.github/workflows/ci.yml)) runs on every push to `main`.

---

## A note on how this was built

A part of the code and CI workflows in this repository were designed with the help of Claude AI (Anthropic). The overall architecture and security choices were reviewed and validated before deployment.

---

## License

MIT — see [LICENSE](./LICENSE).

Feedback, fixes, and additional output targets are welcome.