# CrowdSec CTI Feed

Public threat feed built from alerts collected by my self-hosted CrowdSec instance.

It publishes a rolling 7-day list of source IPs seen triggering CrowdSec scenarios, updated every 12 hours. A curated MISP feed is also published alongside the plain text and JSON feeds for threat intelligence platforms.

> This is a best-effort feed derived from a single self-hosted sensor. It may contain false positives, stale entries, or shared infrastructure IPs — review it before enforcing it blindly.

---

## Feed URLs

Consume the feed directly from GitHub raw URLs:

| Feed | Format | URL |
|---|---|---|
| All IPs (v4 + v6) | Plain text | `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/feeds/crowdsec_7d.txt` |
| IPv4 only | Plain text | `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/feeds/crowdsec_7d_v4.txt` |
| IPv6 only | Plain text | `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/feeds/crowdsec_7d_v6.txt` |
| Enriched | JSON | `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/feeds/crowdsec_7d.json` |
| MISP Feed | MISP Feed format | `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/misp-feed/` |

Use the plain text feeds for direct firewall blocking. Use the JSON feed when you need scenario metadata and observation timestamps. Use the MISP feed if you run a MISP instance and want native ingestion with correlation.

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

The MISP feed is the standard MISP feed layout (`manifest.json`, `hashes.csv`, `<uuid>.json`), directly subscribable from any MISP instance — see [MISP subscription](#misp-subscription).

### Feed status

Current feed health and IP counts are available in [`state/status.json`](./state/status.json).

---

## What is this?

[CrowdSec](https://crowdsec.net) is an open-source security engine that detects malicious behaviors by analyzing logs. When an IP triggers a detection scenario (brute force, port scan, HTTP probing, etc.), CrowdSec records an alert with context: scenario name, timestamps, and source IP.

This project pulls those alerts, deduplicates them by IP, keeps entries for 7 days after their last observation (sliding TTL on `last_seen`), and republishes the result as text, JSON, and MISP feeds.

**This feed is:**
- A rolling list of IPs seen triggering CrowdSec scenarios
- Enriched with scenario names and observation window (timestamps rounded to the hour)
- Published in plain text, JSON, and MISP feed format

**This feed is not:**
- A global reputation feed — it reflects a single sensor's view
- A guarantee that every listed IP is still malicious at time of consumption
- A substitute for your own filtering logic

---

## Architecture

```
CrowdSec LAPI  ──(JWT auth)──▶  feed.py  ──▶  GitHub (feeds/*.txt, feeds/*.json, state/)
                                   │
                                   └────────▶  MISP event (ip-src attributes)
                                                    │
                                                    ▼
                                            misp_export.py  ──▶  GitHub (misp-feed/)
```

The pipeline runs in Docker, scheduled with [supercronic](https://github.com/aptible/supercronic):

1. **`feed.py`** authenticates to the CrowdSec LAPI as a watcher (JWT), fetches recent alerts, normalizes them, deduplicates by IP, merges with the existing state, applies 7-day TTL purge based on `last_seen`, publishes text and JSON feeds to GitHub, and updates a single rolling MISP event.
2. **`misp_export.py`** fetches that MISP event, sanitizes it (strips internal IDs, creator email, sightings), and publishes it to GitHub as a standard MISP feed.

---

## Self-hosting

### Prerequisites

- Docker + Docker Compose
- A running [CrowdSec](https://docs.crowdsec.net) instance (LAPI accessible)
- A GitHub repository, preferably public if the feeds are meant to be consumed directly by firewalls or third-party systems
- A GitHub fine-grained token with **Contents: read/write** scoped to this repo
- *(Optional)* A MISP instance — required only if you want to publish the MISP feed

### 1. Register a CrowdSec watcher machine

On your CrowdSec host:
```bash
sudo cscli machines add feed-publisher --password 'YOUR_STRONG_PASSWORD'
sudo cscli machines list  # verify: status should be "validated"
```

### 2. Configure the environment

```bash
cp env.example .env
# Edit .env with your values
```

See [Configuration](#configuration) below for all available variables.

### 3. Build and test

```bash
# Build the image
docker build -t threat-feed-publisher:latest ./scripts

# One-shot test of the CrowdSec publisher
docker run --rm --env-file .env threat-feed-publisher:latest python /app/feed.py

# One-shot test of the MISP feed publisher (if MISP is configured)
docker run --rm --env-file .env threat-feed-publisher:latest python /app/misp_export.py
```

If your MISP instance runs on the same Docker host, the container needs to reach it. Either attach the test run to the MISP network (`--network <misp_network>` with `MISP_URL=https://misp`) or use `--add-host=host.docker.internal:host-gateway` with `MISP_URL=https://host.docker.internal`.

Expected output of `feed.py`:
```
... [INFO] Token JWT obtained ✓
... [INFO] 12 alerts received
... [INFO] DB after merge: 5 IPs (0 purged)
... [INFO] GitHub ✓ feeds/crowdsec_7d.txt
... [INFO] Done — 5 IPs published
```

Expected output of `misp_export.py`:
```
... [INFO] Connexion MISP → https://misp
... [INFO] Fetch event d177856e-6e46-44ee-8eb5-83ef1c7452c7
... [INFO] Event nettoyé : 113 attributs, 0 objets
... [INFO] GitHub ✓ misp-feed/d177856e-6e46-44ee-8eb5-83ef1c7452c7.json
... [INFO] GitHub ✓ misp-feed/manifest.json
... [INFO] GitHub ✓ misp-feed/hashes.csv
... [INFO] Done.
```

### 4. Deploy

```bash
docker compose up -d
```

The container runs silently and executes the scripts on the following schedule (UTC):
- `feed.py` at **01:00** and **13:00**
- `misp_export.py` at **01:30** and **13:30** (offset by 30 min so the MISP event is up to date when exported)

---

## Configuration

Copy `env.example` to `.env` and fill in your values. **Never commit `.env`** — it is listed in `.gitignore`.

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
| `MISP_URL` | — | MISP instance URL (leave empty to disable MISP push from `feed.py`) |
| `MISP_KEY` | — | MISP auth key |
| `MISP_VERIFY_SSL` | — | `true` / `false`, default `true` |
| `MISP_EVENT_UUID` | ✅ *(for `misp_export.py`)* | UUID of the MISP event to publish as a feed |
| `MISP_FEED_DIR` | — | Subfolder of the repo used as MISP feed root, default `misp-feed` |

---

## MISP Integration

This project integrates with MISP in two complementary ways.

### Push from CrowdSec to MISP

When `MISP_URL` and `MISP_KEY` are set, `feed.py` maintains a **single rolling MISP event** tagged `crowdsec-feed`:

- On first run: creates the event with all current IPs as `ip-src` attributes
- On subsequent runs: replaces attributes with the current TTL-filtered IP set

To disable this push, leave `MISP_URL` empty in your `.env`.

### Publish the MISP event as a public feed

`misp_export.py` fetches that same event from your MISP, sanitizes it (removes `event_creator_email`, internal IDs, sightings, shadow attributes and related events), and publishes it as a standard MISP feed on GitHub. The feed is then subscribable from any other MISP instance.

Requires `MISP_URL`, `MISP_KEY`, and `MISP_EVENT_UUID`.

---

## MISP subscription

Consumers with a MISP instance can subscribe to the feed natively. In MISP → **Sync Actions → Feeds → Add Feed**:

- Provider: `cyberdefense.blue`
- URL: `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/misp-feed/`
- Source Format: `MISP Feed`
- Enabled: ✓

The feed refreshes every 12 hours. IPs are published as `ip-src` attributes, each annotated with the originating CrowdSec scenarios and the `first_seen` / `last_seen` observation window.

---

## pfBlocker-NG Integration

In pfSense → **pfBlockerNG → IP → IP Lists → Add**:

- URL: `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/feeds/crowdsec_7d_v4.txt`
- Format: `IP`
- Action: `Deny Inbound` (or `Alias Only` for custom rules)
- Update frequency: `Every 12 hours`

Add a second entry for the IPv6 feed (`crowdsec_7d_v6.txt`) if needed.

---

## CI / Monitoring

A GitHub Actions workflow ([`monitor.yml`](.github/workflows/monitor.yml)) runs every 13 hours — slightly offset from the 12-hour publish cycle to avoid checking the feed at the exact moment it is being updated. It opens an issue if either the CrowdSec feed (`state/status.json`) or the MISP feed (`misp-feed/manifest.json`) has not been refreshed within the expected window.

A validation workflow ([`ci.yml`](.github/workflows/ci.yml)) runs on every push to `main` and validates the format and internal consistency of all published feeds.

---

## A note on how this was built

A part of the code and CI workflows in this repository were designed with the help of Claude AI (Anthropic). The overall architecture and security choices were reviewed and validated before deployment.

---

## License

MIT — see [LICENSE](./LICENSE).

Feedback, fixes, and additional output targets are welcome.