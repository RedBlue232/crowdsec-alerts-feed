# MISP Feed

This folder is a [MISP feed](https://www.misp-project.org/) root, refreshed every 12 hours from a single MISP event aggregating IPs observed by a self-hosted CrowdSec sensor over a rolling 7-day window.

## Subscribe from MISP

**Sync Actions → Feeds → Add Feed**

- Provider: `cyberdefense.blue`
- URL: `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/misp-feed` *(no trailing slash — MISP appends `/manifest.json` itself)*
- Source Format: `MISP Feed`
- Enabled: ✓

## Contents

| File | Purpose |
|---|---|
| `manifest.json` | Event index (UUID → metadata) |
| `hashes.csv`    | MD5 of every attribute value, for fast lookups |
| `<uuid>.json`   | Full event payload |

Each IP is published as an `ip-src` attribute annotated with the originating CrowdSec scenarios and its `first_seen` / `last_seen` window.

## Disclaimer

Best-effort feed from a single sensor. Expect false positives and shared-infrastructure IPs. See the [main README](../README.md) for the full context.