#!/usr/bin/env python3
"""Valide la fraîcheur et la forme des feeds CrowdSec."""
import json, re, sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

FEEDS_DIR = Path("feeds")
STATE_DIR = Path("state")
MAX_AGE_HOURS = 26  # 12h cadence + 2h marge
IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"          # IPv4
    r"|^[0-9a-fA-F:]+$"                  # IPv6 simplifié
)

errors = []

# 1. Vérifier que les fichiers existent
for f in ["crowdsec_7d.txt", "crowdsec_7d_v4.txt", "crowdsec_7d_v6.txt", "crowdsec_7d.json"]:
    if not (FEEDS_DIR / f).exists():
        errors.append(f"Fichier manquant : feeds/{f}")

# 2. Vérifier la fraîcheur via state/status.json
status_path = STATE_DIR / "status.json"
if not status_path.exists():
    errors.append("Fichier manquant : state/status.json")
else:
    status = json.loads(status_path.read_text())
    updated_at = datetime.fromisoformat(status["updated_at"].replace("Z", "+00:00"))
    age = datetime.now(timezone.utc) - updated_at
    if age > timedelta(hours=MAX_AGE_HOURS):
        errors.append(f"Feed trop ancien : {age} (max {MAX_AGE_HOURS}h)")

# 3. Vérifier le format des TXT (une IP/CIDR par ligne)
txt_path = FEEDS_DIR / "crowdsec_7d.txt"
if txt_path.exists():
    for i, line in enumerate(txt_path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not IP_RE.match(line.split("/")[0]):
            errors.append(f"Ligne invalide dans crowdsec_7d.txt:{i} → {line!r}")

# 4. Vérifier le JSON enrichi
json_path = FEEDS_DIR / "crowdsec_7d.json"
if json_path.exists():
    try:
        data = json.loads(json_path.read_text())
        assert "items" in data and "generated_at" in data
    except Exception as e:
        errors.append(f"crowdsec_7d.json invalide : {e}")

if errors:
    print("Validation échouée :")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)

print("Feeds valides.")
