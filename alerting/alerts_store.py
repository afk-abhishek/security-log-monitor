import os
from datetime import datetime

ALERT_LOG = "alerts.log"

def alert_fingerprint(alert):
    return f"{alert['attack_type']}|{alert['ip']}|{alert['window_seconds']}"

def load_existing_alerts():
    if not os.path.exists(ALERT_LOG):
        return set()

    fingerprints = set()
    with open(ALERT_LOG, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 4:
                fingerprint = "|".join(parts[1:4])
                fingerprints.add(fingerprint)

    return fingerprints

def persist_alerts(alerts):
    existing = load_existing_alerts()

    with open(ALERT_LOG, "a") as f:
        for alert in alerts:
            fp = alert_fingerprint(alert)

            if fp in existing:
                continue  # deduplicated

            timestamp = datetime.utcnow().isoformat() + "Z"
            users = ",".join(alert["users"])

            line = (
                f"{timestamp} | "
                f"{alert['attack_type']} | "
                f"{alert['ip']} | "
                f"users={users} | "
                f"attempts={alert['attempts']} | "
                f"window={alert['window_seconds']}s\n"
            )

            f.write(line)
            existing.add(fp)

