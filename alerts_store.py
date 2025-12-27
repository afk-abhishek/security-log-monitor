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

    updated_lines = []
    seen_fps = set()

    # Read existing alerts
    if os.path.exists(ALERT_LOG):
        with open(ALERT_LOG, "r") as f:
            updated_lines = f.readlines()

    with open(ALERT_LOG, "w") as f:
        for alert in alerts:
            fp = alert_fingerprint(alert)
            users = set(alert["users"])
            timestamp = datetime.utcnow().isoformat() + "Z"

            found = False
            for i, line in enumerate(updated_lines):
                if fp in line:
                    # ENRICH EXISTING ALERT
                    parts = line.strip().split("|")
                    old_users = parts[3].split("=")[1].split(",")

                    merged_users = sorted(set(old_users) | users)

                    updated_lines[i] = (
                        f"{timestamp} | "
                        f"{alert['attack_type']} | "
                        f"{alert['ip']} | "
                        f"users={','.join(merged_users)} | "
                        f"attempts={alert['attempts']} | "
                        f"window={alert['window_seconds']}s\n"
                    )
                    found = True
                    seen_fps.add(fp)
                    break

            if not found:
                # NEW INCIDENT
                updated_lines.append(
                    f"{timestamp} | "
                    f"{alert['attack_type']} | "
                    f"{alert['ip']} | "
                    f"users={','.join(users)} | "
                    f"attempts={alert['attempts']} | "
                    f"window={alert['window_seconds']}s\n"
                )

        f.writelines(updated_lines)

