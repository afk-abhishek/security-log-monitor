from collections import defaultdict
from datetime import timedelta

def detect_slow_bruteforce(events, threshold=10, window_hours=0.1):
    attempts = defaultdict(list)
    alerts = []

    for event in events:
        key = (event["ip"], event["user"])
        attempts[key].append(event["time"])

    for (ip, user), times in attempts.items():
        times.sort()

        for i in range(len(times)):
            window = times[i:i+threshold]
            if len(window) < threshold:
                continue

            if window[-1] - window[0] <= timedelta(hours=window_hours):
                alerts.append({
                    "type": "SLOW_BRUTE_FORCE",
                    "ip": ip,
                    "user": user,
                    "attempts": threshold,
                    "start": window[0],
                    "end": window[-1]
                })
                break

    return alerts

