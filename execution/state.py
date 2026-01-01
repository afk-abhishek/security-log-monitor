from datetime import datetime, timedelta

# in-memory state (later can be persisted)
EXECUTION_STATE = {}


def is_in_cooldown(ip):
    state = EXECUTION_STATE.get(ip)

    if not state:
        return False

    cooldown_until = state.get("cooldown_until")
    if not cooldown_until:
        return False

    return datetime.utcnow() < cooldown_until


def mark_executed(ip, action, cooldown_seconds):
    EXECUTION_STATE[ip] = {
        "last_action": action,
        "executed_at": datetime.utcnow(),
        "cooldown_until": datetime.utcnow() + timedelta(seconds=cooldown_seconds)
    }


def get_state(ip):
    return EXECUTION_STATE.get(ip)

