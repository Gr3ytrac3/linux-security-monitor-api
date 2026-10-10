import os

# gets and retuns the API key i set, or None if not. 

def get_api_key() -> str | None:
    return os.environ.get("API_KEY") or None

# fetches a sting (name and default) and cast to int
def _get_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))

# Splits a comma-seperated string into a list. To avoid empty entries
def _get_list(name: str, default: str) -> list[str]:
    raw = os.environ.get(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]

# Sets the number of failed logins in a window that trigger an alert
def failed_auth_threshold() -> int:
    return _get_int("FAILED_AUTH_THRESHOLD", 5)

# the sliding window for counting failures
def window_seconds() -> int:
    return _get_int("WINDOW_SECONDS", 60)

# defined filesystem paths that look staging areas for malicious processes or potential malware
def suspicious_paths() -> list[str]:
    return _get_list("SUSPICIOUS_PATHS", "/tmp,/dev/shm,/var/tmp")

# ports allowed, considered normal
def allowed_ports() -> list[int]:
    return [int(p) for p in _get_list("ALLOWED_PORTS", "22,53,80,123,443")]
