from collections import defaultdict, deque

from app.models import Alert, SecurityEvent


class FailedAuthRule:
    name = "failed_auth"

    def __init__(self) -> None:
        self._failures = defaultdict(deque)

    def evaluate(self, event: SecurityEvent) -> Alert | None:
        return None
