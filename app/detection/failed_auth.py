from collections import deque
from datetime import timedelta

from app.config import failed_auth_threshold, window_seconds
from app.models import Alert, AuthEvent, SecurityEvent, Severity

MAX_TRACKED_IPS = 10_000


class FailedAuthRule:
    name = "failed_auth"

    def __init__(self) -> None:
        self._failures: dict[str, deque] = {}

    def evaluate(self, event: SecurityEvent) -> Alert | None:
        if not isinstance(event, AuthEvent) or event.outcome != "failed":
            return None

        ip = str(event.source_ip)
        window = timedelta(seconds=window_seconds())

        if ip not in self._failures:
            if len(self._failures) >= MAX_TRACKED_IPS:
                del self._failures[next(iter(self._failures))]
            self._failures[ip] = deque()

        times = self._failures[ip]
        times.append(event.timestamp)
        while times and times[0] < event.timestamp - window:
            times.popleft()

        if len(times) >= failed_auth_threshold():
            count = len(times)
            del self._failures[ip]
            return Alert(
                severity=Severity.high,
                rule=self.name,
                reason=f"{count} failed logins from {ip} within {window_seconds()} seconds",
                event=event,
            )
        return None
