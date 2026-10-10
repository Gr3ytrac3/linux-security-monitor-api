from collections import deque

from app.models import Alert


class AlertStore:
    def __init__(self, max_alerts: int = 1000) -> None:
        self._alerts: deque[Alert] = deque(maxlen=max_alerts)

    def add(self, alert: Alert) -> None:
        self._alerts.append(alert)

    def list(self) -> list[Alert]:
        return list(self._alerts)

    def clear(self) -> None:
        self._alerts.clear()
