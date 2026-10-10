from app.models import Alert, SecurityEvent


class OutboundConnRule:
    name = "outbound_conn"

    def evaluate(self, event: SecurityEvent) -> Alert | None:
        return None
