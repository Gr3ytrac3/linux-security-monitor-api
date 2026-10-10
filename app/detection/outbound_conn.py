from app.config import allowed_ports
from app.models import Alert, NetworkEvent, SecurityEvent, Severity


class OutboundConnRule:
    name = "outbound_conn"

    def evaluate(self, event: SecurityEvent) -> Alert | None:
        if not isinstance(event, NetworkEvent) or event.direction != "out":
            return None
        if event.dest_port in allowed_ports():
            return None
        return Alert(
            severity=Severity.medium,
            rule=self.name,
            reason=f"{event.process_name} connected out to {event.dest_ip} on port {event.dest_port}",
            event=event,
        )
