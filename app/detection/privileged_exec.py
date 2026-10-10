from app.models import Alert, SecurityEvent


class PrivilegedExecRule:
    name = "privileged_exec"

    def evaluate(self, event: SecurityEvent) -> Alert | None:
        return None
