import posixpath

from app.config import suspicious_paths
from app.models import Alert, ProcessEvent, SecurityEvent, Severity


class PrivilegedExecRule:
    name = "privileged_exec"

    def evaluate(self, event: SecurityEvent) -> Alert | None:
        if not isinstance(event, ProcessEvent) or event.uid != 0:
            return None

        path = posixpath.normpath(event.exe_path)
        if path.startswith("//"):
            path = "/" + path.lstrip("/")

        for prefix in suspicious_paths():
            prefix = prefix.rstrip("/")
            if path == prefix or path.startswith(prefix + "/"):
                return Alert(
                    severity=Severity.high,
                    rule=self.name,
                    reason=f"Root process {event.process_name} executed from {path[:100]}",
                    event=event,
                )
        return None
