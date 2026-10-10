from itertools import count

from pydantic import TypeAdapter

from app.models import SecurityEvent

adapter = TypeAdapter(SecurityEvent)
_ids = count(1)


def make_auth_event(ts="2026-10-10T12:00:00Z", ip="192.168.1.10", outcome="failed", **kw):
    data = {
        "event_id": f"evt_{next(_ids)}",
        "timestamp": ts,
        "host": "linux-server",
        "event_type": "auth",
        "source_ip": ip,
        "username": "root",
        "outcome": outcome,
    }
    data.update(kw)
    return adapter.validate_python(data)


def make_process_event(**kw):
    data = {
        "event_id": f"evt_{next(_ids)}",
        "timestamp": "2026-10-10T12:00:00Z",
        "host": "linux-server",
        "event_type": "process",
        "pid": 4321,
        "ppid": 1,
        "uid": 0,
        "exe_path": "/tmp/payload",
        "parent_name": "bash",
        "process_name": "payload",
    }
    data.update(kw)
    return adapter.validate_python(data)


def make_network_event(**kw):
    data = {
        "event_id": f"evt_{next(_ids)}",
        "timestamp": "2026-10-10T12:00:00Z",
        "host": "linux-server",
        "event_type": "network",
        "pid": 999,
        "process_name": "curl",
        "dest_ip": "8.8.8.8",
        "dest_port": 4444,
        "direction": "out",
    }
    data.update(kw)
    return adapter.validate_python(data)
