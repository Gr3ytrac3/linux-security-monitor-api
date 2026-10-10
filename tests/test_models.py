import pytest
from pydantic import TypeAdapter, ValidationError

from app.models import Alert, SecurityEvent, Severity

adapter = TypeAdapter(SecurityEvent)


def auth_event(**overrides):
    event = {
        "event_id": "evt_123",
        "timestamp": "2026-10-10T12:00:00Z",
        "host": "linux-server",
        "event_type": "auth",
        "source_ip": "192.168.1.10",
        "username": "root",
        "outcome": "failed",
    }
    event.update(overrides)
    return event


def process_event(**overrides):
    event = {
        "event_id": "evt_p1",
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
    event.update(overrides)
    return event


def network_event(**overrides):
    event = {
        "event_id": "evt_n1",
        "timestamp": "2026-10-10T12:00:00Z",
        "host": "linux-server",
        "event_type": "network",
        "pid": 999,
        "process_name": "curl",
        "dest_ip": "203.0.113.10",
        "dest_port": 4444,
        "direction": "out",
    }
    event.update(overrides)
    return event


def test_failed_login_parses():
    event = adapter.validate_python(auth_event())
    assert event.event_type == "auth"
    assert event.outcome == "failed"


def test_successful_login_parses():
    event = adapter.validate_python(auth_event(outcome="success"))
    assert event.outcome == "success"


def test_root_process_accepted():
    event = adapter.validate_python(process_event(uid=0))
    assert event.uid == 0


def test_network_event_parses():
    event = adapter.validate_python(network_event())
    assert event.dest_port == 4444


def test_missing_field_rejected():
    data = auth_event()
    del data["source_ip"]
    with pytest.raises(ValidationError):
        adapter.validate_python(data)


@pytest.mark.parametrize(
    "overrides",
    [
        {"outcome": "Failed"},
        {"outcome": "failure"},
        {"source_ip": "banana"},
        {"timestamp": "2026-10-10T12:00:00"},
        {"username": ""},
        {"extra_field": "x"},
        {"event_type": "bogus"},
    ],
)
def test_bad_auth_event_rejected(overrides):
    with pytest.raises(ValidationError):
        adapter.validate_python(auth_event(**overrides))


def test_pid_zero_rejected():
    with pytest.raises(ValidationError):
        adapter.validate_python(process_event(pid=0))


def test_negative_uid_rejected():
    with pytest.raises(ValidationError):
        adapter.validate_python(process_event(uid=-1))


def test_port_out_of_range_rejected():
    with pytest.raises(ValidationError):
        adapter.validate_python(network_event(dest_port=70000))


def test_bad_direction_rejected():
    with pytest.raises(ValidationError):
        adapter.validate_python(network_event(direction="sideways"))


def test_alert_builds_with_defaults():
    event = adapter.validate_python(auth_event())
    alert = Alert(
        severity=Severity.high,
        rule="failed_auth",
        reason="5 failed logins from 192.168.1.10 within 60 seconds",
        event=event,
    )
    assert alert.severity == Severity.high
    assert alert.alert_id
    assert alert.timestamp.tzinfo is not None


def test_invalid_severity_rejected():
    with pytest.raises(ValueError):
        Severity("hgih")


def test_alert_with_bad_severity_rejected():
    event = adapter.validate_python(auth_event())
    with pytest.raises(ValidationError):
        Alert(severity="hgih", rule="x", reason="x", event=event)
