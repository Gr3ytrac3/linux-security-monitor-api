import pytest

from app.detection.privileged_exec import PrivilegedExecRule
from app.models import Severity
from tests.helpers import make_auth_event, make_process_event

rule = PrivilegedExecRule()


@pytest.mark.parametrize("path", ["/tmp/payload", "/dev/shm/x", "/tmp/../tmp/x", "/var/tmp/a", "//tmp/payload"])
def test_root_in_suspicious_path_alerts(path):
    alert = rule.evaluate(make_process_event(uid=0, exe_path=path))
    assert alert is not None
    assert alert.severity == Severity.high


@pytest.mark.parametrize(
    "kwargs",
    [
        {"uid": 1000, "exe_path": "/tmp/x"},
        {"uid": 0, "exe_path": "/usr/bin/ls"},
        {"uid": 0, "exe_path": "/tmp/../usr/bin/ls"},
        {"uid": 0, "exe_path": "/tmpfiles/x"},
    ],
)
def test_benign_cases_do_not_alert(kwargs):
    assert rule.evaluate(make_process_event(**kwargs)) is None


def test_long_path_still_produces_valid_alert():
    path = "/tmp/" + "a" * 195
    assert rule.evaluate(make_process_event(uid=0, exe_path=path)) is not None


def test_non_process_event_ignored():
    assert rule.evaluate(make_auth_event()) is None
