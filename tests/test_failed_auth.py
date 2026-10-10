import pytest

from app.detection.failed_auth import FailedAuthRule
from app.models import Severity
from tests.helpers import make_auth_event


@pytest.fixture
def rule(monkeypatch):
    monkeypatch.setenv("FAILED_AUTH_THRESHOLD", "5")
    monkeypatch.setenv("WINDOW_SECONDS", "60")
    return FailedAuthRule()


def seconds(i):
    return f"2026-10-10T12:00:{i:02d}Z"


def minutes(i):
    return f"2026-10-10T12:{i:02d}:00Z"


def test_four_failures_no_alert(rule):
    results = [rule.evaluate(make_auth_event(ts=seconds(i))) for i in range(4)]
    assert all(r is None for r in results)


def test_five_failures_alert(rule):
    results = [rule.evaluate(make_auth_event(ts=seconds(i))) for i in range(5)]
    assert all(r is None for r in results[:4])
    assert results[4] is not None
    assert results[4].severity == Severity.high


def test_failures_spread_past_window_no_alert(rule):
    results = [rule.evaluate(make_auth_event(ts=minutes(i))) for i in range(5)]
    assert all(r is None for r in results)


def test_two_ips_do_not_combine(rule):
    results = []
    for i in range(8):
        ip = "10.0.0.1" if i % 2 == 0 else "10.0.0.2"
        results.append(rule.evaluate(make_auth_event(ts=seconds(i), ip=ip)))
    assert all(r is None for r in results)


def test_successes_are_not_counted(rule):
    results = [
        rule.evaluate(make_auth_event(ts=seconds(i), outcome="success"))
        for i in range(10)
    ]
    assert all(r is None for r in results)


def test_sixth_failure_does_not_alert_again(rule):
    results = [rule.evaluate(make_auth_event(ts=seconds(i))) for i in range(6)]
    assert results[4] is not None
    assert results[5] is None
