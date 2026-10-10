from app.detection.outbound_conn import OutboundConnRule
from app.models import Severity
from tests.helpers import make_auth_event, make_network_event

rule = OutboundConnRule()


def test_odd_port_alerts():
    alert = rule.evaluate(make_network_event(dest_port=4444))
    assert alert is not None
    assert alert.severity == Severity.medium


def test_allowed_port_ignored():
    assert rule.evaluate(make_network_event(dest_port=443)) is None


def test_inbound_ignored():
    assert rule.evaluate(make_network_event(direction="in")) is None


def test_ipv6_destination_works():
    event = make_network_event(dest_ip="2001:4860:4860::8888", dest_port=4444)
    assert rule.evaluate(event) is not None


def test_non_network_event_ignored():
    assert rule.evaluate(make_auth_event()) is None
