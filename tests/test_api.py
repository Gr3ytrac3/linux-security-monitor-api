import pytest
from fastapi.testclient import TestClient

from app import main

KEY = "test-key"
HEADERS = {"X-API-Key": KEY}


@pytest.fixture(autouse=True)
def clean_state(monkeypatch):
    monkeypatch.setenv("API_KEY", KEY)
    main.store.clear()
    main.rules = main.build_rules()


@pytest.fixture
def client():
    return TestClient(main.app)


def auth_payload(ts="2026-10-10T12:00:00Z", outcome="failed", ip="192.168.1.10"):
    return {
        "event_id": "evt_a",
        "timestamp": ts,
        "host": "linux-server",
        "event_type": "auth",
        "source_ip": ip,
        "username": "root",
        "outcome": outcome,
    }


def process_payload(exe_path="/tmp/payload", uid=0):
    return {
        "event_id": "evt_p",
        "timestamp": "2026-10-10T12:00:00Z",
        "host": "linux-server",
        "event_type": "process",
        "pid": 4321,
        "ppid": 1,
        "uid": uid,
        "exe_path": exe_path,
        "parent_name": "bash",
        "process_name": "payload",
    }


def network_payload(dest_port=4444):
    return {
        "event_id": "evt_n",
        "timestamp": "2026-10-10T12:00:00Z",
        "host": "linux-server",
        "event_type": "network",
        "pid": 999,
        "process_name": "curl",
        "dest_ip": "8.8.8.8",
        "dest_port": dest_port,
        "direction": "out",
    }


def test_missing_key_rejected(client):
    assert client.post("/events", json=auth_payload()).status_code == 401


def test_wrong_key_rejected(client):
    r = client.post("/events", json=auth_payload(), headers={"X-API-Key": "nope"})
    assert r.status_code == 401


def test_unconfigured_key_fails_closed(client, monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    assert client.post("/events", json=auth_payload(), headers=HEADERS).status_code == 503


def test_bad_body_without_key_gets_401_not_422(client):
    assert client.post("/events", json={"junk": 1}).status_code == 401


def test_malformed_event_rejected(client):
    r = client.post("/events", json={"event_type": "auth"}, headers=HEADERS)
    assert r.status_code == 422


def test_unknown_field_rejected(client):
    body = auth_payload()
    body["extra"] = "x"
    assert client.post("/events", json=body, headers=HEADERS).status_code == 422


def test_normal_event_raises_no_alert(client):
    r = client.post("/events", json=auth_payload(outcome="success"), headers=HEADERS)
    assert r.status_code == 202
    assert r.json()["alerts"] == []


def test_privileged_exec_alert(client):
    r = client.post("/events", json=process_payload(), headers=HEADERS)
    assert r.status_code == 202
    alerts = r.json()["alerts"]
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "privileged_exec"
    assert alerts[0]["severity"] == "high"


def test_outbound_alert(client):
    r = client.post("/events", json=network_payload(), headers=HEADERS)
    assert r.json()["alerts"][0]["rule"] == "outbound_conn"


def test_failed_auth_burst_alerts_on_fifth(client):
    responses = [
        client.post("/events", json=auth_payload(ts=f"2026-10-10T12:00:{i:02d}Z"), headers=HEADERS)
        for i in range(5)
    ]
    assert all(r.json()["alerts"] == [] for r in responses[:4])
    assert responses[4].json()["alerts"][0]["rule"] == "failed_auth"


def test_get_alerts_returns_stored(client):
    client.post("/events", json=process_payload(), headers=HEADERS)
    r = client.get("/alerts", headers=HEADERS)
    assert r.status_code == 200
    assert len(r.json()) == 1


def test_get_alerts_requires_key(client):
    assert client.get("/alerts").status_code == 401
