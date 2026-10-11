import json
from pathlib import Path

import httpx

BASE = "http://localhost:8000"
HEADERS = {"X-API-Key": "dev-key"}
OUT = Path("sample_data")
OUT.mkdir(exist_ok=True)


def save(name, data):
    (OUT / name).write_text(json.dumps(data, indent=2) + "\n")


def post(payload):
    return httpx.post(f"{BASE}/events", json=payload, headers=HEADERS)


common = {"timestamp": "2026-10-10T12:00:00Z", "host": "web01"}

privileged = {**common, "event_id": "s1", "event_type": "process", "pid": 4321,
              "ppid": 1, "uid": 0, "exe_path": "/tmp/payload",
              "parent_name": "bash", "process_name": "payload"}
save("privileged_exec_input.json", privileged)
save("privileged_exec_output.json", post(privileged).json())

outbound = {**common, "event_id": "s2", "event_type": "network", "pid": 999,
            "process_name": "curl", "dest_ip": "8.8.8.8", "dest_port": 4444,
            "direction": "out"}
save("outbound_conn_input.json", outbound)
save("outbound_conn_output.json", post(outbound).json())

failures = [
    {**common, "event_id": f"s3-{i}", "timestamp": f"2026-10-10T12:00:0{i}Z",
     "event_type": "auth", "source_ip": "203.0.113.50", "username": "root",
     "outcome": "failed"}
    for i in range(5)
]
save("failed_auth_input.json", failures)
responses = [post(e).json() for e in failures]
save("failed_auth_output.json", responses[-1])

normal = {**common, "event_id": "s4", "event_type": "auth",
          "source_ip": "192.168.1.10", "username": "alice", "outcome": "success"}
save("normal_input.json", normal)
save("normal_output.json", post(normal).json())

invalid = {**common, "event_id": "s5", "event_type": "auth",
           "username": "root", "outcome": "failed"}
r = post(invalid)
save("invalid_input.json", invalid)
save("invalid_output.json", {"status_code": r.status_code, "response": r.json()})

print("sample_data written")
