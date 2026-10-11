# Linux Security Monitor API


A small FastAPI service that receives Linux security events (JSON), runs
rule-based detections, and returns structured alerts. Synthetic data only.


---

<img src="https://github.com/Gr3ytrac3/linux-security-monitor-api/blob/9b351892ac2ce01a3c275a362a489e29ec9a04dd/assets/cover-channel-path-schema.png"/>



## Requirements
Python 3.10+ (developed and tested on 3.14).

## Setup
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration (environment variables)
| Variable | Default | Meaning |
|---|---|---|
| `API_KEY` | none (required) | Key clients send in `X-API-Key`. If unset, the API refuses all requests (503). |
| `FAILED_AUTH_THRESHOLD` | 5 | Failed logins from one IP that trigger an alert |
| `WINDOW_SECONDS` | 60 | Time window for counting failures |
| `SUSPICIOUS_PATHS` | /tmp,/dev/shm,/var/tmp | Paths root should not execute from |
| `ALLOWED_PORTS` | 22,53,80,123,443 | Outbound ports that do not alert |

## Run
```
API_KEY=dev-key uvicorn app.main:app
```
Interactive docs: http://localhost:8000/docs

## Example
```
curl -X POST localhost:8000/events \
  -H "X-API-Key: dev-key" -H "Content-Type: application/json" \
  -d @sample_data/privileged_exec_input.json
curl localhost:8000/alerts -H "X-API-Key: dev-key"
```

## Endpoints
- `POST /events`: validate an event, run all rules, return 202 and any alerts raised
- `GET /alerts`: list stored alerts (most recent 1000)
Both require the `X-API-Key` header.

## Tests
```
python3 -m pytest
```

## Sample data
`sample_data/` holds an input and the resulting alert for each rule, plus a
normal event and an invalid one. Regenerate with the server running:
`python3 scripts/generate_samples.py`. Alert timestamps are set by the server
in UTC, so they will differ when you regenerate.

## Layout
app/ (models, config, auth, alerts, main, detection/), tests/, sample_data/,
scripts/, docs/design.md
