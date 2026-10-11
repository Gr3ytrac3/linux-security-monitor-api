# Full Architectural design and walkthrough of the entire assessment structure

A small security monitoring API that receives Linux security events, identifies potentially suspicious activity, and provides structured alerts for security analysts.

---

<img src="https://github.com/Gr3ytrac3/linux-security-monitor-api/blob/9b351892ac2ce01a3c275a362a489e29ec9a04dd/assets/cover-channel-path-schema.png"/>


## Design structure details

As requested the system has but one task: take a security event, then check it against detection rules, and return an alert if something looks suspicious. It essentially has three layers, and each layer only knows about the one below it. 


Here's a simple representation of the three layers: 

Client (synthetic events)
   |  POST /events  + X-API-Key header
   v
INGESTION     auth.py checks the key, models.py validates the shape (main.py wires it together)
   v
DETECTION     detection/ runs each rule against the validated event
   v
ALERTING      alerts.py stores the alerts, main.py returns them


A clear seperation was made between ingestion and rules, rules and HTTP

### Project Tree

linux-security-monitor-api/
  app/
    models.py                  data validation using Pydantic
    config.py                  settings from environment variables
    auth.py                    API key check
    alerts.py                  alert storage
    main.py                    the API and the joint logic
    detection/
      privileged_exec.py       first detection rule
      outbound_conn.py         second detection rule
      failed_auth.py           third detection rule
  tests/
    helpers.py                 builders for valid test events
    test_models.py             validation tests
    test_privileged_exec.py 
    test_outbound_conn.py
    test_failed_auth.py
    test_api.py                end-to-end tests through HTTP
  sample_data/                 example inputs and resulting alerts
  scripts/generate_samples.py   regenerates the samples from a live server
  docs/design.md               design architecture and reasoning document
  README.md                    installation guide, runing, and testing
  pytest.ini                   tells pytest where `app` lives
  requirements.txt             pinned dependencies
  .gitignore                   keeps venv, caches and secrets out of Git



## Application files

**`models.py` (your file, the foundation)**  
This file defines what valid data looks like, and it’s the foundation of the system: detection only makes sense if the input is trustworthy. `EventBase` holds the fields every event shares (`event_id`, `timestamp`, `host`), and `AuthEvent`, `ProcessEvent` and `NetworkEvent` add the fields specific to each type. I kept this file free of any HTTP or detection logic so each layer can change without breaking the others.

I used Pydantic because FastAPI is built on it: the same model validates incoming data and defines the API contract, and invalid input is rejected automatically with a 422. It also supports discriminated unions, which `SecurityEvent` relies on. Pydantic reads the `event_type` field and picks the matching model, so the API has one entry point but strict, type-specific validation behind it. Required fields can’t be missing, and strings have minimum lengths.

Specific choices: `extra="forbid"` rejects unknown fields, so typos and smuggled data can’t pass silently. `IPvAnyAddress` rejects invalid IPs. `AwareDatetime` rejects timestamps without a timezone, which would break the time-window comparisons later. Maximum lengths limit memory abuse and make log injection harder, though they don’t filter characters. Outcomes, directions and severities are fixed sets, so a typo like “hgih” can never become a severity. `uid` 0 is allowed on purpose, since root is exactly what the privileged-execution rule needs to see.



**`config.py`**  

This file holds every setting the system depends on and reads them from environment variables, so behaviour can be changed without editing code. Each setting is a small function and not a constant, because a constant is read once at import time. Reading on each call lets tests and operators change a value and have it take effect.

The API key function returns the key if one is set, or `None` otherwise, and treats an empty value as unset so an empty string can never act as a valid key. A shared helper reads a name and a default, and converts the value to an integer. Another helper splits a comma-separated string into a clean list and drops empty entries.

On top of those helpers sit the detection settings. The failed-login threshold defaults to 5 and the sliding window to 60 seconds, so five failures from one IP within a minute raise an alert. The suspicious-paths list (`/tmp`, `/dev/shm`, `/var/tmp`) is where the privileged-execution rule looks for root processes running from places they shouldn’t. The allowed-ports list (22, 53, 80, 123, 443) works as an allowlist, so an outbound connection to any other port is flagged.

Limitation: a malformed value, such as text in a number setting, raises an error at request time. A stronger design would validate all settings once at startup.

**`auth.py`**  

This file decides who is allowed to use the API. It doesn’t validate event data, which is the models’ job; it only checks that the caller holds the correct API key.

It’s a FastAPI dependency that reads the `X-API-Key` header. The value is either a string or nothing, and the dependency then compares it with the key configured on the server. If the header is missing or wrong, the request is rejected with a 401 and a message that doesn’t say which of the two it was, so an attacker learns nothing from the response.

In this case, two security decisions matter most. First, if the server has no key configured at all, it refuses every request with a 503 (fail closed), that way a misconfigured deployment can never run unprotected. Second, keys are compared with `secrets.compare_digest`, which takes the same time whether the guess is nearly right or completely wrong, so response timing can’t be used to work out the key.

The check runs before the request body is validated, so unauthenticated callers can’t probe the schema through validation errors. The key is read on each request, which lets tests and any operator change it without a restart.

The Limitation despite being a assessment project,  there is a single shared key with no rotation, expiry or per-client identity, and nothing limits repeated guessing. In a real deployment scenario, It would be considered as security-wise to add per-client keys and rate limiting.

**`alerts.py`** 

This file is the alert store. It keeps the most recent alerts in memory, up to a fixed maximum (1000 by default). When the limit is reached, the oldest alert is dropped, so memory use stays bounded even under a flood of events. It supports adding an alert, listing alerts in the order they were raised, and clearing the store, which the tests use to start each test clean.

Limitation: because everything is in memory, alerts disappear when the server restarts, and each worker process would have its own separate store. In a real deployment I’d move alerts to a persistent store, add per-client access control, and keep an append-only audit log so any change to stored alerts can be traced.

**`main.py`**  
Creates the app, builds the rule list once, and exposes two endpoints. `POST /events` is protected by auth, validated automatically by the `SecurityEvent` type, runs every rule, stores any alerts, and returns 202 plus the alerts raised. `GET /alerts` returns the stored ones. `rules` is built once at startup because the failed-auth rule keeps state between requests. The endpoint is `async def` with no `await`, so rule evaluation runs on the single event loop and can't interleave.

## Detection files

**`base.py`**  
Says what a rule is: an object with a `name` and an `evaluate(event)` method returning an `Alert` or `None`. It exists so the engine can treat every rule the same way.

**`privileged_exec.py`**  
False positives: backup agents, installers or CI jobs that legitimately run as root from /tmp. Limitation: the rule is path-based only, so an attacker running from a normal directory isn’t caught, and it doesn’t look at the parent process or at what was just written to disk. Improvements: allowlist known-good executables (by path or hash), check the parent process, and correlate with authentication events on the same host, for example a root process starting shortly after a login from an unfamiliar address.**`outbound_conn.py`**  
Stateless. Looks at outbound `NetworkEvent`s and alerts when the destination port isn't on the allowlist. Severity medium. Likely false positives: scanners, monitoring probes, and unusual but legitimate services.

**`failed_auth.py`**  

This rule detects brute-force login attempts. It only looks at authentication events, and only at failed ones, so successful logins are ignored. For each source IP it keeps a list of timestamps of recent failures. Each new failure is added to that IP’s list, and any timestamps older than the sliding window (60 seconds by default) are dropped. If the number of remaining failures reaches the threshold (5 by default), the rule raises a high-severity alert saying how many failed logins came from that IP in what time.

The window is measured against the event’s own timestamp, not the server’s clock, so replayed or out-of-order test data behaves predictably. After an alert, that IP’s history is cleared, so the sixth failure starts a new count instead of raising another alert immediately. The number of tracked IPs is capped, so an attacker rotating through thousands of addresses can’t make memory grow without limit.

Limitations: counting is per IP only, so an attacker rotating IPs, or one IP trying many usernames slowly, can evade it. State is in memory, so it’s lost on restart and not shared between workers. Replayed events with the same ID are counted twice, late events can slip into the window out of order, and when the IP cap is reached the first-seen IP is evicted, not the least recently used one.

**`outbound_conn.py`

This rule watches outbound network events and raises a medium-severity alert when the destination port isn’t on the allowlist from the configuration. Inbound traffic is ignored. Because the allowlist is static, it will flag legitimate but unusual services (monitoring probes, internal tools on custom ports) and miss malicious traffic on allowed ports such as 443. Improvements: per-host baselines, destination reputation, and skipping private address ranges.

## Test files

**`helpers.py`**: builds valid events with one call, so each test changes only the field it cares about.  
**`test_models.py`**: valid events parse, and bad ones like wrong case, bad IP, naive timestamp, extra field, out-of-range port are rejected.  
**`test_privileged_exec.py`, `test_outbound_conn.py`, `test_failed_auth.py`**: each rule is tested alone, with normal, suspicious and edge cases.  
**`test_api.py`**: the full path through HTTP: auth failures (401, 503), validation failures (422), normal events, each rule with its own aler, and the 5-failure burst.

The layers mirror the architecture: model tests check validation, rule tests check detection, and API tests check the whole flow.

The general idea behind this design was to make everything stand on its own definition, rules and validation inputs. 

## Supporting files

- **`pytest.ini`**: `pythonpath = .` so tests can import `app`.
- **`requirements.txt`**: pinned versions so a fresh clone installs exactly what was tested.
- **`sample_data/`** and **`scripts/generate_samples.py`**: real inputs and outputs, produced by the running server.

## How a request travels 

Everything can be summarised into the following steps:

1. A request hits `POST /events`.
2. `auth.py` checks the key. Unauthenticated callers get 401 (or 503) before validation, so they can never probe the schema through error messages.
3. FastAPI validates the body against `SecurityEvent`. Bad data gets 422.
4. `main.py` hands the validated event to each rule. A rule ignores events of types it doesn't care about as long as it isn't its defined type.
5. Any alert goes into the store and into the response.
6. `GET /alerts` reads from the store.
suspicious paths and allowed ports. Each setting is a function, not a constant, so it is read when called. That lets tests change settings with `monkeypatch`, and lets operators change behavior without editing code.


## Security considerations
- Authentication: API key in the `X-API-Key` header, compared in constant time; the server refuses all requests if no key is configured (fail closed).
- Validation: strict models reject unknown fields, malformed IPs, naive timestamps, out-of-range values and oversized strings before any rule runs.
- Auth runs before body validation, so unauthenticated callers cannot probe the schema.
- Path normalisation stops `..` and `//` tricks from evading the privileged-execution rule.
- Memory is bounded: the alert store keeps at most 1000 alerts and the failed-auth rule tracks at most 10,000 IPs.
- Alert text is truncated so long inputs cannot make a valid detection fail.
- Synthetic data only; no secrets are stored, and the key comes from the environment.

## Limitations
- Events are trusted once the caller is authenticated, so a compromised sender could forge events.
- Detection is rule-based with static thresholds, so it is evadable: rotating source IPs, slow low-volume guessing, or malware that runs from normal directories.
- State is in memory: it is lost on restart and not shared between workers.
- Replayed events with the same ID are counted twice, late events can enter the window out of order, and the IP cap evicts the first-seen address, not the least recently used one.
- No rate limiting or request size limit, and the API key travels in a header, so TLS (for example via a reverse proxy) is required in any real deployment.
- A single shared key: no rotation, expiry or per-client identity.
- Invalid settings (for example text in a numeric variable) fail at request time, not at startup.

## Possible improvements
Persistent storage (for example Redis), per-client keys and rate limiting, deduplication by event ID, correlation across event types and hosts, per-host baselines, structured logging and an audit trail, and validating configuration at startup.

## Implementation notes and AI use
I wrote and debugged `models.py` myself, including the validation choices. The remaining code (configuration, authentication, alert store, API wiring, the three detection rules and the tests) started from reference implementations generated with Claude. I read, ran, tested and adapted them. I also used Claude for architecture guidance, code review(along with documented walkthroughs of the used Python Library: Pydantic), and for correcting technical wording in this document. The explanations are based on my own recorded walkthroughs of each file. Libraries: FastAPI, Pydantic, Uvicorn, httpx, pytest.
