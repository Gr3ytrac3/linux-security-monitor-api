from fastapi import Depends, FastAPI

from app.alerts import AlertStore
from app.auth import require_api_key
from app.detection.failed_auth import FailedAuthRule
from app.detection.outbound_conn import OutboundConnRule
from app.detection.privileged_exec import PrivilegedExecRule
from app.models import Alert, SecurityEvent

app = FastAPI(title="Linux Security Monitor API")
store = AlertStore()


def build_rules():
    return [PrivilegedExecRule(), OutboundConnRule(), FailedAuthRule()]


rules = build_rules()


@app.post("/events", status_code=202, dependencies=[Depends(require_api_key)])
async def ingest_event(event: SecurityEvent) -> dict:
    raised: list[Alert] = []
    for rule in rules:
        alert = rule.evaluate(event)
        if alert is not None:
            store.add(alert)
            raised.append(alert)
    return {"accepted": True, "alerts": [a.model_dump(mode="json") for a in raised]}


@app.get("/alerts", dependencies=[Depends(require_api_key)])
async def list_alerts() -> list[Alert]:
    return store.list()
