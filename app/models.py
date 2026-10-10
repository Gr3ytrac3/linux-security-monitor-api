# continuing the above example...

from datetime import datetime, timezone
from pydantic import BaseModel, PositiveInt, ValidationError, Field, ConfigDict, PydanticUserError
from fastapi import FastAPI
from test import adapter 

# Literal for enforced string match, Union and Annoted for single entry point type that FastAPI endpoint can accept
from typing import Literal, Union, Annotated



class EventBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=64)
    timestamp: AwareDatatime
    host: str = Field(min_length=10, max_length=30)
    event_type: str
    

class AuthEvent(EventBase):
    event_type: Literal ["auth"] = "auth"
    source_ip: str
    username: str
    outcome: Literal ["failed", "success"]

class ProcessEvent(EventBase):
    event_type: Literal ["process"] = "process"
    pid: int = Field(ge=1, le=7)
    ppid: int = Field(ge=0, le=10)
    uid: int = Field(ge=0, le=3)
    exe_path: str
    parent_name: str
    process_name: str

class NetworkEvent(EventBase):
    event_type: Literal ["network"] = "network"
    pid: int
    process_name: str
    dest_ip: str | None
    dest_port: int = Field(ge=0, le=65535)
    direction: Literal["in", "out"]

# single type descriptor that dynamically picks the right model base on event_type

SecurityEvent = Annotated[
Union[AuthEvent, ProcessEvent, NetworkEvent],
Field(discriminator = "event_type")
]

# Alert section
class Alert(BaseModel):
    alert_id: str
    severity: str
    rule: str
    reason: str
    timestamp: dt
    event: SecurityEvent


