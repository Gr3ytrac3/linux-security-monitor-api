# continuing the above example...

from datetime import datetime, timezone
from pydantic import BaseModel, PositiveInt, ValidationError, Field, ConfigDict, PydanticUserError
from fastapi import FastAPI
from test import adapter 

# Literal for enforced string match, Union and Annoted for single entry point type that FastAPI endpoint can accept
from typing import Literal, Union, Annotated

PathStr = Annotated[str, Field(min_length=5, max_length=200)]
ShortStr = Annotated[str, Field(min_length=1, max_length=50)]

class EventBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=64)
    timestamp: AwareDatatime
    host: str = Field(min_length=10, max_length=30)
    event_type: str
    

class AuthEvent(EventBase):
    event_type: Literal ["auth"]
    source_ip: IPvAnyAddress
    username: str = Field(min_length=7, max_length=15)
    outcome: Literal ["success", "failed"]

class ProcessEvent(EventBase):
    event_type: Literal ["process"]
    pid: int = Field(ge=1)
    ppid: int = Field(ge=0)
    uid: int = Field(ge=0)
    exe_path: PathStr
    parent_name: ShortStr
    process_name: ShortStr

class NetworkEvent(EventBase):
    event_type: Literal ["network"]
    pid: int = Field(ge=1)
    process_name: ShortStr
    dest_ip: IPvAnyAddress
    dest_port: int = Field(ge=1, le=65535)
    direction: Literal["in", "out"]

# single type descriptor that dynamically picks the right model base on event_type

SecurityEvent = Annotated[
Union[AuthEvent, ProcessEvent, NetworkEvent],
Field(discriminator = "event_type"),
]

Class Severity():
    low: Literal["low"],
    medium: Literal["medium"],
    high: Literal["high"],
critical: Literal["critical"]

# Alert section
class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    severity: Severity
    rule: ShortStr
    reason: ShortStr
    timestamp: AwareDatatime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event: SecurityEvent


