# continuing the above example...

from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict, AwareDatetime, IPvAnyAddress
from uuid import uuid4 

# Literal for enforced string match, Union and Annoted for single entry point type that FastAPI endpoint can accept
from typing import Literal, Union, Annotated

PathStr = Annotated[str, Field(min_length=5, max_length=200)]
ShortStr = Annotated[str, Field(min_length=1, max_length=50)]

class EventBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=64)
    timestamp: AwareDatetime
    host: str = Field(min_length=1, max_length=253)
    

class AuthEvent(EventBase):
    event_type: Literal ["auth"]
    source_ip: IPvAnyAddress
    username: str = Field(min_length=1, max_length=64)
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

class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

# Alert section
class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    severity: Severity
    rule: ShortStr
    reason: str = Field(min_length=1, max_length=250)
    timestamp: AwareDatetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event: SecurityEvent
