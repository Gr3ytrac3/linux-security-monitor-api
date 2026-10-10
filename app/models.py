# continuing the above example...

from datetime import datetime
from pydantic import BaseModel, PositiveInt, ValidationError, Field
from fastapi import FastAPI



class Event(BaseModel):
    event_id: str
    timestamp: datetime
    host: str
    event_type: str


class AuthEvent(EventBase):

    source_ip: str
    username: str
    outcome: str

class ProcessEvent(EventBase):

    pid: int
    ppid: int
    uid: int
    exe_path: str
    parent_name: str
    process_name: str

class NetworkEvent(EventBase):

    pid: int
    process_name: str
    dest_ip: str
    dest_port: str
    direction: str
