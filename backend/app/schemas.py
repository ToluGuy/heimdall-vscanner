# backend/app/schemas.py

from pydantic import BaseModel
from typing import Optional, Any


class AgentCreate(BaseModel):
    name: str
    capabilities: Optional[str] = None


class AgentResponse(BaseModel):
    api_key: str

    class Config:
        from_attributes = True


class JobResponse(BaseModel):
    id: int
    type: str
    target: str

    class Config:
        from_attributes = True


class ResultCreate(BaseModel):
    job_id: int
    output: str


class ResultResponse(BaseModel):
    id: int
    job_id: int
    output: Any
    cleared: bool = False
    job_info: Optional[Any] = None
    analysis: Optional[str] = None

    class Config:
        from_attributes = True


class JobCreate(BaseModel):
    type: str
    target: str
    agent_id: Optional[int] = None
    priority: str | None = "medium"
    mode: str | None = "remote"
    profile: str | None = "standard"
    port: Optional[int] = None
    ports: Optional[str] = None
