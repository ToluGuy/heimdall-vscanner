# backend/app/models.py

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from datetime import datetime
import uuid

from .db import Base


def generate_api_key():
    return str(uuid.uuid4())


class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    api_key = Column(String, unique=True, index=True, default=generate_api_key)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    capabilities = Column(String, default="nmap_scan")


class Job(Base):
    __tablename__ = "jobs"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String, nullable=False)
    target = Column(String, nullable=False)
    status = Column(String, default="pending")
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)        # set when job finishes
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    next_run_at = Column(DateTime, nullable=True)
    priority = Column(String, default="medium")
    retries = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    mode = Column(String, default="remote")
    profile = Column(String, default="standard")
    cleared = Column(Boolean, default=False)              # False = visible, True = archived


class Result(Base):
    __tablename__ = "results"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, nullable=False)
    output = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    cleared = Column(Boolean, default=False) #false = active, true = archived
