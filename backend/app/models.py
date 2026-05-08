# backend/app/models.py

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Text
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
    is_stale = Column(Boolean, default=False)


class Job(Base):
    __tablename__ = "jobs"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String, nullable=False)
    target = Column(String, nullable=False)
    status = Column(String, default="pending")
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    next_run_at = Column(DateTime, nullable=True)
    priority = Column(String, default="medium")
    retries = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    mode = Column(String, default="remote")
    profile = Column(String, default="standard")
    port = Column(Integer, nullable=True)       # single port — used by nikto_scan
    ports = Column(String, nullable=True)       # comma-separated — used by nse_scan
    cleared = Column(Boolean, default=False)


class Result(Base):
    __tablename__ = "results"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, nullable=False)
    output = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    cleared = Column(Boolean, default=False)


class DiscoverySweep(Base):
    __tablename__ = "discovery_sweeps"

    id = Column(Integer, primary_key=True, index=True)
    subnet = Column(String, nullable=False)           # e.g. 192.168.1.0/24
    status = Column(String, default="running")        # running, done, failed
    hosts_found = Column(Integer, default=0)
    jobs_created = Column(Integer, default=0)
    result = Column(Text, nullable=True)              # JSON list of discovered hosts
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
