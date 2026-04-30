# backend/app/models.py

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
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
    type = Column(String, nullable=False)  # e.g. nmap_scan
    target = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending, running, done
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    priority = Column(String,default="medium") #high/medium/low
    retries = Column(Integer, default=0)
    max_retries = Column(Integer, default=3) #max of 3 but can be changed
    #job model maybe
    started_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    next_run_at = Column(DateTime, nullable=True)
    mode = Column(String, default="remote") # agent / remote
    profile = Column(String,default="standard") # light / standard / full
    

class Result(Base):
    __tablename__ = "results"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, nullable=False)
    output = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
