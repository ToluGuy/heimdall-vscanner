# backend/routes/hosts.py

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Agent, Host
from ..core import require_auth

router = APIRouter()


@router.get("/hosts")
def get_hosts(db: Session = Depends(get_db), username: str = Depends(require_auth)):
    hosts = db.query(Host).order_by(Host.last_seen.desc()).all()
    out = []
    for h in hosts:
        agent_name = None
        if h.agent_id:
            a = db.query(Agent).filter(Agent.id == h.agent_id).first()
            if a:
                agent_name = a.name
        out.append({
            "id": h.id,
            "ip": h.ip,
            "mac": h.mac,
            "hostname": h.hostname,
            "os": h.os_fingerprint,
            "agent_id": h.agent_id,
            "agent_name": agent_name,
            "first_seen": h.first_seen.isoformat() if h.first_seen else None,
            "last_seen": h.last_seen.isoformat() if h.last_seen else None,
            "last_ip": h.last_ip,
            "ip_changed_at": h.ip_changed_at.isoformat() if h.ip_changed_at else None,
        })
    return out
