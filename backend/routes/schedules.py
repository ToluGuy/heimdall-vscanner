# backend/app/routes/schedules.py

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Schedule
from ..core import logger, require_auth, validate_target, get_valid_job_types, get_job_type_risk_tier

router = APIRouter()


@router.get("/schedules")
def get_schedules(
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    schedules = db.query(Schedule).order_by(Schedule.id).all()
    return [
        {
            "id": s.id,
            "name": s.name,
            "type": s.type,
            "target": s.target,
            "mode": s.mode,
            "profile": s.profile,
            "priority": s.priority,
            "ports": s.ports,
            "port": s.port,
            "interval_hours": s.interval_hours,
            "paused": s.paused,
            "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
            "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
        }
        for s in schedules
    ]


@router.post("/schedules")
def create_schedule(
    data: dict,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    name = data.get("name", "").strip()
    scan_type = data.get("type", "").strip()
    target = validate_target(data.get("target", ""))
    interval_hours = data.get("interval_hours")

    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    valid_types = get_valid_job_types(db)
    if scan_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid type. Valid: {sorted(valid_types)}")
    if get_job_type_risk_tier(db, scan_type) == "high":
        raise HTTPException(
            status_code=400,
            detail="High-risk job types (credential attacks, exploitation-class tooling) can't be "
                   "scheduled — they require a fresh, explicit, time-boxed authorization each time, "
                   "which a recurring schedule can't provide. Run these as one-off jobs only."
        )
    if not interval_hours or int(interval_hours) < 1:
        raise HTTPException(status_code=400, detail="interval_hours must be >= 1")

    now = datetime.utcnow()
    schedule = Schedule(
        name=name,
        type=scan_type,
        target=target,
        mode=data.get("mode", "remote"),
        profile=data.get("profile", "standard"),
        priority=data.get("priority", "medium"),
        ports=data.get("ports") or None,
        port=int(data["port"]) if data.get("port") else None,
        interval_hours=int(interval_hours),
        next_run_at=now,   # fire immediately on first tick
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    logger.info(f"Schedule '{name}' created — {scan_type} on {target} every {interval_hours}h")
    return {"id": schedule.id, "name": schedule.name}


@router.post("/schedules/{schedule_id}/pause")
def pause_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    s = db.query(Schedule).filter(Schedule.id == schedule_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Schedule not found")
    s.paused = True
    db.commit()
    return {"ok": True}


@router.post("/schedules/{schedule_id}/resume")
def resume_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    s = db.query(Schedule).filter(Schedule.id == schedule_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Schedule not found")
    s.paused = False
    # Reset next_run_at so it fires on the next scheduler tick rather than immediately
    s.next_run_at = datetime.utcnow() + timedelta(hours=s.interval_hours)
    db.commit()
    return {"ok": True}


@router.delete("/schedules/{schedule_id}")
def delete_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    s = db.query(Schedule).filter(Schedule.id == schedule_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Schedule not found")
    db.delete(s)
    db.commit()
    return {"ok": True}
