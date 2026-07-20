# backend/app/routes/authorizations.py
#
# Backs the authorization gate checked in routes/jobs.py's create_job() for
# any job type whose risk_tier is "high". See
# PLUGIN_ARCHITECTURE_PROPOSAL.md section 10 for the reasoning — short-lived,
# scoped to one exact target + job type, never a blanket "authorize this
# host" switch.

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import TargetAuthorization
from ..core import logger, require_auth, validate_target, get_setting, get_job_type_risk_tier

router = APIRouter()


@router.get("/authorizations")
def list_authorizations(db: Session = Depends(get_db), username: str = Depends(require_auth)):
    """All authorizations, past and present — lets the Pen Test tab show what's live vs expired."""
    now = datetime.utcnow()
    rows = db.query(TargetAuthorization).order_by(TargetAuthorization.created_at.desc()).all()
    return [
        {
            "id": a.id,
            "target": a.target,
            "job_type": a.job_type,
            "authorized_by": a.authorized_by,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "expires_at": a.expires_at.isoformat() if a.expires_at else None,
            "active": a.expires_at > now,
        }
        for a in rows
    ]


@router.post("/authorizations")
def create_authorization(
    data: dict,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    target = validate_target(data.get("target", ""))
    job_type = data.get("job_type", "").strip()
    if not job_type:
        raise HTTPException(status_code=400, detail="job_type is required")

    if get_job_type_risk_tier(db, job_type) != "high":
        raise HTTPException(
            status_code=400,
            detail=f"'{job_type}' isn't a high-risk job type — it doesn't need an authorization."
        )

    max_hours = float(get_setting(db, "high_risk_auth_max_hours"))
    requested_hours = float(data.get("hours", max_hours))
    if requested_hours <= 0 or requested_hours > max_hours:
        raise HTTPException(
            status_code=400,
            detail=f"hours must be between 0 and {max_hours} (set by the high_risk_auth_max_hours setting)"
        )

    # One active window per target+job_type at a time — replace rather than
    # stack, so there's never ambiguity about which expiry actually governs.
    existing = db.query(TargetAuthorization).filter(
        TargetAuthorization.target == target,
        TargetAuthorization.job_type == job_type,
        TargetAuthorization.expires_at > datetime.utcnow(),
    ).first()
    if existing:
        db.delete(existing)

    auth = TargetAuthorization(
        target=target,
        job_type=job_type,
        authorized_by=username,
        expires_at=datetime.utcnow() + timedelta(hours=requested_hours),
    )
    db.add(auth)
    db.commit()
    db.refresh(auth)

    logger.warning(
        f"Target authorization granted: '{job_type}' against '{target}' by '{username}', "
        f"expires {auth.expires_at.isoformat()}"
    )
    return {"ok": True, "id": auth.id, "expires_at": auth.expires_at.isoformat()}


@router.delete("/authorizations/{auth_id}")
def revoke_authorization(
    auth_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    """Revoke early — e.g. testing wrapped up before the window expired."""
    auth = db.query(TargetAuthorization).filter(TargetAuthorization.id == auth_id).first()
    if not auth:
        raise HTTPException(status_code=404, detail="Authorization not found")
    db.delete(auth)
    db.commit()
    logger.info(f"Authorization {auth_id} revoked early by '{username}'")
    return {"ok": True}
