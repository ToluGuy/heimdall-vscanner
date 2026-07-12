# backend/app/routes/jobs.py

import json
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Agent, Job, TargetAuthorization
from ..schemas import JobCreate
from ..core import (
    logger, require_auth, validate_target, get_setting,
    get_valid_job_types, get_job_type_risk_tier, WEB_PORTS, JOB_TIMEOUT_SECONDS,
)

router = APIRouter()


@router.post("/jobs/create")
def create_job(job: JobCreate, db: Session = Depends(get_db), username: str = Depends(require_auth)):

    # validate job type — built-in or plugin-provided, whatever's currently enabled
    valid_types = get_valid_job_types(db)
    if job.type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown job type '{job.type}'. Valid types: {sorted(valid_types)}"
        )

    target = validate_target(job.target)

    # high-risk job types (credential attacks, exploitation-class tooling) require
    # an active, time-boxed authorization for this exact target + job type —
    # see routes/authorizations.py. Built-ins and read_only/intrusive plugin
    # types never hit this gate.
    if get_job_type_risk_tier(db, job.type) == "high":
        live_auth = db.query(TargetAuthorization).filter(
            TargetAuthorization.target == target,
            TargetAuthorization.job_type == job.type,
            TargetAuthorization.expires_at > datetime.utcnow(),
        ).first()
        if not live_auth:
            raise HTTPException(
                status_code=403,
                detail=f"'{job.type}' against '{target}' requires an active authorization. "
                       "Authorize this target for this job type first."
            )

    # validate port for nikto jobs
    if job.type == "nikto_scan" and job.port is not None:
        if job.port not in WEB_PORTS:
            raise HTTPException(
                status_code=400,
                detail=f"Port {job.port} is not a recognised web port. "
                       f"Nikto only scans web services. Valid ports: {sorted(WEB_PORTS)}"
            )

    # validate ports for nse jobs — warn if all are web ports, but still create the job
    # (the actual filtering + warning is returned in the scan result by the agent/scanner)

    nse_ports_warning = None
    if job.type == "nse_scan" and job.ports and job.profile != "custom":
        requested = [int(p.strip()) for p in job.ports.split(",") if p.strip().isdigit()]
        web_in_request = [p for p in requested if p in WEB_PORTS]
        if web_in_request:
            nse_ports_warning = (
                f"Note: port(s) {web_in_request} are web ports. NSE will scan them but "
                "consider also running a Web Scan for deeper web surface testing."
            )

    # Custom profile validation — must have at least one script selected
    if job.profile == "custom" and job.type == "nse_scan":
        if not job.custom_scripts:
            raise HTTPException(
                status_code=400,
                detail="Custom profile requires at least one script to be selected."
            )

    # Custom profile validation for nikto_scan — must have at least one tuning category
    if job.profile == "custom" and job.type == "nikto_scan":
        if not job.nikto_tuning:
            raise HTTPException(
                status_code=400,
                detail="Custom Web Scan profile requires at least one tuning category to be selected."
            )

    # Serialise custom_scripts list to comma-separated string for DB storage
    custom_scripts_str = None
    if job.custom_scripts:
        custom_scripts_str = ",".join(s.strip() for s in job.custom_scripts if s.strip())

    # Serialise nikto_tuning list to comma-separated string for DB storage
    nikto_tuning_str = None
    if job.nikto_tuning:
        nikto_tuning_str = ",".join(s.strip() for s in job.nikto_tuning if s.strip())

    extra_params_str = json.dumps(job.extra_params) if job.extra_params else None

    new_job = Job(
        type=job.type,
        target=target,
        agent_id=job.agent_id,
        status="pending",
        priority=job.priority if job.priority else "medium",
        mode=job.mode if job.mode else "remote",
        profile=job.profile if job.profile else "standard",
        port=job.port if job.port else None,
        ports=job.ports if job.ports else None,
        custom_scripts=custom_scripts_str,
        nikto_tuning=nikto_tuning_str,
        extra_params=extra_params_str,
    )
    db.add(new_job)
    db.commit()
    db.refresh(new_job)

    response = {"id": new_job.id, "status": new_job.status}
    if nse_ports_warning:
        response["warning"] = nse_ports_warning

    return response


@router.get("/jobs")
def get_jobs(
    db: Session = Depends(get_db),
    show_history: bool = False
):
    if show_history:
        jobs = db.query(Job).all()
    else:
        jobs = db.query(Job).filter(Job.cleared == False).all()

    result = []
    for j in jobs:
        agent_name = None
        if j.agent_id:
            agent = db.query(Agent).filter(Agent.id == j.agent_id).first()
            if agent:
                agent_name = agent.name

        result.append({
            "id": j.id,
            "type": j.type,
            "target": j.target,
            "status": j.status,
            "priority": j.priority,
            "agent": agent_name or "any",
            "mode": j.mode,
            "profile": j.profile,
            "started_at": j.started_at.isoformat() if j.started_at else None,
            "completed_at": j.completed_at,
            "cleared": j.cleared
        })

    return result


def get_agent_load(db, agent_id: int):
    return db.query(Job).filter(
        Job.agent_id == agent_id,
        Job.status == "running"
    ).count()


@router.get("/jobs/next")
def get_next_job(
    db: Session = Depends(get_db),
    x_api_key: str = Header(...),
    x_agent_mode: str = Header(default="agent")
):
    now = datetime.utcnow()

    agent = db.query(Agent).filter(Agent.api_key == x_api_key).first()
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid API key")

    jobs = db.query(Job).filter(
        Job.status == "pending",
        Job.mode == x_agent_mode,
        (Job.next_run_at == None) | (Job.next_run_at <= now)
    ).all()

    if not jobs:
        return None

    agent_caps = agent.capabilities.split(",")

    eligible_jobs = [
        j for j in jobs
        if (j.agent_id is None or j.agent_id == agent.id)
        and j.type in agent_caps
    ]

    if not eligible_jobs:
        return None

    priority_order = {"high": 0, "medium": 1, "low": 2}
    eligible_jobs.sort(key=lambda j: (
        priority_order.get(j.priority, 1),  # high first
        j.agent_id is None,                 # agent-specific before any-agent
        j.id                                # oldest first as tiebreaker
    ))

    current_load = get_agent_load(db, agent.id)
    if current_load >= 2:
        return None

    job = eligible_jobs[0]
    job.agent_id = agent.id
    job.status = "running"
    job.started_at = datetime.utcnow()
    db.commit()

    # Deserialise custom_scripts from comma-separated DB string back to a list
    custom_scripts_list = None
    if job.custom_scripts:
        custom_scripts_list = [s.strip() for s in job.custom_scripts.split(",") if s.strip()]

    # Deserialise nikto_tuning from comma-separated DB string back to a list
    nikto_tuning_list = None
    if job.nikto_tuning:
        nikto_tuning_list = [s.strip() for s in job.nikto_tuning.split(",") if s.strip()]

    # Deserialise extra_params (plugin form_fields values) back to a dict
    extra_params = json.loads(job.extra_params) if job.extra_params else {}

    # Read auto_nikto setting so agents/scanner can respect it
    auto_nikto = get_setting(db, "auto_nikto") == "true"

    return {
        "id": job.id,
        "type": job.type,
        "target": job.target,
        "mode": job.mode,
        "profile": job.profile,
        "port": job.port,
        "ports": job.ports,
        "custom_scripts": custom_scripts_list,
        "nikto_tuning": nikto_tuning_list,
        "extra_params": extra_params,
        "auto_nikto": auto_nikto,
    }


@router.get("/jobs/recover-stuck")
def recover_stuck_jobs(db: Session = Depends(get_db)):
    now = datetime.utcnow()
    stuck_jobs = db.query(Job).filter(Job.status == "running").all()
    recovered = 0

    for job in stuck_jobs:
        if job.started_at is None:
            continue

        elapsed = now - job.started_at

        if elapsed > timedelta(seconds=JOB_TIMEOUT_SECONDS):
            logger.warning(f"Job {job.id} stuck for {elapsed}, resetting")

            if job.retries < job.max_retries:
                job.retries += 1
                delay = job.retries * 30
                job.next_run_at = datetime.utcnow() + timedelta(seconds=delay)
                job.status = "pending"
                job.started_at = None
                recovered += 1
                logger.info(f"Job {job.id} retrying in {delay}s ({job.retries}/{job.max_retries})")
            else:
                job.status = "failed"
                job.started_at = None
                job.completed_at = datetime.utcnow()
                logger.error(f"Job {job.id} exceeded max retries, marking failed")

    db.commit()
    return {"checked": len(stuck_jobs), "recovered": recovered}


@router.post("/jobs/{job_id}/clear")
def clear_job(job_id: int, db: Session = Depends(get_db)):
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status in ("pending", "failed"):
        db.delete(job)
        db.commit()
        return {"ok": True, "action": "deleted"}

    job.cleared = True
    db.commit()
    return {"ok": True, "action": "archived"}


@router.post("/jobs/{job_id}/cancel")
def cancel_job(
    job_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status not in ("pending", "running"):
        raise HTTPException(status_code=400, detail=f"Cannot cancel job with status '{job.status}'")
    job.status = "cancelled"
    job.completed_at = datetime.utcnow()
    db.commit()
    logger.info(f"Job {job_id} cancelled by user")
    return {"ok": True, "job_id": job_id, "status": "cancelled"}


@router.get("/jobs/{job_id}/status")
def get_job_status(
    job_id: int,
    db: Session = Depends(get_db),
    x_api_key: str = Header(None),
):
    """Lightweight endpoint for scanners/agents to poll job status mid-execution."""
    # Accepts both agent api key and dashboard auth
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"job_id": job.id, "status": job.status}
