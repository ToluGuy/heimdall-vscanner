# backend/app/main.py

import secrets
import os
import json
import subprocess
import threading
import xml.etree.ElementTree as ET
from fastapi import FastAPI, Depends, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import List
from dotenv import load_dotenv

load_dotenv()

from .db import Base, engine, get_db, SessionLocal
from .models import Agent, Job, Result, DiscoverySweep, Schedule, Host, Setting
from .schemas import AgentCreate, AgentResponse, JobResponse, ResultCreate, ResultResponse, JobCreate
from .logger import get_logger
from .ai_analysis import analyse_scan, AI_AUTO_ANALYSE, AI_PROVIDER

logger = get_logger("vapt.server", "server.log")

JOB_TIMEOUT_SECONDS = 120
STALE_AGENT_HOURS = int(os.environ.get("STALE_AGENT_HOURS", "24"))

SCHEDULE_TICK_SECONDS = 60   # how often the scheduler wakes up to check

Base.metadata.create_all(bind=engine)

app = FastAPI()


security = HTTPBasic()


# --- STALE AGENT CLEANUP ---

def mark_stale_agents(db: Session):
    """Flag agents whose last heartbeat is older than STALE_AGENT_HOURS."""
    stale_hours = int(get_setting(db, "stale_agent_hours"))
    cutoff = datetime.utcnow() - timedelta(hours=stale_hours)
    stale = db.query(Agent).filter(
        Agent.last_seen < cutoff,
        Agent.is_stale == False
    ).all()
    for agent in stale:
        agent.is_stale = True
        logger.info(f"Agent '{agent.name}' (id={agent.id}) marked stale — "
                    f"last seen {agent.last_seen}")
    if stale:
        db.commit()
    return len(stale)


def run_stale_cleanup():
    """Background thread: runs cleanup on startup then every hour."""
    import time as _time
    while True:
        db = SessionLocal()
        try:
            marked = mark_stale_agents(db)
            if marked:
                logger.info(f"Stale agent cleanup: {marked} agent(s) flagged")
        except Exception as e:
            logger.error(f"Stale agent cleanup error: {e}")
        finally:
            db.close()
        _time.sleep(3600)  # re-check every hour


def run_scheduler():
    """Background thread: checks every SCHEDULE_TICK_SECONDS for schedules that are due."""
    import time as _time
    while True:
        db = SessionLocal()
        try:
            now = datetime.utcnow()
            due = db.query(Schedule).filter(
                Schedule.paused == False,
                (Schedule.next_run_at == None) | (Schedule.next_run_at <= now)
            ).all()

            for schedule in due:
                new_job = Job(
                    type=schedule.type,
                    target=schedule.target,
                    status="pending",
                    mode=schedule.mode,
                    profile=schedule.profile,
                    priority=schedule.priority,
                    ports=schedule.ports,
                )
                db.add(new_job)
                schedule.last_run_at = now
                schedule.next_run_at = now + timedelta(hours=schedule.interval_hours)
                logger.info(
                    f"Schedule '{schedule.name}' fired — created {schedule.type} job "
                    f"for {schedule.target}, next run in {schedule.interval_hours}h"
                )

            if due:
                db.commit()

        except Exception as e:
            logger.error(f"Scheduler error: {e}")
        finally:
            db.close()

        _time.sleep(SCHEDULE_TICK_SECONDS)


SETTING_DEFAULTS = {
    "ai_auto_analyse":    "true",
    "stale_agent_hours":  "24",
}
 
def _init_default_settings():
    """Insert default settings rows if they don't already exist."""
    db = SessionLocal()
    try:
        for key, value in SETTING_DEFAULTS.items():
            existing = db.query(Setting).filter(Setting.key == key).first()
            if not existing:
                db.add(Setting(key=key, value=value))
        db.commit()
    except Exception as e:
        logger.error(f"Settings init error: {e}")
    finally:
        db.close()
 
 
def get_setting(db, key: str) -> str:
    """Get a setting value, falling back to env var then hardcoded default."""
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        return row.value
    # Fall back to env / hardcoded defaults
    if key == "stale_agent_hours":
        return os.environ.get("STALE_AGENT_HOURS", "24")
    if key == "ai_auto_analyse":
        return "true" if AI_AUTO_ANALYSE else "false"
    return SETTING_DEFAULTS.get(key, "")


@app.on_event("startup")
def startup_cleanup():
    thread = threading.Thread(target=run_stale_cleanup, daemon=True)
    thread.start()
    logger.info("Stale agent cleanup thread started")

    sched_thread = threading.Thread(target=run_scheduler, daemon=True)
    sched_thread.start()
    logger.info("Job scheduler thread started")
    
    _init_default_settings()

DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "vapt-admin")

# Web ports are Nikto's domain — NSE and standalone jobs validate against this
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}

VALID_JOB_TYPES = {"nmap_scan", "nikto_scan", "nse_scan"}


def require_auth(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(
        credentials.username.encode("utf8"),
        DASHBOARD_USERNAME.encode("utf8")
    )
    correct_password = secrets.compare_digest(
        credentials.password.encode("utf8"),
        DASHBOARD_PASSWORD.encode("utf8")
    )
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


@app.get("/")
def root():
    return {"message": "VAPT system running"}


@app.post("/agents/register", response_model=AgentResponse)
def register_agent(agent: AgentCreate, db: Session = Depends(get_db)):
    new_agent = Agent(
        name=agent.name,
        capabilities=agent.capabilities or "nmap_scan"
    )
    db.add(new_agent)
    db.commit()
    db.refresh(new_agent)
    return {"api_key": new_agent.api_key}


def get_agent_by_api_key(api_key: str, db: Session):
    agent = db.query(Agent).filter(Agent.api_key == api_key).first()
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return agent


def find_or_create_host(db: Session, ip: str, mac: str = None, hostname: str = None,
                        agent_id: int = None, os_fingerprint: str = None):
    """
    Finds an existing Host record using priority matching, or creates a new one.
    Priority: agent_id > MAC > hostname > IP.
    Updates metadata and logs IP changes.
    """
    now = datetime.utcnow()
    host = None

    if agent_id:
        host = db.query(Host).filter(Host.agent_id == agent_id).first()
    if not host and mac:
        host = db.query(Host).filter(Host.mac == mac).first()
    if not host and hostname:
        host = db.query(Host).filter(Host.hostname == hostname).first()
    if not host:
        host = db.query(Host).filter(Host.ip == ip).first()

    if host:
        if host.ip != ip:
            host.last_ip = host.ip
            host.ip_changed_at = now
            logger.info(f"Host #{host.id} IP changed: {host.ip} -> {ip}")
        host.ip = ip
        if mac:
            host.mac = mac
        if hostname:
            host.hostname = hostname
        if agent_id and not host.agent_id:
            host.agent_id = agent_id
        if os_fingerprint and not host.os_fingerprint:
            host.os_fingerprint = os_fingerprint
        host.last_seen = now
    else:
        host = Host(ip=ip, mac=mac, hostname=hostname, agent_id=agent_id,
                    os_fingerprint=os_fingerprint, first_seen=now, last_seen=now)
        db.add(host)
        db.flush()
        logger.info(f"New host: {ip} mac={mac} hostname={hostname}")

    return host


def run_ai_analysis(result_id: int, output: dict):
    """Background task: generates AI analysis and stores it on the result."""
    db = SessionLocal()
    try:
        analysis = analyse_scan(output)
        if analysis:
            result = db.query(Result).filter(Result.id == result_id).first()
            if result:
                result.analysis = analysis
                db.commit()
                logger.info(f"AI analysis stored for result #{result_id}")
    except Exception as e:
        logger.error(f"AI analysis background task failed for result #{result_id}: {e}")
    finally:
        db.close()


@app.post("/agents/results")
def submit_result(
    result: ResultCreate,
    x_api_key: str = Header(...),
    db: Session = Depends(get_db),
):
    agent = get_agent_by_api_key(x_api_key, db)

    parsed_output = json.loads(result.output)
    job = db.query(Job).filter(Job.id == result.job_id).first()
    target_ip = job.target if job else None

    # Extract identity signals from Nmap output
    mac = None
    hostname = None
    os_fingerprint = None
    if target_ip and parsed_output.get("nmap"):
        for h in parsed_output["nmap"]:
            if h.get("host") == target_ip:
                mac = h.get("mac")
                hostname = h.get("hostname")
                os_fingerprint = h.get("os")
                break
        if not mac and not hostname and parsed_output["nmap"]:
            first = parsed_output["nmap"][0]
            mac = first.get("mac")
            hostname = first.get("hostname")
            os_fingerprint = first.get("os")

    # Link agent identity only for agent-mode jobs
    linked_agent_id = agent.id if (job and job.mode == "agent") else None

    # Resolve host record
    host = None
    if target_ip:
        try:
            host = find_or_create_host(db, ip=target_ip, mac=mac, hostname=hostname,
                                       agent_id=linked_agent_id, os_fingerprint=os_fingerprint)
        except Exception as e:
            logger.error(f"Host resolution failed for {target_ip}: {e}")
            try:
                db.rollback()
            except Exception:
                pass

    new_result = Result(
        job_id=result.job_id,
        host_id=host.id if host else None,
        output=result.output,
    )
    db.add(new_result)

    if job:
        job.status = "done"
        job.completed_at = datetime.utcnow()

    db.commit()
    db.refresh(new_result)

    # Trigger AI analysis in background if enabled
    db_auto = get_setting(db, "ai_auto_analyse")
    if db_auto == "true":
        result_id = new_result.id
        thread = threading.Thread(
            target=run_ai_analysis,
            args=(result_id, parsed_output),
            daemon=True
        )
        thread.start()

    return {"message": "Result stored"}


# --- RESULTS ---

@app.get("/results", response_model=List[ResultResponse])
def get_results(
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
    show_history: bool = False
):
    if show_history:
        results = db.query(Result).filter(Result.cleared == True).all()
    else:
        results = db.query(Result).filter(Result.cleared == False).all()

    response = []

    for r in results:
        parsed_output = json.loads(r.output)

        job_info = None
        job = db.query(Job).filter(Job.id == r.job_id).first()
        if job:
            job_info = {
                "id": job.id,
                "type": job.type,
                "target": job.target,
                "mode": job.mode,
                "profile": job.profile,
                "priority": job.priority,
                "status": job.status,
                "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            }

        response.append({
            "id": r.id,
            "job_id": r.job_id,
            "output": parsed_output,
            "cleared": r.cleared,
            "job_info": job_info,
            "analysis": r.analysis,
        })

    return response


@app.post("/results/{result_id}/clear")
def clear_result(
    result_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth)
):
    result = db.query(Result).filter(Result.id == result_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")

    result.cleared = True

    job = db.query(Job).filter(Job.id == result.job_id).first()
    if job:
        job.cleared = True

    db.commit()
    return {"ok": True}


@app.delete("/results/clear-all-history")
def clear_all_history(
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    """Permanently delete all cleared (archived) results and their jobs."""
    cleared_results = db.query(Result).filter(Result.cleared == True).all()
    job_ids = [r.job_id for r in cleared_results]
 
    deleted_results = len(cleared_results)
    for r in cleared_results:
        db.delete(r)
 
    deleted_jobs = 0
    if job_ids:
        jobs = db.query(Job).filter(Job.id.in_(job_ids)).all()
        for j in jobs:
            db.delete(j)
            deleted_jobs += 1
 
    db.commit()
    logger.info(f"Bulk history clear: {deleted_results} results, {deleted_jobs} jobs deleted")
    return {"ok": True, "deleted_results": deleted_results, "deleted_jobs": deleted_jobs}


@app.delete("/results/bulk")
def delete_results_bulk(
    data: dict,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth)
):
    ids = data.get("ids", [])
    if not ids:
        raise HTTPException(status_code=400, detail="No IDs provided")

    results = db.query(Result).filter(Result.id.in_(ids)).all()
    job_ids = [r.job_id for r in results]

    for r in results:
        db.delete(r)

    if job_ids:
        jobs = db.query(Job).filter(Job.id.in_(job_ids)).all()
        for j in jobs:
            db.delete(j)

    db.commit()
    return {"ok": True, "deleted": len(results)}


@app.delete("/results/{result_id}")
def delete_result(
    result_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth)
):
    result = db.query(Result).filter(Result.id == result_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")

    job = db.query(Job).filter(Job.id == result.job_id).first()

    db.delete(result)
    if job:
        db.delete(job)

    db.commit()
    return {"ok": True}


# --- HOSTS ---

@app.get("/hosts")
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


# --- EXPORT ---

@app.get("/export/results")
def export_results(
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
    show_history: bool = False
):
    if show_history:
        results = db.query(Result).filter(Result.cleared == True).all()
    else:
        results = db.query(Result).filter(Result.cleared == False).all()

    export = []
    for r in results:
        parsed_output = json.loads(r.output)
        job = db.query(Job).filter(Job.id == r.job_id).first()

        job_info = None
        if job:
            job_info = {
                "target": job.target,
                "type": job.type,
                "mode": job.mode,
                "profile": job.profile,
                "priority": job.priority,
                "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            }

        export.append({
            "result_id": r.id,
            "job": job_info or {"job_id": r.job_id},
            "nmap": parsed_output.get("nmap"),
            "nikto": parsed_output.get("nikto"),
            "nse": parsed_output.get("nse"),
        })

    return {
        "exported_at": datetime.utcnow().isoformat(),
        "source": "VAPT Scanner",
        "total": len(export),
        "results": export
    }


# --- JOBS ---

@app.post("/jobs/create")
def create_job(job: JobCreate, db: Session = Depends(get_db), username: str = Depends(require_auth)):

    # validate job type
    if job.type not in VALID_JOB_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown job type '{job.type}'. Valid types: {sorted(VALID_JOB_TYPES)}"
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
    if job.type == "nse_scan" and job.ports:
        requested = [int(p.strip()) for p in job.ports.split(",") if p.strip().isdigit()]
        non_web = [p for p in requested if p not in WEB_PORTS]
        if requested and not non_web:
            # All ports are web ports — surface this immediately so the user knows
            # before the job even runs (the agent will also warn in its result output)
            nse_ports_warning = (
                f"Warning: all specified ports {requested} are web ports. "
                "NSE will have nothing to scan on those. Use a Nikto job for web surface testing."
            )

    new_job = Job(
        type=job.type,
        target=job.target,
        agent_id=job.agent_id,
        status="pending",
        priority=job.priority if job.priority else "medium",
        mode=job.mode if job.mode else "remote",
        profile=job.profile if job.profile else "standard",
        port=job.port if job.port else None,
        ports=job.ports if job.ports else None,
    )
    db.add(new_job)
    db.commit()
    db.refresh(new_job)

    response = {"id": new_job.id, "status": new_job.status}
    if nse_ports_warning:
        response["warning"] = nse_ports_warning

    return response


@app.get("/agents")
def get_agents(
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
    show_stale: bool = False,
):
    if show_stale:
        agents = db.query(Agent).all()
    else:
        agents = db.query(Agent).filter(Agent.is_stale == False).all()

    response = []
    for a in agents:
        status = "offline"
        if a.last_seen and (datetime.utcnow() - a.last_seen) < timedelta(seconds=30):
            status = "online"

        response.append({
            "id": a.id,
            "name": a.name,
            "api_key": a.api_key,
            "status": status,
            "last_seen": a.last_seen,
            "is_stale": a.is_stale,
        })

    return response


@app.post("/agents/{agent_id}/dismiss")
def dismiss_agent(
    agent_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    """Permanently remove a stale agent record."""
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if not agent.is_stale:
        raise HTTPException(status_code=400, detail="Agent is not stale — cannot dismiss active agents")
 
    db.query(Job).filter(Job.agent_id == agent_id).update({"agent_id": None})
 
    db.delete(agent)
    db.commit()
    return {"ok": True}

@app.post("/agents/{agent_id}/restore")
def restore_agent(
    agent_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    """Clear the stale flag so an agent shows up normally again."""
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.is_stale = False
    db.commit()
    return {"ok": True}


@app.get("/jobs")
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


@app.get("/jobs/next")
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

    return {
        "id": job.id,
        "type": job.type,
        "target": job.target,
        "mode": job.mode,
        "profile": job.profile,
        "port": job.port,
        "ports": job.ports,     # <-- now included so agents/scanner can use it
    }


@app.post("/agents/heartbeat")
def heartbeat(
    x_api_key: str = Header(...),
    db: Session = Depends(get_db),
):
    agent = get_agent_by_api_key(x_api_key, db)
    agent.last_seen = datetime.utcnow()
    db.commit()
    return {"status": "alive"}


@app.post("/agents/job-status")
def update_job_status(
    data: dict,
    x_api_key: str = Header(...),
    db: Session = Depends(get_db)
):
    agent = get_agent_by_api_key(x_api_key, db)

    job = db.query(Job).filter(Job.id == data["job_id"]).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    new_status = data["status"]

    if new_status == "running":
        if job.agent_id is None:
            job.agent_id = agent.id
        elif job.agent_id != agent.id:
            raise HTTPException(status_code=403, detail="This job does not belong to you")
        job.started_at = datetime.utcnow()
    else:
        if job.agent_id != agent.id:
            raise HTTPException(status_code=403, detail="This job does not belong to you")

    job.status = new_status
    db.commit()
    return {"ok": True}


@app.get("/jobs/recover-stuck")
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


@app.post("/jobs/{job_id}/clear")
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


@app.post("/results/{result_id}/analyse")
def trigger_analysis(
    result_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    result = db.query(Result).filter(Result.id == result_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")

    parsed_output = json.loads(result.output)
    thread = threading.Thread(
        target=run_ai_analysis,
        args=(result_id, parsed_output),
        daemon=True
    )
    thread.start()
    return {"ok": True, "message": "Analysis started"}


# --- SCHEDULES ---

@app.get("/schedules")
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
            "interval_hours": s.interval_hours,
            "paused": s.paused,
            "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
            "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
        }
        for s in schedules
    ]


@app.post("/schedules")
def create_schedule(
    data: dict,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    name = data.get("name", "").strip()
    scan_type = data.get("type", "").strip()
    target = data.get("target", "").strip()
    interval_hours = data.get("interval_hours")

    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    if scan_type not in VALID_JOB_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid type. Valid: {sorted(VALID_JOB_TYPES)}")
    if not target:
        raise HTTPException(status_code=400, detail="target is required")
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
        interval_hours=int(interval_hours),
        next_run_at=now,   # fire immediately on first tick
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    logger.info(f"Schedule '{name}' created — {scan_type} on {target} every {interval_hours}h")
    return {"id": schedule.id, "name": schedule.name}


@app.post("/schedules/{schedule_id}/pause")
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


@app.post("/schedules/{schedule_id}/resume")
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


@app.delete("/schedules/{schedule_id}")
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


# --- DISCOVERY ---

def run_ping_sweep(sweep_id: int, subnet: str, mode: str, profile: str):
    db = SessionLocal()
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-oX", "-", subnet],
            capture_output=True,
            text=True,
            timeout=300
        )

        hosts = []
        if result.returncode == 0:
            try:
                root = ET.fromstring(result.stdout)
                for host in root.findall("host"):
                    status = host.find("status")
                    if status is not None and status.get("state") == "up":
                        addr = host.find("address")
                        if addr is not None:
                            hosts.append(addr.get("addr"))
            except ET.ParseError as e:
                logger.error(f"Sweep {sweep_id} XML parse error: {e}")

        jobs_created = 0
        for host_ip in hosts:
            new_job = Job(
                type="nmap_scan",
                target=host_ip,
                status="pending",
                mode=mode,
                profile=profile,
                priority="medium"
            )
            db.add(new_job)
            jobs_created += 1

        sweep = db.query(DiscoverySweep).filter(DiscoverySweep.id == sweep_id).first()
        if sweep:
            sweep.status = "done"
            sweep.hosts_found = len(hosts)
            sweep.jobs_created = jobs_created
            sweep.result = json.dumps(hosts)
            sweep.completed_at = datetime.utcnow()

        db.commit()
        logger.info(f"Sweep {sweep_id} complete: {len(hosts)} hosts found, {jobs_created} jobs created")

    except subprocess.TimeoutExpired:
        sweep = db.query(DiscoverySweep).filter(DiscoverySweep.id == sweep_id).first()
        if sweep:
            sweep.status = "failed"
            sweep.completed_at = datetime.utcnow()
        db.commit()
        logger.error(f"Sweep {sweep_id} timed out")

    except Exception as e:
        sweep = db.query(DiscoverySweep).filter(DiscoverySweep.id == sweep_id).first()
        if sweep:
            sweep.status = "failed"
            sweep.completed_at = datetime.utcnow()
        db.commit()
        logger.error(f"Sweep {sweep_id} failed: {e}")

    finally:
        db.close()


@app.post("/discover")
def start_discovery(
    data: dict,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth)
):
    subnet = data.get("subnet", "").strip()
    mode = data.get("mode", "remote")
    profile = data.get("profile", "standard")

    if not subnet:
        raise HTTPException(status_code=400, detail="subnet is required")

    sweep = DiscoverySweep(
        subnet=subnet,
        status="running"
    )
    db.add(sweep)
    db.commit()
    db.refresh(sweep)

    thread = threading.Thread(
        target=run_ping_sweep,
        args=(sweep.id, subnet, mode, profile),
        daemon=True
    )
    thread.start()

    logger.info(f"Discovery sweep {sweep.id} started for subnet {subnet}")
    return {"sweep_id": sweep.id, "status": "running"}


@app.get("/discover/{sweep_id}")
def get_sweep_status(
    sweep_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth)
):
    sweep = db.query(DiscoverySweep).filter(DiscoverySweep.id == sweep_id).first()
    if not sweep:
        raise HTTPException(status_code=404, detail="Sweep not found")

    return {
        "id": sweep.id,
        "subnet": sweep.subnet,
        "status": sweep.status,
        "hosts_found": sweep.hosts_found,
        "jobs_created": sweep.jobs_created,
        "hosts": json.loads(sweep.result) if sweep.result else [],
        "started_at": sweep.started_at.isoformat() if sweep.started_at else None,
        "completed_at": sweep.completed_at.isoformat() if sweep.completed_at else None,
    }


@app.get("/discover")
def get_sweep_history(
    db: Session = Depends(get_db),
    username: str = Depends(require_auth)
):
    sweeps = db.query(DiscoverySweep).order_by(DiscoverySweep.id.desc()).limit(20).all()
    return [
        {
            "id": s.id,
            "subnet": s.subnet,
            "status": s.status,
            "hosts_found": s.hosts_found,
            "jobs_created": s.jobs_created,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        }
        for s in sweeps
    ]


@app.post("/discover/ping")
def ping_sweep(
    data: dict,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth)
):
    """
    Fast ping sweep — discovers live hosts in a subnet but does NOT create jobs.
    Returns the list of responding hosts for the user to review before committing.
    """
    subnet = data.get("subnet", "").strip()
    if not subnet:
        raise HTTPException(status_code=400, detail="subnet is required")
 
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-oX", "-", subnet],
            capture_output=True,
            text=True,
            timeout=120
        )
 
        hosts = []
        if result.returncode == 0:
            try:
                root = ET.fromstring(result.stdout)
                for host in root.findall("host"):
                    status = host.find("status")
                    if status is not None and status.get("state") == "up":
                        addr = host.find("address")
                        hostname_el = host.find(".//hostname")
                        if addr is not None:
                            hosts.append({
                                "ip": addr.get("addr"),
                                "hostname": hostname_el.get("name") if hostname_el is not None else None,
                            })
            except ET.ParseError as e:
                raise HTTPException(status_code=500, detail=f"XML parse error: {e}")
 
        logger.info(f"Ping sweep on {subnet}: {len(hosts)} host(s) found")
        return {"subnet": subnet, "hosts": hosts, "count": len(hosts)}
 
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Ping sweep timed out")
 
 
@app.delete("/discover/{sweep_id}")
def delete_sweep(
    sweep_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    """Permanently delete a discovery sweep record."""
    sweep = db.query(DiscoverySweep).filter(DiscoverySweep.id == sweep_id).first()
    if not sweep:
        raise HTTPException(status_code=404, detail="Sweep not found")
    db.delete(sweep)
    db.commit()
    return {"ok": True}
 
 
@app.delete("/discover")
def delete_all_sweeps(
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    """Permanently delete all discovery sweep records."""
    count = db.query(DiscoverySweep).count()
    db.query(DiscoverySweep).delete()
    db.commit()
    logger.info(f"Deleted all {count} discovery sweep records")
    return {"ok": True, "deleted": count}


# --- REPORT ---

@app.get("/report/{result_id}", response_class=HTMLResponse)
def generate_report(
    result_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    result = db.query(Result).filter(Result.id == result_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")

    output = json.loads(result.output)
    job = db.query(Job).filter(Job.id == result.job_id).first()

    # Build job metadata block
    if job:
        job_meta = {
            "id": job.id,
            "type": job.type,
            "target": job.target,
            "mode": job.mode,
            "profile": job.profile,
            "priority": job.priority,
            "status": job.status,
            "started_at": job.started_at.strftime("%Y-%m-%d %H:%M:%S UTC") if job.started_at else "—",
            "completed_at": job.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC") if job.completed_at else "—",
        }
    else:
        job_meta = {"id": result.job_id}

    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # ── Nmap section ──────────────────────────────────────────────────────────
    nmap_html = ""
    if output.get("nmap"):
        rows = []
        for host in output["nmap"]:
            for p in host.get("ports", []):
                state_class = "text-green-700 font-semibold" if p["state"] == "open" else "text-gray-400"
                rows.append(f"""
                <tr>
                    <td class="py-1.5 pr-6 font-mono text-sm text-blue-700">{host["host"]}</td>
                    <td class="py-1.5 pr-6 font-mono text-sm font-semibold">{p["port"]}</td>
                    <td class="py-1.5 pr-6 text-sm {state_class}">{p["state"]}</td>
                    <td class="py-1.5 text-sm text-gray-600">{p["service"]}</td>
                </tr>""")
        if rows:
            nmap_html = f"""
            <section class="mb-8">
                <h2 class="section-title">Port Scan Results</h2>
                <table class="w-full border-collapse">
                    <thead>
                        <tr class="border-b-2 border-gray-200 text-left text-xs uppercase tracking-wider text-gray-500">
                            <th class="pb-2 pr-6">Host</th>
                            <th class="pb-2 pr-6">Port</th>
                            <th class="pb-2 pr-6">State</th>
                            <th class="pb-2">Service</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-100">{"".join(rows)}</tbody>
                </table>
            </section>"""
        else:
            nmap_html = """
            <section class="mb-8">
                <h2 class="section-title">Port Scan Results</h2>
                <p class="text-sm text-gray-500">No open ports found.</p>
            </section>"""

    # ── NSE section ───────────────────────────────────────────────────────────
    nse_html = ""
    if output.get("nse"):
        nse = output["nse"]
        findings = nse.get("findings", [])
        warning = nse.get("warning", "")

        warning_block = ""
        if warning:
            warning_block = f'<div class="warning-box mb-4"><strong>Warning:</strong> {warning}</div>'

        if findings:
            cards = []
            for f in findings:
                port_label = f"{f['port']} ({f['service']})" if f.get("port") else "host-level"
                # Escape any HTML in output
                safe_output = str(f.get("output", "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                cards.append(f"""
                <div class="finding-card mb-3">
                    <div class="flex flex-wrap gap-4 mb-1">
                        <span class="font-mono font-semibold text-purple-700 text-sm">{f["script_id"]}</span>
                        <span class="text-gray-500 text-sm">port {port_label}</span>
                        <span class="text-gray-400 text-xs font-mono">{f["host"]}</span>
                    </div>
                    <pre class="text-xs text-gray-700 whitespace-pre-wrap leading-relaxed mt-1">{safe_output}</pre>
                </div>""")
            nse_html = f"""
            <section class="mb-8">
                <h2 class="section-title">NSE Findings <span class="badge">{len(findings)}</span></h2>
                {warning_block}
                {"".join(cards)}
            </section>"""
        else:
            nse_html = f"""
            <section class="mb-8">
                <h2 class="section-title">NSE Findings</h2>
                {warning_block}
                <p class="text-sm text-gray-500">No NSE findings.</p>
            </section>"""

    # ── Nikto section ─────────────────────────────────────────────────────────
    nikto_html = ""
    if output.get("nikto"):
        port_sections = []
        for port, data in output["nikto"].items():
            if data.get("error"):
                port_sections.append(
                    f'<p class="text-sm text-red-600 mb-3">Port {port}: {data["error"]}</p>'
                )
                continue

            vulns = []
            if data.get("raw"):
                for line in data["raw"].split("\n"):
                    if line.startswith("+ ["):
                        safe_line = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        vulns.append(f'<div class="finding-card mb-2 text-sm">{safe_line.lstrip("+ ")}</div>')
            elif isinstance(data, list) and data:
                for v in data[0].get("vulnerabilities", []):
                    url_part = f' — <a href="{v.get("url","")}" class="text-blue-600">{v.get("url","")}</a>' if v.get("url") else ""
                    safe_msg = str(v.get("msg", "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    vulns.append(f'<div class="finding-card mb-2 text-sm"><span class="font-mono text-yellow-700">[{v.get("id","")}]</span> {safe_msg}{url_part}</div>')

            count = len(vulns)
            block = "".join(vulns) if vulns else '<p class="text-sm text-gray-500">No findings on this port.</p>'
            port_sections.append(f"""
                <div class="mb-4">
                    <h3 class="text-sm font-semibold text-orange-700 mb-2">Port {port} — {count} finding(s)</h3>
                    {block}
                </div>""")

        nikto_html = f"""
        <section class="mb-8">
            <h2 class="section-title">Web Vulnerability Scan (Nikto)</h2>
            {"".join(port_sections)}
        </section>"""

    # ── Summary counts ────────────────────────────────────────────────────────
    open_ports = sum(
        len([p for p in h.get("ports", []) if p["state"] == "open"])
        for h in output.get("nmap", [])
    )
    nse_count = len(output.get("nse", {}).get("findings", []))
    nikto_count = 0
    for data in output.get("nikto", {}).values():
        if data.get("raw"):
            nikto_count += len([l for l in data["raw"].split("\n") if l.startswith("+ [")])
        elif isinstance(data, list) and data:
            nikto_count += len(data[0].get("vulnerabilities", []))

    summary_items = []
    if output.get("nmap"):
        summary_items.append(f'<div class="stat-box"><div class="stat-num">{open_ports}</div><div class="stat-label">Open Ports</div></div>')
    if output.get("nse"):
        summary_items.append(f'<div class="stat-box"><div class="stat-num">{nse_count}</div><div class="stat-label">NSE Findings</div></div>')
    if output.get("nikto"):
        summary_items.append(f'<div class="stat-box"><div class="stat-num">{nikto_count}</div><div class="stat-label">Web Findings</div></div>')

    summary_html = f'<div class="flex gap-4 flex-wrap mb-8">{"".join(summary_items)}</div>' if summary_items else ""

    # ── Job metadata table ────────────────────────────────────────────────────
    meta_rows = ""
    for label, key in [
        ("Job ID", "id"), ("Target", "target"), ("Type", "type"),
        ("Mode", "mode"), ("Profile", "profile"), ("Priority", "priority"),
        ("Started", "started_at"), ("Completed", "completed_at"),
    ]:
        val = job_meta.get(key, "—")
        meta_rows += f"""
        <tr class="border-b border-gray-100">
            <td class="py-1.5 pr-8 text-sm text-gray-500 w-32">{label}</td>
            <td class="py-1.5 text-sm font-medium text-gray-800">{val}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VAPT Report — Result #{result_id}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @media print {{
            body {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
            .no-print {{ display: none !important; }}
            section {{ page-break-inside: avoid; }}
            .finding-card {{ page-break-inside: avoid; }}
        }}
        .section-title {{
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #6b7280;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 0.4rem;
            margin-bottom: 1rem;
        }}
        .finding-card {{
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 0.4rem;
            padding: 0.6rem 0.8rem;
        }}
        .badge {{
            display: inline-block;
            background: #ede9fe;
            color: #6d28d9;
            font-size: 0.65rem;
            font-weight: 700;
            padding: 0.1rem 0.4rem;
            border-radius: 9999px;
            vertical-align: middle;
            margin-left: 0.4rem;
        }}
        .stat-box {{
            background: #f3f4f6;
            border: 1px solid #e5e7eb;
            border-radius: 0.5rem;
            padding: 0.75rem 1.25rem;
            text-align: center;
            min-width: 7rem;
        }}
        .stat-num {{ font-size: 1.5rem; font-weight: 700; color: #111827; }}
        .stat-label {{ font-size: 0.7rem; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.1rem; }}
        .warning-box {{
            background: #fffbeb;
            border: 1px solid #fcd34d;
            border-radius: 0.4rem;
            padding: 0.6rem 0.8rem;
            font-size: 0.8rem;
            color: #92400e;
        }}
    </style>
</head>
<body class="bg-white text-gray-900 max-w-4xl mx-auto px-8 py-10 font-sans">

    <!-- Print button -->
    <div class="no-print flex justify-end mb-6">
        <button onclick="window.print()"
            class="bg-gray-900 hover:bg-gray-700 text-white text-sm font-semibold px-5 py-2 rounded-lg transition">
            ↓ Save as PDF
        </button>
    </div>

    <!-- Header -->
    <div class="mb-8 pb-6 border-b-2 border-gray-200">
        <div class="flex items-center gap-3 mb-1">
            <div class="w-2 h-2 rounded-full bg-green-500"></div>
            <span class="text-xs font-semibold tracking-widest text-gray-400 uppercase">VAPT Scanner</span>
        </div>
        <h1 class="text-2xl font-bold text-gray-900 mb-1">Scan Report — Result #{result_id}</h1>
        <p class="text-xs text-gray-400">Generated {generated_at}</p>
    </div>

    <!-- Summary stats -->
    {summary_html}

    <!-- Job metadata -->
    <section class="mb-8">
        <h2 class="section-title">Job Details</h2>
        <table class="w-full">
            <tbody>{meta_rows}</tbody>
        </table>
    </section>

    <!-- Scan sections -->
    {nmap_html}
    {nse_html}
    {nikto_html}

    <div class="mt-10 pt-4 border-t border-gray-200 text-xs text-gray-400 text-center">
        VAPT Scanner Report &nbsp;·&nbsp; Result #{result_id} &nbsp;·&nbsp; {generated_at}
    </div>

    <script>
        // Auto-open print dialog once page has rendered
        window.addEventListener("load", () => setTimeout(() => window.print(), 400));
    </script>
</body>
</html>"""

    return HTMLResponse(content=html)


# --- INSIGHTS ---

@app.get("/insights")
def get_insights(
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
    window: str = "7d",
    host: str = None,
):
    import re
 
    window_map = {"24h": 1, "7d": 7, "30d": 30, "3m": 90}
    days   = window_map.get(window, 7)
    cutoff = datetime.utcnow() - timedelta(days=days)
 
    job_q = db.query(Job).filter(
        Job.completed_at >= cutoff,
        Job.status == "done"
    )
    if host:
        job_q = job_q.filter(Job.target == host)
 
    jobs    = job_q.all()
    job_ids = [j.id for j in jobs]
    job_map = {j.id: j for j in jobs}
 
    results = db.query(Result).filter(Result.job_id.in_(job_ids)).all() if job_ids else []
 
    # ── Aggregate stats ───────────────────────────────────────────────────────
    total_scans  = len(jobs)
    unique_hosts = len(set(j.target for j in jobs))
 
    unique_open_ports: set = set()
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNANALYSED": 0}
 
    for r in results:
        try:
            out = json.loads(r.output)
        except Exception:
            continue
        j_ref = job_map.get(r.job_id)
        target_ip = j_ref.target if j_ref else None
        for h in out.get("nmap", []):
            host_ip = h.get("host") or target_ip or ""
            for p in h.get("ports", []):
                if p.get("state") == "open":
                    unique_open_ports.add((host_ip, p["port"]))
        # Also collect ports from NSE findings
        for f in out.get("nse", {}).get("findings", []):
            if f.get("port") and f.get("host"):
                unique_open_ports.add((f["host"], f["port"]))
 
        if r.analysis:
            # Single backslash — this is real Python regex, not an embedded string
            m = re.search(r"##\s*Risk Level\s*\n+(\w+)", r.analysis, re.IGNORECASE)
            risk = m.group(1).upper() if m else "INFO"
            if risk in risk_counts:
                risk_counts[risk] += 1
            else:
                risk_counts["INFO"] += 1
        else:
            risk_counts["UNANALYSED"] += 1
 
    total_open_ports = len(unique_open_ports)
 
    # ── Scans per day ─────────────────────────────────────────────────────────
    scans_by_day = {}
    for j in jobs:
        if j.completed_at:
            day = j.completed_at.strftime("%Y-%m-%d")
            scans_by_day[day] = scans_by_day.get(day, 0) + 1
 
    days_list = []
    for i in range(days - 1, -1, -1):
        d = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        days_list.append(d)
    scan_activity = [{"date": d, "count": scans_by_day.get(d, 0)} for d in days_list]
 
    # ── Per-host summary ──────────────────────────────────────────────────────
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNANALYSED"]
    host_data: dict = {}
 
    for j in jobs:
        ip = j.target
        if ip not in host_data:
            host_data[ip] = {
                "ip":               ip,
                "scan_count":       0,
                "open_ports_set":   set(),
                "findings":         0,
                "last_scan":        None,
                "risk":             "UNANALYSED",
                "result_id":        None,
                "latest_result_ts": None,
            }
        host_data[ip]["scan_count"] += 1
        if j.completed_at:
            cur = host_data[ip]["last_scan"]
            if cur is None or j.completed_at > cur:
                host_data[ip]["last_scan"] = j.completed_at
 
    for r in results:
        j = job_map.get(r.job_id)
        if not j:
            continue
        ip = j.target
        if ip not in host_data:
            continue
        try:
            out = json.loads(r.output)
        except Exception:
            continue
 
        # Deduplicated open ports — nmap + NSE findings
        for h in out.get("nmap", []):
            host_ip = h.get("host") or ip
            for p in h.get("ports", []):
                if p.get("state") == "open":
                    host_data[ip]["open_ports_set"].add((host_ip, p["port"]))
        for f in out.get("nse", {}).get("findings", []):
            if f.get("port") and f.get("host"):
                host_data[ip]["open_ports_set"].add((f["host"], f["port"]))
 
        # Findings from the latest result only
        result_ts = j.completed_at or datetime.min
        if host_data[ip]["latest_result_ts"] is None or result_ts > host_data[ip]["latest_result_ts"]:
            host_data[ip]["latest_result_ts"] = result_ts
            host_data[ip]["result_id"]        = r.id
 
            nse_count = len(out.get("nse", {}).get("findings", [])) if out.get("nse") else 0
            nikto_count = 0
            for v in out.get("nikto", {}).values():
                if v.get("error"):
                    continue
                if v.get("raw"):
                    nikto_count += len([l for l in v["raw"].split("\n") if l.startswith("+ [")])
                elif isinstance(v, list) and v:
                    nikto_count += len(v[0].get("vulnerabilities", []))
            host_data[ip]["findings"] = nse_count + nikto_count
 
        # Risk: worst seen
        if r.analysis:
            m = re.search(r"##\s*Risk Level\s*\n+(\w+)", r.analysis, re.IGNORECASE)
            risk    = m.group(1).upper() if m else "INFO"
            current = host_data[ip]["risk"]
            try:
                if severity_order.index(risk) < severity_order.index(current):
                    host_data[ip]["risk"] = risk
            except ValueError:
                pass
 
    hosts_list = []
    for ip, d in host_data.items():
        hosts_list.append({
            "ip":         d["ip"],
            "scan_count": d["scan_count"],
            "open_ports": len(d["open_ports_set"]),
            "findings":   d["findings"],
            "last_scan":  d["last_scan"].isoformat() if d["last_scan"] else None,
            "risk":       d["risk"],
            "result_id":  d["result_id"],
        })
    hosts_list.sort(key=lambda x: x["findings"], reverse=True)
 
    # ── Per-host drilldown ────────────────────────────────────────────────────
    scan_history = []
    if host:
        for j in sorted(jobs, key=lambda x: x.completed_at or datetime.min):
            result_for_job = next((r for r in results if r.job_id == j.id), None)
            entry = {
                "date":       j.completed_at.strftime("%Y-%m-%d") if j.completed_at else None,
                "type":       j.type,
                "profile":    j.profile,
                "open_ports": 0,
                "findings":   0,
                "risk":       "UNANALYSED",
                "result_id":  result_for_job.id if result_for_job else None,
            }
            if result_for_job:
                try:
                    out = json.loads(result_for_job.output)
 
                    # Count unique open ports: nmap + NSE findings
                    ports_in_scan: set = set()
                    for h in out.get("nmap", []):
                        for p in h.get("ports", []):
                            if p.get("state") == "open":
                                ports_in_scan.add(p["port"])
                    for f in out.get("nse", {}).get("findings", []):
                        if f.get("port"):
                            ports_in_scan.add(f["port"])
                    entry["open_ports"] = len(ports_in_scan)
 
                    nse_f   = len(out.get("nse", {}).get("findings", [])) if out.get("nse") else 0
                    nikto_f = 0
                    for v in out.get("nikto", {}).values():
                        if v.get("error"):
                            continue
                        if v.get("raw"):
                            nikto_f += len([l for l in v["raw"].split("\n") if l.startswith("+ [")])
                        elif isinstance(v, list) and v:
                            nikto_f += len(v[0].get("vulnerabilities", []))
                    entry["findings"] = nse_f + nikto_f
                except Exception:
                    pass
 
                if result_for_job.analysis:
                    m = re.search(r"##\s*Risk Level\s*\n+(\w+)", result_for_job.analysis, re.IGNORECASE)
                    entry["risk"] = m.group(1).upper() if m else "INFO"
            scan_history.append(entry)
 
    return {
        "window": window,
        "host":   host,
        "stats": {
            "total_scans":      total_scans,
            "unique_hosts":     unique_hosts,
            "total_open_ports": total_open_ports,
            "risk_counts":      risk_counts,
        },
        "scan_activity": scan_activity,
        "hosts":         hosts_list,
        "scan_history":  scan_history,
    }


# ── TOPOLOGY ──────────────────────────────────────────────────────────────────

@app.get("/topology")
def get_topology(
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    """
    Returns a network topology graph for the frontend map.

    Nodes: every host in the hosts table, enriched with:
      - latest scan result (open ports, services)
      - AI risk level (from latest result with analysis)
      - linked agent name
      - subnet group (first 3 octets of IP)

    Edges: hosts in the same /24 subnet are connected to a
    virtual subnet-gateway node, giving the cluster layout
    something to anchor against.
    """
    import re as _re

    hosts = db.query(Host).order_by(Host.last_seen.desc()).all()

    nodes = []
    edges = []
    subnet_set = set()

    for host in hosts:
        # Agent name
        agent_name = None
        if host.agent_id:
            agent = db.query(Agent).filter(Agent.id == host.agent_id).first()
            if agent:
                agent_name = agent.name

        # Latest scan result for this host
        latest_result = (
            db.query(Result)
            .join(Job, Job.id == Result.job_id)
            .filter(Job.target == host.ip, Result.cleared == False)
            .order_by(Result.id.desc())
            .first()
        )

        open_ports = []
        risk = "UNSCANNED"
        last_scan_at = None

        if latest_result:
            try:
                out = json.loads(latest_result.output)
                for h in out.get("nmap", []):
                    for p in h.get("ports", []):
                        if p.get("state") == "open":
                            open_ports.append({
                                "port": p["port"],
                                "service": p.get("service", "unknown"),
                            })

                # NSE findings count
                nse_count = len(out.get("nse", {}).get("findings", [])) if out.get("nse") else 0

                # Nikto findings count
                nikto_count = 0
                for v in out.get("nikto", {}).values():
                    if v.get("raw"):
                        nikto_count += len([l for l in v["raw"].split("\n") if l.startswith("+ [")])
                    elif isinstance(v, list) and v:
                        nikto_count += len(v[0].get("vulnerabilities", []))

            except Exception:
                nse_count = 0
                nikto_count = 0

            # Risk from AI analysis
            if latest_result.analysis:
                m = _re.search(r"##\s*Risk Level\s*\n+(\w+)", latest_result.analysis, _re.IGNORECASE)
                risk = m.group(1).upper() if m else "INFO"
            else:
                risk = "UNANALYSED"

            job = db.query(Job).filter(Job.id == latest_result.job_id).first()
            if job and job.completed_at:
                last_scan_at = job.completed_at.isoformat()
        else:
            nse_count = 0
            nikto_count = 0

        # Subnet group — first 3 octets
        parts = host.ip.split(".")
        subnet = ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else "unknown"
        subnet_set.add(subnet)

        nodes.append({
            "id": f"host-{host.id}",
            "type": "host",
            "ip": host.ip,
            "hostname": host.hostname,
            "mac": host.mac,
            "os": host.os_fingerprint,
            "agent_name": agent_name,
            "is_agent": agent_name is not None,
            "subnet": subnet,
            "risk": risk,
            "open_ports": open_ports,
            "port_count": len(open_ports),
            "nse_findings": nse_count,
            "nikto_findings": nikto_count,
            "last_seen": host.last_seen.isoformat() if host.last_seen else None,
            "last_scan_at": last_scan_at,
            "result_id": latest_result.id if latest_result else None,
        })

        # Edge: host → subnet gateway node
        edges.append({
            "source": f"host-{host.id}",
            "target": f"subnet-{subnet}",
        })

    # Subnet gateway nodes (virtual — anchor for clustering)
    for subnet in subnet_set:
        nodes.append({
            "id": f"subnet-{subnet}",
            "type": "subnet",
            "label": subnet,
            "subnet": subnet,
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "subnets": sorted(subnet_set),
        "stats": {
            "total_hosts": len([n for n in nodes if n["type"] == "host"]),
            "total_subnets": len(subnet_set),
            "risk_counts": _count_risks(nodes),
        }
    }


def _count_risks(nodes):
    counts = {}
    for n in nodes:
        if n.get("type") == "host":
            risk = n.get("risk", "UNSCANNED")
            counts[risk] = counts.get(risk, 0) + 1
    return counts


# --- SETTINGS ---
 
@app.get("/settings")
def get_settings(
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    """Return all server-side settings as a flat dict."""
    rows = db.query(Setting).all()
    result = {r.key: r.value for r in rows}
    # Fill in any missing keys with defaults
    for key, default in SETTING_DEFAULTS.items():
        if key not in result:
            result[key] = default
    return result
 
 
@app.patch("/settings")
def update_settings(
    data: dict,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    """Update one or more settings. Unknown keys are ignored."""
    allowed_keys = set(SETTING_DEFAULTS.keys())
    updated = []
    for key, value in data.items():
        if key not in allowed_keys:
            continue
        row = db.query(Setting).filter(Setting.key == key).first()
        if row:
            row.value = str(value)
        else:
            db.add(Setting(key=key, value=str(value)))
        updated.append(key)
 
    db.commit()
    logger.info(f"Settings updated: {updated}")
    return {"ok": True, "updated": updated}


# --- DASHBOARD ---

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    ai_provider_name = AI_PROVIDER or "none"
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Heimdall V-Scanner</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"></script>
        <style>
            .nav-tab { transition: all 0.15s ease; }
            .nav-tab.active {
                background: rgba(74, 222, 128, 0.1);
                color: #4ade80;
                border-color: #4ade80;
            }
            .tab-panel { display: none; }
            .tab-panel.active { display: block; }
            
            /* ── Light theme ── */
            body.theme-light {
                --tw-bg-opacity: 1;
                background-color: #f1f5f9 !important;
                color: #0f172a !important;
            }
            body.theme-light .bg-gray-950  { background-color: #f1f5f9 !important; }
            body.theme-light .bg-gray-900  { background-color: #ffffff !important; }
            body.theme-light .bg-gray-800  { background-color: #f8fafc !important; }
            body.theme-light .bg-gray-750  { background-color: #f1f5f9 !important; }
            body.theme-light .bg-gray-700  { background-color: #e2e8f0 !important; }
            body.theme-light .border-gray-800 { border-color: #e2e8f0 !important; }
            body.theme-light .border-gray-700 { border-color: #cbd5e1 !important; }
            body.theme-light .text-gray-100 { color: #0f172a !important; }
            body.theme-light .text-gray-200 { color: #1e293b !important; }
            body.theme-light .text-gray-300 { color: #334155 !important; }
            body.theme-light .text-gray-400 { color: #475569 !important; }
            body.theme-light .text-gray-500 { color: #64748b !important; }
            body.theme-light .text-gray-600 { color: #94a3b8 !important; }
            body.theme-light .text-gray-700 { color: #cbd5e1 !important; }
            body.theme-light .text-white    { color: #0f172a !important; }
            body.theme-light .bg-gray-950.bg-opacity-95 { background-color: rgba(241,245,249,0.97) !important; }
            /* Keep accent colours as-is in light mode — green, blue, red etc stay vivid */
            
        </style>
    </head>
    <body class="bg-gray-950 text-gray-100 min-h-screen">

        <!-- ── DIALOGS ──────────────────────────────────────────────────── -->

        <!-- Confirm Dialog -->
        <div id="confirmDialog" class="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50 hidden">
            <div class="bg-gray-900 border border-gray-700 rounded-xl p-6 w-full max-w-sm">
                <h3 class="text-sm font-semibold text-white mb-2">Confirm Action</h3>
                <p id="confirmMsg" class="text-xs text-gray-400 mb-5">This action cannot be undone.</p>
                <div class="flex gap-3 justify-end">
                    <button onclick="cancelConfirm()" class="text-xs px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 transition">Cancel</button>
                    <button id="confirmOkBtn" class="text-xs px-4 py-2 rounded-lg bg-red-700 hover:bg-red-600 text-white font-semibold transition">Confirm</button>
                </div>
            </div>
        </div>

        <!-- Sweep Confirm Dialog (ping results → assign jobs?) -->
        <div id="sweepConfirmDialog" class="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50 hidden">
            <div class="bg-gray-900 border border-gray-700 rounded-xl p-6 w-full max-w-md">
                <div class="flex items-center gap-3 mb-3">
                    <span class="text-cyan-400 text-lg">⌖</span>
                    <h3 class="text-sm font-semibold text-white">Assign Scan Jobs?</h3>
                </div>
                <p id="sweepConfirmMsg" class="text-xs text-gray-400 mb-2"></p>
                <div id="sweepHostList" class="max-h-40 overflow-y-auto mb-4 space-y-1"></div>
                <p class="text-xs text-gray-500 mb-5">Confirming will create an Nmap scan job for each host above.</p>
                <div class="flex gap-3 justify-end">
                    <button onclick="cancelSweepConfirm()" class="text-xs px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 transition">Cancel</button>
                    <button onclick="confirmSweep()" class="text-xs px-4 py-2 rounded-lg bg-cyan-700 hover:bg-cyan-600 text-white font-semibold transition">Assign Jobs</button>
                </div>
            </div>
        </div>

        <!-- Exploit Warning Dialog -->
        <div id="exploitWarningDialog" class="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50 hidden">
            <div class="bg-gray-900 border border-red-800 rounded-xl p-6 w-full max-w-md">
                <div class="flex items-center gap-3 mb-3">
                    <span class="text-red-400 text-xl">⚠</span>
                    <h3 class="text-sm font-semibold text-red-400">Intrusive Scan Warning</h3>
                </div>
                <p class="text-xs text-gray-300 mb-2">You are about to run an NSE scan with the <span class="text-red-300 font-mono font-semibold">full</span> profile.</p>
                <p class="text-xs text-gray-400 mb-4">This uses <span class="font-mono text-orange-300">--script vuln,exploit</span> — intrusive scripts that can disrupt or crash services. Only proceed with explicit authorisation.</p>
                <div class="flex gap-3 justify-end">
                    <button onclick="cancelExploitWarning()" class="text-xs px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 transition">Cancel</button>
                    <button onclick="confirmExploitWarning()" class="text-xs px-4 py-2 rounded-lg bg-red-700 hover:bg-red-600 text-white font-semibold transition">I understand — proceed</button>
                </div>
            </div>
        </div>

        <!-- Login Overlay -->
        <div id="loginOverlay" class="fixed inset-0 bg-gray-950 bg-opacity-95 flex items-center justify-center z-50">
            <div class="bg-gray-900 border border-gray-700 rounded-xl p-8 w-full max-w-sm">
                <div class="flex items-center gap-3 mb-6">
                    <div class="w-3 h-3 rounded-full bg-green-400"></div>
                    <h2 class="text-lg font-bold text-green-400">Heimdall V-Scanner</h2>
                </div>
                <p class="text-sm text-gray-400 mb-6">Sign in to continue</p>
                <div class="space-y-4">
                    <div>
                        <label class="text-xs text-gray-400 mb-1 block">Username</label>
                        <input id="loginUsername" type="text" placeholder="Username"
                            class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                    </div>
                    <div>
                        <label class="text-xs text-gray-400 mb-1 block">Password</label>
                        <input id="loginPassword" type="password" placeholder="••••••••"
                            class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                    </div>
                    <p id="loginError" class="text-xs text-red-400 hidden">Invalid credentials. Please try again.</p>
                    <button onclick="submitLogin()" class="w-full bg-green-600 hover:bg-green-500 text-white font-semibold py-2 rounded-lg transition text-sm">Sign In</button>
                </div>
            </div>
        </div>
        
        
        <!-- ── SETTINGS PANEL ─────────────────────────────────────────── -->
        
        <!-- Backdrop -->
        <div id="settingsBackdrop"
             class="fixed inset-0 bg-black bg-opacity-50 z-40 hidden transition-opacity"
             onclick="closeSettings()"></div>
 
        <!-- Slide-in panel -->
        <div id="settingsPanel"
             class="fixed top-0 right-0 h-full w-80 bg-gray-900 border-l border-gray-800 z-50 transform translate-x-full transition-transform duration-300 overflow-y-auto flex flex-col">
 
            <!-- Panel header -->
            <div class="flex items-center justify-between px-6 py-4 border-b border-gray-800 flex-shrink-0">
                <div class="flex items-center gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="3"></circle>
                        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
                    </svg>
                    <h2 class="text-sm font-semibold text-green-400 tracking-wide">Settings</h2>
                </div>
                <button onclick="closeSettings()" class="text-gray-500 hover:text-gray-300 transition text-lg leading-none">✕</button>
            </div>
 
            <!-- Panel body -->
            <div class="flex-1 px-6 py-5 space-y-7 overflow-y-auto">
 
                <!-- ── Appearance ── -->
                <section>
                    <p class="text-xs font-bold uppercase tracking-wider text-gray-500 mb-3">Appearance</p>
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-sm text-gray-200">Theme</p>
                            <p class="text-xs text-gray-500 mt-0.5">Light or dark dashboard</p>
                        </div>
                        <div class="flex items-center gap-1 bg-gray-800 rounded-lg p-1 border border-gray-700">
                            <button onclick="setTheme('dark')" id="theme-dark"
                                class="theme-btn text-xs px-3 py-1.5 rounded-md transition font-medium bg-gray-700 text-white">
                                Dark
                            </button>
                            <button onclick="setTheme('light')" id="theme-light"
                                class="theme-btn text-xs px-3 py-1.5 rounded-md transition font-medium text-gray-400 hover:text-white">
                                Light
                            </button>
                        </div>
                    </div>
                </section>
 
                <hr class="border-gray-800">
 
                <!-- ── Scan defaults ── -->
                <section>
                    <p class="text-xs font-bold uppercase tracking-wider text-gray-500 mb-3">Scan Defaults</p>
                    <p class="text-xs text-gray-600 mb-3">Pre-fills the Create Job form. You can still change them per job.</p>
 
                    <div class="space-y-3">
                        <div class="flex items-center justify-between gap-3">
                            <label class="text-sm text-gray-300 flex-shrink-0">Profile</label>
                            <select id="setting-default-profile" onchange="saveClientSetting('defaultProfile', this.value)"
                                class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:border-green-500 w-36">
                                <option value="standard">Standard</option>
                                <option value="light">Light</option>
                                <option value="full">Full</option>
                            </select>
                        </div>
                        <div class="flex items-center justify-between gap-3">
                            <label class="text-sm text-gray-300 flex-shrink-0">Mode</label>
                            <select id="setting-default-mode" onchange="saveClientSetting('defaultMode', this.value)"
                                class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:border-green-500 w-36">
                                <option value="remote">Remote</option>
                                <option value="agent">Agent</option>
                            </select>
                        </div>
                        <div class="flex items-center justify-between gap-3">
                            <label class="text-sm text-gray-300 flex-shrink-0">Priority</label>
                            <select id="setting-default-priority" onchange="saveClientSetting('defaultPriority', this.value)"
                                class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:border-green-500 w-36">
                                <option value="medium">Medium</option>
                                <option value="high">High</option>
                                <option value="low">Low</option>
                            </select>
                        </div>
                    </div>
                </section>
 
                <hr class="border-gray-800">
 
                <!-- ── Dashboard behaviour ── -->
                <section>
                    <p class="text-xs font-bold uppercase tracking-wider text-gray-500 mb-3">Dashboard</p>
 
                    <div class="space-y-3">
                        <div class="flex items-center justify-between gap-3">
                            <div>
                                <p class="text-sm text-gray-300">Auto-refresh interval</p>
                                <p class="text-xs text-gray-600 mt-0.5">Jobs &amp; agents poll rate</p>
                            </div>
                            <select id="setting-refresh-interval" onchange="saveClientSetting('refreshInterval', this.value); applyRefreshInterval()"
                                class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:border-green-500 w-24">
                                <option value="3000">3s</option>
                                <option value="5000">5s</option>
                                <option value="10000">10s</option>
                                <option value="30000">30s</option>
                                <option value="0">Off</option>
                            </select>
                        </div>
                    </div>
                </section>
 
                <hr class="border-gray-800">
 
                <!-- ── Server settings ── -->
                <section>
                    <p class="text-xs font-bold uppercase tracking-wider text-gray-500 mb-3">Server</p>
                    <p class="text-xs text-gray-600 mb-3">These are saved to the database and take effect immediately.</p>
 
                    <div class="space-y-4">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-gray-300">AI auto-analysis</p>
                                <p class="text-xs text-gray-600 mt-0.5">Analyse results automatically after each scan</p>
                            </div>
                            <button id="setting-ai-toggle" onclick="toggleServerSetting('ai_auto_analyse')"
                                class="relative w-11 h-6 rounded-full transition-colors duration-200 focus:outline-none bg-gray-700 border border-gray-600">
                                <span id="setting-ai-knob"
                                    class="absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-gray-400 transition-transform duration-200"></span>
                            </button>
                        </div>
 
                        <div class="flex items-center justify-between gap-3">
                            <div>
                                <p class="text-sm text-gray-300">Stale agent threshold</p>
                                <p class="text-xs text-gray-600 mt-0.5">Hours before an agent is marked stale</p>
                            </div>
                            <div class="flex items-center gap-2">
                                <input id="setting-stale-hours" type="number" min="1" max="720"
                                    class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:border-green-500 w-20 text-right"
                                    onchange="saveServerSetting('stale_agent_hours', this.value)">
                                <span class="text-xs text-gray-500">hrs</span>
                            </div>
                        </div>
                    </div>
                </section>
 
            </div>
 
            <!-- Panel footer -->
            <div class="px-6 py-4 border-t border-gray-800 flex-shrink-0">
                <p class="text-xs text-gray-700 text-center">Heimdall V-Scanner</p>
            </div>
        </div>
        

        <!-- ── HEADER ───────────────────────────────────────────────────── -->
        <div class="bg-gray-900 border-b border-gray-800 px-6 py-3 flex items-center justify-between">
            <div class="flex items-center gap-3">
                <div class="w-3 h-3 rounded-full bg-green-400 animate-pulse"></div>
                <h1 class="text-lg font-bold text-green-400 tracking-wider">Heimdall V-Scanner</h1>
            </div>

            <!-- Tab navigation -->
            <nav class="flex items-center gap-1">
                <button onclick="switchTab('dashboard')" id="nav-dashboard"
                    class="nav-tab active text-xs px-4 py-1.5 rounded-lg border border-transparent text-gray-400 hover:text-gray-200 font-medium">
                    Dashboard
                </button>
                <button onclick="switchTab('discovery')" id="nav-discovery"
                    class="nav-tab text-xs px-4 py-1.5 rounded-lg border border-transparent text-gray-400 hover:text-gray-200 font-medium">
                    Discovery
                </button>
                <button onclick="switchTab('schedules')" id="nav-schedules"
                    class="nav-tab text-xs px-4 py-1.5 rounded-lg border border-transparent text-gray-400 hover:text-gray-200 font-medium">
                    Schedules
                </button>
                <button onclick="switchTab('insights')" id="nav-insights"
                    class="nav-tab text-xs px-4 py-1.5 rounded-lg border border-transparent text-gray-400 hover:text-gray-200 font-medium">
                    Insights
                </button>
                <button onclick="switchTab('topology')" id="nav-topology"
                    class="nav-tab text-xs px-4 py-1.5 rounded-lg border border-transparent text-gray-400 hover:text-gray-200 font-medium">
                    Topology
                </button>
            </nav>
            <div class="flex items-center gap-2">
                <button onclick="loadAll()" class="text-sm bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded-lg transition">↻ Refresh</button>
                <button onclick="openSettings()" class="text-sm bg-gray-800 hover:bg-gray-700 w-9 h-9 rounded-lg transition flex items-center justify-center" title="Settings">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="3"></circle>
                        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
                    </svg>
                </button>
            </div>
        </div>

        <!-- ── TAB: DASHBOARD ───────────────────────────────────────────── -->
        <div id="tab-dashboard" class="tab-panel active">
        <div class="max-w-screen-xl mx-auto px-6 py-8 space-y-10">

            <!-- Create Job -->
            <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <h2 class="text-lg font-semibold text-green-400 mb-4">Create Job</h2>
                <div class="flex flex-wrap gap-3 items-end">
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Target IP</label>
                        <input id="target" placeholder="127.0.0.1"
                            class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500 w-44">
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Agent ID (optional)</label>
                        <input id="agent_id" placeholder="Leave blank for any"
                            class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500 w-44">
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Scan Type</label>
                        <select id="job_type" onchange="onJobTypeChange()"
                            class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                            <option value="nmap_scan">Port Scan</option>
                            <option value="nikto_scan">Web Scan</option>
                            <option value="nse_scan">Vuln Scan</option>
                        </select>
                    </div>
                    <div class="flex flex-col gap-1" id="portField" style="display:none">
                        <label class="text-xs text-gray-400">Port</label>
                        <input id="port" placeholder="80"
                            class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500 w-24">
                    </div>
                    <div class="flex flex-col gap-1" id="portsField" style="display:none">
                        <label class="text-xs text-gray-400">Ports (optional, comma-separated)</label>
                        <input id="ports" placeholder="22,445,3389"
                            class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500 w-52">
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Mode</label>
                        <select id="mode" class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                            <option value="remote">Remote</option>
                            <option value="agent">Agent</option>
                        </select>
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Profile</label>
                        <select id="profile" class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                            <option value="standard">Standard</option>
                            <option value="light">Light</option>
                            <option value="full">Full</option>
                        </select>
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Priority</label>
                        <select id="priority" class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                            <option value="medium">Medium</option>
                            <option value="high">High</option>
                            <option value="low">Low</option>
                        </select>
                    </div>
                    <button onclick="createJob()" class="bg-green-600 hover:bg-green-500 text-white font-semibold px-5 py-2 rounded-lg transition text-sm">+ Create</button>
                </div>
                <div id="nseExploitBanner" class="hidden mt-4 flex items-start justify-between gap-3 bg-red-950 border border-red-800 rounded-lg px-4 py-3">
                    <div class="flex items-start gap-3">
                        <span class="text-red-400 text-sm mt-0.5">⚠</span>
                        <p class="text-xs text-red-300"><strong class="text-red-200">Full profile with Vulnerability Scan</strong> uses <span class="font-mono">--script vuln,exploit</span> — intrusive scripts that may disrupt services.</p>
                    </div>
                    <button onclick="dismissExploitBanner()" class="text-red-500 hover:text-red-300 transition text-sm leading-none flex-shrink-0">✕</button>
                </div>
            </div>

            <!-- Agents -->
            <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-lg font-semibold text-green-400">Agents</h2>
                    <button onclick="toggleStaleAgents()" id="staleAgentsBtn"
                        class="text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-yellow-500 transition">Show Stale</button>
                </div>
                <div id="agents" class="overflow-x-auto"></div>
            </div>

            <!-- Jobs -->
            <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <div class="flex items-center justify-between mb-3">
                    <h2 class="text-lg font-semibold text-green-400">Jobs</h2>
                    <div class="flex gap-2 flex-wrap justify-end">
                        <button onclick="setJobFilter('all')" id="filter-all" class="filter-btn active-filter text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-green-500 transition">All</button>
                        <button onclick="setJobFilter('pending')" id="filter-pending" class="filter-btn text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-yellow-500 transition">Pending</button>
                        <button onclick="setJobFilter('running')" id="filter-running" class="filter-btn text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-blue-500 transition">Running</button>
                        <button onclick="setJobFilter('done')" id="filter-done" class="filter-btn text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-green-500 transition">Done</button>
                        <button onclick="setJobFilter('failed')" id="filter-failed" class="filter-btn text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-red-500 transition">Failed</button>
                        <button onclick="toggleJobHistory()" id="jobHistoryBtn" class="text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-purple-500 transition">Show History</button>
                    </div>
                </div>
                <div class="flex gap-2 mb-3">
                    <button onclick="clearAllByStatus('pending')" class="text-xs px-3 py-1 rounded-lg bg-yellow-950 hover:bg-yellow-900 text-yellow-300 border border-yellow-800 transition">Delete all pending</button>
                    <button onclick="clearAllByStatus('failed')" class="text-xs px-3 py-1 rounded-lg bg-red-950 hover:bg-red-900 text-red-300 border border-red-800 transition">Delete all failed</button>
                </div>
                <div id="jobs" class="overflow-x-auto"></div>
            </div>

            <!-- Results -->
            <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-lg font-semibold text-green-400">Scan Results</h2>
                    <div class="flex gap-1 bg-gray-800 rounded-lg p-1">
                        <button onclick="setResultTab('active')" id="tab-active" class="result-tab text-xs px-4 py-1.5 rounded-md transition font-medium bg-gray-700 text-white">Active</button>
                        <button onclick="setResultTab('history')" id="tab-history" class="result-tab text-xs px-4 py-1.5 rounded-md transition font-medium text-gray-400 hover:text-gray-200">History</button>
                    </div>
                </div>
                <div id="activeToolbar" class="mb-4 flex items-center gap-3">
                    <label class="flex items-center gap-2 text-xs text-gray-400 cursor-pointer select-none">
                        <input type="checkbox" id="selectAllActiveCheckbox" onchange="toggleSelectAllActive()" class="accent-yellow-500"> Select all
                    </label>
                    <button onclick="clearSelected()" class="text-xs px-3 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-600 transition font-medium">Clear Selected</button>
                    <button onclick="exportResults()" class="text-xs px-3 py-1.5 rounded-lg bg-cyan-900 hover:bg-cyan-800 text-cyan-200 border border-cyan-700 transition font-medium">↓ Export JSON</button>
                </div>
                <div id="historyToolbar" class="hidden mb-4 flex items-center gap-3">
                    <label class="flex items-center gap-2 text-xs text-gray-400 cursor-pointer select-none">
                        <input type="checkbox" id="selectAllCheckbox" onchange="toggleSelectAll()" class="accent-red-500"> Select all
                    </label>
                    <button onclick="deleteSelected()" class="text-xs px-3 py-1.5 rounded-lg bg-red-900 hover:bg-red-800 text-red-200 border border-red-700 transition font-medium">Delete Selected</button>
                    <button onclick="clearAllHistory()" class="text-xs px-3 py-1.5 rounded-lg bg-red-950 hover:bg-red-900 text-red-300 border border-red-800 transition font-medium">⚠ Clear All History</button>
                    <button onclick="exportResults()" class="text-xs px-3 py-1.5 rounded-lg bg-cyan-900 hover:bg-cyan-800 text-cyan-200 border border-cyan-700 transition font-medium">↓ Export JSON</button>
                </div>
                <div id="results" class="space-y-4"></div>
            </div>

        </div>
        </div>

        <!-- ── TAB: DISCOVERY ───────────────────────────────────────────── -->
        <div id="tab-discovery" class="tab-panel">
        <div class="max-w-screen-xl mx-auto px-6 py-8 space-y-8">

            <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <h2 class="text-lg font-semibold text-green-400 mb-1">Network Discovery</h2>
                <p class="text-xs text-gray-500 mb-5">Ping scans find live hosts. Sweep scans find hosts and automatically assign Nmap jobs.</p>

                <div class="flex flex-wrap gap-3 items-end mb-5">
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Subnet (CIDR)</label>
                        <input id="discoverSubnet" placeholder="192.168.1.0/24"
                            class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500 w-52">
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Mode</label>
                        <select id="discoverMode" class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                            <option value="remote">Remote</option>
                            <option value="agent">Agent</option>
                        </select>
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Profile</label>
                        <select id="discoverProfile" class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                            <option value="standard">Standard</option>
                            <option value="light">Light</option>
                            <option value="full">Full</option>
                        </select>
                    </div>
                    <div class="flex gap-2">
                        <button onclick="startPing()" id="pingBtn"
                            class="bg-gray-700 hover:bg-gray-600 text-white font-semibold px-5 py-2 rounded-lg transition text-sm">
                            ⬡ Ping
                        </button>
                        <button onclick="startSweep()" id="sweepBtn"
                            class="bg-cyan-700 hover:bg-cyan-600 text-white font-semibold px-5 py-2 rounded-lg transition text-sm">
                            ⌖ Sweep
                        </button>
                    </div>
                </div>

                <!-- Status bar — dismissible -->
                <div id="sweepStatus" class="hidden mb-4 p-3 bg-gray-800 rounded-lg border border-gray-700 text-xs text-gray-300 flex items-center gap-3">
                    <div id="sweepSpinner" class="w-3 h-3 rounded-full bg-cyan-400 animate-pulse flex-shrink-0"></div>
                    <span id="sweepStatusText" class="flex-1">Working...</span>
                    <button onclick="dismissSweepStatus()" class="text-gray-500 hover:text-gray-300 transition text-base leading-none">✕</button>
                </div>

                <!-- Ping results panel -->
                <div id="pingResults" class="hidden mb-4 p-4 bg-gray-800 rounded-lg border border-gray-700">
                    <div class="flex items-center justify-between mb-3">
                        <p class="text-xs font-semibold text-gray-300" id="pingResultsTitle">Ping Results</p>
                        <button onclick="dismissPingResults()" class="text-gray-500 hover:text-gray-300 transition text-sm">✕</button>
                    </div>
                    <div id="pingResultsList" class="space-y-1 max-h-48 overflow-y-auto"></div>
                </div>

            </div>

            <!-- Sweep History -->
            <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-lg font-semibold text-green-400">Sweep History</h2>
                    <button onclick="clearAllSweeps()" class="text-xs px-3 py-1.5 rounded-lg bg-red-950 hover:bg-red-900 text-red-300 border border-red-800 transition">Clear All</button>
                </div>
                <div id="sweepHistory"></div>
            </div>

        </div>
        </div>

        <!-- ── TAB: SCHEDULES ───────────────────────────────────────────── -->
        <div id="tab-schedules" class="tab-panel">
        <div class="max-w-screen-xl mx-auto px-6 py-8 space-y-8">

            <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <h2 class="text-lg font-semibold text-green-400 mb-4">Create Schedule</h2>
                <div class="flex flex-wrap gap-3 items-end mb-5">
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Name</label>
                        <input id="sched_name" placeholder="Daily firewall scan"
                            class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500 w-48">
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Target IP</label>
                        <input id="sched_target" placeholder="192.168.1.1"
                            class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500 w-36">
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Scan Type</label>
                        <select id="sched_type" class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                            <option value="nmap_scan">Port Scan</option>
                            <option value="nikto_scan">Web Scan</option>
                            <option value="nse_scan">Vuln Scan</option>
                        </select>
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Profile</label>
                        <select id="sched_profile" class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                            <option value="standard">Standard</option>
                            <option value="light">Light</option>
                            <option value="full">Full</option>
                        </select>
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Mode</label>
                        <select id="sched_mode" class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                            <option value="remote">Remote</option>
                            <option value="agent">Agent</option>
                        </select>
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Priority</label>
                        <select id="sched_priority" class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                            <option value="medium">Medium</option>
                            <option value="high">High</option>
                            <option value="low">Low</option>
                        </select>
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Every (hours)</label>
                        <input id="sched_interval" type="number" min="1" placeholder="24"
                            class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500 w-24">
                    </div>
                    <button onclick="createSchedule()" class="bg-green-600 hover:bg-green-500 text-white font-semibold px-5 py-2 rounded-lg transition text-sm">+ Schedule</button>
                </div>
            </div>

            <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <h2 class="text-lg font-semibold text-green-400 mb-4">Active Schedules</h2>
                <div id="schedules" class="overflow-x-auto"></div>
            </div>

        </div>
        </div>

        <!-- ── TAB: INSIGHTS ───────────────────────────────────────────── -->
        <div id="tab-insights" class="tab-panel">
        <div class="max-w-screen-xl mx-auto px-6 py-8 space-y-6">

            <!-- Controls row -->
            <div class="flex items-center justify-between flex-wrap gap-4">
                <div class="flex items-center gap-2">
                    <span class="text-xs text-gray-500 mr-1">Window:</span>
                    <button onclick="setInsightWindow('24h')" id="iw-24h"
                        class="insight-win text-xs px-3 py-1.5 rounded-lg border border-gray-700 text-gray-400 hover:text-gray-200 transition">24h</button>
                    <button onclick="setInsightWindow('7d')" id="iw-7d"
                        class="insight-win text-xs px-3 py-1.5 rounded-lg border border-gray-700 text-gray-400 hover:text-gray-200 transition">7d</button>
                    <button onclick="setInsightWindow('30d')" id="iw-30d"
                        class="insight-win text-xs px-3 py-1.5 rounded-lg border border-gray-700 text-gray-400 hover:text-gray-200 transition">30d</button>
                    <button onclick="setInsightWindow('3m')" id="iw-3m"
                        class="insight-win text-xs px-3 py-1.5 rounded-lg border border-gray-700 text-gray-400 hover:text-gray-200 transition">3m</button>
                </div>
                <div id="insightHostBreadcrumb" class="hidden flex items-center gap-2">
                    <button onclick="clearInsightHost()" class="text-xs text-gray-500 hover:text-gray-300 transition">← All Hosts</button>
                    <span class="text-xs text-gray-600">|</span>
                    <span id="insightHostLabel" class="text-xs font-mono text-green-400"></span>
                </div>
                <button onclick="loadInsights()" class="text-xs px-3 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-400 transition">↻ Refresh</button>
            </div>

            <!-- Stat cards -->
            <div id="insightStats" class="grid grid-cols-2 md:grid-cols-4 gap-4"></div>

            <!-- Scan activity chart -->
            <div class="bg-gray-900 rounded-xl border border-gray-800 p-5">
                <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">Scan Activity</h3>
                <div class="relative h-48">
                    <canvas id="chartActivity"></canvas>
                </div>
            </div>

            <!-- Risk + Top Hosts side by side -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="bg-gray-900 rounded-xl border border-gray-800 p-5">
                    <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">Risk Distribution</h3>
                    <div class="relative h-48 flex items-center justify-center">
                        <canvas id="chartRisk"></canvas>
                    </div>
                </div>
                <div class="bg-gray-900 rounded-xl border border-gray-800 p-5">
                    <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4" id="topHostsTitle">Top Hosts by Findings</h3>
                    <div class="relative h-48">
                        <canvas id="chartTopHosts"></canvas>
                    </div>
                </div>
            </div>

            <!-- Host table (aggregate) or scan timeline (per-host) -->
            <div id="insightHostTable" class="bg-gray-900 rounded-xl border border-gray-800 p-5">
                <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">Scanned Hosts</h3>
                <div id="insightHostTableBody"></div>
            </div>

            <!-- Per-host scan history (only visible in drilldown) -->
            <div id="insightScanHistory" class="hidden bg-gray-900 rounded-xl border border-gray-800 p-5">
                <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">Scan History</h3>
                <div class="relative h-48 mb-6">
                    <canvas id="chartScanHistory"></canvas>
                </div>
                <div id="insightScanHistoryTable"></div>
            </div>

            <!-- Empty state -->
            <div id="insightEmpty" class="hidden text-center py-16">
                <p class="text-gray-600 text-sm">No scan data in the selected window.</p>
                <p class="text-gray-700 text-xs mt-1">Run some scans and come back here to see analytics.</p>
            </div>

        </div>
        </div>
        
        <!-- ── TAB: TOPOLOGY ──────────────────────────────────────────── -->
        <div id="tab-topology" class="tab-panel">
        <div class="max-w-screen-xl mx-auto px-6 py-8">
 
            <!-- Top bar: stats + controls -->
            <div class="flex items-center justify-between mb-6 flex-wrap gap-4">
                <div id="topoStats" class="flex gap-4 flex-wrap"></div>
                <div class="flex items-center gap-3">
                    <div class="flex items-center gap-1 bg-gray-900 border border-gray-800 rounded-lg p-1">
                        <button onclick="setTopoFilter('all')" id="tf-all"
                            class="topo-filter text-xs px-3 py-1 rounded-md transition font-medium bg-gray-700 text-white">All</button>
                        <button onclick="setTopoFilter('CRITICAL')" id="tf-CRITICAL"
                            class="topo-filter text-xs px-3 py-1 rounded-md transition font-medium text-gray-400 hover:text-white">Critical</button>
                        <button onclick="setTopoFilter('HIGH')" id="tf-HIGH"
                            class="topo-filter text-xs px-3 py-1 rounded-md transition font-medium text-gray-400 hover:text-white">High</button>
                        <button onclick="setTopoFilter('MEDIUM')" id="tf-MEDIUM"
                            class="topo-filter text-xs px-3 py-1 rounded-md transition font-medium text-gray-400 hover:text-white">Medium</button>
                        <button onclick="setTopoFilter('UNANALYSED')" id="tf-UNANALYSED"
                            class="topo-filter text-xs px-3 py-1 rounded-md transition font-medium text-gray-400 hover:text-white">Unanalysed</button>
                    </div>
                    <button onclick="resetTopoZoom()" class="text-xs px-3 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-400 transition">⊙ Reset</button>
                    <button onclick="loadTopology()" class="text-xs px-3 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-400 transition">↻ Refresh</button>
                </div>
            </div>
 
            <!-- Map + side panel -->
            <div class="flex gap-4" style="height: 680px;">
 
                <!-- D3 canvas -->
                <div class="flex-1 bg-gray-900 rounded-xl border border-gray-800 relative overflow-hidden" id="topoCanvasWrap">
                    <div id="topoEmpty" class="absolute inset-0 flex items-center justify-center hidden">
                        <div class="text-center">
                            <p class="text-gray-600 text-sm">No hosts discovered yet.</p>
                            <p class="text-gray-700 text-xs mt-1">Run a discovery sweep or scan some hosts first.</p>
                        </div>
                    </div>
                    <svg id="topoSvg" class="w-full h-full">
                        <defs>
                            <filter id="glow">
                                <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                                <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
                            </filter>
                            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1f2937" stroke-width="0.5"/>
                            </pattern>
                        </defs>
                        <rect width="100%" height="100%" fill="url(#grid)"/>
                        <g id="topoG"></g>
                    </svg>
                    <div class="absolute bottom-3 left-3 text-xs text-gray-700 select-none pointer-events-none">
                        Scroll to zoom · Drag to pan · Click host to inspect
                    </div>
                    <div class="absolute top-3 left-3 bg-gray-950 bg-opacity-80 border border-gray-800 rounded-lg px-3 py-2 text-xs space-y-1">
                        <div class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-red-500 inline-block"></span><span class="text-gray-400">Critical</span></div>
                        <div class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-orange-500 inline-block"></span><span class="text-gray-400">High</span></div>
                        <div class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-yellow-400 inline-block"></span><span class="text-gray-400">Medium</span></div>
                        <div class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-blue-500 inline-block"></span><span class="text-gray-400">Low</span></div>
                        <div class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-gray-500 inline-block"></span><span class="text-gray-400">Info / Unanalysed</span></div>
                        <div class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-green-400 inline-block"></span><span class="text-gray-400">Unscanned</span></div>
                        <hr class="border-gray-800 my-1">
                        <div class="flex items-center gap-2"><span class="w-3 h-3 rounded border border-gray-500 inline-block"></span><span class="text-gray-400">Subnet</span></div>
                        <div class="flex items-center gap-2"><span class="w-3 h-3 rounded-full border-2 border-green-400 inline-block"></span><span class="text-gray-400">Agent host</span></div>
                    </div>
                </div>
 
                <!-- Side panel -->
                <div id="topoPanel" class="w-72 bg-gray-900 rounded-xl border border-gray-800 flex-shrink-0 overflow-y-auto hidden">
                    <div class="p-4 border-b border-gray-800 flex items-center justify-between">
                        <span class="text-xs font-bold uppercase tracking-wider text-gray-400">Host Details</span>
                        <button onclick="closeTopoPanel()" class="text-gray-600 hover:text-gray-300 transition text-sm">✕</button>
                    </div>
                    <div id="topoPanelContent" class="p-4"></div>
                </div>
 
            </div>
        </div>
        </div>

        <!-- ── SCRIPTS ──────────────────────────────────────────────────── -->
        <script>
        
         function goToResult(resultId) {
            resultTab = 'active';
            switchTab('dashboard');
            setTimeout(async () => {
                await loadResults();
                setTimeout(() => {
                    const cards = document.querySelectorAll('#results > div');
                    let targetCard = null;
                    for (const c of cards) {
                        if (c.querySelector('#result-body-' + resultId)) {
                            targetCard = c;
                            break;
                        }
                    }
                    if (targetCard) {
                        targetCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        targetCard.style.transition = 'box-shadow 0.2s';
                        targetCard.style.boxShadow  = '0 0 0 2px #4ade80';
                        setTimeout(() => {
                            targetCard.style.boxShadow  = '';
                            targetCard.style.transition = '';
                        }, 1800);
                        const bodyEl  = document.getElementById('result-body-'  + resultId);
                        const arrowEl = document.getElementById('result-arrow-' + resultId);
                        if (bodyEl && bodyEl.classList.contains('hidden')) {
                            bodyEl.classList.remove('hidden');
                            if (arrowEl) arrowEl.innerText = '▲';
                        }
                    }
                }, 400);
            }, 100);
        }
        
        // ── STATE ──────────────────────────────────────────────────────────
        let jobFilter = "all";
        let showJobHistory = false;
        let resultTab = "active";
        let authCredentials = "";
        let confirmCallback = null;
        let exploitWarningCallback = null;
        let showStaleAgents = false;
        let activeTab = "dashboard";
        let exploitBannerDismissed = false;
        let topoData = null;
        let topoSimulation = null;
        let topoZoom = null;
        let topoFilter = 'all';
        let topoSelectedNode = null;

        // Tracks job statuses from last poll — used to detect completions
        let lastJobStatuses = {};
        
        // Friendly display names for scan types
        const SCAN_TYPE_LABELS = {
            nmap_scan:   'Port Scan',
            nikto_scan:  'Web Scan',
            nse_scan:    'Vulnerability Scan',
        };
        function scanTypeLabel(type) {
            return SCAN_TYPE_LABELS[type] || type;
        }

        // Pending sweep payload (hosts + params) waiting for user confirmation
        let pendingSweepPayload = null;
        
        // ── SETTINGS ──────────────────────────────────────────────────────────
 
        // Server settings cache
        let serverSettings = {};
 
        // ── Panel open/close ──────────────────────────────────────────────────
        function openSettings() {
            loadServerSettings();
            applyClientSettingsToPanel();
            document.getElementById('settingsPanel').classList.remove('translate-x-full');
            document.getElementById('settingsBackdrop').classList.remove('hidden');
        }
 
        function closeSettings() {
            document.getElementById('settingsPanel').classList.add('translate-x-full');
            document.getElementById('settingsBackdrop').classList.add('hidden');
        }
 
        // Close on Escape key
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') closeSettings();
        });
 
        // ── Theme ─────────────────────────────────────────────────────────────
        function setTheme(theme) {
            document.body.classList.toggle('theme-light', theme === 'light');
            localStorage.setItem('heimdall_theme', theme);
 
            // Update toggle buttons
            document.querySelectorAll('.theme-btn').forEach(b => {
                b.classList.remove('bg-gray-700', 'text-white');
                b.classList.add('text-gray-400');
            });
            const active = document.getElementById('theme-' + theme);
            if (active) {
                active.classList.add('bg-gray-700', 'text-white');
                active.classList.remove('text-gray-400');
            }
        }
 
        function applyStoredTheme() {
            const stored = localStorage.getItem('heimdall_theme') || 'dark';
            setTheme(stored);
        }
 
        // ── Client-side settings (localStorage) ──────────────────────────────
        function saveClientSetting(key, value) {
            localStorage.setItem('heimdall_' + key, value);
        }
 
        function getClientSetting(key, defaultValue) {
            return localStorage.getItem('heimdall_' + key) || defaultValue;
        }
 
        function applyClientSettingsToPanel() {
            // Theme
            const theme = getClientSetting('theme', 'dark');
            document.querySelectorAll('.theme-btn').forEach(b => {
                b.classList.remove('bg-gray-700', 'text-white');
                b.classList.add('text-gray-400');
            });
            const activeTheme = document.getElementById('theme-' + theme);
            if (activeTheme) {
                activeTheme.classList.add('bg-gray-700', 'text-white');
                activeTheme.classList.remove('text-gray-400');
            }
 
            // Scan defaults — also apply to the actual form dropdowns
            const profile = getClientSetting('defaultProfile', 'standard');
            const mode    = getClientSetting('defaultMode', 'remote');
            const prio    = getClientSetting('defaultPriority', 'medium');
            const refresh = getClientSetting('refreshInterval', '5000');
 
            const sp = document.getElementById('setting-default-profile');
            const sm = document.getElementById('setting-default-mode');
            const sr = document.getElementById('setting-default-priority');
            const si = document.getElementById('setting-refresh-interval');
            if (sp) sp.value = profile;
            if (sm) sm.value = mode;
            if (sr) sr.value = prio;
            if (si) si.value = refresh;
 
            // Apply defaults to the Create Job form
            const fp = document.getElementById('profile');
            const fm = document.getElementById('mode');
            const fr = document.getElementById('priority');
            if (fp && !fp.dataset.userChanged) fp.value = profile;
            if (fm && !fm.dataset.userChanged) fm.value = mode;
            if (fr && !fr.dataset.userChanged) fr.value = prio;
        }
 
        // ── Auto-refresh interval ─────────────────────────────────────────────
        let autoRefreshTimer = null;
 
        function applyRefreshInterval() {
            if (autoRefreshTimer) {
                clearInterval(autoRefreshTimer);
                autoRefreshTimer = null;
            }
            const ms = parseInt(getClientSetting('refreshInterval', '5000'));
            if (ms > 0) {
                autoRefreshTimer = setInterval(() => {
                    loadAgents();
                    loadJobs();
                }, ms);
            }
        }
 
        // ── Server settings ───────────────────────────────────────────────────
        async function loadServerSettings() {
            const res = await apiFetch('/settings');
            if (!res) return;
            serverSettings = await res.json();
            renderServerSettings();
        }
 
        function renderServerSettings() {
            // AI auto-analysis toggle
            const aiOn = serverSettings['ai_auto_analyse'] === 'true';
            const toggleBtn  = document.getElementById('setting-ai-toggle');
            const toggleKnob = document.getElementById('setting-ai-knob');
            if (toggleBtn && toggleKnob) {
                toggleBtn.classList.toggle('bg-green-600',  aiOn);
                toggleBtn.classList.toggle('border-green-500', aiOn);
                toggleBtn.classList.toggle('bg-gray-700',  !aiOn);
                toggleBtn.classList.toggle('border-gray-600', !aiOn);
                toggleKnob.style.transform = aiOn ? 'translateX(20px)' : 'translateX(0)';
                toggleKnob.classList.toggle('bg-white',    aiOn);
                toggleKnob.classList.toggle('bg-gray-400', !aiOn);
            }
 
            // Stale agent hours
            const staleInput = document.getElementById('setting-stale-hours');
            if (staleInput) {
                staleInput.value = serverSettings['stale_agent_hours'] || '24';
            }
        }
 
        async function toggleServerSetting(key) {
            const current = serverSettings[key] === 'true';
            const newVal  = (!current).toString();
            await saveServerSetting(key, newVal);
        }
 
        async function saveServerSetting(key, value) {
            const res = await apiFetch('/settings', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ [key]: value }),
            });
            if (!res) return;
            serverSettings[key] = value;
            renderServerSettings();
        }
 
        // ── Initialise on load ────────────────────────────────────────────────
        function initSettings() {
            applyStoredTheme();
            applyClientSettingsToPanel();
            applyRefreshInterval();
        }

        // ── TAB SWITCHING ──────────────────────────────────────────────────
        function switchTab(tab) {
            activeTab = tab;
            document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
            document.getElementById('tab-' + tab).classList.add('active');
            document.getElementById('nav-' + tab).classList.add('active');

            if (tab === 'discovery') { loadSweepHistory(); }
            if (tab === 'schedules') { loadSchedules(); }
            if (tab === 'insights') { loadInsights(); }
            if (tab === 'topology') { setTimeout(loadTopology, 50); }
        }

        // ── AUTH ───────────────────────────────────────────────────────────
        function submitLogin() {
            const username = document.getElementById("loginUsername").value;
            const password = document.getElementById("loginPassword").value;
            if (!username || !password) return;
            authCredentials = 'Basic ' + btoa(username + ':' + password);
            fetch('/agents', { headers: { 'Authorization': authCredentials } }).then(res => {
                if (res.status === 401) {
                    authCredentials = "";
                    document.getElementById("loginError").classList.remove('hidden');
                } else {
                    document.getElementById("loginOverlay").classList.add('hidden');
                    loadAll();
                }
            });
        }
        document.getElementById("loginPassword").addEventListener('keydown', e => { if (e.key === 'Enter') submitLogin(); });
        document.getElementById("loginUsername").addEventListener('keydown', e => { if (e.key === 'Enter') submitLogin(); });

        async function apiFetch(url, options = {}) {
            options.headers = { ...options.headers, 'Authorization': authCredentials };
            const res = await fetch(url, options);
            if (res.status === 401) {
                authCredentials = "";
                document.getElementById("loginOverlay").classList.remove('hidden');
                return null;
            }
            return res;
        }

        // ── DIALOGS ────────────────────────────────────────────────────────
        function showConfirm(message, onConfirm, okLabel = 'Confirm') {
            document.getElementById("confirmMsg").textContent = message;
            document.getElementById("confirmOkBtn").textContent = okLabel;
            document.getElementById("confirmDialog").classList.remove('hidden');
            document.getElementById("confirmOkBtn").onclick = () => {
                document.getElementById("confirmDialog").classList.add('hidden');
                if (onConfirm) onConfirm();
            };
        }
        function cancelConfirm() { document.getElementById("confirmDialog").classList.add('hidden'); }

        function showExploitWarning(onConfirm) {
            exploitWarningCallback = onConfirm;
            document.getElementById("exploitWarningDialog").classList.remove('hidden');
        }
        function cancelExploitWarning() { document.getElementById("exploitWarningDialog").classList.add('hidden'); exploitWarningCallback = null; }
        function confirmExploitWarning() { document.getElementById("exploitWarningDialog").classList.add('hidden'); if (exploitWarningCallback) exploitWarningCallback(); }

        // ── LOAD ALL ───────────────────────────────────────────────────────
        async function loadAll() {
            loadAgents();
            loadJobs();
            loadResults();
            if (activeTab === 'discovery') loadSweepHistory();
            if (activeTab === 'schedules') loadSchedules();
        }

        // ── JOB TYPE CHANGE ────────────────────────────────────────────────
        function onJobTypeChange() {
            const type = document.getElementById("job_type").value;
            document.getElementById("portField").style.display = type === "nikto_scan" ? "flex" : "none";
            document.getElementById("portsField").style.display = type === "nse_scan" ? "flex" : "none";
            updateNseExploitBanner();
        }
        function dismissExploitBanner() {
            exploitBannerDismissed = true;
            document.getElementById('nseExploitBanner').classList.add('hidden');
        }
        function updateNseExploitBanner() {
            const type = document.getElementById("job_type").value;
            const profile = document.getElementById("profile").value;
            const should  = type === "nse_scan" && profile === "full";
            if (!should || exploitBannerDismissed) {
                document.getElementById('nseExploitBanner').classList.add('hidden');
            } else {
                document.getElementById('nseExploitBanner').classList.remove('hidden');
            }
        }

        // ── JOB FILTERS ────────────────────────────────────────────────────
        function setJobFilter(filter) {
            jobFilter = filter;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active-filter', 'border-green-500', 'text-green-400'));
            const active = document.getElementById('filter-' + filter);
            if (active) active.classList.add('active-filter', 'border-green-500', 'text-green-400');
            loadJobs();
        }
        function toggleJobHistory() {
            showJobHistory = !showJobHistory;
            document.getElementById("jobHistoryBtn").innerText = showJobHistory ? "Hide History" : "Show History";
            document.getElementById("jobHistoryBtn").classList.toggle('border-purple-500');
            document.getElementById("jobHistoryBtn").classList.toggle('text-purple-400');
            loadJobs();
        }
        function toggleStaleAgents() {
            showStaleAgents = !showStaleAgents;
            const btn = document.getElementById("staleAgentsBtn");
            btn.innerText = showStaleAgents ? "Hide Stale" : "Show Stale";
            btn.classList.toggle('border-yellow-500');
            btn.classList.toggle('text-yellow-400');
            loadAgents();
        }

        // ── RESULT TABS ────────────────────────────────────────────────────
        function setResultTab(tab) {
            resultTab = tab;
            document.querySelectorAll('.result-tab').forEach(b => { b.classList.remove('bg-gray-700', 'text-white'); b.classList.add('text-gray-400'); });
            document.getElementById('tab-' + tab).classList.add('bg-gray-700', 'text-white');
            document.getElementById('tab-' + tab).classList.remove('text-gray-400');
            document.getElementById('historyToolbar').classList.toggle('hidden', tab !== 'history');
            document.getElementById('activeToolbar').classList.toggle('hidden', tab === 'history');
            document.getElementById('selectAllCheckbox').checked = false;
            document.getElementById('selectAllActiveCheckbox').checked = false;
            loadResults();
        }
        function toggleSelectAll() {
            const checked = document.getElementById('selectAllCheckbox').checked;
            document.querySelectorAll('.result-checkbox').forEach(cb => cb.checked = checked);
        }
        function toggleSelectAllActive() {
            const checked = document.getElementById('selectAllActiveCheckbox').checked;
            document.querySelectorAll('.result-checkbox').forEach(cb => cb.checked = checked);
        }
        function getSelectedIds() {
            return Array.from(document.querySelectorAll('.result-checkbox:checked')).map(cb => parseInt(cb.dataset.id));
        }

        async function clearSelected() {
            const ids = getSelectedIds();
            if (!ids.length) { alert("No results selected."); return; }
            showConfirm(`Clear ${ids.length} result(s)? They will move to History.`, async () => {
                await Promise.all(ids.map(id => apiFetch(`/results/${id}/clear`, { method: 'POST' })));
                document.getElementById('selectAllActiveCheckbox').checked = false;
                loadResults(); loadJobs();
            }, 'Clear');
        }
        async function deleteSelected() {
            const ids = getSelectedIds();
            if (!ids.length) { alert("No results selected."); return; }
            showConfirm(`Permanently delete ${ids.length} result(s) and their jobs? This cannot be undone.`, async () => {
                await apiFetch('/results/bulk', { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids }) });
                document.getElementById('selectAllCheckbox').checked = false;
                loadResults(); loadJobs();
            }, 'Delete');
        }
        async function clearAllHistory() {
            showConfirm('Permanently delete ALL archived results and their jobs? This cannot be undone.', async () => {
                const res = await apiFetch('/results/clear-all-history', { method: 'DELETE' });
                if (!res) return;
                const data = await res.json();
                loadResults(); loadJobs();
            }, 'Clear All');
        }

        async function exportResults() {
            const selectedIds = getSelectedIds();
            const isHistory = resultTab === 'history';
            const url = isHistory ? '/results?show_history=true' : '/results';
            const res = await apiFetch(url);
            if (!res) return;
            const data = await res.json();
            const toExport = selectedIds.length ? data.filter(r => selectedIds.includes(r.id)) : data;
            if (!toExport.length) { alert("No results to export."); return; }
            const exportDoc = {
                exported_at: new Date().toISOString(),
                source: "Heimdall V-Scanner",
                tab: resultTab,
                total: toExport.length,
                results: toExport.map(r => ({
                    result_id: r.id,
                    job: r.job_info ? { target: r.job_info.target, type: r.job_info.type, mode: r.job_info.mode, profile: r.job_info.profile, priority: r.job_info.priority, completed_at: r.job_info.completed_at } : { job_id: r.job_id },
                    nmap: r.output.nmap || null,
                    nikto: r.output.nikto || null,
                    nse: r.output.nse || null,
                }))
            };
            const blob = new Blob([JSON.stringify(exportDoc, null, 2)], { type: 'application/json' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `heimdall-export-${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}.json`;
            document.body.appendChild(a); a.click(); document.body.removeChild(a);
            URL.revokeObjectURL(a.href);
        }

        // ── BADGES ─────────────────────────────────────────────────────────
        function statusBadge(status) {
            const map = { pending: 'bg-yellow-900 text-yellow-300 border border-yellow-700', running: 'bg-blue-900 text-blue-300 border border-blue-700', done: 'bg-green-900 text-green-300 border border-green-700', failed: 'bg-red-900 text-red-300 border border-red-700' };
            return `<span class="text-xs px-2 py-0.5 rounded-full font-medium ${map[status] || 'bg-gray-700 text-gray-300'}">${status}</span>`;
        }
        function priorityBadge(priority) {
            const map = { high: 'text-red-400', medium: 'text-yellow-400', low: 'text-gray-400' };
            return `<span class="text-xs font-medium ${map[priority] || 'text-gray-400'}">${priority}</span>`;
        }
        function formatTimestamp(ts) {
            if (!ts) return '—';
            const normalized = ts.endsWith('Z') ? ts : ts + 'Z';
            const d = new Date(normalized);
            return `${d.toISOString().split('T')[0]} at ${d.toTimeString().split(' ')[0]}`;
        }
        function relativeTime(ts) {
            if (!ts) return '';
            const normalized = ts.endsWith('Z') ? ts : ts + 'Z';
            const diff = Math.floor((Date.now() - new Date(normalized).getTime()) / 1000);
            if (diff < 60)    return 'just now';
            if (diff < 3600)  return Math.floor(diff / 60) + 'm ago';
            if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
            return Math.floor(diff / 86400) + 'd ago';
        }
        function elapsedDisplay(startedAt) {
            if (!startedAt) return 'running…';
            const ts = startedAt.endsWith('Z') ? startedAt : startedAt + 'Z';
            const secs = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
            if (secs < 60) return `${secs}s elapsed`;
            return `${Math.floor(secs / 60)}m ${secs % 60}s elapsed`;
        }

        setInterval(() => {
            document.querySelectorAll('[id^="job-time-"]').forEach(cell => {
                const startedAt = cell.dataset.startedAt;
                if (!startedAt) return;
                const statusCell = cell.closest('tr')?.querySelector('[data-field="status"] span');
                if (statusCell && statusCell.textContent.trim() === 'running') {
                    cell.textContent = elapsedDisplay(startedAt);
                }
            });
        }, 1000);

        // ── AGENTS ─────────────────────────────────────────────────────────
        async function loadAgents() {
            const url = showStaleAgents ? '/agents?show_stale=true' : '/agents';
            const res = await apiFetch(url);
            if (!res) return;
            const data = await res.json();
            data.sort((a, b) => a.id - b.id);
            let html = `<table class="w-full text-sm"><thead><tr class="text-left text-gray-400 border-b border-gray-800"><th class="pb-2 pr-4">ID</th><th class="pb-2 pr-4">Name</th><th class="pb-2 pr-4">Status</th><th class="pb-2 pr-4">Last Seen</th><th class="pb-2">Action</th></tr></thead><tbody>`;
            if (!data.length) html += `<tr><td colspan="5" class="py-4 text-gray-500 text-sm">No agents registered.</td></tr>`;
            data.forEach((a, idx) => {
                const isStale = a.is_stale;
                const rowClass = isStale ? 'border-b border-gray-800 bg-gray-900 opacity-60' : 'border-b border-gray-800 hover:bg-gray-800 transition';
                const dot = a.status === 'online' ? '<span class="inline-block w-2 h-2 rounded-full bg-green-400 mr-2"></span>' : '<span class="inline-block w-2 h-2 rounded-full bg-red-500 mr-2"></span>';
                const staleTag = isStale ? '<span class="ml-2 text-xs px-1.5 py-0.5 rounded bg-yellow-900 text-yellow-400 border border-yellow-700">stale</span>' : '';
                const action = isStale
                    ? `<div class="flex gap-3"><button onclick="restoreAgent(${a.id})" class="text-xs text-blue-400 hover:text-blue-300 transition">Restore</button><button onclick="dismissAgent(${a.id})" class="text-xs text-red-400 hover:text-red-300 transition">Dismiss</button></div>`
                    : '<span class="text-xs text-gray-600">—</span>';
                html += `<tr class="${rowClass}"><td class="py-2 pr-4 text-gray-400">#${idx + 1}</td><td class="py-2 pr-4 font-medium">${a.name}${staleTag}</td><td class="py-2 pr-4">${dot}${a.status}</td><td class="py-2 pr-4 text-gray-400 text-xs">${formatTimestamp(a.last_seen)}</td><td class="py-2">${action}</td></tr>`;
            });
            html += '</tbody></table>';
            document.getElementById("agents").innerHTML = html;
        }
        async function dismissAgent(agent_id) {
            showConfirm('Permanently remove this stale agent?', async () => { await apiFetch(`/agents/${agent_id}/dismiss`, { method: 'POST' }); loadAgents(); }, 'Remove');
        }
        async function restoreAgent(agent_id) { await apiFetch(`/agents/${agent_id}/restore`, { method: 'POST' }); loadAgents(); }

        // ── JOBS ───────────────────────────────────────────────────────────
        async function loadJobs() {
            const url = showJobHistory ? '/jobs?show_history=true' : '/jobs';
            const res = await apiFetch(url);
            if (!res) return;
            const data = await res.json();
            data.sort((a, b) => b.id - a.id);

            // Detect newly completed jobs — auto-refresh results if any finished
            let anyNewlyDone = false;
            data.forEach(j => {
                const prev = lastJobStatuses[j.id];
                if (prev === 'running' && j.status === 'done') anyNewlyDone = true;
                lastJobStatuses[j.id] = j.status;
            });
            if (anyNewlyDone && resultTab === 'active') loadResults();

            const filtered = jobFilter === 'all' ? data : data.filter(j => j.status === jobFilter);
            if (!filtered.length) { document.getElementById("jobs").innerHTML = '<p class="text-gray-500 text-sm">No jobs found.</p>'; return; }

            let html = `<table class="w-full text-sm"><thead><tr class="text-left text-gray-400 border-b border-gray-800"><th class="pb-2 pr-3">#</th><th class="pb-2 pr-3">DB ID</th><th class="pb-2 pr-3">Type</th><th class="pb-2 pr-3">Target</th><th class="pb-2 pr-3">Status</th><th class="pb-2 pr-3">Priority</th><th class="pb-2 pr-3">Mode</th><th class="pb-2 pr-3">Profile</th><th class="pb-2 pr-3">Agent</th><th class="pb-2 pr-3">Time</th><th class="pb-2">Action</th></tr></thead><tbody>`;
            filtered.forEach((j, idx) => {
                let action;
                if (j.cleared) action = '<span class="text-xs text-gray-500 italic">archived</span>';
                else if (j.status === 'pending' || j.status === 'failed') action = `<button onclick="clearJob(${j.id}, '${j.status}')" class="text-xs text-red-500 hover:text-red-400 transition font-medium">Delete</button>`;
                else action = `<button onclick="clearJob(${j.id}, '${j.status}')" class="text-xs text-gray-400 hover:text-red-400 transition">Clear</button>`;
                html += `<tr class="border-b border-gray-800 hover:bg-gray-800 transition"><td class="py-2 pr-3 text-gray-500 text-xs">${idx + 1}</td><td class="py-2 pr-3 text-gray-500 text-xs font-mono">${j.id}</td><td class="py-2 pr-3 text-xs text-blue-300">${scanTypeLabel(j.type)}</td><td class="py-2 pr-3 font-mono text-xs">${j.target}</td><td class="py-2 pr-3" data-field="status">${statusBadge(j.status)}</td><td class="py-2 pr-3">${priorityBadge(j.priority)}</td><td class="py-2 pr-3 text-xs text-gray-300">${j.mode}</td><td class="py-2 pr-3 text-xs text-gray-300">${j.profile}</td><td class="py-2 pr-3 text-xs text-gray-300">${j.agent}</td><td class="py-2 pr-3 text-xs text-gray-400 tabular-nums" id="job-time-${j.id}" data-started-at="${j.started_at || ''}">${j.status === 'running' ? elapsedDisplay(j.started_at) : formatTimestamp(j.completed_at)}</td><td class="py-2">${action}</td></tr>`;
            });
            html += '</tbody></table>';
            document.getElementById("jobs").innerHTML = html;
        }
        async function clearJob(job_id, status) {
            if (status === 'pending' || status === 'failed') {
                showConfirm(`Permanently delete this ${status} job?`, async () => { await apiFetch(`/jobs/${job_id}/clear`, { method: 'POST' }); loadJobs(); }, 'Delete');
            } else { await apiFetch(`/jobs/${job_id}/clear`, { method: 'POST' }); loadJobs(); }
        }
        async function clearAllByStatus(status) {
            showConfirm(`Permanently delete ALL ${status} jobs?`, async () => {
                const res = await apiFetch('/jobs');
                if (!res) return;
                const jobs = await res.json();
                await Promise.all(jobs.filter(j => j.status === status && !j.cleared).map(j => apiFetch(`/jobs/${j.id}/clear`, { method: 'POST' })));
                loadJobs();
            }, 'Delete All');
        }

        // ── CREATE JOB ─────────────────────────────────────────────────────
        async function createJob() {
            const target   = document.getElementById("target").value.trim();
            const agent_id = document.getElementById("agent_id").value.trim();
            const type     = document.getElementById("job_type").value;
            const mode     = document.getElementById("mode").value;
            const profile  = document.getElementById("profile").value;
            const port     = document.getElementById("port").value.trim();
            const ports    = document.getElementById("ports").value.trim();
            const priority = document.getElementById("priority").value;
            if (!target) { alert("Please enter a target IP."); return; }
            if (type === "nse_scan" && profile === "full") {
                showExploitWarning(() => submitCreateJob(target, agent_id, type, mode, profile, port, ports, priority));
                return;
            }
            await submitCreateJob(target, agent_id, type, mode, profile, port, ports, priority);
        }
        async function submitCreateJob(target, agent_id, type, mode, profile, port, ports, priority) {
            let payload = { type, target, mode, profile, priority };
            if (agent_id) payload.agent_id = parseInt(agent_id);
            if (type === "nikto_scan" && port) payload.port = parseInt(port);
            if (type === "nse_scan" && ports) payload.ports = ports;
            const res = await apiFetch('/jobs/create', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
            if (!res) return;
            if (res.status === 400) { const err = await res.json(); alert(`Job creation failed: ${err.detail}`); return; }
            const data = await res.json();
            if (data.warning) alert(`Job created with warning:\\n\\n${data.warning}`);
            document.getElementById("target").value = "";
            document.getElementById("port").value = "";
            document.getElementById("ports").value = "";
            setTimeout(loadAll, 300);
        }

        // ── RESULTS ────────────────────────────────────────────────────────
        function toggleResult(id) {
            const body = document.getElementById(`result-body-${id}`);
            const arrow = document.getElementById(`result-arrow-${id}`);
            body.classList.toggle('hidden');
            arrow.innerText = body.classList.contains('hidden') ? '▼' : '▲';
        }
        function renderNmapResult(nmap) {
            if (!nmap || !nmap.length) return '<p class="text-gray-500 text-xs">No hosts found.</p>';
            return nmap.map(host => {
                const ports = host.ports && host.ports.length
                    ? host.ports.map(p => `<tr class="border-b border-gray-700"><td class="py-1 pr-4 font-mono text-blue-300">${p.port}</td><td class="py-1 pr-4 text-green-400">${p.state}</td><td class="py-1 text-gray-300">${p.service}</td></tr>`).join('')
                    : '<tr><td colspan="3" class="py-2 text-gray-500">No open ports found</td></tr>';
                return `<div class="mb-2"><p class="text-xs text-gray-400 mb-1">Host: <span class="text-white font-mono">${host.host}</span></p><table class="w-full text-xs"><thead><tr class="text-gray-500"><th class="text-left pb-1 pr-4">Port</th><th class="text-left pb-1 pr-4">State</th><th class="text-left pb-1">Service</th></tr></thead><tbody>${ports}</tbody></table></div>`;
            }).join('');
        }
        function renderNiktoResult(nikto) {
            if (!nikto) return '';
            return Object.entries(nikto).map(([port, result]) => {
                if (result.error) return `<div class="mt-2"><p class="text-xs text-gray-400">Nikto port ${port}:</p><p class="text-xs text-red-400">${result.error}</p></div>`;
                if (result.raw) {
                    const findings = result.raw.split('\\n').filter(l => l.match(/^\\+ \\[/));
                    if (!findings.length) return `<div class="mt-2"><p class="text-xs text-gray-500">Nikto port ${port}: no findings.</p></div>`;
                    return `<div class="mt-2"><p class="text-xs text-gray-400 mb-2">Nikto port ${port} — ${findings.length} finding(s):</p><div class="space-y-1">${findings.map(line => { const m = line.match(/^\\+ \\[(\\w+)\\] (.+?):\\s*(.+)$/); return m ? `<div class="bg-gray-950 rounded p-2 text-xs"><span class="text-yellow-400 font-mono">[${m[1]}]</span><span class="text-gray-400 font-mono ml-2">${m[2]}:</span><span class="text-gray-200 ml-1">${m[3]}</span></div>` : `<div class="bg-gray-950 rounded p-2 text-xs text-gray-300">${line.replace(/^\\+ /, '')}</div>`; }).join('')}</div></div>`;
                }
                const vulns = result[0]?.vulnerabilities || [];
                if (!vulns.length) return `<p class="text-xs text-gray-500 mt-2">Nikto port ${port}: no vulnerabilities found.</p>`;
                return `<div class="mt-2"><p class="text-xs text-gray-400 mb-1">Nikto port ${port} — ${vulns.length} finding(s):</p><div class="space-y-1">${vulns.map(v => `<div class="bg-gray-950 rounded p-2 text-xs"><span class="text-yellow-400 font-mono">[${v.id}]</span><span class="text-gray-200 ml-2">${v.msg}</span>${v.url ? `<span class="text-gray-500 ml-2"><a href="${v.url}" target="_blank" class="hover:text-blue-400">${v.url}</a></span>` : ''}</div>`).join('')}</div></div>`;
            }).join('');
        }
        function renderNseResult(nse) {
            if (!nse) return '';
            let warningHtml = nse.warning ? `<div class="mb-3 flex items-start gap-2 bg-yellow-950 border border-yellow-800 rounded-lg px-3 py-2"><span class="text-yellow-400 text-xs mt-0.5">⚠</span><p class="text-xs text-yellow-300">${nse.warning}</p></div>` : '';
            const findings = nse.findings || [];
            if (!findings.length) return `${warningHtml}<p class="text-xs text-gray-500">No NSE findings.</p>`;
            const rows = findings.map(f => {
                const portLabel = f.port !== null ? `<span class="font-mono text-blue-300">${f.port}</span>${f.service ? `<span class="text-gray-500 ml-1">(${f.service})</span>` : ''}` : '<span class="text-gray-500 italic">host-level</span>';
                const outputId = `nse-output-${Math.random().toString(36).slice(2)}`;
                const shortOutput = f.output.length > 200 ? f.output.slice(0, 200) + '...' : f.output;
                const hasMore = f.output.length > 200;
                return `<div class="bg-gray-950 rounded-lg p-3 text-xs space-y-1"><div class="flex items-center gap-3 flex-wrap"><span class="text-purple-400 font-mono font-semibold">${f.script_id}</span><span class="text-gray-500">on</span>${portLabel}<span class="text-gray-600 font-mono">${f.host}</span></div><div class="text-gray-300 whitespace-pre-wrap leading-relaxed" id="${outputId}-short">${shortOutput}</div>${hasMore ? `<div class="text-gray-300 whitespace-pre-wrap leading-relaxed hidden" id="${outputId}-full">${f.output}</div><button onclick="document.getElementById('${outputId}-short').classList.toggle('hidden');document.getElementById('${outputId}-full').classList.toggle('hidden');this.textContent=this.textContent==='Show more'?'Show less':'Show more';" class="text-xs text-gray-500 hover:text-gray-300 underline transition">Show more</button>` : ''}</div>`;
            }).join('');
            return `${warningHtml}<p class="text-xs text-gray-400 mb-2">${findings.length} NSE finding(s):</p><div class="space-y-2">${rows}</div>`;
        }
        function renderAnalysis(analysis) {
            if (!analysis) return '';

            // Parse risk level for badge colour
            const riskMatch = analysis.match(/##\\s*Risk Level\\s*\\n+(\\w+)/i);
            const risk = riskMatch ? riskMatch[1].toUpperCase() : null;
            const riskColour = {
                CRITICAL: 'bg-red-900 text-red-200 border-red-700',
                HIGH:     'bg-orange-900 text-orange-200 border-orange-700',
                MEDIUM:   'bg-yellow-900 text-yellow-200 border-yellow-700',
                LOW:      'bg-blue-900 text-blue-200 border-blue-700',
                INFO:     'bg-gray-800 text-gray-300 border-gray-600',
            }[risk] || 'bg-gray-800 text-gray-300 border-gray-600';

            // Convert markdown to simple HTML
            const html = analysis
                .replace(/^## (.+)$/gm, '<h4 class="text-xs font-bold uppercase tracking-wider text-gray-400 mt-4 mb-2 border-b border-gray-700 pb-1">$1</h4>')
                .replace(/^\\*\\*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\\*\\* (.+)$/gm, (_, sev, rest) => {
                    const c = {CRITICAL:'text-red-400',HIGH:'text-orange-400',MEDIUM:'text-yellow-400',LOW:'text-blue-400',INFO:'text-gray-400'}[sev] || 'text-gray-400';
                    return `<p class="text-xs mt-2"><span class="font-bold ${c}">[${sev}]</span> <span class="text-gray-200 font-semibold">${rest}</span></p>`;
                })
                .replace(/^\\*\\*(.+?)\\*\\*/gm, '<strong class="text-gray-200">$1</strong>')
                .replace(/^(\\d+\\.) (.+)$/gm, '<div class="flex gap-2 text-xs mt-1"><span class="text-gray-500 flex-shrink-0">$1</span><span class="text-gray-300">$2</span></div>')
                .replace(/^- (.+)$/gm, '<div class="flex gap-2 text-xs mt-1"><span class="text-gray-500 flex-shrink-0">•</span><span class="text-gray-300">$1</span></div>')
                .replace(/\\n\\n/g, '<div class="mt-2"></div>')
                .replace(/\\n/g, ' ');

            return `
            <div class="mt-2 bg-gray-900 rounded-lg border border-gray-700 overflow-hidden">
                <div class="flex items-center gap-3 px-4 py-3 border-b border-gray-700">
                    <span class="text-xs font-bold uppercase tracking-wider text-purple-400">Analysis</span>
                    ${risk ? `<span class="text-xs px-2 py-0.5 rounded-full border font-semibold ${riskColour}">${risk}</span>` : ''}
                    <span class="text-xs text-gray-600 ml-auto">Powered by ${AI_PROVIDER}</span>
                </div>
                <div class="px-4 py-3 text-xs text-gray-300 leading-relaxed">${html}</div>
            </div>`;
        }
        async function triggerAnalysis(result_id) {
            await apiFetch(`/results/${result_id}/analyse`, { method: 'POST' });
            setTimeout(() => loadResults(), 4000);
        }
        function renderJobInfo(job_info) {
            if (!job_info) return '';
            return `<div class="mb-4 bg-gray-900 rounded-lg p-3 border border-gray-700"><p class="text-xs font-semibold text-purple-400 uppercase tracking-wider mb-2">Associated Job</p><div class="grid grid-cols-2 gap-x-6 gap-y-1 text-xs"><div><span class="text-gray-500">Job ID:</span> <span class="text-gray-200 font-mono">#${job_info.id}</span></div><div><span class="text-gray-500">Target:</span> <span class="text-gray-200 font-mono">${job_info.target}</span></div><div><span class="text-gray-500">Type:</span> <span class="text-gray-200">${job_info.type}</span></div><div><span class="text-gray-500">Mode:</span> <span class="text-gray-200">${job_info.mode}</span></div><div><span class="text-gray-500">Profile:</span> <span class="text-gray-200">${job_info.profile}</span></div><div><span class="text-gray-500">Priority:</span> <span class="text-gray-200">${job_info.priority}</span></div><div class="col-span-2"><span class="text-gray-500">Completed:</span> <span class="text-gray-200">${formatTimestamp(job_info.completed_at)}</span></div></div></div>`;
        }
        async function clearResult(result_id) { await apiFetch(`/results/${result_id}/clear`, { method: 'POST' }); loadResults(); loadJobs(); }
        async function deleteResult(result_id) {
            showConfirm(`Permanently delete Result #${result_id} and its job?`, async () => { await apiFetch(`/results/${result_id}`, { method: 'DELETE' }); loadResults(); loadJobs(); }, 'Delete');
        }
        async function loadResults() {
            const isHistory = resultTab === 'history';
            const res = await apiFetch(isHistory ? '/results?show_history=true' : '/results');
            if (!res) return;
            const data = await res.json();
            if (!data.length) { document.getElementById("results").innerHTML = `<p class="text-gray-500 text-sm">${isHistory ? 'No archived results.' : 'No results yet.'}</p>`; return; }
            
            const html = data.slice().sort((a, b) => b.id - a.id).map(r => {
                const out = r.output;
 
                // ── Counts ────────────────────────────────────────────────
                const nmapCount = out.nmap
                    ? out.nmap.reduce((a, h) => a + (h.ports || []).filter(p => p.state === 'open').length, 0)
                    : 0;
                const niktoCount = out.nikto
                    ? Object.values(out.nikto).reduce((a, v) => {
                        if (v.error) return a;
                        if (v.raw) return a + (v.raw.match(/^\\+ \\[/gm) || []).length;
                        return a + (v[0]?.vulnerabilities?.length || 0);
                      }, 0)
                    : 0;
                const nseCount = out.nse ? (out.nse.findings || []).length : 0;
 
                // ── Risk badge ────────────────────────────────────────────
                let riskBadge = '';
                if (r.analysis) {
                    const rm = r.analysis.match(/##\\s*Risk Level\\s*\\n+(\\w+)/i);
                    const riskLevel = rm ? rm[1].toUpperCase() : 'INFO';
                    const riskStyles = {
                        CRITICAL: 'bg-red-900 text-red-200 border-red-700',
                        HIGH:     'bg-orange-900 text-orange-200 border-orange-700',
                        MEDIUM:   'bg-yellow-900 text-yellow-200 border-yellow-700',
                        LOW:      'bg-blue-900 text-blue-200 border-blue-700',
                        INFO:     'bg-gray-800 text-gray-400 border-gray-600',
                    };
                    const riskCls = riskStyles[riskLevel] || riskStyles.INFO;
                    riskBadge = '<span class="text-xs px-2 py-0.5 rounded-full border font-bold tracking-wide flex-shrink-0 ' + riskCls + '">' + riskLevel + '</span>';
                } else {
                    riskBadge = '<span class="text-xs px-2 py-0.5 rounded-full border border-gray-700 text-gray-600 font-medium animate-pulse flex-shrink-0" title="Click Analyse to generate AI risk assessment">unanalysed</span>';
                }
 
                // ── Target label: hostname > IP ───────────────────────────
                let targetLabel = r.job_info ? r.job_info.target : ('Job #' + r.job_id);
                if (out.nmap && out.nmap.length > 0 && out.nmap[0].hostname) {
                    targetLabel = out.nmap[0].hostname;
                }
                const targetEl = '<span class="font-mono text-xs text-green-400 font-semibold flex-shrink-0">' + targetLabel + '</span>';
 
                // ── Finding pills ─────────────────────────────────────────
                const pills = [];
                if (out.nmap !== undefined) {
                    pills.push('<span class="text-xs px-2 py-0.5 rounded-full bg-blue-950 text-blue-300 border border-blue-900 whitespace-nowrap">' + nmapCount + ' open port' + (nmapCount !== 1 ? 's' : '') + '</span>');
                }
                if (niktoCount > 0) {
                    pills.push('<span class="text-xs px-2 py-0.5 rounded-full bg-orange-950 text-orange-300 border border-orange-900 whitespace-nowrap">' + niktoCount + ' web finding' + (niktoCount !== 1 ? 's' : '') + '</span>');
                }
                if (nseCount > 0) {
                    pills.push('<span class="text-xs px-2 py-0.5 rounded-full bg-purple-950 text-purple-300 border border-purple-900 whitespace-nowrap">' + nseCount + ' NSE finding' + (nseCount !== 1 ? 's' : '') + '</span>');
                }
                if (!pills.length && !out.nmap && !out.nse && !out.nikto) {
                    pills.push('<span class="text-xs text-gray-600 italic">no data</span>');
                }
 
                // ── Timestamp ─────────────────────────────────────────────
                const ts = r.job_info ? relativeTime(r.job_info.completed_at) : '';
 
                // ── Scan type label ───────────────────────────────────────
                const scanLabel = SCAN_TYPE_LABELS[r.job_info?.type] || (r.job_info?.type || '');
 
                // ── Actions ───────────────────────────────────────────────
                const actions = isHistory
                    ? '<div class="flex items-center gap-3">'
                      + '<input type="checkbox" class="result-checkbox accent-red-500" data-id="' + r.id + '">'
                      + '<a href="/report/' + r.id + '" target="_blank" class="text-xs text-cyan-400 hover:text-cyan-300 transition">Report</a>'
                      + '<button onclick="deleteResult(' + r.id + ')" class="text-xs text-red-400 hover:text-red-300 transition">Delete</button>'
                      + '</div>'
                    : '<div class="flex items-center gap-3">'
                      + '<input type="checkbox" class="result-checkbox accent-yellow-500" data-id="' + r.id + '">'
                      + '<a href="/report/' + r.id + '" target="_blank" class="text-xs text-cyan-400 hover:text-cyan-300 transition">Report</a>'
                      + '<button onclick="triggerAnalysis(' + r.id + ')" class="text-xs text-purple-400 hover:text-purple-300 transition">Analyse</button>'
                      + '<button onclick="clearResult(' + r.id + ')" class="text-xs text-gray-400 hover:text-red-400 transition">Clear</button>'
                      + '</div>';
 
                return '<div class="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">'
 
                    // ── Collapsed header ──────────────────────────────────
                    + '<div class="flex items-center justify-between px-5 py-3.5 cursor-pointer hover:bg-gray-750 transition" onclick="toggleResult(' + r.id + ')">'
 
                        // Left: id · risk · target · pills
                        + '<div class="flex items-center gap-2.5 flex-wrap min-w-0 pr-2">'
                        +     '<span class="text-sm font-semibold text-white flex-shrink-0">Result #' + r.id + '</span>'
                        +     riskBadge
                        +     targetEl
                        +     '<div class="flex items-center gap-1.5 flex-wrap">' + pills.join('') + '</div>'
                        + '</div>'
 
                        // Right: timestamp · actions · chevron
                        + '<div class="flex items-center gap-3 flex-shrink-0">'
                        +     (ts ? '<span class="text-xs text-gray-600 hidden md:block">' + ts + '</span>' : '')
                        +     '<div onclick="event.stopPropagation()">' + actions + '</div>'
                        +     '<span id="result-arrow-' + r.id + '" class="text-gray-500 text-xs pointer-events-none">▼</span>'
                        + '</div>'
 
                    + '</div>'
 
                    // ── Expanded body ─────────────────────────────────────
                    + '<div id="result-body-' + r.id + '" class="hidden px-5 pb-5 border-t border-gray-700 pt-4">'
                    +     (isHistory ? renderJobInfo(r.job_info) : '')
                    +     (out.nmap  ? '<div class="mb-4"><p class="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-2">Port Scan</p>'          + renderNmapResult(out.nmap)   + '</div>' : '')
                    +     (out.nikto ? '<div class="mb-4"><p class="text-xs font-semibold text-orange-400 uppercase tracking-wider mb-1">Web Scan</p>'         + renderNiktoResult(out.nikto) + '</div>' : '')
                    +     (out.nse   ? '<div class="mb-4"><p class="text-xs font-semibold text-purple-400 uppercase tracking-wider mb-2">Vulnerability Scan</p>' + renderNseResult(out.nse)    + '</div>' : '')
                    +     (!out.nmap && !out.nikto && !out.nse ? '<pre class="text-xs text-gray-400 overflow-x-auto">' + JSON.stringify(out, null, 2) + '</pre>' : '')
                    +     (r.analysis
                            ? '<div class="mb-4">' + renderAnalysis(r.analysis) + '</div>'
                            : '<div class="mb-2"><span class="text-xs text-gray-600 italic">Analysis pending — click Analyse above to generate assessment</span></div>'
                          )
                    + '</div>'
 
                + '</div>';
            }).join('');
            document.getElementById("results").innerHTML = html;
        }

        // ── DISCOVERY ──────────────────────────────────────────────────────
        function dismissSweepStatus() { document.getElementById("sweepStatus").classList.add('hidden'); }
        function dismissPingResults() { document.getElementById("pingResults").classList.add('hidden'); }

        function showSweepStatus(text, color = 'bg-cyan-400') {
            const el = document.getElementById("sweepStatus");
            const spinner = document.getElementById("sweepSpinner");
            el.classList.remove('hidden');
            spinner.className = `w-3 h-3 rounded-full flex-shrink-0 ${color}`;
            document.getElementById("sweepStatusText").textContent = text;
        }

        async function startPing() {
            const subnet = document.getElementById("discoverSubnet").value.trim();
            if (!subnet) { alert("Please enter a subnet in CIDR format (e.g. 192.168.1.0/24)"); return; }
            const btn = document.getElementById("pingBtn");
            btn.disabled = true;
            btn.textContent = 'Pinging…';
            dismissPingResults();
            showSweepStatus(`Pinging ${subnet}…`, 'bg-cyan-400 animate-pulse');
            try {
                const res = await apiFetch('/discover/ping', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ subnet }) });
                if (!res) return;
                const data = await res.json();
                showSweepStatus(`Ping complete — ${data.count} host(s) responded`, 'bg-green-400');
                const listEl = document.getElementById("pingResultsList");
                document.getElementById("pingResultsTitle").textContent = `${data.count} host(s) found in ${subnet}`;
                if (data.hosts.length) {
                    listEl.innerHTML = data.hosts.map(h => `<div class="flex items-center gap-3 text-xs py-1 border-b border-gray-700"><span class="font-mono text-green-400 w-36">${h.ip}</span><span class="text-gray-500">${h.hostname || ''}</span></div>`).join('');
                } else {
                    listEl.innerHTML = '<p class="text-xs text-gray-500">No hosts responded to ping.</p>';
                }
                document.getElementById("pingResults").classList.remove('hidden');
            } catch(e) { showSweepStatus('Ping failed. Check server logs.', 'bg-red-500'); }
            finally { btn.disabled = false; btn.textContent = '⬡ Ping'; }
        }

        let sweepPollInterval = null;

        async function startSweep() {
            const subnet = document.getElementById("discoverSubnet").value.trim();
            const mode   = document.getElementById("discoverMode").value;
            const profile = document.getElementById("discoverProfile").value;
            if (!subnet) { alert("Please enter a subnet in CIDR format (e.g. 192.168.1.0/24)"); return; }

            // First ping to find hosts, then show confirmation dialog
            const btn = document.getElementById("sweepBtn");
            btn.disabled = true;
            btn.textContent = 'Scanning…';
            showSweepStatus(`Discovering hosts in ${subnet}…`, 'bg-cyan-400 animate-pulse');

            try {
                const res = await apiFetch('/discover/ping', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ subnet }) });
                if (!res) return;
                const data = await res.json();
                dismissSweepStatus();

                if (!data.count) {
                    showSweepStatus(`No hosts found in ${subnet}.`, 'bg-yellow-400');
                    return;
                }

                // Show confirmation dialog
                pendingSweepPayload = { subnet, mode, profile };
                document.getElementById("sweepConfirmMsg").textContent = `${data.count} host(s) found in ${subnet}:`;
                const hostListEl = document.getElementById("sweepHostList");
                hostListEl.innerHTML = data.hosts.map(h => `<div class="flex items-center gap-3 text-xs py-1 border-b border-gray-700 last:border-0"><span class="font-mono text-green-400 w-36">${h.ip}</span><span class="text-gray-500">${h.hostname || ''}</span></div>`).join('');
                document.getElementById("sweepConfirmDialog").classList.remove('hidden');

            } catch(e) { showSweepStatus('Discovery failed. Check server logs.', 'bg-red-500'); }
            finally { btn.disabled = false; btn.textContent = '⌖ Sweep'; }
        }

        function cancelSweepConfirm() {
            document.getElementById("sweepConfirmDialog").classList.add('hidden');
            pendingSweepPayload = null;
        }

        async function confirmSweep() {
            document.getElementById("sweepConfirmDialog").classList.add('hidden');
            if (!pendingSweepPayload) return;
            const { subnet, mode, profile } = pendingSweepPayload;
            pendingSweepPayload = null;

            showSweepStatus(`Sweeping ${subnet} and assigning jobs…`, 'bg-cyan-400 animate-pulse');

            const res = await apiFetch('/discover', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ subnet, mode, profile }) });
            if (!res) return;
            const data = await res.json();

            sweepPollInterval = setInterval(async () => {
                const r = await apiFetch(`/discover/${data.sweep_id}`);
                if (!r) return;
                const s = await r.json();
                if (s.status === 'done') {
                    clearInterval(sweepPollInterval);
                    showSweepStatus(`Sweep complete — ${s.hosts_found} host(s) found, ${s.jobs_created} job(s) created`, 'bg-green-400');
                    loadSweepHistory(); loadJobs();
                } else if (s.status === 'failed') {
                    clearInterval(sweepPollInterval);
                    showSweepStatus('Sweep failed. Check server logs.', 'bg-red-500');
                    loadSweepHistory();
                }
            }, 3000);
        }

        async function loadSweepHistory() {
            const res = await apiFetch('/discover');
            if (!res) return;
            const sweeps = await res.json();
            const el = document.getElementById("sweepHistory");
            if (!sweeps.length) { el.innerHTML = '<p class="text-gray-600 text-xs">No sweeps yet.</p>'; return; }
            const statusColor = { running: 'text-blue-400', done: 'text-green-400', failed: 'text-red-400' };
            const rows = sweeps.map(s => `<tr class="border-b border-gray-800 hover:bg-gray-800 transition text-xs">
            <td class="py-2 pr-4 text-gray-400">#${s.id}</td>
            <td class="py-2 pr-4 font-mono">${s.subnet}</td>
            <td class="py-2 pr-4 ${statusColor[s.status] || 'text-gray-400'}">${s.status}</td>
            <td class="py-2 pr-4 text-gray-300">${s.hosts_found} host(s)</td>
            <td class="py-2 pr-4 text-gray-300">${s.jobs_created} job(s)</td>
            <td class="py-2 pr-4 text-gray-500">${formatTimestamp(s.started_at)}</td>
            <td class="py-2"><button onclick="deleteSweep(${s.id})" class="text-xs text-red-400 hover:text-red-300 transition">Delete</button></td></tr>`).join('');
            el.innerHTML = `<table class="w-full text-sm"><thead>
            <tr class="text-left text-gray-500 border-b border-gray-800">
            <th class="pb-2 pr-4">ID</th><th class="pb-2 pr-4">Subnet</th><th class="pb-2 pr-4">Status</th><th class="pb-2 pr-4">Hosts</th>
            <th class="pb-2 pr-4">Jobs</th><th class="pb-2 pr-4">Started</th>
            <th class="pb-2">Action</th></tr></thead><tbody>${rows}</tbody></table>`;
        }

        async function deleteSweep(sweep_id) {
            showConfirm('Delete this sweep record?', async () => { await apiFetch(`/discover/${sweep_id}`, { method: 'DELETE' }); loadSweepHistory(); }, 'Delete');
        }
        async function clearAllSweeps() {
            showConfirm('Delete all sweep history records?', async () => { await apiFetch('/discover', { method: 'DELETE' }); loadSweepHistory(); }, 'Clear All');
        }

        // ── SCHEDULES ──────────────────────────────────────────────────────
        async function loadSchedules() {
            const res = await apiFetch('/schedules');
            if (!res) return;
            const data = await res.json();
            const el = document.getElementById("schedules");
            if (!data.length) { el.innerHTML = '<p class="text-gray-500 text-sm">No schedules yet.</p>'; return; }
            let html = `<table class="w-full text-sm">
            <thead><tr class="text-left text-gray-400 border-b border-gray-800">
            <th class="pb-2 pr-3">Name</th>
            <th class="pb-2 pr-3">Type</th>
            <th class="pb-2 pr-3">Target</th>
            <th class="pb-2 pr-3">Profile</th>
            <th class="pb-2 pr-3">Every</th>
            <th class="pb-2 pr-3">Status</th>
            <th class="pb-2 pr-3">Last Run</th>
            <th class="pb-2 pr-3">Next Run</th>
            <th class="pb-2">Actions</th>
            </tr></thead><tbody>`;
            
            data.forEach(s => {
                const badge = s.paused 
                ? '<span class="text-xs px-2 py-0.5 rounded-full bg-yellow-900 text-yellow-300 border border-yellow-700">paused</span>' 
                : '<span class="text-xs px-2 py-0.5 rounded-full bg-green-900 text-green-300 border border-green-700">active</span>';
                
                const toggle = s.paused 
                ? `<button onclick="resumeSchedule(${s.id})" class="text-xs text-blue-400 hover:text-blue-300 transition">Resume</button>` 
                : `<button onclick="pauseSchedule(${s.id})" class="text-xs text-yellow-400 hover:text-yellow-300 transition">Pause</button>`;
                html += `<tr class="border-b border-gray-800 hover:bg-gray-800 transition">
                <td class="py-2 pr-3 font-medium text-sm">${s.name}</td>
                <td class="py-2 pr-3 text-xs text-blue-300">${scanTypeLabel(s.type)}</td>
                <td class="py-2 pr-3 font-mono text-xs">${s.target}</td>
                <td class="py-2 pr-3 text-xs text-gray-300">${s.profile}</td>
                <td class="py-2 pr-3 text-xs text-gray-300">${s.interval_hours}h</td>
                <td class="py-2 pr-3">${badge}</td>
                <td class="py-2 pr-3 text-xs text-gray-400">${formatTimestamp(s.last_run_at)}</td>
                <td class="py-2 pr-3 text-xs text-gray-400">${s.paused ? '—' : formatTimestamp(s.next_run_at)}</td>
                <td class="py-2 flex gap-3">
                ${toggle}
                <button onclick="deleteSchedule(${s.id})" class="text-xs text-red-400 hover:text-red-300 transition">Delete</button></td></tr>`;
            });
            html += '</tbody></table>';
            el.innerHTML = html;
        }
        async function createSchedule() {
            const name = document.getElementById("sched_name").value.trim();
            const target = document.getElementById("sched_target").value.trim();
            const type = document.getElementById("sched_type").value;
            const profile = document.getElementById("sched_profile").value;
            const mode = document.getElementById("sched_mode").value;
            const priority = document.getElementById("sched_priority").value;
            const interval = document.getElementById("sched_interval").value.trim();
            
            if (!name || !target || !interval) { alert("Name, target, and interval are required."); return; }
            if (parseInt(interval) < 1) { alert("Interval must be at least 1 hour."); return; }
            
            const res = await apiFetch('/schedules', { 
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' }, 
            body: JSON.stringify({ name, target, type, profile, mode, priority, interval_hours: parseInt(interval) }) 
            });
            
            if (!res) return;
            
            if (res.status === 400) { const err = await res.json(); alert(`Failed: ${err.detail}`); return; }
            document.getElementById("sched_name").value = "";
            document.getElementById("sched_target").value = "";
            document.getElementById("sched_interval").value = "";
            loadSchedules();
        }
        async function pauseSchedule(id) { await apiFetch(`/schedules/${id}/pause`, { method: 'POST' }); loadSchedules(); }
        async function resumeSchedule(id) { await apiFetch(`/schedules/${id}/resume`, { method: 'POST' }); loadSchedules(); }
        async function deleteSchedule(id) {
            showConfirm('Delete this schedule? Jobs already created are not affected.', async () => { await apiFetch(`/schedules/${id}`, { method: 'DELETE' }); loadSchedules(); }, 'Delete');
        }

        // ── INSIGHTS ───────────────────────────────────────────────────────
        let insightWindow = '7d';
        let insightHost = null;
        let chartActivity = null, chartRisk = null, chartTopHosts = null, chartScanHistory = null;

        function setInsightWindow(w) {
            insightWindow = w;
            document.querySelectorAll('.insight-win').forEach(b => {
                b.style.borderColor = '#374151';
                b.style.color = '#9ca3af';
                b.style.background = '';
            });
            const active = document.getElementById('iw-' + w);
            if (active) {
                active.style.borderColor = '#4ade80';
                active.style.color = '#4ade80';
                active.style.background = 'rgba(74,222,128,0.1)';
            }
            loadInsights();
        }

        function clearInsightHost() {
            insightHost = null;
            document.getElementById('insightHostBreadcrumb').classList.add('hidden');
            document.getElementById('insightScanHistory').classList.add('hidden');
            document.getElementById('insightHostTable').classList.remove('hidden');
            loadInsights();
        }

        function drillIntoHost(ip) {
            insightHost = ip;
            document.getElementById('insightHostLabel').textContent = ip;
            document.getElementById('insightHostBreadcrumb').classList.remove('hidden');
            document.getElementById('insightScanHistory').classList.remove('hidden');
            document.getElementById('insightHostTable').classList.add('hidden');
            loadInsights();
        }

        function riskColour(risk) {
            return {CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#eab308',LOW:'#3b82f6',INFO:'#6b7280',UNANALYSED:'#374151'}[risk] || '#6b7280';
        }
        function riskBadgeHtml(risk) {
            const cls = {CRITICAL:'bg-red-900 text-red-300 border-red-700',HIGH:'bg-orange-900 text-orange-300 border-orange-700',MEDIUM:'bg-yellow-900 text-yellow-300 border-yellow-700',LOW:'bg-blue-900 text-blue-300 border-blue-700',INFO:'bg-gray-800 text-gray-400 border-gray-600',UNANALYSED:'bg-gray-900 text-gray-600 border-gray-700'}[risk] || 'bg-gray-900 text-gray-600 border-gray-700';
            return `<span class="text-xs px-2 py-0.5 rounded-full border font-semibold ${cls}">${risk}</span>`;
        }

        function destroyChart(ref) { if (ref) { ref.destroy(); } return null; }

        async function loadInsights() {
            // Always sync the active window button styling
            document.querySelectorAll('.insight-win').forEach(b => {
                b.style.borderColor = '#374151';
                b.style.color = '#9ca3af';
                b.style.background = '';
            });
            const activeBtn = document.getElementById('iw-' + insightWindow);
            if (activeBtn) {
                activeBtn.style.borderColor = '#4ade80';
                activeBtn.style.color = '#4ade80';
                activeBtn.style.background = 'rgba(74,222,128,0.1)';
            }

            let url = `/insights?window=${insightWindow}`;
            if (insightHost) url += `&host=${encodeURIComponent(insightHost)}`;
            const res = await apiFetch(url);
            if (!res) return;
            const data = await res.json();

            const isEmpty = data.stats.total_scans === 0;
            document.getElementById('insightEmpty').classList.toggle('hidden', !isEmpty);

            // ── Stat cards ────────────────────────────────────────────────
            const riskSummary = ['CRITICAL','HIGH','MEDIUM','LOW'].map(r =>
                data.stats.risk_counts[r] > 0
                    ? `<span style="color:${riskColour(r)}" class="font-semibold">${data.stats.risk_counts[r]} ${r}</span>`
                    : null
            ).filter(Boolean).join(' · ') || '<span class="text-gray-600">None analysed</span>';

            document.getElementById('insightStats').innerHTML = [
                [insightHost ? 'Scans (this host)' : 'Total Scans', insightHost ? data.stats.total_scans : data.stats.total_scans, 'text-green-400'],
                [insightHost ? 'Host' : 'Unique Hosts', insightHost ? insightHost : data.stats.unique_hosts, 'text-blue-400'],
                ['Open Ports Found', data.stats.total_open_ports, 'text-orange-400'],
            ].map(([label, val, cls]) => `
                <div class="bg-gray-900 rounded-xl border border-gray-800 p-4 text-center">
                    <div class="text-2xl font-bold ${cls}">${val}</div>
                    <div class="text-xs text-gray-500 mt-1 uppercase tracking-wider">${label}</div>
                </div>
            `).join('') + `
                <div class="bg-gray-900 rounded-xl border border-gray-800 p-4 text-center">
                    <div class="text-xs mt-2 leading-relaxed">${riskSummary}</div>
                    <div class="text-xs text-gray-500 mt-1 uppercase tracking-wider">Risk Summary</div>
                </div>`;

            // ── Scan activity bar chart ───────────────────────────────────
            chartActivity = destroyChart(chartActivity);
            const actCtx = document.getElementById('chartActivity').getContext('2d');
            const labels = data.scan_activity.map(d => {
                const parts = d.date.split('-');
                return `${parts[1]}/${parts[2]}`;
            });
            chartActivity = new Chart(actCtx, {
                type: 'bar',
                data: {
                    labels,
                    datasets: [{
                        label: 'Scans',
                        data: data.scan_activity.map(d => d.count),
                        backgroundColor: 'rgba(74,222,128,0.5)',
                        borderColor: '#4ade80',
                        borderWidth: 1,
                        borderRadius: 3,
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: '#6b7280', font: { size: 10 } }, grid: { color: '#1f2937' } },
                        y: { ticks: { color: '#6b7280', font: { size: 10 }, stepSize: 1 }, grid: { color: '#1f2937' }, beginAtZero: true }
                    }
                }
            });

            // ── Risk doughnut chart ───────────────────────────────────────
            chartRisk = destroyChart(chartRisk);
            const riskCtx = document.getElementById('chartRisk').getContext('2d');
            const riskKeys = ['CRITICAL','HIGH','MEDIUM','LOW','INFO','UNANALYSED'];
            const riskVals = riskKeys.map(k => data.stats.risk_counts[k] || 0);
            const hasRiskData = riskVals.some(v => v > 0);
            chartRisk = new Chart(riskCtx, {
                type: 'doughnut',
                data: {
                    labels: riskKeys,
                    datasets: [{
                        data: hasRiskData ? riskVals : [1],
                        backgroundColor: hasRiskData ? riskKeys.map(riskColour) : ['#1f2937'],
                        borderWidth: 0,
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'right', labels: { color: '#9ca3af', font: { size: 10 }, boxWidth: 12, padding: 8 } },
                        tooltip: { enabled: hasRiskData }
                    },
                    cutout: '65%'
                }
            });

            // ── Top hosts bar chart ───────────────────────────────────────
            chartTopHosts = destroyChart(chartTopHosts);
            const topCtx = document.getElementById('chartTopHosts').getContext('2d');
            const topHosts = data.hosts.slice(0, 8);
            chartTopHosts = new Chart(topCtx, {
                type: 'bar',
                data: {
                    labels: topHosts.map(h => h.ip),
                    datasets: [{
                        label: 'Findings',
                        data: topHosts.map(h => h.findings),
                        backgroundColor: topHosts.map(h => riskColour(h.risk) + '99'),
                        borderColor: topHosts.map(h => riskColour(h.risk)),
                        borderWidth: 1,
                        borderRadius: 3,
                    }]
                },
                options: {
                    indexAxis: 'y',
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: '#6b7280', font: { size: 10 }, stepSize: 1 }, grid: { color: '#1f2937' }, beginAtZero: true },
                        y: { ticks: { color: '#9ca3af', font: { size: 10 } }, grid: { display: false } }
                    }
                }
            });

            // ── Host table ────────────────────────────────────────────────
            if (!insightHost) {
                var tbody = document.getElementById('insightHostTableBody');
                if (!data.hosts.length) {
                    tbody.innerHTML = '<p class="text-xs text-gray-600">No hosts found in this window.</p>';
                } else {
                    var hostRows = '';
                    for (var hi = 0; hi < data.hosts.length; hi++) {
                        var h = data.hosts[hi];
 
                        var nameCell = h.hostname
                            ? '<span class="text-gray-300">' + h.hostname + '</span>'
                            : (h.agent_name
                                ? '<span class="text-blue-400">agent: ' + h.agent_name + '</span>'
                                : '<span class="text-gray-700 italic">unknown</span>');
                        var macCell = h.mac ? '<div class="text-gray-600 font-mono text-xs">' + h.mac + '</div>' : '';
                        var osCell  = h.os  ? '<div class="text-gray-600 text-xs">' + h.os + '</div>' : '';
                        var ipWarn  = h.ip_changed ? ' <span class="text-yellow-500" title="IP changed from ' + (h.previous_ip || '') + '">\u26a0</span>' : '';
                        var lastScan = h.last_scan ? h.last_scan.split('T')[0] : '\u2014';
 
                        var actionCell = '';
                        if (h.result_id) {
                            actionCell =
                                '<div class="flex gap-1.5 flex-wrap">'
                                + '<a href="/report/' + h.result_id + '" target="_blank" '
                                + 'class="text-xs px-2 py-1 rounded bg-cyan-900 hover:bg-cyan-800 text-cyan-300 border border-cyan-800 transition whitespace-nowrap">'
                                + 'Report \u2197</a>'
                                + '<button onclick="goToResult(' + h.result_id + ')" '
                                + 'class="text-xs px-2 py-1 rounded bg-gray-800 hover:bg-gray-700 text-green-400 border border-gray-700 transition whitespace-nowrap">'
                                + '\u2192 Result</button>'
                                + '</div>';
                        } else {
                            actionCell = '<span class="text-xs text-gray-700 italic">no result</span>';
                        }
 
                        hostRows +=
                            '<tr class="border-b border-gray-800 hover:bg-gray-800 transition">'
                            + '<td class="py-2 pr-4 cursor-pointer" onclick="drillIntoHost(\\'' + h.ip + '\\')">'
                            +     '<div class="font-mono text-green-400 text-xs">' + h.ip + ipWarn + '</div>' + osCell
                            + '</td>'
                            + '<td class="py-2 pr-4 cursor-pointer" onclick="drillIntoHost(\\'' + h.ip + '\\')">'
                            +     '<div class="text-xs">' + nameCell + '</div>' + macCell
                            + '</td>'
                            + '<td class="py-2 pr-4 text-xs text-gray-300 cursor-pointer" onclick="drillIntoHost(\\'' + h.ip + '\\')">' + h.scan_count + '</td>'
                            + '<td class="py-2 pr-4 text-xs text-gray-300 cursor-pointer" onclick="drillIntoHost(\\'' + h.ip + '\\')">' + h.open_ports + '</td>'
                            + '<td class="py-2 pr-4 text-xs text-gray-300 cursor-pointer" onclick="drillIntoHost(\\'' + h.ip + '\\')">' + h.findings   + '</td>'
                            + '<td class="py-2 pr-4 cursor-pointer" onclick="drillIntoHost(\\'' + h.ip + '\\')">' + riskBadgeHtml(h.risk) + '</td>'
                            + '<td class="py-2 pr-4 text-xs text-gray-500 cursor-pointer" onclick="drillIntoHost(\\'' + h.ip + '\\')">' + lastScan + '</td>'
                            + '<td class="py-2">' + actionCell + '</td>'
                            + '</tr>';
                    }
                    tbody.innerHTML =
                        '<table class="w-full text-sm">'
                        + '<thead><tr class="text-left text-gray-500 border-b border-gray-800 text-xs">'
                        + '<th class="pb-2 pr-4">Host</th>'
                        + '<th class="pb-2 pr-4">Identity</th>'
                        + '<th class="pb-2 pr-4">Scans</th>'
                        + '<th class="pb-2 pr-4">Open Ports</th>'
                        + '<th class="pb-2 pr-4">Findings</th>'
                        + '<th class="pb-2 pr-4">Risk</th>'
                        + '<th class="pb-2 pr-4">Last Scan</th>'
                        + '<th class="pb-2">Actions</th>'
                        + '</tr></thead>'
                        + '<tbody>' + hostRows + '</tbody>'
                        + '</table>';
                }
            }
            

            // ── Per-host scan history ─────────────────────────────────────
            if (insightHost && data.scan_history.length) {
                // Line chart: open ports over time
                chartScanHistory = destroyChart(chartScanHistory);
                const histCtx = document.getElementById('chartScanHistory').getContext('2d');
                const histLabels = data.scan_history.map(e => e.date || '?');
                chartScanHistory = new Chart(histCtx, {
                    type: 'line',
                    data: {
                        labels: histLabels,
                        datasets: [
                            {
                                label: 'Open Ports',
                                data: data.scan_history.map(e => e.open_ports),
                                borderColor: '#4ade80',
                                backgroundColor: 'rgba(74,222,128,0.1)',
                                tension: 0.3, fill: true, pointRadius: 4,
                            },
                            {
                                label: 'Findings',
                                data: data.scan_history.map(e => e.findings),
                                borderColor: '#f97316',
                                backgroundColor: 'rgba(249,115,22,0.05)',
                                tension: 0.3, fill: true, pointRadius: 4,
                            }
                        ]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        plugins: { legend: { labels: { color: '#9ca3af', font: { size: 10 }, boxWidth: 12 } } },
                        scales: {
                            x: { ticks: { color: '#6b7280', font: { size: 10 } }, grid: { color: '#1f2937' } },
                            y: { ticks: { color: '#6b7280', font: { size: 10 }, stepSize: 1 }, grid: { color: '#1f2937' }, beginAtZero: true }
                        }
                    }
                });

                // History table — no backticks
                var histRows = '';
                for (var si = 0; si < data.scan_history.length; si++) {
                    var e = data.scan_history[si];
                    var histAction = e.result_id
                        ? '<div class="flex gap-1">'
                          + '<a href="/report/' + e.result_id + '" target="_blank" '
                          + 'class="text-xs px-1.5 py-0.5 rounded bg-cyan-900 hover:bg-cyan-800 text-cyan-300 border border-cyan-800 transition">\u2197</a>'
                          + '<button onclick="goToResult(' + e.result_id + ')" '
                          + 'class="text-xs px-1.5 py-0.5 rounded bg-gray-800 hover:bg-gray-700 text-green-400 border border-gray-700 transition">\u2192</button>'
                          + '</div>'
                        : '';
                    histRows +=
                        '<tr class="border-b border-gray-800 text-xs">'
                        + '<td class="py-2 pr-4 text-gray-400">'       + (e.date || '\u2014') + '</td>'
                        + '<td class="py-2 pr-4 font-mono text-blue-300">' + e.type           + '</td>'
                        + '<td class="py-2 pr-4 text-blue-300">'           + scanTypeLabel(e.type) + '</td>'
                        + '<td class="py-2 pr-4 text-gray-400">'       + e.profile            + '</td>'
                        + '<td class="py-2 pr-4 text-gray-300">'       + e.open_ports         + '</td>'
                        + '<td class="py-2 pr-4 text-gray-300">'       + e.findings           + '</td>'
                        + '<td class="py-2 pr-4">'                     + riskBadgeHtml(e.risk) + '</td>'
                        + '<td class="py-2">'                          + histAction            + '</td>'
                        + '</tr>';
                }
                document.getElementById('insightScanHistoryTable').innerHTML =
                    '<table class="w-full text-sm">'
                    + '<thead><tr class="text-left text-gray-500 border-b border-gray-800 text-xs">'
                    + '<th class="pb-2 pr-4">Date</th>'
                    + '<th class="pb-2 pr-4">Type</th>'
                    + '<th class="pb-2 pr-4">Profile</th>'
                    + '<th class="pb-2 pr-4">Open Ports</th>'
                    + '<th class="pb-2 pr-4">Findings</th>'
                    + '<th class="pb-2 pr-4">Risk</th>'
                    + '<th class="pb-2">Actions</th>'
                    + '</tr></thead>'
                    + '<tbody>' + histRows + '</tbody>'
                    + '</table>';
            } else if (insightHost) {
                document.getElementById('insightScanHistoryTable').innerHTML = '<p class="text-xs text-gray-600">No scan history for this host in the selected window.</p>';
                chartScanHistory = destroyChart(chartScanHistory);
            }
        }
        
        const RISK_COLOR = {
    CRITICAL:   '#ef4444',
    HIGH:       '#f97316',
    MEDIUM:     '#eab308',
    LOW:        '#3b82f6',
    INFO:       '#6b7280',
    UNANALYSED: '#4b5563',
    UNSCANNED:  '#4ade80',
};
 
const RISK_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNANALYSED', 'UNSCANNED'];
 
function riskColor(risk) {
    return RISK_COLOR[risk] || RISK_COLOR.UNANALYSED;
}
 
function setTopoFilter(f) {
    topoFilter = f;
    document.querySelectorAll('.topo-filter').forEach(b => {
        b.classList.remove('bg-gray-700', 'text-white');
        b.classList.add('text-gray-400');
    });
    const active = document.getElementById('tf-' + f);
    if (active) {
        active.classList.add('bg-gray-700', 'text-white');
        active.classList.remove('text-gray-400');
    }
    if (topoData) renderTopology(topoData);
}
 
function resetTopoZoom() {
    const svg = d3.select('#topoSvg');
    svg.transition().duration(500).call(
        topoZoom.transform,
        d3.zoomIdentity.translate(
            document.getElementById('topoSvg').clientWidth / 2,
            document.getElementById('topoSvg').clientHeight / 2
        ).scale(0.85)
    );
}
 
function closeTopoPanel() {
    document.getElementById('topoPanel').classList.add('hidden');
    topoSelectedNode = null;
    // deselect all nodes
    d3.selectAll('.topo-host-node').attr('stroke', d => d.is_agent ? '#4ade80' : 'none').attr('stroke-width', d => d.is_agent ? 2 : 0);
}
 
async function loadTopology() {
    const res = await apiFetch('/topology');
    if (!res) return;
    topoData = await res.json();
 
    // Stats bar
    const s = topoData.stats;
    const riskParts = RISK_ORDER
        .filter(r => s.risk_counts[r] > 0)
        .map(r => `<span class="flex items-center gap-1.5"><span class="w-2 h-2 rounded-full inline-block" style="background:${riskColor(r)}"></span><span class="text-gray-300 text-xs">${s.risk_counts[r]} ${r}</span></span>`)
        .join('');
 
    document.getElementById('topoStats').innerHTML = `
        <div class="flex items-center gap-1.5 bg-gray-900 border border-gray-800 rounded-lg px-3 py-1.5">
            <span class="text-xs text-gray-500">Hosts</span>
            <span class="text-xs font-bold text-green-400">${s.total_hosts}</span>
        </div>
        <div class="flex items-center gap-1.5 bg-gray-900 border border-gray-800 rounded-lg px-3 py-1.5">
            <span class="text-xs text-gray-500">Subnets</span>
            <span class="text-xs font-bold text-blue-400">${s.total_subnets}</span>
        </div>
        <div class="flex items-center gap-2 bg-gray-900 border border-gray-800 rounded-lg px-3 py-1.5 flex-wrap">
            ${riskParts || '<span class="text-xs text-gray-600">No scan data</span>'}
        </div>`;
 
    if (s.total_hosts === 0) {
        document.getElementById('topoEmpty').classList.remove('hidden');
        document.getElementById('topoG').innerHTML = '';
        return;
    }
    document.getElementById('topoEmpty').classList.add('hidden');
 
    renderTopology(topoData);
}
 
function renderTopology(data) {
    const wrap = document.getElementById('topoCanvasWrap');
    const W = wrap.clientWidth;
    const H = wrap.clientHeight;
 
    const svg = d3.select('#topoSvg');
    const g   = d3.select('#topoG');
    g.selectAll('*').remove();
 
    // Apply filter
    let visibleHosts = data.nodes.filter(n => n.type === 'host');
    if (topoFilter !== 'all') {
        visibleHosts = visibleHosts.filter(n => n.risk === topoFilter);
    }
    const visibleHostIds = new Set(visibleHosts.map(n => n.id));
 
    // Only include subnets that have at least one visible host
    const relevantSubnets = new Set(visibleHosts.map(n => n.subnet));
    const subnetNodes = data.nodes.filter(n => n.type === 'subnet' && relevantSubnets.has(n.label));
 
    const nodes = [...visibleHosts, ...subnetNodes];
    const nodeIds = new Set(nodes.map(n => n.id));
    const edges = data.edges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target));
 
    // Clone for D3 mutation
    const simNodes = nodes.map(n => ({ ...n }));
    const simEdges = edges.map(e => ({ ...e }));
 
    // Group subnets into clusters using a subnet-center attraction
    const subnetCenters = {};
    const subnetsArr = [...relevantSubnets];
    const cols = Math.ceil(Math.sqrt(subnetsArr.length));
    subnetsArr.forEach((subnet, i) => {
        const col = i % cols;
        const row = Math.floor(i / cols);
        subnetCenters[subnet] = {
            x: (W / (cols + 1)) * (col + 1),
            y: (H / (Math.ceil(subnetsArr.length / cols) + 1)) * (row + 1),
        };
    });
 
    // Pre-position subnet nodes
    simNodes.forEach(n => {
        if (n.type === 'subnet' && subnetCenters[n.label]) {
            n.fx = subnetCenters[n.label].x;
            n.fy = subnetCenters[n.label].y;
        }
        if (n.type === 'host' && subnetCenters[n.subnet]) {
            n.x = subnetCenters[n.subnet].x + (Math.random() - 0.5) * 120;
            n.y = subnetCenters[n.subnet].y + (Math.random() - 0.5) * 120;
        }
    });
 
    // Force simulation
    if (topoSimulation) topoSimulation.stop();
 
    topoSimulation = d3.forceSimulation(simNodes)
        .force('link', d3.forceLink(simEdges).id(d => d.id).distance(d => {
            if (d.target.type === 'subnet') return 90;
            return 60;
        }).strength(0.6))
        .force('charge', d3.forceManyBody().strength(d => d.type === 'subnet' ? -300 : -180))
        .force('collide', d3.forceCollide().radius(d => d.type === 'subnet' ? 40 : 22))
        .alphaDecay(0.03);
 
    // Edges
    const link = g.append('g').attr('class', 'topo-links')
        .selectAll('line')
        .data(simEdges)
        .enter().append('line')
        .attr('stroke', '#1f2937')
        .attr('stroke-width', 1.5)
        .attr('stroke-dasharray', d => d.target.type === 'subnet' ? '4,3' : 'none')
        .attr('opacity', 0.7);
 
    // Subnet nodes (rectangles)
    const subnetGroup = g.append('g').attr('class', 'topo-subnets')
        .selectAll('g')
        .data(simNodes.filter(n => n.type === 'subnet'))
        .enter().append('g')
        .attr('class', 'topo-subnet-node');
 
    subnetGroup.append('rect')
        .attr('width', 100).attr('height', 28)
        .attr('x', -50).attr('y', -14)
        .attr('rx', 6)
        .attr('fill', '#111827')
        .attr('stroke', '#374151')
        .attr('stroke-width', 1.5);
 
    subnetGroup.append('text')
        .text(d => d.label)
        .attr('text-anchor', 'middle')
        .attr('dy', '0.35em')
        .attr('fill', '#6b7280')
        .attr('font-family', 'IBM Plex Mono, monospace')
        .attr('font-size', 10);
 
    // Host nodes
    const hostGroup = g.append('g').attr('class', 'topo-hosts')
        .selectAll('g')
        .data(simNodes.filter(n => n.type === 'host'))
        .enter().append('g')
        .attr('class', 'topo-host-node-group')
        .style('cursor', 'pointer')
        .on('click', (event, d) => {
            event.stopPropagation();
            selectTopoHost(d);
        })
        .call(d3.drag()
            .on('start', (event, d) => {
                if (!event.active) topoSimulation.alphaTarget(0.3).restart();
                d.fx = d.x; d.fy = d.y;
            })
            .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
            .on('end', (event, d) => {
                if (!event.active) topoSimulation.alphaTarget(0);
                d.fx = null; d.fy = null;
            })
        );
 
    // Outer ring for agent hosts
    hostGroup.filter(d => d.is_agent)
        .append('circle')
        .attr('r', 20)
        .attr('fill', 'none')
        .attr('stroke', '#4ade80')
        .attr('stroke-width', 1.5)
        .attr('stroke-dasharray', '3,2')
        .attr('opacity', 0.6);
 
    // Main circle
    hostGroup.append('circle')
        .attr('class', 'topo-host-node')
        .attr('r', d => {
            // Size by port count
            const base = 14;
            return base + Math.min(d.port_count, 10);
        })
        .attr('fill', d => riskColor(d.risk))
        .attr('fill-opacity', 0.15)
        .attr('stroke', d => riskColor(d.risk))
        .attr('stroke-width', 2)
        .attr('filter', d => ['CRITICAL', 'HIGH'].includes(d.risk) ? 'url(#glow)' : null);
 
    // IP label
    hostGroup.append('text')
        .text(d => d.ip)
        .attr('text-anchor', 'middle')
        .attr('dy', '0.35em')
        .attr('fill', d => riskColor(d.risk))
        .attr('font-family', 'IBM Plex Mono, monospace')
        .attr('font-size', 9)
        .attr('font-weight', '600');
 
    // Port count badge (top-right of node)
    hostGroup.filter(d => d.port_count > 0)
        .append('text')
        .text(d => d.port_count)
        .attr('x', d => 14 + Math.min(d.port_count, 10) - 4)
        .attr('y', d => -(14 + Math.min(d.port_count, 10) - 4))
        .attr('text-anchor', 'middle')
        .attr('fill', '#9ca3af')
        .attr('font-size', 8)
        .attr('font-family', 'IBM Plex Mono, monospace');
 
    // Pulse animation for CRITICAL nodes
    hostGroup.filter(d => d.risk === 'CRITICAL')
        .append('circle')
        .attr('r', d => 14 + Math.min(d.port_count, 10))
        .attr('fill', 'none')
        .attr('stroke', '#ef4444')
        .attr('stroke-width', 1)
        .attr('opacity', 0)
        .each(function pulse() {
            d3.select(this)
                .transition().duration(1500)
                .attr('r', d => (14 + Math.min(d.port_count, 10)) + 12)
                .attr('opacity', 0)
                .on('end', function() {
                    d3.select(this).attr('r', d => 14 + Math.min(d.port_count, 10)).attr('opacity', 0.5);
                    pulse.call(this);
                });
        });
 
    // Tick
    topoSimulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);
 
        subnetGroup.attr('transform', d => `translate(${d.x},${d.y})`);
        hostGroup.attr('transform', d => `translate(${d.x},${d.y})`);
    });
 
    // Zoom + pan
    topoZoom = d3.zoom()
        .scaleExtent([0.2, 4])
        .on('zoom', (event) => {
            g.attr('transform', event.transform);
        });
    
     svg.call(topoZoom);

    // Re-read dimensions after layout is complete, then center
    requestAnimationFrame(() => {
        const svgEl = document.getElementById('topoSvg');
        const fw = svgEl.clientWidth  || wrap.clientWidth;
        const fh = svgEl.clientHeight || wrap.clientHeight;
        svg.call(topoZoom.transform, d3.zoomIdentity
            .translate(fw / 2, fh / 2)
            .scale(0.85));
    });

    // Click on background → deselect
    svg.on('click', () => closeTopoPanel());
}
 
function selectTopoHost(d) {
    topoSelectedNode = d.id;
 
    // Highlight selected
    d3.selectAll('.topo-host-node')
        .attr('stroke-width', n => n.id === d.id ? 3 : 2)
        .attr('fill-opacity', n => n.id === d.id ? 0.35 : 0.15);
 
    // Show panel
    const panel = document.getElementById('topoPanel');
    panel.classList.remove('hidden');
 
    const riskCls = {
        CRITICAL: 'text-red-400', HIGH: 'text-orange-400',
        MEDIUM: 'text-yellow-400', LOW: 'text-blue-400',
        INFO: 'text-gray-400', UNANALYSED: 'text-gray-500', UNSCANNED: 'text-green-400',
    }[d.risk] || 'text-gray-400';
 
    const portRows = d.open_ports.length
        ? d.open_ports.map(p => `
            <tr class="border-b border-gray-800">
                <td class="py-1 pr-3 font-mono text-blue-300 text-xs">${p.port}</td>
                <td class="py-1 text-gray-300 text-xs">${p.service}</td>
            </tr>`).join('')
        : '<tr><td colspan="2" class="py-2 text-gray-600 text-xs italic">No open ports found</td></tr>';
 
    const lastScan = d.last_scan_at
        ? new Date(d.last_scan_at + (d.last_scan_at.endsWith('Z') ? '' : 'Z')).toLocaleString()
        : 'Never';
 
    document.getElementById('topoPanelContent').innerHTML = `
        <!-- IP + risk -->
        <div class="mb-4">
            <div class="font-mono text-lg font-bold text-white mb-1">${d.ip}</div>
            <span class="text-xs font-semibold ${riskCls} uppercase tracking-wider">${d.risk}</span>
            ${d.is_agent ? '<span class="ml-2 text-xs px-2 py-0.5 rounded-full bg-green-900 text-green-300 border border-green-700">agent</span>' : ''}
        </div>
 
        <!-- Identity -->
        <div class="mb-4 space-y-1">
            ${d.hostname ? `<div class="flex gap-2 text-xs"><span class="text-gray-500 w-20">Hostname</span><span class="text-gray-200 font-mono">${d.hostname}</span></div>` : ''}
            ${d.mac ? `<div class="flex gap-2 text-xs"><span class="text-gray-500 w-20">MAC</span><span class="text-gray-400 font-mono">${d.mac}</span></div>` : ''}
            ${d.os ? `<div class="flex gap-2 text-xs"><span class="text-gray-500 w-20">OS</span><span class="text-gray-300">${d.os}</span></div>` : ''}
            ${d.agent_name ? `<div class="flex gap-2 text-xs"><span class="text-gray-500 w-20">Agent</span><span class="text-green-400">${d.agent_name}</span></div>` : ''}
            <div class="flex gap-2 text-xs"><span class="text-gray-500 w-20">Subnet</span><span class="text-gray-400 font-mono">${d.subnet}</span></div>
            <div class="flex gap-2 text-xs"><span class="text-gray-500 w-20">Last scan</span><span class="text-gray-400">${lastScan}</span></div>
        </div>
 
        <!-- Findings summary -->
        <div class="mb-4 grid grid-cols-3 gap-2">
            <div class="bg-gray-800 rounded-lg p-2 text-center">
                <div class="text-sm font-bold text-blue-400">${d.port_count}</div>
                <div class="text-xs text-gray-500">Ports</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-2 text-center">
                <div class="text-sm font-bold text-purple-400">${d.nse_findings}</div>
                <div class="text-xs text-gray-500">NSE</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-2 text-center">
                <div class="text-sm font-bold text-orange-400">${d.nikto_findings}</div>
                <div class="text-xs text-gray-500">Nikto</div>
            </div>
        </div>
 
        <!-- Open ports -->
        <div class="mb-4">
            <p class="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-2">Open Ports</p>
            <table class="w-full">
                <thead><tr>
                    <th class="text-left text-xs text-gray-600 pb-1 pr-3">Port</th>
                    <th class="text-left text-xs text-gray-600 pb-1">Service</th>
                </tr></thead>
                <tbody>${portRows}</tbody>
            </table>
        </div>
 
        <!-- Actions -->
        <div class="flex flex-col gap-2">
            ${d.result_id ? `
            <a href="/report/${d.result_id}" target="_blank"
                class="text-xs text-center px-3 py-2 rounded-lg bg-cyan-900 hover:bg-cyan-800 text-cyan-200 border border-cyan-700 transition font-medium">
                View Report
            </a>
            <button onclick="createJobFromTopo('${d.ip}')"
                class="text-xs px-3 py-2 rounded-lg bg-green-900 hover:bg-green-800 text-green-200 border border-green-700 transition font-medium">
                + New Scan Job
            </button>` : `
            <button onclick="createJobFromTopo('${d.ip}')"
                class="text-xs px-3 py-2 rounded-lg bg-green-900 hover:bg-green-800 text-green-200 border border-green-700 transition font-medium">
                + Scan This Host
            </button>`}
        </div>`;
}
 
function createJobFromTopo(ip) {
    // Switch to dashboard tab, pre-fill target
    switchTab('dashboard');
    document.getElementById('target').value = ip;
    document.getElementById('target').focus();
    // Brief highlight
    document.getElementById('target').style.borderColor = '#4ade80';
    setTimeout(() => document.getElementById('target').style.borderColor = '', 1500);
}

        const AI_PROVIDER = '__AI_PROVIDER__';
        initSettings();

        </script>
    </body>
    </html>
    """
    html = html.replace("__AI_PROVIDER__", ai_provider_name)
    return html
