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
from .db import Base, engine, get_db, SessionLocal
from .models import Agent, Job, Result, DiscoverySweep, Schedule
from .schemas import AgentCreate, AgentResponse, JobResponse, ResultCreate, ResultResponse, JobCreate
from dotenv import load_dotenv
from .logger import get_logger

load_dotenv()

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
    cutoff = datetime.utcnow() - timedelta(hours=STALE_AGENT_HOURS)
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


@app.on_event("startup")
def startup_cleanup():
    thread = threading.Thread(target=run_stale_cleanup, daemon=True)
    thread.start()
    logger.info("Stale agent cleanup thread started")

    sched_thread = threading.Thread(target=run_scheduler, daemon=True)
    sched_thread.start()
    logger.info("Job scheduler thread started")

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


@app.post("/agents/results")
def submit_result(
    result: ResultCreate,
    x_api_key: str = Header(...),
    db: Session = Depends(get_db),
):
    agent = get_agent_by_api_key(x_api_key, db)

    new_result = Result(
        job_id=result.job_id,
        output=result.output,
    )
    db.add(new_result)

    job = db.query(Job).filter(Job.id == result.job_id).first()
    if job:
        job.status = "done"
        job.completed_at = datetime.utcnow()

    db.commit()
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
            "job_info": job_info
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


# --- DASHBOARD ---

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Heimdall V-Scanner</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            .nav-tab { transition: all 0.15s ease; }
            .nav-tab.active {
                background: rgba(74, 222, 128, 0.1);
                color: #4ade80;
                border-color: #4ade80;
            }
            .tab-panel { display: none; }
            .tab-panel.active { display: block; }
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
            </nav>

            <button onclick="loadAll()" class="text-sm bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded-lg transition">↻ Refresh</button>
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
                        <input id="target" placeholder="192.168.1.50"
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
                            <option value="nmap_scan">Nmap Scan</option>
                            <option value="nikto_scan">Nikto Scan</option>
                            <option value="nse_scan">NSE Scan</option>
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
                <div id="nseExploitBanner" class="hidden mt-4 flex items-start gap-3 bg-red-950 border border-red-800 rounded-lg px-4 py-3">
                    <span class="text-red-400 text-sm mt-0.5">⚠</span>
                    <p class="text-xs text-red-300"><strong class="text-red-200">Full profile with NSE</strong> uses <span class="font-mono">--script vuln,exploit</span> — intrusive scripts that may disrupt services.</p>
                </div>
                <div id="nseExploitBanner" class="hidden mt-4 flex items-start justify-between gap-3 bg-red-950 border border-red-800 rounded-lg px-4 py-3">
                    <div class="flex items-start gap-3">
                        <span class="text-red-400 text-sm mt-0.5">⚠</span>
                        <p class="text-xs text-red-300"><strong class="text-red-200">Full profile with NSE</strong> uses <span class="font-mono">--script vuln,exploit</span> — intrusive scripts that may disrupt services.</p>
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
                            <option value="nmap_scan">Nmap Scan</option>
                            <option value="nikto_scan">Nikto Scan</option>
                            <option value="nse_scan">NSE Scan</option>
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

        <!-- ── SCRIPTS ──────────────────────────────────────────────────── -->
        <script>
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

        // Tracks job statuses from last poll — used to detect completions
        let lastJobStatuses = {};

        // Pending sweep payload (hosts + params) waiting for user confirmation
        let pendingSweepPayload = null;

        // ── TAB SWITCHING ──────────────────────────────────────────────────
        function switchTab(tab) {
            activeTab = tab;
            document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
            document.getElementById('tab-' + tab).classList.add('active');
            document.getElementById('nav-' + tab).classList.add('active');

            if (tab === 'discovery') { loadSweepHistory(); }
            if (tab === 'schedules') { loadSchedules(); }
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
            const d = new Date(ts);
            return `${d.toISOString().split('T')[0]} at ${d.toTimeString().split(' ')[0]}`;
        }
        function elapsedDisplay(startedAt) {
            if (!startedAt) return 'running…';
            const secs = Math.floor((Date.now() - new Date(startedAt).getTime()) / 1000);
            if (secs < 60) return `${secs}s elapsed`;
            return `${Math.floor(secs / 60)}m ${secs % 60}s elapsed`;
        }

        setInterval(() => {
            document.querySelectorAll('[id^="job-time-"]').forEach(cell => {
                const startedAt = cell.dataset.startedAt;
                if (!startedAt) return;
                const badge = cell.closest('tr')?.querySelector('span');
                if (badge && badge.textContent.trim() === 'running') cell.textContent = elapsedDisplay(startedAt);
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
            data.forEach(a => {
                const isStale = a.is_stale;
                const rowClass = isStale ? 'border-b border-gray-800 bg-gray-900 opacity-60' : 'border-b border-gray-800 hover:bg-gray-800 transition';
                const dot = a.status === 'online' ? '<span class="inline-block w-2 h-2 rounded-full bg-green-400 mr-2"></span>' : '<span class="inline-block w-2 h-2 rounded-full bg-red-500 mr-2"></span>';
                const staleTag = isStale ? '<span class="ml-2 text-xs px-1.5 py-0.5 rounded bg-yellow-900 text-yellow-400 border border-yellow-700">stale</span>' : '';
                const action = isStale
                    ? `<div class="flex gap-3"><button onclick="restoreAgent(${a.id})" class="text-xs text-blue-400 hover:text-blue-300 transition">Restore</button><button onclick="dismissAgent(${a.id})" class="text-xs text-red-400 hover:text-red-300 transition">Dismiss</button></div>`
                    : '<span class="text-xs text-gray-600">—</span>';
                html += `<tr class="${rowClass}"><td class="py-2 pr-4 text-gray-400">#${a.id}</td><td class="py-2 pr-4 font-medium">${a.name}${staleTag}</td><td class="py-2 pr-4">${dot}${a.status}</td><td class="py-2 pr-4 text-gray-400 text-xs">${formatTimestamp(a.last_seen)}</td><td class="py-2">${action}</td></tr>`;
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
                html += `<tr class="border-b border-gray-800 hover:bg-gray-800 transition"><td class="py-2 pr-3 text-gray-500 text-xs">${idx + 1}</td><td class="py-2 pr-3 text-gray-500 text-xs font-mono">${j.id}</td><td class="py-2 pr-3 font-mono text-xs text-blue-300">${j.type}</td><td class="py-2 pr-3 font-mono text-xs">${j.target}</td><td class="py-2 pr-3">${statusBadge(j.status)}</td><td class="py-2 pr-3">${priorityBadge(j.priority)}</td><td class="py-2 pr-3 text-xs text-gray-300">${j.mode}</td><td class="py-2 pr-3 text-xs text-gray-300">${j.profile}</td><td class="py-2 pr-3 text-xs text-gray-300">${j.agent}</td><td class="py-2 pr-3 text-xs text-gray-400 tabular-nums" id="job-time-${j.id}" data-started-at="${j.started_at || ''}">${j.status === 'running' ? elapsedDisplay(j.started_at) : formatTimestamp(j.completed_at)}</td><td class="py-2">${action}</td></tr>`;
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
            const html = data.slice().reverse().map(r => {
                const out = r.output;
                const nmapCount = out.nmap ? out.nmap.reduce((a, h) => a + (h.ports || []).filter(p => p.state === 'open').length, 0) : 0;
                const niktoCount = out.nikto ? Object.values(out.nikto).reduce((a, v) => { if (v.error) return a; if (v.raw) return a + (v.raw.match(/^\\+ \\[/gm) || []).length; return a + (v[0]?.vulnerabilities?.length || 0); }, 0) : 0;
                const nseCount = out.nse ? (out.nse.findings || []).length : 0;
                const summary = [out.nmap ? `${nmapCount} open port(s)` : null, out.nikto ? `${niktoCount} web finding(s)` : null, out.nse ? `${nseCount} NSE finding(s)` : null].filter(Boolean).join(' · ') || 'No data';
                const actions = isHistory
                    ? `<div class="flex items-center gap-3"><input type="checkbox" class="result-checkbox accent-red-500" data-id="${r.id}"><a href="/report/${r.id}" target="_blank" class="text-xs text-cyan-400 hover:text-cyan-300 transition">Report</a><button onclick="deleteResult(${r.id})" class="text-xs text-red-400 hover:text-red-300 transition">Delete</button></div>`
                    : `<div class="flex items-center gap-3"><input type="checkbox" class="result-checkbox accent-yellow-500" data-id="${r.id}"><a href="/report/${r.id}" target="_blank" class="text-xs text-cyan-400 hover:text-cyan-300 transition">Report</a><button onclick="clearResult(${r.id})" class="text-xs text-gray-400 hover:text-red-400 transition">Clear</button></div>`;
                return `<div class="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden"><div class="flex items-center justify-between px-5 py-4 cursor-pointer hover:bg-gray-750 transition" onclick="toggleResult(${r.id})"><div class="flex items-center gap-4"><span class="text-sm font-semibold text-white">Result #${r.id}</span><span class="text-xs text-gray-400">Job #${r.job_id}</span><span class="text-xs text-gray-500">${summary}</span></div><div class="flex items-center gap-4" onclick="event.stopPropagation()">${actions}<span id="result-arrow-${r.id}" class="text-gray-400 text-xs pointer-events-none">▼</span></div></div><div id="result-body-${r.id}" class="hidden px-5 pb-5 border-t border-gray-700 pt-4">${isHistory ? renderJobInfo(r.job_info) : ''}${out.nmap ? `<div class="mb-4"><p class="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-2">Nmap</p>${renderNmapResult(out.nmap)}</div>` : ''}${out.nikto ? `<div class="mb-4"><p class="text-xs font-semibold text-orange-400 uppercase tracking-wider mb-1">Nikto</p>${renderNiktoResult(out.nikto)}</div>` : ''}${out.nse ? `<div class="mb-4"><p class="text-xs font-semibold text-purple-400 uppercase tracking-wider mb-2">NSE</p>${renderNseResult(out.nse)}</div>` : ''}${!out.nmap && !out.nikto && !out.nse ? `<pre class="text-xs text-gray-400 overflow-x-auto">${JSON.stringify(out, null, 2)}</pre>` : ''}</div></div>`;
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
            const rows = sweeps.map(s => `<tr class="border-b border-gray-800 hover:bg-gray-800 transition text-xs"><td class="py-2 pr-4 text-gray-400">#${s.id}</td><td class="py-2 pr-4 font-mono">${s.subnet}</td><td class="py-2 pr-4 ${statusColor[s.status] || 'text-gray-400'}">${s.status}</td><td class="py-2 pr-4 text-gray-300">${s.hosts_found} host(s)</td><td class="py-2 pr-4 text-gray-300">${s.jobs_created} job(s)</td><td class="py-2 pr-4 text-gray-500">${formatTimestamp(s.started_at)}</td><td class="py-2"><button onclick="deleteSweep(${s.id})" class="text-xs text-red-400 hover:text-red-300 transition">Delete</button></td></tr>`).join('');
            el.innerHTML = `<table class="w-full text-sm"><thead><tr class="text-left text-gray-500 border-b border-gray-800"><th class="pb-2 pr-4">ID</th><th class="pb-2 pr-4">Subnet</th><th class="pb-2 pr-4">Status</th><th class="pb-2 pr-4">Hosts</th><th class="pb-2 pr-4">Jobs</th><th class="pb-2 pr-4">Started</th><th class="pb-2">Action</th></tr></thead><tbody>${rows}</tbody></table>`;
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
            let html = `<table class="w-full text-sm"><thead><tr class="text-left text-gray-400 border-b border-gray-800"><th class="pb-2 pr-3">Name</th><th class="pb-2 pr-3">Type</th><th class="pb-2 pr-3">Target</th><th class="pb-2 pr-3">Profile</th><th class="pb-2 pr-3">Every</th><th class="pb-2 pr-3">Status</th><th class="pb-2 pr-3">Last Run</th><th class="pb-2 pr-3">Next Run</th><th class="pb-2">Actions</th></tr></thead><tbody>`;
            data.forEach(s => {
                const badge = s.paused ? '<span class="text-xs px-2 py-0.5 rounded-full bg-yellow-900 text-yellow-300 border border-yellow-700">paused</span>' : '<span class="text-xs px-2 py-0.5 rounded-full bg-green-900 text-green-300 border border-green-700">active</span>';
                const toggle = s.paused ? `<button onclick="resumeSchedule(${s.id})" class="text-xs text-blue-400 hover:text-blue-300 transition">Resume</button>` : `<button onclick="pauseSchedule(${s.id})" class="text-xs text-yellow-400 hover:text-yellow-300 transition">Pause</button>`;
                html += `<tr class="border-b border-gray-800 hover:bg-gray-800 transition"><td class="py-2 pr-3 font-medium text-sm">${s.name}</td><td class="py-2 pr-3 font-mono text-xs text-blue-300">${s.type}</td><td class="py-2 pr-3 font-mono text-xs">${s.target}</td><td class="py-2 pr-3 text-xs text-gray-300">${s.profile}</td><td class="py-2 pr-3 text-xs text-gray-300">${s.interval_hours}h</td><td class="py-2 pr-3">${badge}</td><td class="py-2 pr-3 text-xs text-gray-400">${formatTimestamp(s.last_run_at)}</td><td class="py-2 pr-3 text-xs text-gray-400">${s.paused ? '—' : formatTimestamp(s.next_run_at)}</td><td class="py-2 flex gap-3">${toggle}<button onclick="deleteSchedule(${s.id})" class="text-xs text-red-400 hover:text-red-300 transition">Delete</button></td></tr>`;
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
            const res = await apiFetch('/schedules', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, target, type, profile, mode, priority, interval_hours: parseInt(interval) }) });
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

        // ── AUTO POLL ──────────────────────────────────────────────────────
        setInterval(() => { loadAgents(); loadJobs(); }, 5000);

        </script>
    </body>
    </html>
    """
