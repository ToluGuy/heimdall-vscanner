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

# ── Scanner auto-spawn settings ───────────────────────────────────────────────
# INSTALL_DIR: the project root (two levels up from this file: backend/app/main.py)
import sys as _sys
INSTALL_DIR  = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PYTHON_BIN   = _sys.executable
ENV_FILE     = os.path.join(INSTALL_DIR, ".env")
SCANNER_PY   = os.path.join(INSTALL_DIR, "backend", "app", "scanner.py")
# Set SCANNER_AUTOSTART=true in .env to allow the dashboard to spawn scanner
# instances via systemctl. Requires the sudoers rule added by install.sh.
SCANNER_AUTOSTART = os.environ.get("SCANNER_AUTOSTART", "false").lower() == "true"

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
    "auto_nikto":         "true",   # automatically run Nikto after nmap_scan when web ports are found
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
    if key == "auto_nikto":
        return os.environ.get("AUTO_NIKTO", "true")
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
        custom_scripts=custom_scripts_str,
        nikto_tuning=nikto_tuning_str,
    )
    db.add(new_job)
    db.commit()
    db.refresh(new_job)

    response = {"id": new_job.id, "status": new_job.status}
    if nse_ports_warning:
        response["warning"] = nse_ports_warning

    return response


@app.post("/scanners/register")
def register_scanner(
    agent: AgentCreate,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    """
    Dashboard-initiated scanner registration.
    Creates an Agent record and — if SCANNER_AUTOSTART=true and systemd is
    available — writes a service file and starts it automatically.
    Returns the API key, service name, and spawn status.
    """
    name = agent.name.strip()
    caps = agent.capabilities or "nmap_scan,nikto_scan,nse_scan"

    import re as _re
    if not _re.match(r'^[a-zA-Z0-9_-]+$', name):
        raise HTTPException(status_code=400, detail="Scanner name may only contain letters, numbers, hyphens, and underscores.")
    if name == 'scanner-default':
        raise HTTPException(status_code=400, detail="'scanner-default' is the system scanner name and cannot be used for new registrations.")
    if db.query(Agent).filter(Agent.name == name).first():
        raise HTTPException(status_code=409, detail=f"An agent named '{name}' already exists.")

    new_agent = Agent(name=name, capabilities=caps)
    db.add(new_agent)
    db.commit()
    db.refresh(new_agent)

    api_key      = new_agent.api_key
    service_name = f"vapt-scanner-{name}"
    key_file     = os.path.join(INSTALL_DIR, f"{name}_key.txt")

    spawn_status = "manual"   # default: user must start it themselves
    spawn_error  = None

    if SCANNER_AUTOSTART:
        try:
            # Write the API key to disk so the scanner process can load it
            with open(key_file, "w") as f:
                f.write(api_key)

            # Build the systemd service file content
            current_user = os.environ.get("USER", "vapt")
            service_content = (
                f"[Unit]\n"
                f"Description=Heimdall V-Scanner — {name}\n"
                f"After=network.target vapt-server.service\n"
                f"Wants=vapt-server.service\n\n"
                f"[Service]\n"
                f"Type=simple\n"
                f"User={current_user}\n"
                f"WorkingDirectory={INSTALL_DIR}\n"
                f"EnvironmentFile={ENV_FILE}\n"
                f"Environment=VAPT_AGENT_NAME={name}\n"
                f"Environment=VAPT_SERVER_URL=http://127.0.0.1:8000\n"
                f"Environment=VAPT_CAPABILITIES={caps}\n"
                f"Environment=VAPT_KEY_FILE={key_file}\n"
                f"ExecStart={PYTHON_BIN} {SCANNER_PY}\n"
                f"Restart=on-failure\n"
                f"RestartSec=10\n"
                f"StandardOutput=journal\n"
                f"StandardError=journal\n\n"
                f"[Install]\n"
                f"WantedBy=multi-user.target\n"
            )

            # Write to a temp file then sudo mv into place
            tmp_path = f"/tmp/{service_name}.service"
            with open(tmp_path, "w") as f:
                f.write(service_content)

            cmds = [
                ["sudo", "mv", tmp_path, f"/etc/systemd/system/{service_name}.service"],
                ["sudo", "systemctl", "daemon-reload"],
                ["sudo", "systemctl", "enable", service_name],
                ["sudo", "systemctl", "start", service_name],
            ]
            for cmd in cmds:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if result.returncode != 0:
                    raise RuntimeError(f"{' '.join(cmd)} failed: {result.stderr.strip()}")

            spawn_status = "started"
            logger.info(f"Scanner '{name}' registered and started as {service_name}")

        except Exception as e:
            spawn_status = "failed"
            spawn_error  = str(e)
            logger.error(f"Scanner auto-spawn failed for '{name}': {e}")
    else:
        logger.info(f"Scanner '{name}' registered (SCANNER_AUTOSTART=false — manual start required)")

    return {
        "id":           new_agent.id,
        "name":         name,
        "api_key":      api_key,
        "capabilities": caps,
        "service_name": service_name,
        "key_file":     key_file,
        "spawn_status": spawn_status,   # "started" | "manual" | "failed"
        "spawn_error":  spawn_error,
        "autostart":    SCANNER_AUTOSTART,
    }


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
            "capabilities": a.capabilities or "",
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


@app.delete("/scanners/{agent_id}")
def delete_scanner(
    agent_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    """
    Delete a dashboard-registered scanner.
    If SCANNER_AUTOSTART is true, also stops and removes its systemd service.
    scanner-default cannot be deleted — it is the primary system scanner.
    """
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    protected = {"scanner-default"}
    if agent.name in protected:
        raise HTTPException(status_code=403, detail=f"'{agent.name}' is the system scanner and cannot be deleted from the dashboard. Use psql to remove stale duplicates.")

    service_name = f"vapt-scanner-{agent.name}"
    key_file     = os.path.join(INSTALL_DIR, f"{agent.name}_key.txt")
    stop_status  = "skipped"

    if SCANNER_AUTOSTART:
        try:
            # Stop and disable the service — ignore errors if it never started
            subprocess.run(["sudo", "systemctl", "stop",    service_name], capture_output=True, timeout=10)
            subprocess.run(["sudo", "systemctl", "disable", service_name], capture_output=True, timeout=10)
            service_file = f"/etc/systemd/system/{service_name}.service"
            subprocess.run(["sudo", "rm", "-f", service_file],             capture_output=True, timeout=10)
            subprocess.run(["sudo", "systemctl", "daemon-reload"],         capture_output=True, timeout=10)
            # Remove the key file
            if os.path.exists(key_file):
                os.remove(key_file)
            stop_status = "stopped"
            logger.info(f"Scanner '{agent.name}' service stopped and removed")
        except Exception as e:
            stop_status = f"error: {e}"
            logger.warning(f"Could not fully stop scanner '{agent.name}': {e}")

    db.delete(agent)
    db.commit()
    return {"ok": True, "service_name": service_name, "stop_status": stop_status}


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

    # Deserialise custom_scripts from comma-separated DB string back to a list
    custom_scripts_list = None
    if job.custom_scripts:
        custom_scripts_list = [s.strip() for s in job.custom_scripts.split(",") if s.strip()]

    # Deserialise nikto_tuning from comma-separated DB string back to a list
    nikto_tuning_list = None
    if job.nikto_tuning:
        nikto_tuning_list = [s.strip() for s in job.nikto_tuning.split(",") if s.strip()]

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
        "auto_nikto": auto_nikto,
    }

@app.post("/agents/heartbeat")
def heartbeat(
    x_api_key: str = Header(...),
    db: Session = Depends(get_db),
):
    agent = get_agent_by_api_key(x_api_key, db)
    agent.last_seen = datetime.utcnow()
    # Auto-restore stale agents when they come back online
    if agent.is_stale:
        agent.is_stale = False
        logger.info(f"Agent '{agent.name}' (id={agent.id}) came back online — stale flag cleared")
    db.commit()
    return {"status": "alive"}


@app.post("/agents/recover")
def agent_recover(
    x_api_key: str = Header(...),
    db: Session = Depends(get_db),
):
    """
    Called by scanner/agent on startup. Marks any jobs that were left in
    'running' status (assigned to this agent) as 'failed'. This handles
    the case where the process was killed mid-execution and the job was
    never completed or reported back.
    """
    agent = get_agent_by_api_key(x_api_key, db)
    orphaned = db.query(Job).filter(
        Job.agent_id == agent.id,
        Job.status == "running"
    ).all()
    for job in orphaned:
        job.status = "failed"
        job.completed_at = datetime.utcnow()
        logger.warning(f"Crash recovery: job {job.id} (target={job.target}) marked failed — was running when agent restarted")
    db.commit()
    return {"recovered": len(orphaned)}

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


@app.post("/jobs/{job_id}/cancel")
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


@app.get("/jobs/{job_id}/status")
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

        # Check if sweep was cancelled while nmap was running — discard results if so
        sweep = db.query(DiscoverySweep).filter(DiscoverySweep.id == sweep_id).first()
        if sweep and sweep.status == "cancelled":
            logger.info(f"Sweep {sweep_id} was cancelled — discarding results")
            return

        jobs_created = 0
        for host_ip in hosts:
            new_job = Job(
                type="nmap_scan",
                target=host_ip,
                status="pending",
                mode=mode,
                profile=profile,
                priority="medium",
                sweep_id=sweep_id
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


@app.post("/discover/{sweep_id}/cancel")
def cancel_sweep(
    sweep_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth)
):
    """Mark a running sweep as cancelled. The background thread checks this flag
    before committing jobs and will discard results if it sees 'cancelled'."""
    sweep = db.query(DiscoverySweep).filter(DiscoverySweep.id == sweep_id).first()
    if not sweep:
        raise HTTPException(status_code=404, detail="Sweep not found")
    if sweep.status != "running":
        raise HTTPException(status_code=400, detail=f"Sweep is not running (status: {sweep.status})")
    sweep.status = "cancelled"
    sweep.completed_at = datetime.utcnow()
    db.commit()
    logger.info(f"Sweep {sweep_id} cancelled by user")
    return {"ok": True, "sweep_id": sweep_id, "status": "cancelled"}


@app.post("/sweeps/{sweep_id}/cancel-jobs")
def cancel_sweep_jobs(
    sweep_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    """
    Cancel all pending and running jobs that were created by a sweep.
    Useful for aborting a large sweep after it has already created many jobs.
    """
    sweep = db.query(DiscoverySweep).filter(DiscoverySweep.id == sweep_id).first()
    if not sweep:
        raise HTTPException(status_code=404, detail="Sweep not found")

    cancellable = db.query(Job).filter(
        Job.sweep_id == sweep_id,
        Job.status.in_(["pending", "running"])
    ).all()

    count = 0
    for job in cancellable:
        job.status = "cancelled"
        job.completed_at = datetime.utcnow()
        count += 1

    db.commit()
    logger.info(f"Bulk cancelled {count} job(s) from sweep {sweep_id}")
    return {"ok": True, "sweep_id": sweep_id, "cancelled": count}
def get_sweep_results(
    sweep_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth)
):
    """Return all jobs and their results for a given sweep, grouped by host."""
    sweep = db.query(DiscoverySweep).filter(DiscoverySweep.id == sweep_id).first()
    if not sweep:
        raise HTTPException(status_code=404, detail="Sweep not found")

    jobs = db.query(Job).filter(Job.sweep_id == sweep_id).all()

    hosts = []
    for job in jobs:
        result = db.query(Result).filter(Result.job_id == job.id).first()
        output = None
        if result:
            try:
                output = json.loads(result.output)
            except Exception:
                output = result.output

        hosts.append({
            "job_id": job.id,
            "target": job.target,
            "status": job.status,
            "profile": job.profile,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "result_id": result.id if result else None,
            "output": output,
        })

    return {
        "sweep_id": sweep.id,
        "subnet": sweep.subnet,
        "status": sweep.status,
        "started_at": sweep.started_at.isoformat() if sweep.started_at else None,
        "completed_at": sweep.completed_at.isoformat() if sweep.completed_at else None,
        "hosts": hosts,
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
                <h2 class="section-title">Open Port Scan Results</h2>
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
                <h2 class="section-title">Open Port Scan Results</h2>
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

    # ── Scan type breakdown ────────────────────────────────────────────────────
    scan_type_counts = {}
    for j in jobs:
        label = {"nmap_scan": "Open Port Scan", "nikto_scan": "Web Scan", "nse_scan": "Vulnerability Scan"}.get(j.type, j.type)
        scan_type_counts[label] = scan_type_counts.get(label, 0) + 1

    # ── Port frequency ─────────────────────────────────────────────────────────
    port_host_map: dict = {}
    for r in results:
        try:
            out = json.loads(r.output)
        except Exception:
            continue
        j_ref = job_map.get(r.job_id)
        target_ip = j_ref.target if j_ref else "unknown"
        for h in out.get("nmap", []):
            host_ip = h.get("host") or target_ip
            for p in h.get("ports", []):
                if p.get("state") == "open":
                    port_num = str(p["port"])
                    if port_num not in port_host_map:
                        port_host_map[port_num] = set()
                    port_host_map[port_num].add(host_ip)

    top_ports = sorted(
        [{"port": k, "host_count": len(v)} for k, v in port_host_map.items()],
        key=lambda x: x["host_count"],
        reverse=True
    )[:15]

    # ── Coverage gaps (all-time, not window-scoped) ────────────────────────────
    # Hosts that have ever been port-scanned but whose last vuln scan
    # is either absent or older than 30 days — genuinely unassessed hosts.
    all_nmap_jobs = db.query(Job).filter(
        Job.type == "nmap_scan",
        Job.status == "done"
    ).all()
    all_nse_jobs = db.query(Job).filter(
        Job.type == "nse_scan",
        Job.status == "done"
    ).all()

    all_nmap_hosts = set(j.target for j in all_nmap_jobs)
    # Map each host to its most recent completed nse scan date
    nse_by_host: dict = {}
    for j in all_nse_jobs:
        if j.completed_at:
            nse_by_host[j.target] = max(nse_by_host.get(j.target, datetime.min), j.completed_at)

    stale_threshold = datetime.utcnow() - timedelta(days=30)
    coverage_gaps = []
    for host in sorted(all_nmap_hosts):
        last_nse = nse_by_host.get(host)
        if last_nse is None:
            coverage_gaps.append({"ip": host, "last_vuln_scan": None, "days_ago": None})
        elif last_nse < stale_threshold:
            days = (datetime.utcnow() - last_nse).days
            coverage_gaps.append({"ip": host, "last_vuln_scan": last_nse.strftime("%Y-%m-%d"), "days_ago": days})
    coverage_gaps.sort(key=lambda x: (x["last_vuln_scan"] or "", x["ip"]))
 
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
        "scan_activity":    scan_activity,
        "scan_type_counts": scan_type_counts,
        "top_ports":        top_ports,
        "coverage_gaps":    coverage_gaps,
        "hosts":            hosts_list,
        "scan_history":     scan_history,
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
             
            /* ── Result card hover tooltip ── */
            .result-tooltip {
                position: absolute;
                bottom: calc(100% + 8px);
                left: 50%;
                transform: translateX(-50%);
                min-width: 240px;
                max-width: 320px;
                background: #060a10;
                border: 1px solid #2a3347;
                border-radius: 8px;
                padding: 10px 14px;
                pointer-events: none;
                opacity: 0;
                transition: opacity 0.12s ease;
                z-index: 30;
                white-space: nowrap;
                box-shadow: 0 8px 32px rgba(0,0,0,0.6);
            }
            .result-tooltip.visible {
                opacity: 1;
            }
            /* Arrow pointing down */
            .result-tooltip::after {
                content: '';
                position: absolute;
                top: 100%;
                left: 50%;
                transform: translateX(-50%);
                border: 5px solid transparent;
                border-top-color: #2a3347;
            }
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
            <div class="bg-gray-900 border border-gray-700 rounded-xl p-6 w-full max-w-lg max-h-screen overflow-y-auto">
                <div class="flex items-center gap-3 mb-3">
                    <span class="text-cyan-400 text-lg">⌖</span>
                    <h3 class="text-sm font-semibold text-white">Assign Scan Jobs?</h3>
                </div>
                <p id="sweepConfirmMsg" class="text-xs text-gray-400 mb-2"></p>
                <!-- Large sweep warning — shown when host count exceeds threshold -->
                <div id="sweepLargeWarning" class="hidden mb-3 p-3 bg-yellow-950 border border-yellow-700 rounded-lg text-xs text-yellow-300 space-y-1">
                    <p class="font-semibold">⚠ Large sweep detected</p>
                    <p id="sweepLargeWarningMsg"></p>
                    <p>For faster results, consider registering additional scanner instances from the Agents tab.</p>
                </div>
                <div id="sweepHostList" class="max-h-32 overflow-y-auto mb-4 space-y-1"></div>

                <!-- Job type + profile selectors -->
                <div class="bg-gray-800 border border-gray-700 rounded-lg p-4 mb-4 space-y-3">
                    <p class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Scan Settings</p>
                    <div class="grid grid-cols-2 gap-3">
                        <div class="flex flex-col gap-1">
                            <label class="text-xs text-gray-500">Scan Type</label>
                            <select id="sweepJobType" onchange="onSweepJobTypeChange()"
                                class="bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-cyan-500">
                                <option value="nmap_scan">Open Port Scan</option>
                                <option value="nse_scan">Vulnerability Scan</option>
                                <option value="nikto_scan">Web Scan</option>
                            </select>
                        </div>
                        <div class="flex flex-col gap-1">
                            <label class="text-xs text-gray-500">Profile</label>
                            <select id="sweepProfile" onchange="onSweepProfileChange()"
                                class="bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-cyan-500">
                                <option value="standard">Standard</option>
                                <option value="light">Light</option>
                                <option value="full">Full</option>
                                <option value="custom">Custom</option>
                            </select>
                        </div>
                    </div>

                    <!-- Sweep mode + priority -->
                    <div class="grid grid-cols-2 gap-3">
                        <div class="flex flex-col gap-1">
                            <label class="text-xs text-gray-500">Mode</label>
                            <select id="sweepJobMode"
                                class="bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-cyan-500">
                                <option value="remote">Remote</option>
                                <option value="agent">Agent</option>
                            </select>
                        </div>
                        <div class="flex flex-col gap-1">
                            <label class="text-xs text-gray-500">Priority</label>
                            <select id="sweepJobPriority"
                                class="bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-cyan-500">
                                <option value="medium">Medium</option>
                                <option value="high">High</option>
                                <option value="low">Low</option>
                            </select>
                        </div>
                    </div>

                    <!-- Intrusive warning — shown for full profile -->
                    <div id="sweepFullWarning" class="hidden flex items-start gap-2 bg-red-950 border border-red-800 rounded-lg px-3 py-2">
                        <span class="text-red-400 text-xs mt-0.5 flex-shrink-0">⚠</span>
                        <p class="text-xs text-red-300">Full profile with Vulnerability Scan uses <span class="font-mono">--script vuln,exploit</span> — intrusive scripts that may disrupt services.</p>
                    </div>
                </div>

                <!-- Custom profile capability cards (compact) — shown when type=nse_scan + profile=custom -->
                <div id="sweepCustomPanel" class="hidden mb-4">
                    <div class="flex items-center justify-between mb-2">
                        <p class="text-xs font-semibold text-green-400 uppercase tracking-wider">Select Capabilities</p>
                        <div class="flex items-center gap-3">
                            <button onclick="sweepSelectAll()" class="text-xs text-gray-500 hover:text-gray-300 transition">Select all</button>
                            <button onclick="sweepClearAll()" class="text-xs text-gray-500 hover:text-gray-300 transition">Clear all</button>
                            <span id="sweepScriptCount" class="text-xs text-gray-600">0 scripts selected</span>
                        </div>
                    </div>
                    <div id="sweepCapabilityCards" class="space-y-1.5"></div>
                    <p id="sweepCustomWarning" class="hidden mt-2 text-xs text-red-400">Select at least one capability before assigning jobs.</p>
                </div>

                <p id="sweepConfirmNote" class="text-xs text-gray-500 mb-5">Confirming will create a Open Port Scan job for each host above.</p>
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
                        <div class="flex items-center justify-between gap-4">
                            <div class="min-w-0">
                                <p class="text-sm text-gray-300">AI auto-analysis</p>
                                <p class="text-xs text-gray-600 mt-0.5">Analyse results automatically after each scan</p>
                            </div>
                            <button id="setting-ai-toggle" onclick="toggleServerSetting('ai_auto_analyse')"
                                class="relative w-11 h-6 rounded-full transition-colors duration-200 focus:outline-none flex-shrink-0">
                                <span id="setting-ai-knob"
                                    class="absolute top-0.5 left-0.5 w-5 h-5 rounded-full transition-transform duration-200"></span>
                            </button>
                        </div>

                        <div class="flex items-center justify-between gap-4">
                            <div class="min-w-0">
                                <p class="text-sm text-gray-300">Auto web scan after port scan</p>
                                <p class="text-xs text-gray-600 mt-0.5">Automatically run Nikto when web ports are found in an Open Port Scan. Disable to make port scans faster.</p>
                            </div>
                            <button id="setting-nikto-toggle" onclick="toggleServerSetting('auto_nikto')"
                                class="relative w-11 h-6 rounded-full transition-colors duration-200 focus:outline-none flex-shrink-0">
                                <span id="setting-nikto-knob"
                                    class="absolute top-0.5 left-0.5 w-5 h-5 rounded-full transition-transform duration-200"></span>
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
                <div class="w-3 h-3 rounded-full bg-green-400 animate-ping opacity-75"></div>
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
                    Network Map
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
                        <label class="text-xs text-gray-400">Target</label>
                        <input id="target" placeholder="IP or hostname"
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
                            <option value="nmap_scan">Open Port Scan</option>
                            <option value="nikto_scan">Web Scan</option>
                            <option value="nse_scan">Vulnerability Scan</option>
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
                        <select id="profile" onchange="onProfileChange()" class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                            <option value="standard">Standard</option>
                            <option value="light">Light</option>
                            <option value="full">Full</option>
                            <option value="custom">Custom</option>
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
                <!-- Custom Profile — Capability Cards -->
                <div id="customProfilePanel" class="hidden mt-5">
                    <div class="flex items-center justify-between mb-3">
                        <p class="text-xs font-semibold text-green-400 uppercase tracking-wider">Select Capabilities</p>
                        <div class="flex items-center gap-3">
                            <button onclick="selectAllCapabilities()" class="text-xs text-gray-500 hover:text-gray-300 transition">Select all</button>
                            <button onclick="clearAllCapabilities()" class="text-xs text-gray-500 hover:text-gray-300 transition">Clear all</button>
                            <span id="customScriptCount" class="text-xs text-gray-600">0 scripts selected</span>
                        </div>
                    </div>
                    <div id="capabilityCards" class="space-y-2"></div>
                    <p id="customProfileWarning" class="hidden mt-3 text-xs text-red-400">Select at least one capability before creating the job.</p>
                </div>

                <!-- Custom Nikto Profile — Tuning Category Cards -->
                <div id="niktoCustomPanel" class="hidden mt-5">
                    <div class="flex items-center justify-between mb-3">
                        <p class="text-xs font-semibold text-purple-400 uppercase tracking-wider">Select Test Categories</p>
                        <div class="flex items-center gap-3">
                            <button onclick="selectAllNiktoCategories()" class="text-xs text-gray-500 hover:text-gray-300 transition">Select all</button>
                            <button onclick="clearAllNiktoCategories()" class="text-xs text-gray-500 hover:text-gray-300 transition">Clear all</button>
                            <span id="niktoCategoryCount" class="text-xs text-gray-600">0 categories selected</span>
                        </div>
                    </div>
                    <div id="niktoCategoryCards" class="grid grid-cols-2 gap-2"></div>
                    <p id="niktoCustomWarning" class="hidden mt-3 text-xs text-red-400">Select at least one category before creating the job.</p>
                </div>
            </div>

            <!-- Agents -->
            <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-lg font-semibold text-green-400">Agents</h2>
                    <div class="flex items-center gap-2">
                        <button onclick="openRegisterScanner()"
                            class="text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-green-500 hover:text-green-400 transition">+ Register Scanner</button>
                        <button onclick="toggleStaleAgents()" id="staleAgentsBtn"
                            class="text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-yellow-500 transition">Show Stale</button>
                    </div>
                </div>
                <div id="agents" class="overflow-x-auto"></div>
            </div>

            <!-- Register Scanner Modal -->
            <div id="registerScannerBackdrop" class="hidden fixed inset-0 bg-black bg-opacity-60 z-40" onclick="closeRegisterScanner()"></div>
            <div id="registerScannerModal" class="hidden fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full max-w-lg">
                <div class="flex items-center justify-between px-6 py-4 border-b border-gray-800">
                    <h3 class="text-sm font-semibold text-green-400">Register New Scanner</h3>
                    <button onclick="closeRegisterScanner()" class="text-gray-500 hover:text-gray-300 transition text-lg leading-none">✕</button>
                </div>
                <div id="registerScannerForm" class="px-6 py-5 space-y-4">
                    <div>
                        <label class="text-xs text-gray-400 block mb-1">Scanner name</label>
                        <input id="scannerName" placeholder="scanner-2" class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                        <p class="text-xs text-gray-600 mt-1">Leave blank to use the suggested name.</p>
                    </div>
                    <div>
                        <label class="text-xs text-gray-400 block mb-1">Capabilities</label>
                        <input id="scannerCaps" value="nmap_scan,nikto_scan,nse_scan" class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                        <p class="text-xs text-gray-600 mt-1">Comma-separated. Options: <span class="font-mono">nmap_scan</span>, <span class="font-mono">nikto_scan</span>, <span class="font-mono">nse_scan</span></p>
                    </div>
                    <button onclick="submitRegisterScanner()" class="w-full bg-green-700 hover:bg-green-600 text-white text-sm font-medium py-2 rounded-lg transition">Register</button>
                    <p class="text-xs text-gray-600 text-center">Registration creates the agent record and API key. To enable auto-start on this server, add <span class="font-mono text-gray-500">SCANNER_AUTOSTART=true</span> to your <span class="font-mono text-gray-500">.env</span> file and restart the server.</p>
                </div>
                <div id="registerScannerResult" class="hidden px-6 pb-6 space-y-4">
                    <div id="registerScannerStatusBanner" class="mb-3 p-3 bg-green-950 border border-green-800 rounded-lg text-xs text-green-300">
                        Scanner registered.
                    </div>
                    <div>
                        <div class="flex items-center justify-between mb-1">
                            <p class="text-xs text-gray-400">API key</p>
                            <button onclick="copyText('resultApiKey')" class="text-xs text-gray-500 hover:text-gray-300 transition">Copy</button>
                        </div>
                        <pre id="resultApiKey" class="text-xs font-mono bg-gray-800 rounded-lg p-3 text-cyan-300 overflow-x-auto select-all whitespace-pre-wrap break-all"></pre>
                    </div>
                    <div>
                        <div class="flex items-center justify-between mb-1">
                            <p class="text-xs text-gray-400">Setup commands</p>
                            <button onclick="copyText('resultSetupCmds')" class="text-xs text-gray-500 hover:text-gray-300 transition">Copy</button>
                        </div>
                        <pre id="resultSetupCmds" class="text-xs font-mono bg-gray-800 rounded-lg p-3 text-gray-300 overflow-x-auto whitespace-pre-wrap break-all"></pre>
                    </div>
                    <div>
                        <div class="flex items-center justify-between mb-1">
                            <p class="text-xs text-gray-400">Systemd service (save as <span class="font-mono">/etc/systemd/system/vapt-scanner-<span id="resultServiceName"></span>.service</span>)</p>
                            <button onclick="copyText('resultServiceFile')" class="text-xs text-gray-500 hover:text-gray-300 transition">Copy</button>
                        </div>
                        <pre id="resultServiceFile" class="text-xs font-mono bg-gray-800 rounded-lg p-3 text-gray-300 overflow-x-auto whitespace-pre-wrap break-all"></pre>
                    </div>
                    <button onclick="closeRegisterScanner()" class="w-full border border-gray-700 hover:border-gray-500 text-gray-400 hover:text-gray-200 text-sm py-2 rounded-lg transition">Done</button>
                </div>
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
                    <button id="cancelSweepBtn" onclick="cancelActiveSweep()" class="hidden text-xs px-2 py-1 rounded bg-red-900 hover:bg-red-800 text-red-300 hover:text-red-200 transition">Cancel Sweep</button>
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

                <!-- Sweep result detail panel -->
                <div id="sweepResultPanel" class="hidden mb-4 bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
                    <div class="flex items-center justify-between px-4 py-3 border-b border-gray-700">
                        <p class="text-xs font-semibold text-cyan-400" id="sweepResultTitle">Sweep Results</p>
                        <div class="flex items-center gap-3">
                            <button id="sweepCancelJobsBtn" onclick="cancelSweepJobs()" class="hidden text-xs px-2 py-1 rounded bg-red-900 hover:bg-red-800 text-red-300 hover:text-red-200 transition">Cancel All Jobs</button>
                            <button onclick="closeSweepResultPanel()" class="text-gray-500 hover:text-gray-300 transition text-sm">✕</button>
                        </div>
                    </div>
                    <div id="sweepResultBody" class="p-4 overflow-x-auto max-h-80 overflow-y-auto text-xs"></div>
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
                        <label class="text-xs text-gray-400">Target</label>
                        <input id="sched_target" placeholder="IP or hostname"
                            class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500 w-36">
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Scan Type</label>
                        <select id="sched_type" onchange="onSchedTypeChange()" class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                            <option value="nmap_scan">Open Port Scan</option>
                            <option value="nikto_scan">Web Scan</option>
                            <option value="nse_scan">Vulnerability Scan</option>
                        </select>
                    </div>
                    <div class="flex flex-col gap-1" id="schedPortField" style="display:none">
                        <label class="text-xs text-gray-400">Port</label>
                        <input id="sched_port" type="number" placeholder="80"
                            class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500 w-20">
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

            <!-- Scan type breakdown + Port frequency side by side -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6" id="insightExtraCharts">
                <div class="bg-gray-900 rounded-xl border border-gray-800 p-5">
                    <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">Scan Type Breakdown</h3>
                    <div class="relative h-48 flex items-center justify-center">
                        <canvas id="chartScanTypes"></canvas>
                    </div>
                </div>
                <div class="bg-gray-900 rounded-xl border border-gray-800 p-5">
                    <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">Top Open Ports (by host count)</h3>
                    <div class="relative h-48">
                        <canvas id="chartTopPorts"></canvas>
                    </div>
                </div>
            </div>

            <!-- Coverage gaps -->
            <div id="insightCoverageGaps" class="hidden bg-gray-900 rounded-xl border border-yellow-900 p-5">
                <div class="flex items-center gap-2 mb-3">
                    <h3 class="text-xs font-semibold text-yellow-400 uppercase tracking-wider">Coverage Gaps</h3>
                    <span class="text-xs text-gray-600">— hosts port-scanned but not vuln-scanned in the last 30 days (all-time)</span>
                </div>
                <div id="insightCoverageGapsBody" class="flex flex-wrap gap-2 items-center"></div>
            </div>

            <!-- Host table (aggregate) or scan timeline (per-host) -->
            <div id="insightHostTable" class="bg-gray-900 rounded-xl border border-gray-800 p-5">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Scanned Hosts</h3>
                </div>
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

            <!-- Top bar -->
            <div class="flex items-center justify-between mb-6 flex-wrap gap-4">
                <div>
                    <h2 class="text-lg font-semibold text-green-400">Network Map</h2>
                    <p class="text-xs text-gray-600 mt-0.5">All discovered hosts grouped by subnet, coloured by risk level</p>
                </div>
                <div class="flex items-center gap-3">
                    <!-- Risk filter -->
                    <div class="flex items-center gap-1 bg-gray-900 border border-gray-800 rounded-lg p-1">
                        <button onclick="setMapFilter('all')"        id="mf-all"        class="map-filter-btn text-xs px-3 py-1 rounded-md transition font-medium bg-gray-700 text-white">All</button>
                        <button onclick="setMapFilter('CRITICAL')"   id="mf-CRITICAL"   class="map-filter-btn text-xs px-3 py-1 rounded-md transition font-medium text-gray-400 hover:text-white">Critical</button>
                        <button onclick="setMapFilter('HIGH')"       id="mf-HIGH"       class="map-filter-btn text-xs px-3 py-1 rounded-md transition font-medium text-gray-400 hover:text-white">High</button>
                        <button onclick="setMapFilter('MEDIUM')"     id="mf-MEDIUM"     class="map-filter-btn text-xs px-3 py-1 rounded-md transition font-medium text-gray-400 hover:text-white">Medium</button>
                        <button onclick="setMapFilter('UNANALYSED')" id="mf-UNANALYSED" class="map-filter-btn text-xs px-3 py-1 rounded-md transition font-medium text-gray-400 hover:text-white">Unanalysed</button>
                    </div>
                    <button onclick="loadTopology()" class="text-xs px-3 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-400 transition">↻ Refresh</button>
                </div>
            </div>

            <!-- Summary stats row -->
            <div id="mapStats" class="flex gap-4 flex-wrap mb-6"></div>

            <!-- Network map body -->
            <div id="mapBody" class="space-y-6"></div>

            <!-- Empty state -->
            <div id="mapEmpty" class="hidden text-center py-20">
                <div class="text-4xl mb-4 opacity-20">⌖</div>
                <p class="text-gray-500 text-sm font-medium mb-1">No hosts mapped yet</p>
                <p class="text-gray-700 text-xs mb-4">Run a discovery sweep or an Open Port Scan to populate the map.</p>
                <button onclick="switchTab('discovery')" class="text-xs px-4 py-2 rounded-lg bg-green-900 hover:bg-green-800 text-green-300 border border-green-800 transition font-medium">→ Go to Discovery</button>
            </div>

            <!-- Colour legend -->
            <div class="mt-6 flex flex-wrap gap-4 text-xs text-gray-500">
                <span class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full bg-red-500 inline-block"></span>Critical</span>
                <span class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full bg-orange-500 inline-block"></span>High</span>
                <span class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full bg-yellow-400 inline-block"></span>Medium</span>
                <span class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full bg-blue-400 inline-block"></span>Low / Info</span>
                <span class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full bg-gray-500 inline-block"></span>Unanalysed</span>
                <span class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full bg-green-500 inline-block"></span>Unscanned</span>
                <span class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full border-2 border-cyan-400 bg-transparent inline-block"></span>Agent host</span>
            </div>

        </div>
        </div>

        <!-- ── SCRIPTS ──────────────────────────────────────────────────── -->
        <script>
        
         function goToResult(resultId) {
            resultTab = 'active';
            switchTab('dashboard');
            setTimeout(async () => {
                // First do a full load to get all results into pageData
                await loadResults();

                // Find which page the result is on and jump to it
                const allResults = pageData.results;
                const idx = allResults.findIndex(r => r.id === resultId);
                if (idx >= 0) {
                    const targetPage = Math.floor(idx / PAGE_SIZES.results) + 1;
                    if (pages.results !== targetPage) {
                        pages.results = targetPage;
                        renderResults();
                    }
                }

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
        let mapFilter = 'all';

        // Tracks job statuses from last poll — used to detect completions
        let lastJobStatuses = {};

        // ── PAGINATION STATE ──────────────────────────────────────────────
        // Each tab has its own current page. Page size is shared but can be
        // overridden per tab. All are 1-indexed.
        const PAGE_SIZES = { results: 10, jobs: 20, agents: 20, sweeps: 10 };
        let pages = { results: 1, jobs: 1, agents: 1, sweeps: 1 };
        // Store the last-fetched data so pagination can re-render without re-fetching
        let pageData = { results: [], jobs: [], agents: [], sweeps: [] };
        
        // Friendly display names for scan types
        const SCAN_TYPE_LABELS = {
            nmap_scan:   'Open Port Scan',
            nikto_scan:  'Web Scan',
            nse_scan:    'Vulnerability Scan',
        };
        function scanTypeLabel(type) {
            return SCAN_TYPE_LABELS[type] || type;
        }

        // ── PAGINATION HELPERS ─────────────────────────────────────────────
        /**
         * Returns the slice of `items` for the current page of `tab`.
         */
        function getPage(tab, items) {
            const size  = PAGE_SIZES[tab];
            const start = (pages[tab] - 1) * size;
            return items.slice(start, start + size);
        }

        /**
         * Builds and returns the pagination bar HTML for a given tab.
         * `total` is the total number of items (before slicing).
         * Calls `goPage_<tab>(n)` on click.
         */
        function paginationBar(tab, total) {
            const size     = PAGE_SIZES[tab];
            const numPages = Math.ceil(total / size);
            if (numPages <= 1) return '';

            const cur = pages[tab];
            const fn  = `goPage_${tab}`;

            // Build page number buttons — show at most 5 around current page
            let pageNums = '';
            const lo = Math.max(1, cur - 2);
            const hi = Math.min(numPages, cur + 2);
            if (lo > 1) pageNums += `<button onclick="${fn}(1)" class="pagination-num px-2 py-1 rounded text-xs text-gray-400 hover:text-gray-200 hover:bg-gray-700 transition">1</button>`;
            if (lo > 2) pageNums += `<span class="text-gray-600 text-xs px-1">…</span>`;
            for (let p = lo; p <= hi; p++) {
                const active = p === cur ? 'bg-gray-700 text-gray-100' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700';
                pageNums += `<button onclick="${fn}(${p})" class="pagination-num px-2 py-1 rounded text-xs ${active} transition">${p}</button>`;
            }
            if (hi < numPages - 1) pageNums += `<span class="text-gray-600 text-xs px-1">…</span>`;
            if (hi < numPages) pageNums += `<button onclick="${fn}(${numPages})" class="pagination-num px-2 py-1 rounded text-xs text-gray-400 hover:text-gray-200 hover:bg-gray-700 transition">${numPages}</button>`;

            const start = (cur - 1) * size + 1;
            const end   = Math.min(cur * size, total);

            return `<div class="flex items-center justify-between mt-4 pt-3 border-t border-gray-800">
                <span class="text-xs text-gray-600">${start}–${end} of ${total}</span>
                <div class="flex items-center gap-1">
                    <button onclick="${fn}(${cur - 1})" ${cur === 1 ? 'disabled' : ''} class="px-2 py-1 rounded text-xs text-gray-400 hover:text-gray-200 hover:bg-gray-700 transition disabled:opacity-30 disabled:cursor-not-allowed">‹</button>
                    ${pageNums}
                    <button onclick="${fn}(${cur + 1})" ${cur === numPages ? 'disabled' : ''} class="px-2 py-1 rounded text-xs text-gray-400 hover:text-gray-200 hover:bg-gray-700 transition disabled:opacity-30 disabled:cursor-not-allowed">›</button>
                </div>
                <select onchange="changePageSize('${tab}', parseInt(this.value))" class="text-xs bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-400 focus:outline-none">
                    ${[10, 20, 50].map(n => `<option value="${n}" ${n === size ? 'selected' : ''}>${n} per page</option>`).join('')}
                </select>
            </div>`;
        }

        function goPage_results(n) { pages.results = n; renderResults(); }
        function goPage_jobs(n)    { pages.jobs    = n; renderJobs();    }
        function goPage_agents(n)  { pages.agents  = n; renderAgents();  }
        function goPage_sweeps(n)  { pages.sweeps  = n; renderSweeps();  }

        function changePageSize(tab, size) {
            PAGE_SIZES[tab] = size;
            pages[tab] = 1;  // reset to page 1 on size change
            if (tab === 'results') renderResults();
            if (tab === 'jobs')    renderJobs();
            if (tab === 'agents')  renderAgents();
            if (tab === 'sweeps')  renderSweeps();
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
                    refreshJobs();
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
            function applyToggle(btnId, knobId, isOn) {
                const btn  = document.getElementById(btnId);
                const knob = document.getElementById(knobId);
                if (!btn || !knob) return;

                // Track classes (button)
                const onClasses  = ['bg-green-600', 'border', 'border-green-500'];
                const offClasses = ['bg-gray-700',  'border', 'border-gray-600'];
                if (isOn) {
                    offClasses.forEach(c => btn.classList.remove(c));
                    onClasses.forEach(c  => btn.classList.add(c));
                } else {
                    onClasses.forEach(c  => btn.classList.remove(c));
                    offClasses.forEach(c => btn.classList.add(c));
                }

                // Knob position and colour
                knob.style.transform = isOn ? 'translateX(20px)' : 'translateX(0)';
                knob.classList.remove('bg-white', 'bg-gray-400');
                knob.classList.add(isOn ? 'bg-white' : 'bg-gray-400');
            }

            applyToggle('setting-ai-toggle',    'setting-ai-knob',    serverSettings['ai_auto_analyse'] === 'true');
            applyToggle('setting-nikto-toggle', 'setting-nikto-knob', serverSettings['auto_nikto'] !== 'false');

            const staleInput = document.getElementById('setting-stale-hours');
            if (staleInput) staleInput.value = serverSettings['stale_agent_hours'] || '24';
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
                    loadServerSettings();
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
            // Hide ports field when custom profile is active (port derivation is automatic)
            if (type === 'nse_scan' && document.getElementById('profile').value === 'custom') {
                document.getElementById("portsField").style.display = "none";
            }
            // Update target placeholder — Nikto accepts URLs, nmap/nse do not
            const targetInput = document.getElementById('target');
            if (targetInput) {
                targetInput.placeholder = type === 'nikto_scan' ? 'IP, hostname, or URL' : 'IP or hostname';
            }
            updateNseExploitBanner();
            onProfileChange();
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
        
        // ── CUSTOM PROFILE CAPABILITY DATA ────────────────────────────────────
        const CUSTOM_CAPABILITIES = [
            {
                id: "auth",
                label: "Authentication & Access Control",
                tooltip: "Checks for anonymous access, weak auth methods, and insecure credential handling across common services.",
                scripts: [
                    { id: "ftp-anon",               label: "FTP Anonymous",          desc: "Checks if the FTP server allows anonymous login.",                                     default: true  },
                    { id: "http-auth-finder",        label: "HTTP Auth Finder",       desc: "Discovers HTTP authentication methods in use (Basic, Digest, NTLM, etc.).",           default: true  },
                    { id: "ssh-auth-methods",        label: "SSH Auth Methods",       desc: "Lists authentication methods accepted by the SSH server.",                             default: true  },
                    { id: "snmp-brute",              label: "SNMP Brute",             desc: "Attempts to guess SNMP community strings using default values only.",                  default: true  },
                    { id: "smb-security-mode",       label: "SMB Security Mode",      desc: "Reports whether SMB message signing and plaintext auth are in use.",                   default: true  },
                    { id: "http-open-proxy",         label: "HTTP Open Proxy",        desc: "Tests whether the HTTP server is acting as an open proxy.",                            default: false },
                    { id: "irc-unrealircd-backdoor", label: "UnrealIRCd Backdoor",    desc: "Checks for the UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075).",                        default: false },
                ],
            },
            {
                id: "smb",
                label: "Windows & SMB Enumeration",
                tooltip: "Enumerates Windows host information, SMB shares, and checks for critical SMB vulnerabilities including EternalBlue.",
                scripts: [
                    { id: "smb-os-discovery",   label: "OS Discovery",       desc: "Attempts to determine the OS, computer name, domain, and workgroup via SMB.",    default: true  },
                    { id: "smb-system-info",    label: "System Info",        desc: "Retrieves system information from the SMB server (OS version, build, etc.).",   default: true  },
                    { id: "smb-enum-shares",    label: "Enum Shares",        desc: "Enumerates SMB shares and their access permissions.",                            default: true  },
                    { id: "smb-security-mode",  label: "Security Mode",      desc: "Reports whether SMB signing is enabled and if plaintext passwords are used.",   default: true  },
                    { id: "smb-vuln-ms17-010",  label: "EternalBlue",        desc: "Checks for MS17-010 (EternalBlue) — the vulnerability exploited by WannaCry.", default: true  },
                    { id: "smb-vuln-ms10-054",  label: "MS10-054",           desc: "Checks for MS10-054, a remote memory corruption vulnerability in SMBv1.",       default: true  },
                    { id: "smb-enum-users",     label: "Enum Users",         desc: "Enumerates local user accounts via SMB (may require credentials).",             default: false },
                    { id: "smb-enum-groups",    label: "Enum Groups",        desc: "Enumerates local groups via SMB (may require credentials).",                    default: false },
                    { id: "smb-enum-sessions",  label: "Enum Sessions",      desc: "Lists active SMB sessions on the server.",                                      default: false },
                    { id: "smb-enum-domains",   label: "Enum Domains",       desc: "Enumerates domains visible through SMB.",                                       default: false },
                ],
            },
            {
                id: "snmp",
                label: "SNMP & Network Device Enumeration",
                tooltip: "Queries SNMP-enabled devices for system information, interface details, and running processes.",
                scripts: [
                    { id: "snmp-info",          label: "SNMP Info",          desc: "Retrieves basic system info from SNMP (sysDescr, sysUpTime, etc.).",            default: true  },
                    { id: "snmp-sysdescr",      label: "System Description", desc: "Fetches the SNMP sysDescr OID — often reveals OS and firmware version.",       default: true  },
                    { id: "snmp-interfaces",    label: "Interfaces",         desc: "Lists network interfaces and their IP addresses via SNMP.",                     default: true  },
                    { id: "snmp-netstat",       label: "Netstat",            desc: "Retrieves the TCP/UDP connection table via SNMP.",                              default: false },
                    { id: "snmp-processes",     label: "Processes",          desc: "Lists running processes on the target via SNMP.",                               default: false },
                    { id: "snmp-win32-users",   label: "Win32 Users",        desc: "Enumerates Windows local user accounts via SNMP (Windows targets only).",      default: false },
                    { id: "snmp-win32-shares",  label: "Win32 Shares",       desc: "Lists Windows file shares via SNMP (Windows targets only).",                   default: false },
                ],
            },
            {
                id: "ssl",
                label: "SSL/TLS Analysis",
                tooltip: "Analyses SSL/TLS configuration for weak ciphers, expired certificates, and known protocol vulnerabilities.",
                scripts: [
                    { id: "ssl-cert",           label: "Certificate",        desc: "Retrieves and displays the server's SSL certificate details.",                  default: true  },
                    { id: "ssl-enum-ciphers",   label: "Cipher Suites",      desc: "Enumerates supported SSL/TLS cipher suites and grades their strength.",        default: true  },
                    { id: "ssl-heartbleed",     label: "Heartbleed",         desc: "Tests for the OpenSSL Heartbleed vulnerability (CVE-2014-0160).",              default: true  },
                    { id: "ssl-poodle",         label: "POODLE",             desc: "Checks for the POODLE vulnerability in SSLv3 (CVE-2014-3566).",               default: true  },
                    { id: "ssl-dh-params",      label: "DH Parameters",      desc: "Checks Diffie-Hellman parameters for weaknesses (Logjam vulnerability).",      default: true  },
                    { id: "ssl-ccs-injection",  label: "CCS Injection",      desc: "Tests for the OpenSSL CCS Injection vulnerability (CVE-2014-0224).",          default: true  },
                    { id: "tls-ticketbleed",    label: "Ticketbleed",        desc: "Checks for the Ticketbleed vulnerability in F5 TLS session tickets.",          default: false },
                    { id: "ssl-known-key",      label: "Known Key",          desc: "Checks whether the SSL key is in a known-compromised key database.",           default: false },
                ],
            },
            {
                id: "discovery",
                label: "Network Service Discovery",
                tooltip: "Probes common network services for misconfigurations — DNS zone transfers, NFS exports, RDP settings, and more.",
                scripts: [
                    { id: "dns-zone-transfer",       label: "DNS Zone Transfer",  desc: "Attempts a DNS zone transfer — reveals all DNS records if misconfigured.",    default: true  },
                    { id: "dns-recursion",           label: "DNS Recursion",      desc: "Checks if the DNS server allows recursive queries (open resolver).",          default: true  },
                    { id: "nfs-ls",                  label: "NFS List",           desc: "Lists files on NFS exports accessible without authentication.",               default: true  },
                    { id: "nfs-showmount",           label: "NFS Showmount",      desc: "Shows the NFS server's export list.",                                        default: true  },
                    { id: "rdp-enum-encryption",     label: "RDP Encryption",     desc: "Enumerates RDP security settings and supported encryption protocols.",        default: true  },
                    { id: "telnet-encryption",       label: "Telnet Encryption",  desc: "Checks whether Telnet is offering encryption (rare — usually it isn't).",    default: true  },
                    { id: "vnc-info",                label: "VNC Info",           desc: "Retrieves VNC server information including protocol version and auth type.",  default: true  },
                    { id: "finger",                  label: "Finger",             desc: "Queries the finger service to enumerate user accounts.",                      default: false },
                    { id: "broadcast-dhcp-discover", label: "DHCP Discover",      desc: "Sends a broadcast DHCP discover packet to identify DHCP servers.",           default: false },
                    { id: "ldap-rootdse",            label: "LDAP Root DSE",      desc: "Retrieves the LDAP root DSE entry — reveals domain and server info.",        default: false },
                ],
            },
        ];

        // ── CUSTOM PROFILE STATE ───────────────────────────────────────────────
        // capabilityState[capId][scriptId] = true/false
        // Tracks individual script toggles independently of the top-level toggle.
        let capabilityState = {};

        function initCapabilityState() {
            capabilityState = {};
            CUSTOM_CAPABILITIES.forEach(cap => {
                capabilityState[cap.id] = {};
                cap.scripts.forEach(s => {
                    capabilityState[cap.id][s.id] = false;
                });
            });
        }

        function isCapabilityOn(capId) {
            // A capability is "on" if at least one script in it is checked
            return Object.values(capabilityState[capId] || {}).some(v => v);
        }

        function areAllScriptsOn(capId) {
            return Object.values(capabilityState[capId] || {}).every(v => v);
        }

        function getSelectedScripts() {
            const selected = [];
            CUSTOM_CAPABILITIES.forEach(cap => {
                cap.scripts.forEach(s => {
                    if (capabilityState[cap.id] && capabilityState[cap.id][s.id]) {
                        selected.push(s.id);
                    }
                });
            });
            return [...new Set(selected)];
        }

        function updateScriptCount() {
            const n = getSelectedScripts().length;
            const el = document.getElementById('customScriptCount');
            if (el) el.textContent = n === 1 ? '1 script selected' : `${n} scripts selected`;
        }

        // ── CAPABILITY CARD RENDERING ──────────────────────────────────────────

        function renderCapabilityCards() {
            const container = document.getElementById('capabilityCards');
            if (!container) return;

            container.innerHTML = CUSTOM_CAPABILITIES.map(cap => {
                const capOn = isCapabilityOn(cap.id);
                const allOn = areAllScriptsOn(cap.id);

                // Top-level toggle state
                const toggleBg    = allOn ? 'bg-green-600 border-green-500' : (capOn ? 'bg-green-900 border-green-700' : 'bg-gray-700 border-gray-600');
                const toggleKnob  = (allOn || capOn) ? 'translate-x-5' : 'translate-x-0';
                const knobColor   = (allOn || capOn) ? 'bg-white' : 'bg-gray-400';

                // Script rows (collapsed by default)
                const scriptRows = cap.scripts.map(s => {
                    const checked = capabilityState[cap.id][s.id];
                    const defaultTag = s.default
                        ? ''
                        : '<span class="ml-1.5 text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-600 border border-gray-700 font-mono leading-none">sensitive</span>';
                    return `
                    <div class="flex items-center justify-between py-1.5 border-b border-gray-800 last:border-0 group">
                        <div class="flex items-center gap-2 min-w-0">
                            <span class="text-xs text-gray-300 font-mono truncate" title="${escHtmlAttr(s.desc)}">${s.label}</span>
                            ${defaultTag}
                            <span class="hidden group-hover:inline text-xs text-gray-600 ml-1 truncate">${escHtmlAttr(s.desc)}</span>
                        </div>
                        <button
                            onclick="toggleScript('${cap.id}', '${s.id}')"
                            id="script-toggle-${cap.id}-${s.id}"
                            class="flex-shrink-0 ml-3 relative w-8 h-4 rounded-full transition-colors duration-150 focus:outline-none ${checked ? 'bg-green-600 border border-green-500' : 'bg-gray-700 border border-gray-600'}"
                            title="${escHtmlAttr(s.desc)}">
                            <span class="absolute top-0.5 left-0.5 w-3 h-3 rounded-full transition-transform duration-150 ${checked ? 'bg-white translate-x-4' : 'bg-gray-400 translate-x-0'}"></span>
                        </button>
                    </div>`;
                }).join('');

                return `
                <div class="capability-card bg-gray-800 border border-gray-700 rounded-xl overflow-hidden" id="cap-card-${cap.id}">

                    <!-- Card header: top-level toggle + label + expand -->
                    <div class="flex items-center gap-3 px-4 py-3">
                        <!-- Top-level capability toggle -->
                        <button
                            onclick="toggleCapability('${cap.id}')"
                            id="cap-toggle-${cap.id}"
                            class="flex-shrink-0 relative w-10 h-5 rounded-full transition-colors duration-150 focus:outline-none border ${toggleBg}"
                            title="${escHtmlAttr(cap.tooltip)}">
                            <span class="absolute top-0.5 left-0.5 w-4 h-4 rounded-full transition-transform duration-150 ${knobColor} ${toggleKnob}"></span>
                        </button>

                        <!-- Label + tooltip -->
                        <div class="flex-1 min-w-0 cursor-pointer" onclick="expandCapability('${cap.id}')" title="${escHtmlAttr(cap.tooltip)}">
                            <span class="text-sm font-medium text-gray-200">${cap.label}</span>
                            <span class="ml-2 text-xs text-gray-600">${Object.values(capabilityState[cap.id]).filter(v => v).length}/${cap.scripts.length} scripts</span>
                        </div>

                        <!-- Expand/collapse chevron -->
                        <button onclick="expandCapability('${cap.id}')" class="text-gray-600 hover:text-gray-400 transition text-xs flex-shrink-0 px-1" id="cap-chevron-${cap.id}">▼</button>
                    </div>

                    <!-- Collapsible script list -->
                    <div id="cap-scripts-${cap.id}" class="hidden px-4 pb-3 border-t border-gray-700 pt-3">
                        ${scriptRows}
                    </div>
                </div>`;
            }).join('');

            updateScriptCount();
        }

        function escHtmlAttr(s) {
            return String(s || '').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }

        // ── CAPABILITY INTERACTIONS ────────────────────────────────────────────

        function toggleCapability(capId) {
            const cap = CUSTOM_CAPABILITIES.find(c => c.id === capId);
            if (!cap) return;

            const allOn = areAllScriptsOn(capId);

            if (allOn) {
                // All on → turn all off
                cap.scripts.forEach(s => { capabilityState[capId][s.id] = false; });
            } else {
                // Some or none on → turn all defaults on
                // (if already had some on, turn ALL on; if fresh toggle, use defaults)
                const anyOn = isCapabilityOn(capId);
                cap.scripts.forEach(s => {
                    capabilityState[capId][s.id] = anyOn ? true : s.default;
                });
            }

            renderCapabilityCards();
        }

        function toggleScript(capId, scriptId) {
            if (capabilityState[capId] === undefined) return;
            capabilityState[capId][scriptId] = !capabilityState[capId][scriptId];
            renderCapabilityCards();
            // Keep the script list open after toggling
            const scriptsEl = document.getElementById(`cap-scripts-${capId}`);
            if (scriptsEl) scriptsEl.classList.remove('hidden');
            const chevron = document.getElementById(`cap-chevron-${capId}`);
            if (chevron) chevron.textContent = '▲';
        }

        function expandCapability(capId) {
            const scriptsEl = document.getElementById(`cap-scripts-${capId}`);
            const chevron   = document.getElementById(`cap-chevron-${capId}`);
            if (!scriptsEl) return;
            const isHidden = scriptsEl.classList.contains('hidden');
            scriptsEl.classList.toggle('hidden', !isHidden);
            if (chevron) chevron.textContent = isHidden ? '▲' : '▼';
        }

        function selectAllCapabilities() {
            CUSTOM_CAPABILITIES.forEach(cap => {
                cap.scripts.forEach(s => { capabilityState[cap.id][s.id] = true; });
            });
            renderCapabilityCards();
        }

        function clearAllCapabilities() {
            CUSTOM_CAPABILITIES.forEach(cap => {
                cap.scripts.forEach(s => { capabilityState[cap.id][s.id] = false; });
            });
            renderCapabilityCards();
        }
        
        // ── SWEEP DIALOG: CUSTOM CAPABILITY STATE ─────────────────────────────
        // Separate state from the Create Job panel — the sweep dialog has its
        // own independent capability selections.
        let sweepCapabilityState = {};

        function initSweepCapabilityState() {
            sweepCapabilityState = {};
            CUSTOM_CAPABILITIES.forEach(cap => {
                sweepCapabilityState[cap.id] = {};
                cap.scripts.forEach(s => {
                    sweepCapabilityState[cap.id][s.id] = false;
                });
            });
        }

        function getSweepSelectedScripts() {
            const selected = [];
            CUSTOM_CAPABILITIES.forEach(cap => {
                cap.scripts.forEach(s => {
                    if (sweepCapabilityState[cap.id] && sweepCapabilityState[cap.id][s.id]) {
                        selected.push(s.id);
                    }
                });
            });
            return selected;
        }

        function updateSweepScriptCount() {
            const n = getSweepSelectedScripts().length;
            const el = document.getElementById('sweepScriptCount');
            if (el) el.textContent = n === 1 ? '1 script selected' : `${n} scripts selected`;
        }

        function isSweepCapabilityOn(capId) {
            return Object.values(sweepCapabilityState[capId] || {}).some(v => v);
        }

        function areAllSweepScriptsOn(capId) {
            return Object.values(sweepCapabilityState[capId] || {}).every(v => v);
        }

        function renderSweepCapabilityCards() {
            const container = document.getElementById('sweepCapabilityCards');
            if (!container) return;

            container.innerHTML = CUSTOM_CAPABILITIES.map(cap => {
                const capOn = isSweepCapabilityOn(cap.id);
                const allOn = areAllSweepScriptsOn(cap.id);

                const toggleBg   = allOn ? 'bg-green-600 border-green-500' : (capOn ? 'bg-green-900 border-green-700' : 'bg-gray-700 border-gray-600');
                const toggleKnob = (allOn || capOn) ? 'translate-x-5' : 'translate-x-0';
                const knobColor  = (allOn || capOn) ? 'bg-white' : 'bg-gray-400';

                const scriptRows = cap.scripts.map(s => {
                    const checked = sweepCapabilityState[cap.id][s.id];
                    const defaultTag = s.default ? '' : '<span class="ml-1.5 text-xs px-1 py-0.5 rounded bg-gray-800 text-gray-600 border border-gray-700 font-mono leading-none">sensitive</span>';
                    return `
                    <div class="flex items-center justify-between py-1 border-b border-gray-800 last:border-0">
                        <span class="text-xs text-gray-300 font-mono" title="${escHtmlAttr(s.desc)}">${s.label}${defaultTag}</span>
                        <button
                            onclick="toggleSweepScript('${cap.id}', '${s.id}')"
                            class="flex-shrink-0 ml-2 relative w-7 h-3.5 rounded-full transition-colors duration-150 focus:outline-none border ${checked ? 'bg-green-600 border-green-500' : 'bg-gray-700 border-gray-600'}">
                            <span class="absolute top-0.5 left-0.5 w-2.5 h-2.5 rounded-full transition-transform duration-150 ${checked ? 'bg-white translate-x-3' : 'bg-gray-400 translate-x-0'}"></span>
                        </button>
                    </div>`;
                }).join('');

                const selectedCount = Object.values(sweepCapabilityState[cap.id]).filter(v => v).length;

                return `
                <div class="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                    <div class="flex items-center gap-2 px-3 py-2">
                        <button onclick="toggleSweepCapability('${cap.id}')"
                            class="flex-shrink-0 relative w-9 h-4.5 rounded-full transition-colors duration-150 focus:outline-none border ${toggleBg}"
                            style="width:2.25rem;height:1.25rem"
                            title="${escHtmlAttr(cap.tooltip)}">
                            <span class="absolute top-0.5 left-0.5 w-3.5 h-3.5 rounded-full transition-transform duration-150 ${knobColor} ${toggleKnob}" style="width:0.875rem;height:0.875rem"></span>
                        </button>
                        <div class="flex-1 min-w-0 cursor-pointer" onclick="expandSweepCapability('${cap.id}')">
                            <span class="text-xs font-medium text-gray-200">${cap.label}</span>
                            <span class="ml-2 text-xs text-gray-600">${selectedCount}/${cap.scripts.length}</span>
                        </div>
                        <button onclick="expandSweepCapability('${cap.id}')" class="text-gray-600 hover:text-gray-400 transition text-xs" id="sweep-chevron-${cap.id}">▼</button>
                    </div>
                    <div id="sweep-scripts-${cap.id}" class="hidden px-3 pb-2 border-t border-gray-700 pt-2">
                        ${scriptRows}
                    </div>
                </div>`;
            }).join('');

            updateSweepScriptCount();
        }

        function toggleSweepCapability(capId) {
            const cap = CUSTOM_CAPABILITIES.find(c => c.id === capId);
            if (!cap) return;
            const allOn = areAllSweepScriptsOn(capId);
            if (allOn) {
                cap.scripts.forEach(s => { sweepCapabilityState[capId][s.id] = false; });
            } else {
                const anyOn = isSweepCapabilityOn(capId);
                cap.scripts.forEach(s => {
                    sweepCapabilityState[capId][s.id] = anyOn ? true : s.default;
                });
            }
            renderSweepCapabilityCards();
        }

        function toggleSweepScript(capId, scriptId) {
            if (!sweepCapabilityState[capId]) return;
            sweepCapabilityState[capId][scriptId] = !sweepCapabilityState[capId][scriptId];
            renderSweepCapabilityCards();
            // Keep expanded after toggle
            const el = document.getElementById(`sweep-scripts-${capId}`);
            if (el) el.classList.remove('hidden');
            const chevron = document.getElementById(`sweep-chevron-${capId}`);
            if (chevron) chevron.textContent = '▲';
        }

        function expandSweepCapability(capId) {
            const el      = document.getElementById(`sweep-scripts-${capId}`);
            const chevron = document.getElementById(`sweep-chevron-${capId}`);
            if (!el) return;
            const isHidden = el.classList.contains('hidden');
            el.classList.toggle('hidden', !isHidden);
            if (chevron) chevron.textContent = isHidden ? '▲' : '▼';
        }

        function sweepSelectAll() {
            CUSTOM_CAPABILITIES.forEach(cap => {
                cap.scripts.forEach(s => { sweepCapabilityState[cap.id][s.id] = true; });
            });
            renderSweepCapabilityCards();
        }

        function sweepClearAll() {
            CUSTOM_CAPABILITIES.forEach(cap => {
                cap.scripts.forEach(s => { sweepCapabilityState[cap.id][s.id] = false; });
            });
            renderSweepCapabilityCards();
        }

        // ── SWEEP DIALOG: TYPE/PROFILE CHANGE HANDLERS ────────────────────────

        function onSweepJobTypeChange() {
            onSweepProfileChange();
            updateSweepConfirmNote();
        }

        function onSweepProfileChange() {
            const type    = document.getElementById('sweepJobType').value;
            const profile = document.getElementById('sweepProfile').value;
            const isCustom = type === 'nse_scan' && profile === 'custom';
            const isFull   = type === 'nse_scan' && profile === 'full';

            // Custom profile panel
            const customPanel = document.getElementById('sweepCustomPanel');
            if (customPanel) {
                customPanel.classList.toggle('hidden', !isCustom);
                if (isCustom && Object.keys(sweepCapabilityState).length === 0) {
                    initSweepCapabilityState();
                    renderSweepCapabilityCards();
                }
            }

            // Custom option only meaningful for nse_scan — disable it for other types
            const profileSel = document.getElementById('sweepProfile');
            const customOpt  = profileSel ? profileSel.querySelector('option[value="custom"]') : null;
            if (customOpt) {
                customOpt.disabled = type !== 'nse_scan';
                // If switching away from nse_scan while custom is selected, revert to standard
                if (type !== 'nse_scan' && profile === 'custom') {
                    profileSel.value = 'standard';
                }
            }

            // Full + Vulnerability Scanintrusive warning
            const fullWarn = document.getElementById('sweepFullWarning');
            if (fullWarn) fullWarn.classList.toggle('hidden', !isFull);

            updateSweepConfirmNote();
        }

        function updateSweepConfirmNote() {
            const type    = document.getElementById('sweepJobType')?.value || 'nmap_scan';
            const profile = document.getElementById('sweepProfile')?.value || 'standard';
            const label   = SCAN_TYPE_LABELS[type] || type;
            const note    = document.getElementById('sweepConfirmNote');
            if (!note) return;
            const profileLabel = profile === 'custom' ? 'Custom' : profile.charAt(0).toUpperCase() + profile.slice(1);
            note.textContent = `Confirming will create a ${profileLabel} ${label} job for each host above.`;
        }

        // ── NIKTO CUSTOM PROFILE ───────────────────────────────────────────
        const NIKTO_CATEGORIES = [
            { id: '0', label: 'File Upload',                  desc: 'Tests for arbitrary file upload vulnerabilities.' },
            { id: '1', label: 'Interesting Files',            desc: 'Looks for files commonly seen in server logs or left by developers.' },
            { id: '2', label: 'Misconfiguration',             desc: 'Checks for default files, default credentials, and misconfigurations.' },
            { id: '3', label: 'Information Disclosure',       desc: 'Identifies responses that leak server or application information.' },
            { id: '4', label: 'Injection (XSS/HTML/Script)',  desc: 'Tests for cross-site scripting and script/HTML injection.' },
            { id: '5', label: 'Remote File Retrieval (Web)',  desc: 'Attempts to retrieve files from inside the web root.' },
            { id: '6', label: 'Denial of Service',            desc: 'Tests for DoS vectors — use with caution in production.' },
            { id: '7', label: 'Remote File Retrieval (Wide)', desc: 'Attempts to retrieve files from anywhere on the server.' },
            { id: '8', label: 'Command Execution',            desc: 'Tests for remote command execution and shell upload vectors.' },
            { id: '9', label: 'SQL Injection',                desc: 'Tests for SQL injection vulnerabilities in parameters.' },
            { id: 'a', label: 'Authentication Bypass',        desc: 'Checks for authentication bypass and weak credential issues.' },
            { id: 'b', label: 'Software Identification',      desc: 'Identifies server software, CMS, and framework versions.' },
            { id: 'c', label: 'Remote Source Inclusion',      desc: 'Tests for remote file/source inclusion vulnerabilities.' },
            { id: 'x', label: 'Reverse Tuning',               desc: 'Run all test categories EXCEPT those additionally selected.' },
        ];

        // Default: all enabled except DoS (6) and Reverse Tuning (x)
        let niktoCategoryState = {};
        function initNiktoCategoryState() {
            niktoCategoryState = {};
            NIKTO_CATEGORIES.forEach(c => {
                niktoCategoryState[c.id] = (c.id !== '6' && c.id !== 'x');
            });
        }

        function renderNiktoCategoryCards() {
            const container = document.getElementById('niktoCategoryCards');
            if (!container) return;
            container.innerHTML = NIKTO_CATEGORIES.map(c => {
                const checked = niktoCategoryState[c.id];
                const danger  = c.id === '6';
                const border  = checked ? (danger ? 'border-red-600' : 'border-purple-600') : 'border-gray-700';
                const bg      = checked ? (danger ? 'bg-red-950' : 'bg-gray-800') : 'bg-gray-900';
                return `<div class="rounded-lg border ${border} ${bg} p-3 transition cursor-pointer" onclick="toggleNiktoCategory('${c.id}')">
                    <div class="flex items-start gap-2">
                        <input type="checkbox" ${checked ? 'checked' : ''} onchange="toggleNiktoCategory('${c.id}')" onclick="event.stopPropagation()" class="mt-0.5 accent-purple-500 flex-shrink-0">
                        <div>
                            <p class="text-xs font-medium text-gray-200">${c.label} <span class="text-gray-600 font-mono">[${c.id}]</span></p>
                            <p class="text-xs text-gray-500 mt-0.5">${c.desc}</p>
                        </div>
                    </div>
                </div>`;
            }).join('');
            updateNiktoCategoryCount();
        }

        function toggleNiktoCategory(id) {
            niktoCategoryState[id] = !niktoCategoryState[id];
            renderNiktoCategoryCards();
        }

        function updateNiktoCategoryCount() {
            const count = Object.values(niktoCategoryState).filter(Boolean).length;
            const el = document.getElementById('niktoCategoryCount');
            if (el) el.textContent = `${count} categor${count === 1 ? 'y' : 'ies'} selected`;
        }

        function getSelectedNiktoCategories() {
            return NIKTO_CATEGORIES.filter(c => niktoCategoryState[c.id]).map(c => c.id);
        }

        function selectAllNiktoCategories() {
            NIKTO_CATEGORIES.forEach(c => { niktoCategoryState[c.id] = true; });
            renderNiktoCategoryCards();
        }

        function clearAllNiktoCategories() {
            NIKTO_CATEGORIES.forEach(c => { niktoCategoryState[c.id] = false; });
            renderNiktoCategoryCards();
        }

        // ── PROFILE CHANGE HANDLER (replaces/extends existing) ────────────────
        // Note: the existing profile select doesn't have onchange — we add it above.
        // This function is called from onJobTypeChange() too for the banner check.

        function onProfileChange() {
            const type    = document.getElementById('job_type').value;
            const profile = document.getElementById('profile').value;
            const isCustomNse   = profile === 'custom' && type === 'nse_scan';
            const isCustomNikto = profile === 'custom' && type === 'nikto_scan';

            // Show/hide NSE custom panel
            const panel = document.getElementById('customProfilePanel');
            if (panel) {
                panel.classList.toggle('hidden', !isCustomNse);
                if (isCustomNse && Object.keys(capabilityState).length === 0) {
                    initCapabilityState();
                    renderCapabilityCards();
                }
            }

            // Show/hide Nikto custom panel
            const niktoPanel = document.getElementById('niktoCustomPanel');
            if (niktoPanel) {
                niktoPanel.classList.toggle('hidden', !isCustomNikto);
                if (isCustomNikto && Object.keys(niktoCategoryState).length === 0) {
                    initNiktoCategoryState();
                    renderNiktoCategoryCards();
                }
            }

            // Hide exploit banner when switching to custom
            if (profile === 'custom') {
                document.getElementById('nseExploitBanner').classList.add('hidden');
            } else {
                updateNseExploitBanner();
            }
        }
        
        // ── JOB FILTERS ────────────────────────────────────────────────────
        function setJobFilter(filter) {
            jobFilter = filter;
            pages.jobs = 1;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active-filter', 'border-green-500', 'text-green-400'));
            const active = document.getElementById('filter-' + filter);
            if (active) active.classList.add('active-filter', 'border-green-500', 'text-green-400');
            renderJobs();
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
            pages.results = 1;
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
            pageData.agents = data;
            pages.agents = 1;
            renderAgents();
        }

        function renderAgents() {
            const data   = pageData.agents;
            const paged  = getPage('agents', data);
            let html = `<table class="w-full text-sm"><thead><tr class="text-left text-gray-400 border-b border-gray-800"><th class="pb-2 pr-4">ID</th><th class="pb-2 pr-4">Name</th><th class="pb-2 pr-4">Status</th><th class="pb-2 pr-4">Last Seen</th><th class="pb-2">Action</th></tr></thead><tbody>`;
            if (!data.length) html += `<tr><td colspan="5" class="py-4 text-gray-500 text-sm">No agents registered.</td></tr>`;
            paged.forEach((a) => {
                const isStale = a.is_stale;
                const rowClass = isStale ? 'border-b border-gray-800 bg-gray-900 opacity-60' : 'border-b border-gray-800 hover:bg-gray-800 transition';
                const dot = a.status === 'online' ? '<span class="inline-block w-2 h-2 rounded-full bg-green-400 mr-2"></span>' : '<span class="inline-block w-2 h-2 rounded-full bg-red-500 mr-2"></span>';
                const staleTag = isStale ? '<span class="ml-2 text-xs px-1.5 py-0.5 rounded bg-yellow-900 text-yellow-400 border border-yellow-700">stale</span>' : '';
                // Setup button only shown for agents/scanners that have never checked in
                const neverSeen = !a.last_seen;
                const isProtected = (a.name === 'scanner-default');
                const setupBtn = neverSeen
                    ? `<button onclick="showAgentSetup(${a.id}, '${a.name}', '${a.api_key}', '${a.capabilities || ''}')" class="text-xs text-yellow-500 hover:text-yellow-300 transition mr-2" title="Agent not yet seen — show setup commands">Setup ⚠</button>`
                    : '';
                const deleteBtn = !isProtected
                    ? `<button onclick="deleteScanner(${a.id}, '${a.name}')" class="text-xs text-red-500 hover:text-red-400 transition">Delete</button>`
                    : '';
                const noAction = !setupBtn && !deleteBtn ? '<span class="text-xs text-gray-600">—</span>' : '';
                const action = isStale
                    ? `<div class="flex gap-3"><button onclick="restoreAgent(${a.id})" class="text-xs text-blue-400 hover:text-blue-300 transition">Restore</button><button onclick="dismissAgent(${a.id})" class="text-xs text-red-400 hover:text-red-300 transition">Dismiss</button></div>`
                    : `${setupBtn}${deleteBtn}${noAction}`;
                html += `<tr class="${rowClass}"><td class="py-2 pr-4 text-gray-400">#${a.id}</td><td class="py-2 pr-4 font-medium">${a.name}${staleTag}</td><td class="py-2 pr-4">${dot}${a.status}</td><td class="py-2 pr-4 text-gray-400 text-xs">${formatTimestamp(a.last_seen)}</td><td class="py-2">${action}</td></tr>`;
            });
            html += '</tbody></table>';
            html += paginationBar('agents', data.length);
            document.getElementById("agents").innerHTML = html;
        }
        async function dismissAgent(agent_id) {
            showConfirm('Permanently remove this stale agent?', async () => { await apiFetch(`/agents/${agent_id}/dismiss`, { method: 'POST' }); loadAgents(); }, 'Remove');
        }
        async function restoreAgent(agent_id) { await apiFetch(`/agents/${agent_id}/restore`, { method: 'POST' }); loadAgents(); }

        async function deleteScanner(agent_id, name) {
            showConfirm(
                `Delete scanner '${name}'? This will stop its systemd service (if auto-spawn is enabled) and remove it permanently.`,
                async () => {
                    const res = await apiFetch(`/scanners/${agent_id}`, { method: 'DELETE' });
                    if (res && (res.ok || res.status === 200)) {
                        loadAgents();
                    } else if (res) {
                        const err = await res.json().catch(() => ({}));
                        alert(`Delete failed: ${err.detail || 'unknown error'}`);
                    }
                },
                'Delete Scanner'
            );
        }

        // ── SCANNER REGISTRATION ───────────────────────────────────────────
        function openRegisterScanner() {
            document.getElementById('registerScannerBackdrop').classList.remove('hidden');
            document.getElementById('registerScannerModal').classList.remove('hidden');
            document.getElementById('registerScannerForm').classList.remove('hidden');
            document.getElementById('registerScannerResult').classList.add('hidden');

            // Compute next available scanner name from the current agents list
            const existing = new Set((pageData.agents || []).map(a => a.name));
            let nextNum = 2;
            while (existing.has(`scanner-${nextNum}`)) nextNum++;
            const suggested = `scanner-${nextNum}`;

            const nameInput = document.getElementById('scannerName');
            nameInput.value = '';
            nameInput.placeholder = suggested;
            document.getElementById('scannerCaps').value = 'nmap_scan,nikto_scan,nse_scan';
            nameInput.focus();
        }

        function closeRegisterScanner() {
            document.getElementById('registerScannerBackdrop').classList.add('hidden');
            document.getElementById('registerScannerModal').classList.add('hidden');
            loadAgents();
        }

        async function submitRegisterScanner() {
            const nameInput = document.getElementById('scannerName');
            // Use typed value, or fall back to the placeholder suggestion
            const name = nameInput.value.trim() || nameInput.placeholder;
            const caps = document.getElementById('scannerCaps').value.trim();
            if (!name) { alert('Scanner name is required.'); return; }
            const res = await apiFetch('/scanners/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, capabilities: caps }),
            });
            if (!res) return;
            if (res.status === 400 || res.status === 409) {
                const err = await res.json();
                alert(`Registration failed: ${err.detail}`);
                return;
            }
            const data = await res.json();

            const serverUrl = window.location.origin;

            // Status banner
            const statusBannerEl = document.getElementById('registerScannerStatusBanner');
            if (data.spawn_status === 'started') {
                statusBannerEl.className = 'mb-3 p-3 bg-green-950 border border-green-800 rounded-lg text-xs text-green-300';
                statusBannerEl.textContent = `✓ Scanner registered and started as ${data.service_name}. It should appear online in the agents table within 30 seconds.`;
            } else if (data.spawn_status === 'failed') {
                statusBannerEl.className = 'mb-3 p-3 bg-red-950 border border-red-800 rounded-lg text-xs text-red-300';
                statusBannerEl.textContent = `Scanner registered but failed to start automatically: ${data.spawn_error || 'unknown error'}. Use the manual commands below.`;
            } else {
                statusBannerEl.className = 'mb-3 p-3 bg-blue-950 border border-blue-800 rounded-lg text-xs text-blue-300';
                statusBannerEl.textContent = `Scanner registered. Auto-spawn is disabled — use the commands below to start it manually.`;
            }

            const setupCmds = `# Save your API key\necho "${data.api_key}" > ${data.key_file || name + '_key.txt'}\n\n# Run the scanner\nVAPT_AGENT_NAME=${name} \\\nVAPT_SERVER_URL=${serverUrl} \\\nVAPT_CAPABILITIES=${data.capabilities} \\\nVAPT_KEY_FILE=${data.key_file || name + '_key.txt'} \\\npython3 backend/app/scanner.py`;

            const serviceFile = `[Unit]\nDescription=Heimdall V-Scanner — ${name}\nAfter=network.target vapt-server.service\nWants=vapt-server.service\n\n[Service]\nType=simple\nUser=$USER\nWorkingDirectory=${data.key_file ? data.key_file.replace(/\\/[^/]+$/, '') : '/opt/vapt-scanner-project'}\nEnvironmentFile=${data.key_file ? data.key_file.replace(/\\/[^/]+$/, '') + '/.env' : '/opt/vapt-scanner-project/.env'}\nEnvironment=VAPT_AGENT_NAME=${name}\nEnvironment=VAPT_SERVER_URL=${serverUrl}\nEnvironment=VAPT_CAPABILITIES=${data.capabilities}\nEnvironment=VAPT_KEY_FILE=${data.key_file || name + '_key.txt'}\nExecStart=${data.key_file ? data.key_file.replace(/\\/[^/]+$/, '') + '/venv/bin/python ' + data.key_file.replace(/\\/[^/]+$/, '') + '/backend/app/scanner.py' : '/opt/vapt-scanner-project/venv/bin/python /opt/vapt-scanner-project/backend/app/scanner.py'}\nRestart=on-failure\nRestartSec=10\nStandardOutput=journal\nStandardError=journal\n\n[Install]\nWantedBy=multi-user.target`;

            document.getElementById('resultApiKey').textContent    = data.api_key;
            document.getElementById('resultSetupCmds').textContent  = setupCmds;
            document.getElementById('resultServiceFile').textContent = serviceFile;
            document.getElementById('resultServiceName').textContent = name;

            document.getElementById('registerScannerForm').classList.add('hidden');
            document.getElementById('registerScannerResult').classList.remove('hidden');
        }

        function showAgentSetup(id, name, apiKey, caps) {
            // Reuse the modal to show setup for an already-registered agent/scanner
            document.getElementById('registerScannerBackdrop').classList.remove('hidden');
            document.getElementById('registerScannerModal').classList.remove('hidden');
            document.getElementById('registerScannerForm').classList.add('hidden');
            document.getElementById('registerScannerResult').classList.remove('hidden');

            const serverUrl = window.location.origin;
            const setupCmds = `# Save API key\necho "${apiKey}" > ${name}_key.txt\n\n# Run scanner\nVAPT_AGENT_NAME=${name} \\\nVAPT_SERVER_URL=${serverUrl} \\\nVAPT_CAPABILITIES=${caps} \\\nVAPT_KEY_FILE=${name}_key.txt \\\npython3 backend/app/scanner.py`;

            const serviceFile = `[Unit]\nDescription=Heimdall V-Scanner — ${name}\nAfter=network.target vapt-server.service\nWants=vapt-server.service\n\n[Service]\nType=simple\nUser=$USER\nWorkingDirectory=/opt/vapt-scanner-project\nEnvironmentFile=/opt/vapt-scanner-project/.env\nEnvironment=VAPT_AGENT_NAME=${name}\nEnvironment=VAPT_SERVER_URL=${serverUrl}\nEnvironment=VAPT_CAPABILITIES=${caps}\nEnvironment=VAPT_KEY_FILE=/opt/vapt-scanner-project/${name}_key.txt\nExecStart=/opt/vapt-scanner-project/venv/bin/python /opt/vapt-scanner-project/backend/app/scanner.py\nRestart=on-failure\nRestartSec=10\nStandardOutput=journal\nStandardError=journal\n\n[Install]\nWantedBy=multi-user.target`;

            document.getElementById('resultApiKey').textContent    = apiKey;
            document.getElementById('resultSetupCmds').textContent  = setupCmds;
            document.getElementById('resultServiceFile').textContent = serviceFile;
            document.getElementById('resultServiceName').textContent = name;
        }

        function copyText(elementId) {
            const el = document.getElementById(elementId);
            navigator.clipboard.writeText(el.textContent).then(() => {
                // Brief visual flash on the element
                el.style.outline = '1px solid #22c55e';
                setTimeout(() => { el.style.outline = ''; }, 800);
            });
        }

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

            pageData.jobs = data;
            pages.jobs = 1;   // explicit load — reset to page 1
            renderJobs();
        }

        // Background refresh: updates data but preserves the current page.
        // Used by the polling interval so navigating to page 3 doesn't snap back.
        async function refreshJobs() {
            const url = showJobHistory ? '/jobs?show_history=true' : '/jobs';
            const res = await apiFetch(url);
            if (!res) return;
            const data = await res.json();
            data.sort((a, b) => b.id - a.id);

            let anyNewlyDone = false;
            data.forEach(j => {
                const prev = lastJobStatuses[j.id];
                if (prev === 'running' && j.status === 'done') anyNewlyDone = true;
                lastJobStatuses[j.id] = j.status;
            });
            if (anyNewlyDone && resultTab === 'active') loadResults();

            pageData.jobs = data;
            // Do NOT reset pages.jobs — preserve current page
            renderJobs();
        }

        function renderJobs() {
            const data     = pageData.jobs;
            const filtered = jobFilter === 'all' ? data : data.filter(j => j.status === jobFilter);
            const paged    = getPage('jobs', filtered);

            if (!filtered.length) { document.getElementById("jobs").innerHTML = '<p class="text-gray-500 text-sm">No jobs found.</p>'; return; }

            let html = `<table class="w-full text-sm"><thead><tr class="text-left text-gray-400 border-b border-gray-800"><th class="pb-2 pr-3">#</th><th class="pb-2 pr-3">DB ID</th><th class="pb-2 pr-3">Type</th><th class="pb-2 pr-3">Target</th><th class="pb-2 pr-3">Status</th><th class="pb-2 pr-3">Priority</th><th class="pb-2 pr-3">Mode</th><th class="pb-2 pr-3">Profile</th><th class="pb-2 pr-3">Agent</th><th class="pb-2 pr-3">Time</th><th class="pb-2">Action</th></tr></thead><tbody>`;
            paged.forEach((j, idx) => {
                const rowNum = (pages.jobs - 1) * PAGE_SIZES.jobs + idx + 1;
                let action;
                if (j.cleared) action = '<span class="text-xs text-gray-500 italic">archived</span>';
                else if (j.status === 'running')  action = `<button onclick="cancelJob(${j.id})" class="text-xs text-orange-400 hover:text-orange-300 transition font-medium">Cancel</button>`;
                else if (j.status === 'pending')  action = `<div class="flex gap-2"><button onclick="cancelJob(${j.id})" class="text-xs text-orange-400 hover:text-orange-300 transition">Cancel</button><button onclick="clearJob(${j.id}, '${j.status}')" class="text-xs text-red-500 hover:text-red-400 transition font-medium">Delete</button></div>`;
                else if (j.status === 'failed')   action = `<button onclick="clearJob(${j.id}, '${j.status}')" class="text-xs text-red-500 hover:text-red-400 transition font-medium">Delete</button>`;
                else action = `<button onclick="clearJob(${j.id}, '${j.status}')" class="text-xs text-gray-400 hover:text-red-400 transition">Clear</button>`;
                html += `<tr class="border-b border-gray-800 hover:bg-gray-800 transition"><td class="py-2 pr-3 text-gray-500 text-xs">${rowNum}</td><td class="py-2 pr-3 text-gray-500 text-xs font-mono">${j.id}</td><td class="py-2 pr-3 text-xs text-blue-300">${scanTypeLabel(j.type)}</td><td class="py-2 pr-3 font-mono text-xs">${j.target}</td><td class="py-2 pr-3" data-field="status">${statusBadge(j.status)}</td><td class="py-2 pr-3">${priorityBadge(j.priority)}</td><td class="py-2 pr-3 text-xs text-gray-300">${j.mode}</td><td class="py-2 pr-3 text-xs text-gray-300">${j.profile}</td><td class="py-2 pr-3 text-xs text-gray-300">${j.agent}</td><td class="py-2 pr-3 text-xs text-gray-400 tabular-nums" id="job-time-${j.id}" data-started-at="${j.started_at || ''}">${j.status === 'running' ? elapsedDisplay(j.started_at) : formatTimestamp(j.completed_at)}</td><td class="py-2">${action}</td></tr>`;
            });
            html += '</tbody></table>';
            html += paginationBar('jobs', filtered.length);
            document.getElementById("jobs").innerHTML = html;
        }
        async function clearJob(job_id, status) {
            if (status === 'pending' || status === 'failed') {
                showConfirm(`Permanently delete this ${status} job?`, async () => { await apiFetch(`/jobs/${job_id}/clear`, { method: 'POST' }); loadJobs(); }, 'Delete');
            } else { await apiFetch(`/jobs/${job_id}/clear`, { method: 'POST' }); loadJobs(); }
        }
        async function cancelJob(job_id) {
            showConfirm('Cancel this job? The scanner will stop after its current tool finishes.', async () => {
                await apiFetch(`/jobs/${job_id}/cancel`, { method: 'POST' });
                loadJobs();
            }, 'Cancel Job');
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
            if (type === "nse_scan" && ports && profile !== 'custom') payload.ports = ports;
            if (type === "nse_scan" && profile === 'custom') {
                const scripts = getSelectedScripts();
                if (!scripts.length) {
                    document.getElementById('customProfileWarning').classList.remove('hidden');
                    return;
                }
                document.getElementById('customProfileWarning').classList.add('hidden');
                payload.custom_scripts = scripts;
            }
            if (type === "nikto_scan" && profile === 'custom') {
                const categories = getSelectedNiktoCategories();
                if (!categories.length) {
                    document.getElementById('niktoCustomWarning').classList.remove('hidden');
                    return;
                }
                document.getElementById('niktoCustomWarning').classList.add('hidden');
                payload.nikto_tuning = categories;
            }
            const res = await apiFetch('/jobs/create', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
            if (!res) return;
            if (res.status === 400) { const err = await res.json(); alert(`Job creation failed: ${err.detail}`); return; }
            const data = await res.json();
            if (data.warning) alert(`Job created with warning:\n\n${data.warning}`);
            document.getElementById("target").value = "";
            document.getElementById("port").value = "";
            document.getElementById("ports").value = "";
            setTimeout(loadAll, 300);

            // Reset custom NSE profile state
            if (type === 'nse_scan' && profile === 'custom') {
                initCapabilityState();
                renderCapabilityCards();
                document.getElementById('customProfilePanel').classList.add('hidden');
                document.getElementById('profile').value = 'standard';
            }
            // Reset custom Nikto profile state
            if (type === 'nikto_scan' && profile === 'custom') {
                initNiktoCategoryState();
                renderNiktoCategoryCards();
                document.getElementById('niktoCustomPanel').classList.add('hidden');
                document.getElementById('profile').value = 'standard';
            }
        }

        // ── RESULTS ────────────────────────────────────────────────────────
        function toggleResult(id) {
            const body = document.getElementById(`result-body-${id}`);
            const arrow = document.getElementById(`result-arrow-${id}`);
            body.classList.toggle('hidden');
            arrow.innerText = body.classList.contains('hidden') ? '▼' : '▲';
        }

        // ── Result card hover tooltip ──────────────────────────────────────
        let _tooltipTimer = null;
 
        function showResultTooltip(event, id) {
            const body = document.getElementById('result-body-' + id);
            if (body && !body.classList.contains('hidden')) return;
            clearTimeout(_tooltipTimer);
            _tooltipTimer = setTimeout(() => {
                const tip = document.getElementById('tip-' + id);
                if (tip) tip.classList.add('visible');
            }, 500);
        }
 
        function hideResultTooltip(id) {
            clearTimeout(_tooltipTimer);
            const tip = document.getElementById('tip-' + id);
            if (tip) tip.classList.remove('visible');
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
            pageData.results = data.slice().sort((a, b) => b.id - a.id);
            pages.results = 1;
            renderResults();
        }

        function renderResults() {
            const isHistory = resultTab === 'history';
            const data  = pageData.results;
            const paged = getPage('results', data);

            if (!data.length) {
                document.getElementById("results").innerHTML = `<p class="text-gray-500 text-sm">${isHistory ? 'No archived results.' : 'No results yet.'}</p>`;
                return;
            }

            const html = paged.map(r => {
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

                // Build tooltip content
                const tipRisk = r.analysis
                    ? (() => {
                        const rm = r.analysis.match(/##\\s*Risk Level\\s*\\n+(\\w+)/i);
                        return rm ? rm[1].toUpperCase() : 'INFO';
                      })()
                    : null;
                const tipRiskStyles = {
                    CRITICAL: 'background:rgba(239,68,68,0.15);color:#fca5a5;border-color:rgba(239,68,68,0.3)',
                    HIGH:     'background:rgba(249,115,22,0.15);color:#fdba74;border-color:rgba(249,115,22,0.3)',
                    MEDIUM:   'background:rgba(234,179,8,0.15);color:#fde047;border-color:rgba(234,179,8,0.3)',
                    LOW:      'background:rgba(59,130,246,0.15);color:#93c5fd;border-color:rgba(59,130,246,0.3)',
                    INFO:     'background:rgba(107,114,128,0.15);color:#9ca3af;border-color:rgba(107,114,128,0.3)',
                };
                const tipRiskBadge = tipRisk
                    ? `<span style="font-size:10px;padding:1px 7px;border-radius:20px;border:1px solid;font-weight:600;${tipRiskStyles[tipRisk] || tipRiskStyles.INFO}">${tipRisk}</span>`
                    : `<span style="font-size:10px;padding:1px 7px;border-radius:20px;border:1px solid;border-color:#374151;color:#4b5563;font-weight:500">UNANALYSED</span>`;
 
                const tipTarget = r.job_info ? r.job_info.target : ('Job #' + r.job_id);
                const tipType   = SCAN_TYPE_LABELS[r.job_info?.type] || (r.job_info?.type || '—');
                const tipTime   = r.job_info ? relativeTime(r.job_info.completed_at) : '';
                const tipPorts  = nmapCount + ' port' + (nmapCount !== 1 ? 's' : '');
                const tipFinds  = (nseCount + niktoCount) + ' finding' + ((nseCount + niktoCount) !== 1 ? 's' : '');
 
                // Build the useful tooltip content:
                // - Open ports list (not visible without expanding)
                // - First sentence of AI analysis (never visible in collapsed state)
                const openPortsList = out.nmap
                    ? out.nmap.flatMap(h => h.ports.filter(p => p.state === 'open'))
                    : [];
 
                let tipPortsHtml = '';
                if (openPortsList.length) {
                    const shown = openPortsList.slice(0, 6);
                    const more  = openPortsList.length - shown.length;
                    tipPortsHtml = '<div style="margin-bottom:6px">'
                        + '<div style="font-size:9px;letter-spacing:0.08em;text-transform:uppercase;color:#4b5563;margin-bottom:4px">Open Ports</div>'
                        + '<div style="display:flex;flex-wrap:wrap;gap:4px">'
                        + shown.map(p =>
                            `<span style="font-family:\'IBM Plex Mono\',monospace;font-size:10px;background:rgba(59,130,246,0.1);color:#93c5fd;border:1px solid rgba(59,130,246,0.2);border-radius:4px;padding:1px 6px">${p.port}<span style="color:#4b5563;font-size:9px"> ${p.service}</span></span>`
                          ).join('')
                        + (more > 0 ? `<span style="font-size:9px;color:#4b5563;align-self:center">+${more} more</span>` : '')
                        + '</div></div>';
                } else if (out.nmap !== undefined) {
                    tipPortsHtml = '<div style="font-size:10px;color:#4b5563;margin-bottom:6px">No open ports found</div>';
                }
 
                let tipAnalysisHtml = '';
                if (r.analysis) {
                    // Extract the Summary section — first meaningful sentence after ## Summary
                    const summaryMatch = r.analysis.match(/##\\s*Summary\\s*\\n+([\\s\\S]+?)(?=\\n##|\\\\n\\*\\*|$)/i);
                    if (summaryMatch) {
                        const summaryText = summaryMatch[1].trim().split(/\\.\\s+/)[0] + '.';
                        tipAnalysisHtml = '<div style="border-top:1px solid #1e2535;padding-top:6px;margin-top:2px">'
                            + '<div style="font-size:9px;letter-spacing:0.08em;text-transform:uppercase;color:#4b5563;margin-bottom:3px">AI Summary</div>'
                            + `<div style="font-size:10px;color:#9ca3af;line-height:1.5;white-space:normal">${summaryText}</div>`
                            + '</div>';
                    }
                }
 
                // Only build the tooltip if there's something useful to show
                const hasTipContent = tipPortsHtml || tipAnalysisHtml;
                const tipHtml = hasTipContent ? `
                    <div id="tip-${r.id}" class="result-tooltip">
                        ${tipPortsHtml}
                        ${tipAnalysisHtml}
                    </div>` : `<div id="tip-${r.id}"></div>`;
   
                return '<div class="bg-gray-800 rounded-xl border border-gray-700" style="position:relative">'
                    + tipHtml

                    // ── Collapsed header ──────────────────────────────────
                    + '<div class="flex items-center justify-between px-5 py-3.5 cursor-pointer hover:bg-gray-750 transition" onclick="toggleResult(' + r.id + ')" onmouseenter="showResultTooltip(event,' + r.id + ')" onmouseleave="hideResultTooltip(' + r.id + ')">'
 
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
                    +     (out.nmap  ? '<div class="mb-4"><p class="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-2">Open Port Scan</p>'          + renderNmapResult(out.nmap)   + '</div>' : '')
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
            document.getElementById("results").innerHTML = html + paginationBar('results', data.length);
        }

        // ── DISCOVERY ──────────────────────────────────────────────────────
        function dismissSweepStatus() { document.getElementById("sweepStatus").classList.add('hidden'); }
        function dismissPingResults() { document.getElementById("pingResults").classList.add('hidden'); }

        async function cancelActiveSweep() {
            if (!activeSweepId) return;
            const sweepId = activeSweepId;
            // Stop polling immediately so we don't race with the status update
            if (sweepPollInterval) { clearInterval(sweepPollInterval); sweepPollInterval = null; }
            activeSweepId = null;
            document.getElementById('cancelSweepBtn').classList.add('hidden');
            showSweepStatus('Cancelling sweep…', 'bg-yellow-400 animate-pulse');
            try {
                const res = await apiFetch(`/discover/${sweepId}/cancel`, { method: 'POST' });
                if (res && res.ok) {
                    showSweepStatus('Sweep cancelled.', 'bg-yellow-400');
                } else {
                    showSweepStatus('Cancel request failed — sweep may have already finished.', 'bg-red-500');
                }
            } catch(e) {
                showSweepStatus('Cancel request failed.', 'bg-red-500');
            }
            loadSweepHistory();
        }

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
        let activeSweepId = null;

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

                // Show confirmation dialog — store hosts list for direct job creation path
                pendingSweepPayload = { subnet, hosts: data.hosts };
                // Reset sweep dialog selectors to sensible defaults
                const sweepJobType = document.getElementById('sweepJobType');
                const sweepProfile = document.getElementById('sweepProfile');
                if (sweepJobType) sweepJobType.value = 'nmap_scan';
                if (sweepProfile) sweepProfile.value = 'standard';
                onSweepProfileChange();
                updateSweepConfirmNote();
                document.getElementById("sweepConfirmMsg").textContent = `${data.count} host(s) found in ${subnet}:`;

                // Large-sweep warning — show if host count is high relative to online scanner count
                const LARGE_SWEEP_THRESHOLD = 20;
                const warningEl  = document.getElementById('sweepLargeWarning');
                const warningMsg = document.getElementById('sweepLargeWarningMsg');
                const onlineScanners = (pageData.agents || []).filter(a => a.status === 'online').length;
                if (data.count >= LARGE_SWEEP_THRESHOLD) {
                    const estTime = onlineScanners > 0
                        ? `With ${onlineScanners} scanner(s) online, this could take ${Math.ceil(data.count / onlineScanners)} sequential batches.`
                        : 'No scanners appear to be online.';
                    warningMsg.textContent = `${data.count} jobs will be created. ${estTime}`;
                    warningEl.classList.remove('hidden');
                } else {
                    warningEl.classList.add('hidden');
                }

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
            const jobType  = document.getElementById('sweepJobType')?.value  || 'nmap_scan';
            const profile  = document.getElementById('sweepProfile')?.value  || 'standard';
            const jobMode  = document.getElementById('sweepJobMode')?.value  || 'remote';
            const priority = document.getElementById('sweepJobPriority')?.value || 'medium';

            // Validate custom profile selection
            if (jobType === 'nse_scan' && profile === 'custom') {
                const scripts = getSweepSelectedScripts();
                if (!scripts.length) {
                    document.getElementById('sweepCustomWarning').classList.remove('hidden');
                    return;
                }
                document.getElementById('sweepCustomWarning').classList.add('hidden');
            }

            document.getElementById("sweepConfirmDialog").classList.add('hidden');
            if (!pendingSweepPayload) return;
            const { subnet, hosts } = pendingSweepPayload;
            pendingSweepPayload = null;

            showSweepStatus(`Assigning ${SCAN_TYPE_LABELS[jobType] || jobType} jobs to ${hosts.length} host(s)…`, 'bg-cyan-400 animate-pulse');

            // For custom profile or non-nmap types, create individual jobs directly
            // rather than using the sweep endpoint (which hardcodes nmap_scan).
            if (jobType !== 'nmap_scan' || profile === 'custom') {
                const customScripts = (jobType === 'nse_scan' && profile === 'custom')
                    ? getSweepSelectedScripts()
                    : undefined;

                const results = await Promise.all(hosts.map(h =>
                    apiFetch('/jobs/create', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            type:           jobType,
                            target:         h.ip,
                            mode:           jobMode,
                            profile:        profile,
                            priority:       priority,
                            custom_scripts: customScripts || undefined,
                        }),
                    })
                ));

                const created = results.filter(r => r && r.ok).length;
                showSweepStatus(`Done — ${created} job(s) created across ${hosts.length} host(s)`, 'bg-green-400');
                loadJobs();

                // Reset sweep custom state
                initSweepCapabilityState();
                return;
            }

            // Standard nmap_scan — use the existing sweep endpoint
            const res = await apiFetch('/discover', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ subnet, mode: jobMode, profile }) });
            if (!res) return;
            const data = await res.json();

            // Track the active sweep so cancelActiveSweep() knows which one to cancel
            activeSweepId = data.sweep_id;
            document.getElementById('cancelSweepBtn').classList.remove('hidden');

            sweepPollInterval = setInterval(async () => {
                const r = await apiFetch(`/discover/${data.sweep_id}`);
                if (!r) return;
                const s = await r.json();
                if (s.status === 'done') {
                    clearInterval(sweepPollInterval); sweepPollInterval = null;
                    activeSweepId = null;
                    document.getElementById('cancelSweepBtn').classList.add('hidden');
                    showSweepStatus(`Sweep complete — ${s.hosts_found} host(s) found, ${s.jobs_created} job(s) created`, 'bg-green-400');
                    loadSweepHistory(); loadJobs();
                } else if (s.status === 'failed') {
                    clearInterval(sweepPollInterval); sweepPollInterval = null;
                    activeSweepId = null;
                    document.getElementById('cancelSweepBtn').classList.add('hidden');
                    showSweepStatus('Sweep failed. Check server logs.', 'bg-red-500');
                    loadSweepHistory();
                } else if (s.status === 'cancelled') {
                    clearInterval(sweepPollInterval); sweepPollInterval = null;
                    activeSweepId = null;
                    document.getElementById('cancelSweepBtn').classList.add('hidden');
                    showSweepStatus('Sweep cancelled.', 'bg-yellow-400');
                    loadSweepHistory();
                }
            }, 3000);
        }

        async function loadSweepHistory() {
            const res = await apiFetch('/discover');
            if (!res) return;
            const sweeps = await res.json();
            pageData.sweeps = sweeps;
            pages.sweeps = 1;
            renderSweeps();
        }

        function renderSweeps() {
            const el     = document.getElementById("sweepHistory");
            const sweeps = pageData.sweeps;
            if (!sweeps.length) { el.innerHTML = '<p class="text-gray-600 text-xs">No sweeps yet.</p>'; return; }
            const paged = getPage('sweeps', sweeps);
            const statusColor = { running: 'text-blue-400', done: 'text-green-400', failed: 'text-red-400', cancelled: 'text-yellow-400' };
            const rows = paged.map(s => {
                const viewBtn = (s.status === 'done' && s.jobs_created > 0)
                    ? `<button onclick="viewSweepResults(${s.id})" class="text-xs text-cyan-400 hover:text-cyan-300 transition mr-3">View Results</button>`
                    : '';
                return `<tr class="border-b border-gray-800 hover:bg-gray-800 transition text-xs">
                <td class="py-2 pr-4 text-gray-400">#${s.id}</td>
                <td class="py-2 pr-4 font-mono">${s.subnet}</td>
                <td class="py-2 pr-4 ${statusColor[s.status] || 'text-gray-400'}">${s.status}</td>
                <td class="py-2 pr-4 text-gray-300">${s.hosts_found} host(s)</td>
                <td class="py-2 pr-4 text-gray-300">${s.jobs_created} job(s)</td>
                <td class="py-2 pr-4 text-gray-500">${formatTimestamp(s.started_at)}</td>
                <td class="py-2 whitespace-nowrap">${viewBtn}<button onclick="deleteSweep(${s.id})" class="text-xs text-red-400 hover:text-red-300 transition">Delete</button></td></tr>`;
            }).join('');
            el.innerHTML = `<table class="w-full text-sm"><thead>
            <tr class="text-left text-gray-500 border-b border-gray-800">
            <th class="pb-2 pr-4">ID</th><th class="pb-2 pr-4">Subnet</th><th class="pb-2 pr-4">Status</th><th class="pb-2 pr-4">Hosts</th>
            <th class="pb-2 pr-4">Jobs</th><th class="pb-2 pr-4">Started</th>
            <th class="pb-2">Actions</th></tr></thead><tbody>${rows}</tbody></table>`
            + paginationBar('sweeps', sweeps.length);
        }

        async function viewSweepResults(sweepId) {
            const panel = document.getElementById('sweepResultPanel');
            const body  = document.getElementById('sweepResultBody');
            body.innerHTML = '<p class="text-gray-500 text-xs animate-pulse">Loading…</p>';
            panel.classList.remove('hidden');
            activeSweepResultId = sweepId;

            const res = await apiFetch(`/sweeps/${sweepId}/results`);
            if (!res) { body.innerHTML = '<p class="text-red-400 text-xs">Failed to load results.</p>'; return; }
            const data = await res.json();

            document.getElementById('sweepResultTitle').textContent = `Sweep #${data.sweep_id} — ${data.subnet}`;

            // Show Cancel All Jobs button if any jobs are still pending or running
            const hasActiveJobs = data.hosts && data.hosts.some(h => h.status === 'pending' || h.status === 'running');
            const cancelBtn = document.getElementById('sweepCancelJobsBtn');
            if (cancelBtn) cancelBtn.classList.toggle('hidden', !hasActiveJobs);

            if (!data.hosts || data.hosts.length === 0) {
                body.innerHTML = '<p class="text-gray-500 text-xs">No jobs were created for this sweep.</p>';
                return;
            }

            const statusBadge = s => {
                const map = { done: 'text-green-400', pending: 'text-blue-400', running: 'text-cyan-400', failed: 'text-red-400' };
                return `<span class="${map[s] || 'text-gray-400'}">${s}</span>`;
            };

            const rows = data.hosts.map(h => {
                // Summarise open ports if available
                let portSummary = '—';
                if (h.output && h.output.nmap && h.output.nmap.ports) {
                    const open = h.output.nmap.ports.filter(p => p.state === 'open');
                    portSummary = open.length ? open.map(p => `${p.port}/${p.protocol}`).join(', ') : 'None open';
                }

                // Count findings
                let findings = '—';
                if (h.output && h.output.nse) {
                    const f = h.output.nse.findings;
                    findings = Array.isArray(f) ? `${f.length} finding${f.length !== 1 ? 's' : ''}` : '—';
                }

                const resultLink = h.result_id
                    ? `<button onclick="closeSweepResultPanel(); switchTab('results'); setTimeout(()=>{ const el=document.getElementById('result-${h.result_id}'); if(el){ el.scrollIntoView({behavior:'smooth'}); el.classList.add('ring-1','ring-cyan-500'); setTimeout(()=>el.classList.remove('ring-1','ring-cyan-500'),2000); }},300);" class="text-xs text-cyan-400 hover:text-cyan-300 transition">View</button>`
                    : '<span class="text-gray-600 text-xs">—</span>';

                return `<tr class="border-b border-gray-800 hover:bg-gray-800 transition text-xs">
                    <td class="py-2 pr-4 font-mono text-gray-200">${h.target}</td>
                    <td class="py-2 pr-4">${statusBadge(h.status)}</td>
                    <td class="py-2 pr-4 text-gray-400 font-mono text-xs max-w-xs truncate" title="${portSummary}">${portSummary}</td>
                    <td class="py-2 pr-4 text-gray-400">${findings}</td>
                    <td class="py-2 pr-4 text-gray-500">${h.completed_at ? formatTimestamp(h.completed_at) : '—'}</td>
                    <td class="py-2">${resultLink}</td>
                </tr>`;
            }).join('');

            body.innerHTML = `
                <table class="w-full text-sm">
                    <thead><tr class="text-left text-gray-500 border-b border-gray-800 text-xs">
                        <th class="pb-2 pr-4">Host</th>
                        <th class="pb-2 pr-4">Status</th>
                        <th class="pb-2 pr-4">Open Ports</th>
                        <th class="pb-2 pr-4">Findings</th>
                        <th class="pb-2 pr-4">Completed</th>
                        <th class="pb-2">Result</th>
                    </tr></thead>
                    <tbody>${rows}</tbody>
                </table>`;
        }

        function closeSweepResultPanel() {
            document.getElementById('sweepResultPanel').classList.add('hidden');
            document.getElementById('sweepCancelJobsBtn').classList.add('hidden');
            activeSweepResultId = null;
        }

        let activeSweepResultId = null;

        async function cancelSweepJobs() {
            if (!activeSweepResultId) return;
            showConfirm(
                'Cancel all pending and running jobs from this sweep? This cannot be undone.',
                async () => {
                    const res = await apiFetch(`/sweeps/${activeSweepResultId}/cancel-jobs`, { method: 'POST' });
                    if (!res) return;
                    const data = await res.json();
                    document.getElementById('sweepCancelJobsBtn').classList.add('hidden');
                    // Refresh the panel to show updated statuses
                    viewSweepResults(activeSweepResultId);
                    loadJobs();
                },
                'Cancel All Jobs'
            );
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
        function onSchedTypeChange() {
            const type = document.getElementById('sched_type').value;
            document.getElementById('schedPortField').style.display = type === 'nikto_scan' ? 'flex' : 'none';
            const targetInput = document.getElementById('sched_target');
            if (targetInput) targetInput.placeholder = type === 'nikto_scan' ? 'IP, hostname, or URL' : 'IP or hostname';
        }
        async function createSchedule() {
            const name = document.getElementById("sched_name").value.trim();
            const target = document.getElementById("sched_target").value.trim();
            const type = document.getElementById("sched_type").value;
            const profile = document.getElementById("sched_profile").value;
            const mode = document.getElementById("sched_mode").value;
            const priority = document.getElementById("sched_priority").value;
            const interval = document.getElementById("sched_interval").value.trim();
            const port = document.getElementById("sched_port")?.value.trim();

            if (!name || !target || !interval) { alert("Name, target, and interval are required."); return; }
            if (parseInt(interval) < 1) { alert("Interval must be at least 1 hour."); return; }

            const payload = { name, target, type, profile, mode, priority, interval_hours: parseInt(interval) };
            if (type === 'nikto_scan' && port) payload.port = parseInt(port);

            const res = await apiFetch('/schedules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
            });

            if (!res) return;

            if (res.status === 400) { const err = await res.json(); alert(`Failed: ${err.detail}`); return; }
            document.getElementById("sched_name").value = "";
            document.getElementById("sched_target").value = "";
            document.getElementById("sched_interval").value = "";
            if (document.getElementById("sched_port")) document.getElementById("sched_port").value = "";
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
        let chartScanTypes = null, chartTopPorts = null;
        // Insight host table pagination (separate from main pageData since it's a sub-view)
        let insightHostsData = [];
        let insightHostPage  = 1;
        const INSIGHT_HOST_PAGE_SIZE = 15;

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

        function goPage_insightHosts(n) { insightHostPage = n; renderInsightHostTable(); }

        function renderInsightHostTable() {
            const tbody  = document.getElementById('insightHostTableBody');
            const total  = insightHostsData.length;
            const size   = INSIGHT_HOST_PAGE_SIZE;
            const start  = (insightHostPage - 1) * size;
            const paged  = insightHostsData.slice(start, start + size);

            if (!total) {
                tbody.innerHTML = '<p class="text-xs text-gray-600">No hosts found in this window.</p>';
                return;
            }

            let hostRows = '';
            for (const h of paged) {
                const nameCell = h.hostname
                    ? '<span class="text-gray-300">' + h.hostname + '</span>'
                    : (h.agent_name
                        ? '<span class="text-blue-400">agent: ' + h.agent_name + '</span>'
                        : '<span class="text-gray-700 italic">unknown</span>');
                const macCell  = h.mac ? '<div class="text-gray-600 font-mono text-xs">' + h.mac + '</div>' : '';
                const osCell   = h.os  ? '<div class="text-gray-600 text-xs">' + h.os + '</div>' : '';
                const ipWarn   = h.ip_changed ? ' <span class="text-yellow-500" title="IP changed from ' + (h.previous_ip || '') + '">⚠</span>' : '';
                const lastScan = h.last_scan ? h.last_scan.split('T')[0] : '—';
                const actionCell = h.result_id
                    ? '<div class="flex gap-1.5 flex-wrap">'
                        + '<a href="/report/' + h.result_id + '" target="_blank" '
                        + 'class="text-xs px-2 py-1 rounded bg-cyan-900 hover:bg-cyan-800 text-cyan-300 border border-cyan-800 transition whitespace-nowrap">Report ↗</a>'
                        + '<button onclick="goToResult(' + h.result_id + ')" '
                        + 'class="text-xs px-2 py-1 rounded bg-gray-800 hover:bg-gray-700 text-green-400 border border-gray-700 transition whitespace-nowrap">→ Result</button>'
                        + '</div>'
                    : '<span class="text-xs text-gray-700 italic">no result</span>';

                hostRows +=
                    '<tr class="border-b border-gray-800 hover:bg-gray-800 transition insight-host-row" data-ip="' + h.ip + '">'
                    + '<td class="py-2 pr-4 cursor-pointer">'
                    +     '<div class="font-mono text-green-400 text-xs">' + h.ip + ipWarn + '</div>' + osCell
                    + '</td>'
                    + '<td class="py-2 pr-4 cursor-pointer">'
                    +     '<div class="text-xs">' + nameCell + '</div>' + macCell
                    + '</td>'
                    + '<td class="py-2 pr-4 text-xs text-gray-300 cursor-pointer">' + h.scan_count + '</td>'
                    + '<td class="py-2 pr-4 text-xs text-gray-300 cursor-pointer">' + h.open_ports + '</td>'
                    + '<td class="py-2 pr-4 text-xs text-gray-300 cursor-pointer">' + h.findings   + '</td>'
                    + '<td class="py-2 pr-4 cursor-pointer">' + riskBadgeHtml(h.risk) + '</td>'
                    + '<td class="py-2 pr-4 text-xs text-gray-500 cursor-pointer">' + lastScan + '</td>'
                    + '<td class="py-2" onclick="event.stopPropagation()">' + actionCell + '</td>'
                    + '</tr>';
            }

            // Pagination bar for insights host table
            const numPages = Math.ceil(total / size);
            let pagBar = '';
            if (numPages > 1) {
                const cur  = insightHostPage;
                const prev = cur > 1 ? `<button onclick="goPage_insightHosts(${cur-1})" class="px-2 py-1 rounded text-xs text-gray-400 hover:text-gray-200 hover:bg-gray-700 transition">‹</button>` : '<span class="px-2 py-1 text-xs text-gray-700">‹</span>';
                const next = cur < numPages ? `<button onclick="goPage_insightHosts(${cur+1})" class="px-2 py-1 rounded text-xs text-gray-400 hover:text-gray-200 hover:bg-gray-700 transition">›</button>` : '<span class="px-2 py-1 text-xs text-gray-700">›</span>';
                const startN = start + 1, endN = Math.min(start + size, total);
                pagBar = `<div class="flex items-center justify-between mt-4 pt-3 border-t border-gray-800">
                    <span class="text-xs text-gray-600">${startN}–${endN} of ${total}</span>
                    <div class="flex items-center gap-1">${prev}
                        <span class="text-xs text-gray-500 px-2">Page ${cur} of ${numPages}</span>
                    ${next}</div></div>`;
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
                + '</table>' + pagBar;
        }

        // Delegated click handler for insight host table rows
        // (avoids inline onclick with escaped quotes which break in Firefox)
        document.addEventListener('click', function(e) {
            const row = e.target.closest('.insight-host-row');
            if (row && !e.target.closest('[onclick]') && !e.target.closest('button') && !e.target.closest('a')) {
                const ip = row.dataset.ip;
                if (ip) drillIntoHost(ip);
            }
        });

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

            // ── Scan type breakdown chart ──────────────────────────────────
            chartScanTypes = destroyChart(chartScanTypes);
            const stCtx = document.getElementById('chartScanTypes').getContext('2d');
            const stLabels = Object.keys(data.scan_type_counts || {});
            const stVals   = stLabels.map(k => data.scan_type_counts[k]);
            const stColors = ['rgba(74,222,128,0.7)', 'rgba(96,165,250,0.7)', 'rgba(251,146,60,0.7)'];
            chartScanTypes = new Chart(stCtx, {
                type: 'doughnut',
                data: {
                    labels: stLabels,
                    datasets: [{ data: stVals.length ? stVals : [1], backgroundColor: stVals.length ? stColors : ['#1f2937'], borderWidth: 0 }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'right', labels: { color: '#9ca3af', font: { size: 10 }, boxWidth: 12, padding: 8 } },
                        tooltip: { enabled: !!stVals.length }
                    },
                    cutout: '60%'
                }
            });

            // ── Port frequency chart ───────────────────────────────────────
            chartTopPorts = destroyChart(chartTopPorts);
            const portCtx  = document.getElementById('chartTopPorts').getContext('2d');
            const portData = (data.top_ports || []).slice(0, 12);
            chartTopPorts = new Chart(portCtx, {
                type: 'bar',
                data: {
                    labels: portData.map(p => p.port),
                    datasets: [{ label: 'Hosts', data: portData.map(p => p.host_count), backgroundColor: 'rgba(96,165,250,0.5)', borderColor: '#60a5fa', borderWidth: 1, borderRadius: 3 }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: '#6b7280', font: { size: 9 } }, grid: { color: '#1f2937' } },
                        y: { ticks: { color: '#6b7280', font: { size: 10 }, stepSize: 1 }, grid: { color: '#1f2937' }, beginAtZero: true }
                    }
                }
            });

            // ── Coverage gaps ──────────────────────────────────────────────
            const gapPanel = document.getElementById('insightCoverageGaps');
            const gapBody  = document.getElementById('insightCoverageGapsBody');
            const gaps = data.coverage_gaps || [];
            if (gaps.length && !insightHost) {
                gapPanel.classList.remove('hidden');
                const shown   = gaps.slice(0, 8);
                const overflow = gaps.length - shown.length;
                gapBody.innerHTML = shown.map(g => {
                    const label = g.days_ago !== null
                        ? `<span class="text-yellow-500">${g.ip}</span><span class="text-yellow-700 ml-1 text-xs">${g.days_ago}d ago</span>`
                        : `<span class="text-orange-400">${g.ip}</span><span class="text-orange-700 ml-1 text-xs">never</span>`;
                    return `<button onclick="drillIntoHost('${g.ip}')" class="flex items-center gap-1 text-xs px-2 py-1 rounded bg-yellow-950 border border-yellow-800 hover:bg-yellow-900 transition">${label}</button>`;
                }).join('')
                + (overflow > 0 ? `<span class="text-xs text-gray-600 self-center">+${overflow} more — run vuln scans to clear them</span>` : '');
            } else {
                gapPanel.classList.add('hidden');
            }

            // ── Host table (paginated) ─────────────────────────────────────
            if (!insightHost) {
                insightHostsData = data.hosts;
                insightHostPage  = 1;
                renderInsightHostTable();
            }

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
 
        // ── NETWORK MAP ────────────────────────────────────────────────────────

        function setMapFilter(f) {
            mapFilter = f;
            document.querySelectorAll('.map-filter-btn').forEach(b => {
                b.classList.remove('bg-gray-700', 'text-white');
                b.classList.add('text-gray-400');
            });
            const active = document.getElementById('mf-' + f);
            if (active) { active.classList.add('bg-gray-700', 'text-white'); active.classList.remove('text-gray-400'); }
            renderNetworkMap(topoData);
        }

        async function loadTopology() {
            const res = await apiFetch('/topology');
            if (!res) return;
            topoData = await res.json();
            renderNetworkMap(topoData);
        }

        function renderNetworkMap(data) {
            const mapBody  = document.getElementById('mapBody');
            const mapEmpty = document.getElementById('mapEmpty');
            const mapStats = document.getElementById('mapStats');

            if (!data || !data.nodes) return;

            const hosts = data.nodes.filter(n => n.type === 'host');

            // Stats row
            const rc = data.stats.risk_counts || {};
            const statItems = [
                { label: 'Hosts',    val: data.stats.total_hosts,   color: 'text-gray-300' },
                { label: 'Subnets',  val: data.stats.total_subnets, color: 'text-gray-300' },
                { label: 'Critical', val: rc.CRITICAL || 0,         color: 'text-red-400'    },
                { label: 'High',     val: rc.HIGH     || 0,         color: 'text-orange-400' },
                { label: 'Medium',   val: rc.MEDIUM   || 0,         color: 'text-yellow-400' },
            ];
            mapStats.innerHTML = statItems.map(s =>
                `<div class="bg-gray-900 border border-gray-800 rounded-lg px-4 py-2 text-center">
                    <div class="text-lg font-bold ${s.color}">${s.val}</div>
                    <div class="text-xs text-gray-600">${s.label}</div>
                </div>`
            ).join('');

            // Filter hosts
            const filtered = mapFilter === 'all' ? hosts : hosts.filter(h => h.risk === mapFilter);

            if (!filtered.length) {
                mapBody.innerHTML = '';
                mapEmpty.classList.remove('hidden');
                return;
            }
            mapEmpty.classList.add('hidden');

            // Group by subnet
            const bySubnet = {};
            filtered.forEach(h => {
                if (!bySubnet[h.subnet]) bySubnet[h.subnet] = [];
                bySubnet[h.subnet].push(h);
            });

            const riskColor = {
                CRITICAL:   'border-red-600    bg-red-950',
                HIGH:       'border-orange-600 bg-orange-950',
                MEDIUM:     'border-yellow-600 bg-yellow-950',
                LOW:        'border-blue-700   bg-blue-950',
                INFO:       'border-blue-800   bg-blue-950',
                UNANALYSED: 'border-gray-700   bg-gray-900',
                UNSCANNED:  'border-green-800  bg-green-950',
            };
            const riskDot = {
                CRITICAL:   'bg-red-500',
                HIGH:       'bg-orange-500',
                MEDIUM:     'bg-yellow-400',
                LOW:        'bg-blue-400',
                INFO:       'bg-blue-400',
                UNANALYSED: 'bg-gray-500',
                UNSCANNED:  'bg-green-500',
            };

            mapBody.innerHTML = Object.entries(bySubnet)
                .sort(([a], [b]) => a.localeCompare(b))
                .map(([subnet, subHosts]) => {
                    const cards = subHosts
                        .sort((a, b) => {
                            // Sort by risk severity then IP
                            const order = ['CRITICAL','HIGH','MEDIUM','LOW','INFO','UNANALYSED','UNSCANNED'];
                            return (order.indexOf(a.risk) - order.indexOf(b.risk)) || a.ip.localeCompare(b.ip);
                        })
                        .map(h => {
                            const borderBg   = riskColor[h.risk] || riskColor.UNANALYSED;
                            const dot        = riskDot[h.risk]   || 'bg-gray-500';
                            const agentRing  = h.is_agent ? 'ring-1 ring-cyan-400' : '';
                            const portList   = h.open_ports.slice(0, 5).map(p =>
                                `<span class="font-mono text-xs text-gray-500">${p.port}</span>`
                            ).join(' ');
                            const moreports  = h.open_ports.length > 5
                                ? `<span class="text-xs text-gray-700">+${h.open_ports.length - 5}</span>` : '';
                            const findings   = (h.nse_findings + h.nikto_findings);
                            const findBadge  = findings
                                ? `<span class="text-xs px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-900">${findings} finding${findings>1?'s':''}</span>` : '';
                            const scanDate   = h.last_scan_at ? h.last_scan_at.split('T')[0] : '—';
                            const resultBtn  = h.result_id
                                ? `<button onclick="goToResult(${h.result_id})" class="text-xs text-green-400 hover:text-green-300 transition">→ Result</button>` : '';
                            const scanBtn    = `<button onclick="createJobFromTopo('${h.ip}')" class="text-xs text-gray-500 hover:text-gray-300 transition">+ Scan</button>`;

                            return `<div class="border rounded-lg p-3 ${borderBg} ${agentRing} min-w-0">
                                <div class="flex items-start justify-between gap-2 mb-2">
                                    <div class="min-w-0">
                                        <div class="flex items-center gap-1.5">
                                            <span class="w-2 h-2 rounded-full flex-shrink-0 ${dot}"></span>
                                            <span class="font-mono text-xs font-semibold text-gray-200 truncate">${h.ip}</span>
                                            ${h.is_agent ? '<span class="text-xs text-cyan-500" title="Agent host">⬡</span>' : ''}
                                        </div>
                                        ${h.hostname ? `<div class="text-xs text-gray-500 truncate mt-0.5 pl-3.5">${h.hostname}</div>` : ''}
                                        ${h.os ? `<div class="text-xs text-gray-600 truncate pl-3.5">${h.os}</div>` : ''}
                                    </div>
                                    ${findBadge}
                                </div>
                                ${h.port_count ? `<div class="flex flex-wrap gap-1 mb-2">${portList}${moreports}</div>` : '<div class="text-xs text-gray-700 mb-2 italic">no open ports</div>'}
                                <div class="flex items-center justify-between">
                                    <span class="text-xs text-gray-700">${scanDate}</span>
                                    <div class="flex gap-2">${resultBtn}${scanBtn}</div>
                                </div>
                            </div>`;
                        }).join('');

                    return `<div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
                        <div class="flex items-center gap-2 mb-4">
                            <span class="font-mono text-xs font-semibold text-cyan-400">${subnet}</span>
                            <span class="text-xs text-gray-600">${subHosts.length} host${subHosts.length!==1?'s':''}</span>
                        </div>
                        <div class="grid gap-3" style="grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));">
                            ${cards}
                        </div>
                    </div>`;
                }).join('');
        }

        function createJobFromTopo(ip) {
            switchTab('dashboard');
            document.getElementById('target').value = ip;
            document.getElementById('target').focus();
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
