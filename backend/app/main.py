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
from .models import Agent, Job, Result, DiscoverySweep
from .schemas import AgentCreate, AgentResponse, JobResponse, ResultCreate, ResultResponse, JobCreate
from dotenv import load_dotenv
from .logger import get_logger

load_dotenv()

logger = get_logger("vapt.server", "server.log")

JOB_TIMEOUT_SECONDS = 120

Base.metadata.create_all(bind=engine)

app = FastAPI()


security = HTTPBasic()

DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "vapt-admin")

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

    # archive the associated job too
    job = db.query(Job).filter(Job.id == result.job_id).first()
    if job:
        job.cleared = True

    db.commit()
    return {"ok": True}


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


# --- JOBS ---

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}

@app.post("/jobs/create")
def create_job(job: JobCreate, db: Session = Depends(get_db), username: str = Depends(require_auth)):

    # validate port for nikto jobs
    if job.type == "nikto_scan" and job.port is not None:
        if job.port not in WEB_PORTS:
            raise HTTPException(
                status_code=400,
                detail=f"Port {job.port} is not a recognised web port. "
                       f"Nikto only scans web services. Valid ports: {sorted(WEB_PORTS)}"
            )

    new_job = Job(
        type=job.type,
        target=job.target,
        agent_id=job.agent_id,
        status="pending",
        priority=job.priority if job.priority else "medium",
        mode=job.mode if job.mode else "remote",
        profile=job.profile if job.profile else "standard",
        port=job.port if job.port else None
    )
    db.add(new_job)
    db.commit()
    db.refresh(new_job)
    return new_job


@app.get("/agents")
def get_agents(db: Session = Depends(get_db), username: str = Depends(require_auth)):
    agents = db.query(Agent).all()

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
            "last_seen": a.last_seen
        })

    return response


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

    eligible_jobs.sort(key=lambda j: j.agent_id is None)

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
        "port": job.port
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

    # When transitioning to running, assign the job to this agent if not yet assigned.
    # This handles the race where the scanner sends running status before get_next_job
    # has fully committed the agent assignment.
    if new_status == "running":
        if job.agent_id is None:
            job.agent_id = agent.id
        elif job.agent_id != agent.id:
            raise HTTPException(status_code=403, detail="This job does not belong to you")
        job.started_at = datetime.utcnow()
    else:
        # For done/failed, only the assigned agent can update
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

    # pending and failed jobs have no results worth keeping — delete permanently
    if job.status in ("pending", "failed"):
        db.delete(job)
        db.commit()
        return {"ok": True, "action": "deleted"}

    # done jobs soft-archive so their results remain accessible in history
    job.cleared = True
    db.commit()
    return {"ok": True, "action": "archived"}


# --- DISCOVERY ---

def run_ping_sweep(sweep_id: int, subnet: str, mode: str, profile: str):
    """
    Runs in a background thread. Performs an Nmap ping sweep,
    then creates nmap_scan jobs for each live host found.
    """
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
                    # only include hosts that are up
                    status = host.find("status")
                    if status is not None and status.get("state") == "up":
                        addr = host.find("address")
                        if addr is not None:
                            hosts.append(addr.get("addr"))
            except ET.ParseError as e:
                logger.error(f"Sweep {sweep_id} XML parse error: {e}")

        # create a job for each discovered host
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


# --- DASHBOARD ---

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>VAPT Dashboard</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-950 text-gray-100 min-h-screen">

        <!-- Confirm Dialog -->
        <div id="confirmDialog" class="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50 hidden">
            <div class="bg-gray-900 border border-gray-700 rounded-xl p-6 w-full max-w-sm">
                <h3 class="text-sm font-semibold text-white mb-2">Confirm Permanent Delete</h3>
                <p id="confirmMsg" class="text-xs text-gray-400 mb-5">This action cannot be undone.</p>
                <div class="flex gap-3 justify-end">
                    <button onclick="cancelConfirm()"
                        class="text-xs px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 transition">Cancel</button>
                    <button id="confirmOkBtn"
                        class="text-xs px-4 py-2 rounded-lg bg-red-700 hover:bg-red-600 text-white font-semibold transition">Delete</button>
                </div>
            </div>
        </div>

        <!-- Login Overlay -->
        <div id="loginOverlay" class="fixed inset-0 bg-gray-950 bg-opacity-95 flex items-center justify-center z-50">
            <div class="bg-gray-900 border border-gray-700 rounded-xl p-8 w-full max-w-sm">
                <div class="flex items-center gap-3 mb-6">
                    <div class="w-3 h-3 rounded-full bg-green-400"></div>
                    <h2 class="text-lg font-bold text-green-400">VAPT Dashboard</h2>
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
                    <button onclick="submitLogin()"
                        class="w-full bg-green-600 hover:bg-green-500 text-white font-semibold py-2 rounded-lg transition text-sm">
                        Sign In
                    </button>
                </div>
            </div>
        </div>

        <!-- Header -->
        <div class="bg-gray-900 border-b border-gray-800 px-6 py-4 flex items-center justify-between">
            <div class="flex items-center gap-3">
                <div class="w-3 h-3 rounded-full bg-green-400 animate-pulse"></div>
                <h1 class="text-xl font-bold text-green-400 tracking-wider">VAPT Control Dashboard</h1>
            </div>
            <button onclick="loadAll()" class="text-sm bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded-lg transition">
                ↻ Refresh
            </button>
        </div>

        <div class="max-w-screen-xl mx-auto px-6 py-8 space-y-10">

            <!-- Network Discovery -->
            <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <h2 class="text-lg font-semibold text-green-400 mb-4">Network Discovery</h2>
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
                    <button onclick="startDiscovery()"
                        class="bg-cyan-700 hover:bg-cyan-600 text-white font-semibold px-5 py-2 rounded-lg transition text-sm">
                        ⌖ Sweep
                    </button>
                </div>

                <!-- Sweep status area -->
                <div id="sweepStatus" class="hidden mb-4 p-3 bg-gray-800 rounded-lg border border-gray-700 text-xs text-gray-300 flex items-center gap-3">
                    <div id="sweepSpinner" class="w-3 h-3 rounded-full bg-cyan-400 animate-pulse"></div>
                    <span id="sweepStatusText">Sweeping...</span>
                </div>

                <!-- Sweep history -->
                <div id="sweepHistory"></div>
            </div>

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
                        <select id="job_type" onchange="togglePortField()"
                            class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                            <option value="nmap_scan">Nmap Scan</option>
                            <option value="nikto_scan">Nikto Scan</option>
                        </select>
                    </div>
                    <div class="flex flex-col gap-1" id="portField" style="display:none">
                        <label class="text-xs text-gray-400">Port</label>
                        <input id="port" placeholder="80"
                            class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500 w-24">
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
                    <button onclick="createJob()"
                        class="bg-green-600 hover:bg-green-500 text-white font-semibold px-5 py-2 rounded-lg transition text-sm">
                        + Create
                    </button>
                </div>
            </div>

            <!-- Agents -->
            <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <h2 class="text-lg font-semibold text-green-400 mb-4">Agents</h2>
                <div id="agents" class="overflow-x-auto"></div>
            </div>

            <!-- Jobs -->
            <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <div class="flex items-center justify-between mb-3">
                    <h2 class="text-lg font-semibold text-green-400">Jobs</h2>
                    <div class="flex gap-2 flex-wrap justify-end">
                        <button onclick="setJobFilter('all')" id="filter-all"
                            class="filter-btn active-filter text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-green-500 transition">All</button>
                        <button onclick="setJobFilter('pending')" id="filter-pending"
                            class="filter-btn text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-yellow-500 transition">Pending</button>
                        <button onclick="setJobFilter('running')" id="filter-running"
                            class="filter-btn text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-blue-500 transition">Running</button>
                        <button onclick="setJobFilter('done')" id="filter-done"
                            class="filter-btn text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-green-500 transition">Done</button>
                        <button onclick="setJobFilter('failed')" id="filter-failed"
                            class="filter-btn text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-red-500 transition">Failed</button>
                        <button onclick="toggleJobHistory()" id="jobHistoryBtn"
                            class="text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-purple-500 transition">Show History</button>
                    </div>
                </div>
                <!-- Bulk actions -->
                <div class="flex gap-2 mb-3">
                    <button onclick="clearAllByStatus('pending')"
                        class="text-xs px-3 py-1 rounded-lg bg-yellow-950 hover:bg-yellow-900 text-yellow-300 border border-yellow-800 transition">
                        Delete all pending
                    </button>
                    <button onclick="clearAllByStatus('failed')"
                        class="text-xs px-3 py-1 rounded-lg bg-red-950 hover:bg-red-900 text-red-300 border border-red-800 transition">
                        Delete all failed
                    </button>
                </div>
                <div id="jobs" class="overflow-x-auto"></div>
            </div>

            <!-- Results -->
            <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-lg font-semibold text-green-400">Scan Results</h2>
                    <!-- Tab switcher -->
                    <div class="flex gap-1 bg-gray-800 rounded-lg p-1">
                        <button onclick="setResultTab('active')" id="tab-active"
                            class="result-tab text-xs px-4 py-1.5 rounded-md transition font-medium bg-gray-700 text-white">
                            Active
                        </button>
                        <button onclick="setResultTab('history')" id="tab-history"
                            class="result-tab text-xs px-4 py-1.5 rounded-md transition font-medium text-gray-400 hover:text-gray-200">
                            History
                        </button>
                    </div>
                </div>

                <!-- History toolbar (hidden when on active tab) -->
                <div id="historyToolbar" class="hidden mb-4 flex items-center gap-3">
                    <label class="flex items-center gap-2 text-xs text-gray-400 cursor-pointer select-none">
                        <input type="checkbox" id="selectAllCheckbox" onchange="toggleSelectAll()" class="accent-red-500">
                        Select all
                    </label>
                    <button onclick="deleteSelected()"
                        class="text-xs px-3 py-1.5 rounded-lg bg-red-900 hover:bg-red-800 text-red-200 border border-red-700 transition font-medium">
                        Delete Selected
                    </button>
                </div>

                <div id="results" class="space-y-4"></div>
            </div>

        </div>

        <script>
        let jobFilter = "all";
        let showJobHistory = false;
        let resultTab = "active";
        let authCredentials = "";
        let confirmCallback = null;

        // --- AUTH ---

        function submitLogin() {
            const username = document.getElementById("loginUsername").value;
            const password = document.getElementById("loginPassword").value;
            if (!username || !password) return;
            authCredentials = 'Basic ' + btoa(username + ':' + password);
            fetch('/agents', {
                headers: { 'Authorization': authCredentials }
            }).then(res => {
                if (res.status === 401) {
                    authCredentials = "";
                    document.getElementById("loginError").classList.remove('hidden');
                } else {
                    document.getElementById("loginOverlay").classList.add('hidden');
                    loadAll();
                }
            });
        }

        document.getElementById("loginPassword").addEventListener('keydown', e => {
            if (e.key === 'Enter') submitLogin();
        });
        document.getElementById("loginUsername").addEventListener('keydown', e => {
            if (e.key === 'Enter') submitLogin();
        });

        async function apiFetch(url, options = {}) {
            options.headers = {
                ...options.headers,
                'Authorization': authCredentials
            };
            const res = await fetch(url, options);
            if (res.status === 401) {
                authCredentials = "";
                document.getElementById("loginOverlay").classList.remove('hidden');
                return null;
            }
            return res;
        }

        // --- CONFIRM DIALOG ---

        function showConfirm(message, onConfirm) {
            document.getElementById("confirmMsg").textContent = message;
            document.getElementById("confirmDialog").classList.remove('hidden');
            confirmCallback = onConfirm;
            document.getElementById("confirmOkBtn").onclick = () => {
                document.getElementById("confirmDialog").classList.add('hidden');
                if (confirmCallback) confirmCallback();
            };
        }

        function cancelConfirm() {
            document.getElementById("confirmDialog").classList.add('hidden');
            confirmCallback = null;
        }

        // --- LOAD ALL ---

        async function loadAll() {
            loadAgents();
            loadJobs();
            loadResults();
        }

        // --- JOB FILTERS ---

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

        // --- RESULT TABS ---

        function setResultTab(tab) {
            resultTab = tab;
            document.querySelectorAll('.result-tab').forEach(b => {
                b.classList.remove('bg-gray-700', 'text-white');
                b.classList.add('text-gray-400');
            });
            const active = document.getElementById('tab-' + tab);
            active.classList.add('bg-gray-700', 'text-white');
            active.classList.remove('text-gray-400');

            const toolbar = document.getElementById('historyToolbar');
            if (tab === 'history') {
                toolbar.classList.remove('hidden');
            } else {
                toolbar.classList.add('hidden');
            }

            // reset select all
            document.getElementById('selectAllCheckbox').checked = false;

            loadResults();
        }

        function toggleSelectAll() {
            const checked = document.getElementById('selectAllCheckbox').checked;
            document.querySelectorAll('.result-checkbox').forEach(cb => cb.checked = checked);
        }

        function getSelectedIds() {
            return Array.from(document.querySelectorAll('.result-checkbox:checked'))
                .map(cb => parseInt(cb.dataset.id));
        }

        async function deleteSelected() {
            const ids = getSelectedIds();
            if (!ids.length) {
                alert("No results selected.");
                return;
            }
            showConfirm(
                `Permanently delete ${ids.length} result(s) and their associated jobs? This cannot be undone.`,
                async () => {
                    await apiFetch('/results/bulk', {
                        method: 'DELETE',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ ids })
                    });
                    document.getElementById('selectAllCheckbox').checked = false;
                    loadResults();
                    loadJobs();
                }
            );
        }

        // --- CREATE JOB ---

        function togglePortField() {
            const type = document.getElementById("job_type").value;
            const portField = document.getElementById("portField");
            portField.style.display = type === "nikto_scan" ? "flex" : "none";
        }

        async function createJob() {
            let target = document.getElementById("target").value;
            let agent_id = document.getElementById("agent_id").value;
            let type = document.getElementById("job_type").value;
            let mode = document.getElementById("mode").value;
            let profile = document.getElementById("profile").value;
            let port = document.getElementById("port").value;

            if (!target) {
                alert("Please enter a target IP.");
                return;
            }

            let payload = { type, target, mode, profile };
            if (agent_id) payload.agent_id = parseInt(agent_id);
            if (type === "nikto_scan" && port) payload.port = parseInt(port);

            const res = await apiFetch('/jobs/create', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (res && res.status === 400) {
                const err = await res.json();
                alert(`Job creation failed: ${err.detail}`);
                return;
            }

            document.getElementById("target").value = "";
            document.getElementById("port").value = "";
            setTimeout(loadAll, 300);
        }

        // --- BADGES ---

        function statusBadge(status) {
            const map = {
                pending: 'bg-yellow-900 text-yellow-300 border border-yellow-700',
                running: 'bg-blue-900 text-blue-300 border border-blue-700',
                done:    'bg-green-900 text-green-300 border border-green-700',
                failed:  'bg-red-900 text-red-300 border border-red-700',
            };
            return `<span class="text-xs px-2 py-0.5 rounded-full font-medium ${map[status] || 'bg-gray-700 text-gray-300'}">${status}</span>`;
        }

        function priorityBadge(priority) {
            const map = {
                high:   'text-red-400',
                medium: 'text-yellow-400',
                low:    'text-gray-400',
            };
            return `<span class="text-xs font-medium ${map[priority] || 'text-gray-400'}">${priority}</span>`;
        }

        function formatTimestamp(ts) {
            if (!ts) return '—';
            const d = new Date(ts);
            const date = d.toISOString().split('T')[0];
            const time = d.toTimeString().split(' ')[0];
            return `${date} at ${time}`;
        }

        // --- AGENTS ---

        async function loadAgents() {
            let res = await apiFetch('/agents');
            if (!res) return;
            let data = await res.json();
            data.sort((a, b) => a.id - b.id);

            let html = `<table class="w-full text-sm">
                <thead><tr class="text-left text-gray-400 border-b border-gray-800">
                    <th class="pb-2 pr-4">ID</th>
                    <th class="pb-2 pr-4">Name</th>
                    <th class="pb-2 pr-4">Status</th>
                    <th class="pb-2">Last Seen</th>
                </tr></thead><tbody>`;

            data.forEach(a => {
                const dot = a.status === 'online'
                    ? '<span class="inline-block w-2 h-2 rounded-full bg-green-400 mr-2"></span>'
                    : '<span class="inline-block w-2 h-2 rounded-full bg-red-500 mr-2"></span>';
                html += `<tr class="border-b border-gray-800 hover:bg-gray-800 transition">
                    <td class="py-2 pr-4 text-gray-400">#${a.id}</td>
                    <td class="py-2 pr-4 font-medium">${a.name}</td>
                    <td class="py-2 pr-4">${dot}${a.status}</td>
                    <td class="py-2 text-gray-400 text-xs">${formatTimestamp(a.last_seen)}</td>
                </tr>`;
            });

            html += '</tbody></table>';
            document.getElementById("agents").innerHTML = html;
        }

        // --- JOBS ---

        async function loadJobs() {
            let url = showJobHistory ? '/jobs?show_history=true' : '/jobs';
            let res = await apiFetch(url);
            if (!res) return;
            let data = await res.json();

            if (jobFilter !== "all") {
                data = data.filter(j => j.status === jobFilter);
            }

            if (data.length === 0) {
                document.getElementById("jobs").innerHTML = '<p class="text-gray-500 text-sm">No jobs found.</p>';
                return;
            }

            let html = `<table class="w-full text-sm">
                <thead><tr class="text-left text-gray-400 border-b border-gray-800">
                    <th class="pb-2 pr-3">#</th>
                    <th class="pb-2 pr-3">DB ID</th>
                    <th class="pb-2 pr-3">Type</th>
                    <th class="pb-2 pr-3">Target</th>
                    <th class="pb-2 pr-3">Status</th>
                    <th class="pb-2 pr-3">Priority</th>
                    <th class="pb-2 pr-3">Mode</th>
                    <th class="pb-2 pr-3">Profile</th>
                    <th class="pb-2 pr-3">Agent</th>
                    <th class="pb-2 pr-3">Completed</th>
                    <th class="pb-2">Action</th>
                </tr></thead><tbody>`;

            data.forEach((j, idx) => {
                const displayNum = idx + 1;
                let action;
                if (j.cleared) {
                    action = '<span class="text-xs text-gray-500 italic">archived</span>';
                } else if (j.status === 'pending' || j.status === 'failed') {
                    action = `<button onclick="clearJob(${j.id}, '${j.status}')" class="text-xs text-red-500 hover:text-red-400 transition font-medium">Delete</button>`;
                } else {
                    action = `<button onclick="clearJob(${j.id}, '${j.status}')" class="text-xs text-gray-400 hover:text-red-400 transition">Clear</button>`;
                }

                html += `<tr class="border-b border-gray-800 hover:bg-gray-800 transition">
                    <td class="py-2 pr-3 text-gray-500 text-xs">${displayNum}</td>
                    <td class="py-2 pr-3 text-gray-500 text-xs font-mono">${j.id}</td>
                    <td class="py-2 pr-3 font-mono text-xs text-blue-300">${j.type}</td>
                    <td class="py-2 pr-3 font-mono text-xs">${j.target}</td>
                    <td class="py-2 pr-3">${statusBadge(j.status)}</td>
                    <td class="py-2 pr-3">${priorityBadge(j.priority)}</td>
                    <td class="py-2 pr-3 text-xs text-gray-300">${j.mode}</td>
                    <td class="py-2 pr-3 text-xs text-gray-300">${j.profile}</td>
                    <td class="py-2 pr-3 text-xs text-gray-300">${j.agent}</td>
                    <td class="py-2 pr-3 text-xs text-gray-400">${formatTimestamp(j.completed_at)}</td>
                    <td class="py-2">${action}</td>
                </tr>`;
            });

            html += '</tbody></table>';
            document.getElementById("jobs").innerHTML = html;
        }

        async function clearJob(job_id, status) {
            // pending and failed = permanent delete, confirm first
            if (status === 'pending' || status === 'failed') {
                showConfirm(
                    `Permanently delete this ${status} job? This cannot be undone.`,
                    async () => {
                        await apiFetch(`/jobs/${job_id}/clear`, { method: 'POST' });
                        loadJobs();
                    }
                );
            } else {
                await apiFetch(`/jobs/${job_id}/clear`, { method: 'POST' });
                loadJobs();
            }
        }

        async function clearAllByStatus(status) {
            showConfirm(
                `Permanently delete ALL ${status} jobs? This cannot be undone.`,
                async () => {
                    const res = await apiFetch('/jobs');
                    if (!res) return;
                    const jobs = await res.json();
                    const targets = jobs.filter(j => j.status === status && !j.cleared);
                    await Promise.all(
                        targets.map(j => apiFetch(`/jobs/${j.id}/clear`, { method: 'POST' }))
                    );
                    loadJobs();
                }
            );
        }

        // --- RESULTS ---

        function toggleResult(id) {
            const body = document.getElementById(`result-body-${id}`);
            const arrow = document.getElementById(`result-arrow-${id}`);
            const isHidden = body.classList.contains('hidden');
            body.classList.toggle('hidden');
            arrow.innerText = isHidden ? '▲' : '▼';
        }

        function renderNmapResult(nmap) {
            if (!nmap || !nmap.length) return '<p class="text-gray-500 text-xs">No hosts found.</p>';
            return nmap.map(host => {
                const ports = host.ports && host.ports.length
                    ? host.ports.map(p => `
                        <tr class="border-b border-gray-700">
                            <td class="py-1 pr-4 font-mono text-blue-300">${p.port}</td>
                            <td class="py-1 pr-4 text-green-400">${p.state}</td>
                            <td class="py-1 text-gray-300">${p.service}</td>
                        </tr>`).join('')
                    : '<tr><td colspan="3" class="py-2 text-gray-500">No open ports found</td></tr>';

                return `<div class="mb-2">
                    <p class="text-xs text-gray-400 mb-1">Host: <span class="text-white font-mono">${host.host}</span></p>
                    <table class="w-full text-xs">
                        <thead><tr class="text-gray-500">
                            <th class="text-left pb-1 pr-4">Port</th>
                            <th class="text-left pb-1 pr-4">State</th>
                            <th class="text-left pb-1">Service</th>
                        </tr></thead>
                        <tbody>${ports}</tbody>
                    </table>
                </div>`;
            }).join('');
        }

        function renderNiktoResult(nikto) {
            if (!nikto) return '';
            return Object.entries(nikto).map(([port, result]) => {
                if (result.error) {
                    return `<div class="mt-2">
                        <p class="text-xs text-gray-400">Nikto port ${port}:</p>
                        <p class="text-xs text-red-400">${result.error}</p>
                    </div>`;
                }

                if (result.raw) {
                    const lines = result.raw.split('\\n');
                    const findings = lines.filter(l => l.match(/^\\+ \\[/));

                    if (!findings.length) {
                        return `<div class="mt-2">
                            <p class="text-xs text-gray-500">Nikto port ${port}: no findings extracted.</p>
                        </div>`;
                    }

                    return `<div class="mt-2">
                        <p class="text-xs text-gray-400 mb-2">Nikto port ${port} — ${findings.length} finding(s):</p>
                        <div class="space-y-1">
                            ${findings.map(line => {
                                const match = line.match(/^\\+ \\[(\\w+)\\] (.+?):\\s*(.+)$/);
                                if (match) {
                                    const [, id, url, msg] = match;
                                    return `<div class="bg-gray-950 rounded p-2 text-xs">
                                        <span class="text-yellow-400 font-mono">[${id}]</span>
                                        <span class="text-gray-400 font-mono ml-2">${url}:</span>
                                        <span class="text-gray-200 ml-1">${msg}</span>
                                    </div>`;
                                }
                                return `<div class="bg-gray-950 rounded p-2 text-xs text-gray-300">${line.replace(/^\\+ /, '')}</div>`;
                            }).join('')}
                        </div>
                    </div>`;
                }

                const vulns = result[0]?.vulnerabilities || [];
                if (!vulns.length) return `<p class="text-xs text-gray-500 mt-2">Nikto port ${port}: no vulnerabilities found.</p>`;
                return `<div class="mt-2">
                    <p class="text-xs text-gray-400 mb-1">Nikto port ${port} — ${vulns.length} finding(s):</p>
                    <div class="space-y-1">
                        ${vulns.map(v => `
                            <div class="bg-gray-950 rounded p-2 text-xs">
                                <span class="text-yellow-400 font-mono">[${v.id}]</span>
                                <span class="text-gray-200 ml-2">${v.msg}</span>
                                ${v.url ? `<span class="text-gray-500 ml-2"><a href="${v.url}" target="_blank" class="hover:text-blue-400 transition">${v.url}</a></span>` : ''}
                            </div>`).join('')}
                    </div>
                </div>`;
            }).join('');
        }

        function renderJobInfo(job_info) {
            if (!job_info) return '';
            return `<div class="mb-4 bg-gray-900 rounded-lg p-3 border border-gray-700">
                <p class="text-xs font-semibold text-purple-400 uppercase tracking-wider mb-2">Associated Job</p>
                <div class="grid grid-cols-2 gap-x-6 gap-y-1 text-xs">
                    <div><span class="text-gray-500">Job ID:</span> <span class="text-gray-200 font-mono">#${job_info.id}</span></div>
                    <div><span class="text-gray-500">Target:</span> <span class="text-gray-200 font-mono">${job_info.target}</span></div>
                    <div><span class="text-gray-500">Type:</span> <span class="text-gray-200">${job_info.type}</span></div>
                    <div><span class="text-gray-500">Mode:</span> <span class="text-gray-200">${job_info.mode}</span></div>
                    <div><span class="text-gray-500">Profile:</span> <span class="text-gray-200">${job_info.profile}</span></div>
                    <div><span class="text-gray-500">Priority:</span> <span class="text-gray-200">${job_info.priority}</span></div>
                    <div class="col-span-2"><span class="text-gray-500">Completed:</span> <span class="text-gray-200">${formatTimestamp(job_info.completed_at)}</span></div>
                </div>
            </div>`;
        }

        async function clearResult(result_id) {
            await apiFetch(`/results/${result_id}/clear`, { method: 'POST' });
            loadResults();
            loadJobs();
        }

        async function deleteResult(result_id) {
            showConfirm(
                `Permanently delete Result #${result_id} and its associated job? This cannot be undone.`,
                async () => {
                    await apiFetch(`/results/${result_id}`, { method: 'DELETE' });
                    loadResults();
                    loadJobs();
                }
            );
        }

        async function loadResults() {
            const isHistory = resultTab === 'history';
            const url = isHistory ? '/results?show_history=true' : '/results';
            let res = await apiFetch(url);
            if (!res) return;
            let data = await res.json();

            if (data.length === 0) {
                document.getElementById("results").innerHTML =
                    `<p class="text-gray-500 text-sm">${isHistory ? 'No archived results.' : 'No results yet.'}</p>`;
                return;
            }

            const html = data.slice().reverse().map(r => {
                const out = r.output;
                const nmapCount = out.nmap
                    ? out.nmap.reduce((acc, h) => acc + (h.ports ? h.ports.filter(p => p.state === 'open').length : 0), 0)
                    : 0;
                const niktoCount = out.nikto
                    ? Object.values(out.nikto).reduce((acc, v) => {
                        if (v.error) return acc;
                        if (v.raw) return acc + (v.raw.match(/^\\+ \\[/gm) || []).length;
                        return acc + (v[0]?.vulnerabilities?.length || 0);
                    }, 0)
                    : 0;

                const summary = [
                    out.nmap ? `${nmapCount} open port(s)` : null,
                    out.nikto ? `${niktoCount} web finding(s)` : null
                ].filter(Boolean).join(' · ') || 'No data';

                const actions = isHistory
                    ? `<div class="flex items-center gap-3">
                        <input type="checkbox" class="result-checkbox accent-red-500" data-id="${r.id}">
                        <button onclick="deleteResult(${r.id})"
                            class="text-xs text-red-400 hover:text-red-300 transition">Delete</button>
                       </div>`
                    : `<button onclick="clearResult(${r.id})"
                        class="text-xs text-gray-400 hover:text-red-400 transition">Clear</button>`;

                return `<div class="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
                    <div class="flex items-center justify-between px-5 py-4 cursor-pointer hover:bg-gray-750 transition"
                        onclick="toggleResult(${r.id})">
                        <div class="flex items-center gap-4">
                            <span class="text-sm font-semibold text-white">Result #${r.id}</span>
                            <span class="text-xs text-gray-400">Job #${r.job_id}</span>
                            <span class="text-xs text-gray-500">${summary}</span>
                        </div>
                        <div class="flex items-center gap-4" onclick="event.stopPropagation()">
                            ${actions}
                            <span id="result-arrow-${r.id}" class="text-gray-400 text-xs pointer-events-none">▼</span>
                        </div>
                    </div>
                    <div id="result-body-${r.id}" class="hidden px-5 pb-5 border-t border-gray-700 pt-4">
                        ${isHistory ? renderJobInfo(r.job_info) : ''}
                        ${out.nmap ? `<div class="mb-3">
                            <p class="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-2">Nmap</p>
                            ${renderNmapResult(out.nmap)}
                        </div>` : ''}
                        ${out.nikto ? `<div>
                            <p class="text-xs font-semibold text-orange-400 uppercase tracking-wider mb-1">Nikto</p>
                            ${renderNiktoResult(out.nikto)}
                        </div>` : ''}
                        ${!out.nmap && !out.nikto ? `<pre class="text-xs text-gray-400 overflow-x-auto">${JSON.stringify(out, null, 2)}</pre>` : ''}
                    </div>
                </div>`;
            }).join('');

            document.getElementById("results").innerHTML = html;
        }

        // --- DISCOVERY ---

        let activeSweepId = null;
        let sweepPollInterval = null;

        async function startDiscovery() {
            const subnet = document.getElementById("discoverSubnet").value.trim();
            const mode = document.getElementById("discoverMode").value;
            const profile = document.getElementById("discoverProfile").value;

            if (!subnet) {
                alert("Please enter a subnet in CIDR format (e.g. 192.168.1.0/24)");
                return;
            }

            const res = await apiFetch('/discover', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ subnet, mode, profile })
            });
            if (!res) return;

            const data = await res.json();
            activeSweepId = data.sweep_id;

            document.getElementById("sweepStatus").classList.remove('hidden');
            document.getElementById("sweepSpinner").classList.add('animate-pulse');
            document.getElementById("sweepStatusText").textContent = `Sweeping ${subnet}...`;

            // poll every 3 seconds until done
            sweepPollInterval = setInterval(() => pollSweep(activeSweepId), 3000);
        }

        async function pollSweep(sweepId) {
            const res = await apiFetch(`/discover/${sweepId}`);
            if (!res) return;
            const data = await res.json();

            if (data.status === 'done') {
                clearInterval(sweepPollInterval);
                sweepPollInterval = null;

                document.getElementById("sweepSpinner").classList.remove('animate-pulse');
                document.getElementById("sweepSpinner").classList.remove('bg-cyan-400');
                document.getElementById("sweepSpinner").classList.add('bg-green-400');
                document.getElementById("sweepStatusText").textContent =
                    `Sweep complete — ${data.hosts_found} host(s) found, ${data.jobs_created} job(s) created`;

                loadSweepHistory();
                loadJobs();

            } else if (data.status === 'failed') {
                clearInterval(sweepPollInterval);
                sweepPollInterval = null;

                document.getElementById("sweepSpinner").classList.remove('bg-cyan-400');
                document.getElementById("sweepSpinner").classList.add('bg-red-500');
                document.getElementById("sweepStatusText").textContent = 'Sweep failed. Check server logs.';
                loadSweepHistory();
            }
        }

        async function loadSweepHistory() {
            const res = await apiFetch('/discover');
            if (!res) return;
            const sweeps = await res.json();

            if (!sweeps.length) {
                document.getElementById("sweepHistory").innerHTML =
                    '<p class="text-gray-600 text-xs">No sweeps yet.</p>';
                return;
            }

            const statusColor = {
                running: 'text-blue-400',
                done:    'text-green-400',
                failed:  'text-red-400',
            };

            const rows = sweeps.map(s => `
                <tr class="border-b border-gray-800 hover:bg-gray-800 transition text-xs">
                    <td class="py-2 pr-4 text-gray-400">#${s.id}</td>
                    <td class="py-2 pr-4 font-mono">${s.subnet}</td>
                    <td class="py-2 pr-4 ${statusColor[s.status] || 'text-gray-400'}">${s.status}</td>
                    <td class="py-2 pr-4 text-gray-300">${s.hosts_found} host(s)</td>
                    <td class="py-2 pr-4 text-gray-300">${s.jobs_created} job(s)</td>
                    <td class="py-2 text-gray-500">${formatTimestamp(s.started_at)}</td>
                </tr>`).join('');

            document.getElementById("sweepHistory").innerHTML = `
                <table class="w-full text-sm mt-2">
                    <thead><tr class="text-left text-gray-500 border-b border-gray-800">
                        <th class="pb-2 pr-4">ID</th>
                        <th class="pb-2 pr-4">Subnet</th>
                        <th class="pb-2 pr-4">Status</th>
                        <th class="pb-2 pr-4">Hosts</th>
                        <th class="pb-2 pr-4">Jobs</th>
                        <th class="pb-2">Started</th>
                    </tr></thead>
                    <tbody>${rows}</tbody>
                </table>`;
        }

        setInterval(() => {
            loadAgents();
            loadJobs();
        }, 5000);

        // load sweep history on first login
        const _origLoadAll = loadAll;
        loadAll = async function() {
            await _origLoadAll();
            loadSweepHistory();
        };
        </script>
    </body>
    </html>
    """
