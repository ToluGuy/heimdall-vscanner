# backend/app/routes/agents.py
#
# Everything to do with the Agent resource: dashboard-facing registration/
# management (HTTP Basic auth) and the agent daemon's own self-reporting
# endpoints (x-api-key auth) — register, heartbeat, crash recovery, job-status
# updates, and result submission. Kept together rather than split by resource
# vs. auth-scheme because "who calls this" is the more useful grouping in a
# tool where the agent/dashboard trust boundary matters.

import os
import json
import secrets
import subprocess
import threading
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Agent, Job, Host, Result
from ..schemas import AgentCreate, AgentResponse, ResultCreate
from ..core import (
    logger, require_auth, get_setting,
    AGENT_REGISTRATION_TOKEN, INSTALL_DIR, ENV_FILE, PYTHON_BIN, SCANNER_PY,
    SCANNER_AUTOSTART,
)
from ..services.hooks import fire_hook
from .results import run_ai_analysis

router = APIRouter()


@router.post("/agents/register", response_model=AgentResponse)
def register_agent(
    agent: AgentCreate,
    db: Session = Depends(get_db),
    x_registration_token: str | None = Header(default=None),
):
    if AGENT_REGISTRATION_TOKEN:
        if not x_registration_token or not secrets.compare_digest(
            x_registration_token, AGENT_REGISTRATION_TOKEN
        ):
            raise HTTPException(status_code=401, detail="Invalid or missing registration token")

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
    Returns (host, was_newly_created) — the caller fires the host.new hook
    itself, after its own commit, since a background thread's hook
    execution opens a fresh DB session that won't see this row until the
    surrounding transaction actually commits.
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
        return host, True

    return host, False


@router.post("/agents/results")
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
    host_is_new = False
    if target_ip:
        try:
            host, host_is_new = find_or_create_host(db, ip=target_ip, mac=mac, hostname=hostname,
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

    # Fire hooks only after the commit above — a background thread's hook
    # execution opens its own DB session, which won't see these rows until
    # this transaction has actually committed.
    if host_is_new:
        threading.Thread(
            target=fire_hook,
            args=("host.new", {"host_id": host.id, "ip": host.ip, "mac": host.mac, "hostname": host.hostname}),
            daemon=True
        ).start()

    if job:
        threading.Thread(
            target=fire_hook,
            args=("job.completed", {
                "job_id": job.id, "type": job.type, "target": job.target,
                "result_id": new_result.id,
            }),
            daemon=True
        ).start()

    return {"message": "Result stored"}


@router.post("/scanners/register")
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


@router.get("/agents")
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


@router.post("/agents/{agent_id}/dismiss")
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

@router.post("/agents/{agent_id}/restore")
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


@router.delete("/scanners/{agent_id}")
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


@router.post("/agents/heartbeat")
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


@router.post("/agents/recover")
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

@router.post("/agents/job-status")
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

    if new_status == "failed":
        threading.Thread(
            target=fire_hook,
            args=("job.failed", {"job_id": job.id, "type": job.type, "target": job.target}),
            daemon=True
        ).start()

    return {"ok": True}
