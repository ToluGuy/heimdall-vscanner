# backend/routes/discovery.py

import json
import threading
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db, SessionLocal
from ..models import DiscoverySweep, Job, Result
from ..core import logger, require_auth, validate_target, get_discovery_job_types

router = APIRouter()


@router.get("/discover/job-types")
def get_sweep_job_types(db: Session = Depends(get_db), username: str = Depends(require_auth)):
    return get_discovery_job_types(db)


def run_ping_sweep(sweep_id: int, subnet: str, mode: str, profile: str, job_type: str):
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
                type=job_type,
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


@router.post("/discover")
def start_discovery(
    data: dict,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth)
):
    subnet = validate_target(data.get("subnet", ""), field_name="subnet")
    mode = data.get("mode", "remote")
    profile = data.get("profile", "standard")
    job_type = data.get("job_type", "nmap_scan")

    allowed = get_discovery_job_types(db)
    if job_type not in {jt["type"] for jt in allowed}:
        raise HTTPException(
            status_code=400,
            detail=f"'{job_type}' isn't available for sweeps. Valid: {sorted(jt['type'] for jt in allowed)}"
        )

    sweep = DiscoverySweep(
        subnet=subnet,
        status="running"
    )
    db.add(sweep)
    db.commit()
    db.refresh(sweep)

    thread = threading.Thread(
        target=run_ping_sweep,
        args=(sweep.id, subnet, mode, profile, job_type),
        daemon=True
    )
    thread.start()

    logger.info(f"Discovery sweep {sweep.id} started for subnet {subnet}")
    return {"sweep_id": sweep.id, "status": "running"}


@router.get("/discover/{sweep_id}")
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


@router.post("/discover/{sweep_id}/cancel")
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


@router.post("/sweeps/{sweep_id}/cancel-jobs")
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


# NOTE: this route previously had no @router/@app decorator at all — it was
# unreachable dead code (a bare `def`, unregistered with FastAPI). The
# dashboard JS already calls GET /sweeps/{sweep_id}/results (see app.js),
# so this was a live 404 in the running app. Restoring the matching
# decorator here, not something I'm introducing new.
@router.get("/sweeps/{sweep_id}/results")
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


@router.get("/discover")
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


@router.post("/discover/ping")
def ping_sweep(
    data: dict,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth)
):
    """
    Fast ping sweep — discovers live hosts in a subnet and creates a sweep
    record for them, but does NOT create scan jobs itself. Returns the host
    list plus sweep_id, so a follow-up flow (e.g. the sweep confirmation
    dialog) can create jobs against sweep_id — keeping them grouped and out
    of the main Jobs/Results lists, same as jobs from POST /discover.
    """
    subnet = validate_target(data.get("subnet", ""), field_name="subnet")

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

        sweep = DiscoverySweep(
            subnet=subnet,
            status="done",
            hosts_found=len(hosts),
            jobs_created=0,  # updated implicitly — /sweeps/{id}/results queries live Job rows, not this counter
            result=json.dumps([h["ip"] for h in hosts]),
            completed_at=datetime.utcnow(),
        )
        db.add(sweep)
        db.commit()
        db.refresh(sweep)

        logger.info(f"Ping sweep on {subnet}: {len(hosts)} host(s) found (sweep_id={sweep.id})")
        return {"subnet": subnet, "hosts": hosts, "count": len(hosts), "sweep_id": sweep.id}

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Ping sweep timed out")


@router.delete("/discover/{sweep_id}")
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


@router.delete("/discover")
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
