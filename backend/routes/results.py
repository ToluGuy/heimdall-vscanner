# backend/app/routes/results.py

import json
import threading
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db, SessionLocal
from ..models import Job, Result
from ..schemas import ResultResponse
from ..core import logger, require_auth
from ..ai_analysis import analyse_scan

router = APIRouter()


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


@router.get("/results", response_model=List[ResultResponse])
def get_results(
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
    show_history: bool = False,
    show_sweep_results: bool = False,
):
    query = db.query(Result).filter(Result.cleared == (True if show_history else False))
    if not show_sweep_results:
        # Same reasoning as get_jobs() — a sweep's results have their own
        # consolidated view, so they're hidden from the main Results list
        # by default rather than flooding it one entry per discovered host.
        sweep_job_ids = [j.id for j in db.query(Job.id).filter(Job.sweep_id != None).all()]
        if sweep_job_ids:
            query = query.filter(Result.job_id.notin_(sweep_job_ids))
    results = query.all()

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


@router.post("/results/{result_id}/clear")
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


@router.delete("/results/clear-all-history")
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


@router.delete("/results/bulk")
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


@router.delete("/results/{result_id}")
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


@router.post("/results/{result_id}/analyse")
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


@router.get("/export/results")
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
