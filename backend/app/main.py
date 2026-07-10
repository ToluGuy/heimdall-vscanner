# backend/app/main.py
#
# FastAPI app assembly only. Route handlers live in routes/*.py (one file per
# resource), background jobs live in services/scheduler.py, and shared
# config/auth/helpers live in core.py. This file used to be ~6,200 lines
# (most of it the embedded dashboard, then a further ~2,300 lines of route
# handlers) — see the git history / handoff notes if you need the old
# monolith for reference.

import threading

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI

from .db import Base, engine
from .core import logger
from .services.scheduler import run_stale_cleanup, run_scheduler, init_default_settings

from .routes import agents, jobs, results, hosts, schedules, discovery, reports, insights, topology, settings, dashboard

Base.metadata.create_all(bind=engine)

app = FastAPI(title="VAPT Scanner API")

app.include_router(dashboard.router)   # "/", "/dashboard", "/static/{filename}"
app.include_router(agents.router)      # Agent resource + agent daemon self-reporting
app.include_router(jobs.router)        # Job resource + dispatch
app.include_router(results.router)     # Result resource + AI analysis + export
app.include_router(hosts.router)       # Host resource
app.include_router(schedules.router)   # Schedule resource
app.include_router(discovery.router)   # Discovery sweeps
app.include_router(reports.router)     # HTML report generation
app.include_router(insights.router)    # Dashboard insights/analytics
app.include_router(topology.router)    # Network topology graph
app.include_router(settings.router)    # Server-side settings


@app.on_event("startup")
def startup_cleanup():
    thread = threading.Thread(target=run_stale_cleanup, daemon=True)
    thread.start()
    logger.info("Stale agent cleanup thread started")

    sched_thread = threading.Thread(target=run_scheduler, daemon=True)
    sched_thread.start()
    logger.info("Job scheduler thread started")

    init_default_settings()
