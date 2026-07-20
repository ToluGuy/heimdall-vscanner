# backend/app/services/scheduler.py
#
# Background threads started at app startup (see main.py's startup event):
# stale-agent flagging (hourly) and schedule-driven job creation (every
# SCHEDULE_TICK_SECONDS). Both open their own DB session per tick since they
# run outside the request/response cycle where FastAPI's Depends(get_db)
# doesn't apply.

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import Agent, Job, Schedule, Setting
from ..core import logger, SCHEDULE_TICK_SECONDS, SETTING_DEFAULTS, get_setting


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
                    port=schedule.port,
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


def init_default_settings():
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
