#!/usr/bin/env python3
# tools/check_db.py
# Heimdall V-Scanner — Database Health Check
#
# Connects to the configured database and prints a summary of current state.
# Useful for a quick sanity check without opening the dashboard.
#
# Usage:
#   python tools/check_db.py
#   python tools/check_db.py --verbose

import sys
import os
import argparse
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from backend.app.db import SessionLocal
    from backend.app.models import Agent, Job, Result, DiscoverySweep, Schedule
except ImportError as e:
    print(f"[✗] Import error: {e}")
    print("    Run this script from the project root directory.")
    sys.exit(1)

# ── colour helpers ────────────────────────────────────────────────────────────

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def ok(msg):    print(f"  {GREEN}[✓]{RESET} {msg}")
def warn(msg):  print(f"  {YELLOW}[!]{RESET} {msg}")
def err(msg):   print(f"  {RED}[✗]{RESET} {msg}")
def info(msg):  print(f"  {CYAN}[→]{RESET} {msg}")
def header(msg): print(f"\n{BOLD}{CYAN}━━━ {msg} ━━━{RESET}")


def main():
    parser = argparse.ArgumentParser(description="Heimdall V-Scanner — Database Health Check")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show individual record details")
    args = parser.parse_args()

    print(f"\n{BOLD}Heimdall V-Scanner — Database Check{RESET}")
    print(f"  {DIM}{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}{RESET}\n")

    db = SessionLocal()

    try:
        # ── Connection test ───────────────────────────────────────────────────
        header("Connection")
        try:
            db.execute(__import__("sqlalchemy").text("SELECT 1"))
            ok("Database connection successful")
        except Exception as e:
            err(f"Cannot connect to database: {e}")
            sys.exit(1)

        # ── Agents ────────────────────────────────────────────────────────────
        header("Agents")
        agents = db.query(Agent).all()
        total_agents   = len(agents)
        online_agents  = sum(1 for a in agents if a.last_seen and
                             (datetime.utcnow() - a.last_seen) < timedelta(seconds=30))
        stale_agents   = sum(1 for a in agents if a.is_stale)
        active_agents  = total_agents - stale_agents

        ok(f"Total: {total_agents}  |  Active: {active_agents}  |  Online now: {online_agents}  |  Stale: {stale_agents}")

        if args.verbose and agents:
            for a in sorted(agents, key=lambda x: x.id):
                age = (datetime.utcnow() - a.last_seen).total_seconds() if a.last_seen else None
                status = f"{GREEN}online{RESET}" if age and age < 30 else f"{RED}offline{RESET}"
                stale_tag = f" {YELLOW}[stale]{RESET}" if a.is_stale else ""
                last = a.last_seen.strftime("%Y-%m-%d %H:%M") if a.last_seen else "never"
                print(f"    #{a.id} {a.name}{stale_tag} — {status} — last seen {last}")

        # ── Jobs ──────────────────────────────────────────────────────────────
        header("Jobs")
        jobs = db.query(Job).all()
        by_status = {}
        for j in jobs:
            by_status[j.status] = by_status.get(j.status, 0) + 1

        pending = by_status.get("pending", 0)
        running = by_status.get("running", 0)
        done    = by_status.get("done", 0)
        failed  = by_status.get("failed", 0)
        cleared = sum(1 for j in jobs if j.cleared)

        ok(f"Total: {len(jobs)}  |  Pending: {pending}  |  Running: {running}  |  Done: {done}  |  Failed: {failed}  |  Archived: {cleared}")

        if running > 0:
            running_jobs = [j for j in jobs if j.status == "running"]
            for j in running_jobs:
                elapsed = (datetime.utcnow() - j.started_at).total_seconds() if j.started_at else 0
                mins = int(elapsed // 60)
                secs = int(elapsed % 60)
                elapsed_str = f"{mins}m {secs}s" if mins else f"{secs}s"
                warn(f"Running: Job #{j.id} — {j.type} on {j.target} ({elapsed_str} elapsed)")

        if failed > 0:
            warn(f"{failed} failed job(s) in the queue — consider running reset_stuck_jobs.py")

        if pending > 50:
            warn(f"{pending} pending jobs is high — is the scanner running?")

        if args.verbose and jobs:
            print(f"\n  {DIM}Recent jobs (last 10):{RESET}")
            recent = sorted(jobs, key=lambda x: x.id, reverse=True)[:10]
            for j in recent:
                ts = j.created_at.strftime("%m-%d %H:%M") if j.created_at else "—"
                status_colour = GREEN if j.status == "done" else (RED if j.status == "failed" else YELLOW)
                print(f"    #{j.id} [{status_colour}{j.status}{RESET}] {j.type} → {j.target}  {DIM}{ts}{RESET}")

        # ── Results ───────────────────────────────────────────────────────────
        header("Results")
        results = db.query(Result).all()
        active_results  = sum(1 for r in results if not r.cleared)
        history_results = sum(1 for r in results if r.cleared)

        ok(f"Total: {len(results)}  |  Active: {active_results}  |  History: {history_results}")

        if history_results > 100:
            warn(f"{history_results} archived results — consider running purge_history.py to clean up")

        # ── Schedules ─────────────────────────────────────────────────────────
        header("Schedules")
        schedules = db.query(Schedule).all()
        active_scheds = sum(1 for s in schedules if not s.paused)
        paused_scheds = sum(1 for s in schedules if s.paused)

        ok(f"Total: {len(schedules)}  |  Active: {active_scheds}  |  Paused: {paused_scheds}")

        if args.verbose and schedules:
            for s in schedules:
                state = f"{GREEN}active{RESET}" if not s.paused else f"{YELLOW}paused{RESET}"
                next_run = s.next_run_at.strftime("%m-%d %H:%M") if s.next_run_at and not s.paused else "—"
                print(f"    {s.name} — {s.type} on {s.target} every {s.interval_hours}h — {state} — next: {next_run}")

        # ── Discovery sweeps ──────────────────────────────────────────────────
        header("Discovery Sweeps")
        sweeps = db.query(DiscoverySweep).all()
        done_sweeps   = sum(1 for s in sweeps if s.status == "done")
        failed_sweeps = sum(1 for s in sweeps if s.status == "failed")

        ok(f"Total: {len(sweeps)}  |  Done: {done_sweeps}  |  Failed: {failed_sweeps}")

        # ── Summary ───────────────────────────────────────────────────────────
        header("Summary")

        issues = []
        if running > 0:
            elapsed_all = []
            for j in jobs:
                if j.status == "running" and j.started_at:
                    elapsed_all.append((datetime.utcnow() - j.started_at).total_seconds())
            long_running = [e for e in elapsed_all if e > 300]
            if long_running:
                issues.append(f"{len(long_running)} job(s) running for over 5 minutes — may be stuck")
        if failed > 0:
            issues.append(f"{failed} failed job(s) in queue")
        if stale_agents > 0:
            issues.append(f"{stale_agents} stale agent(s) — use dashboard to restore or dismiss")
        if failed_sweeps > 0:
            issues.append(f"{failed_sweeps} failed discovery sweep(s)")

        if issues:
            for issue in issues:
                warn(issue)
        else:
            ok("Everything looks healthy")

        print()

    finally:
        db.close()


if __name__ == "__main__":
    main()
