#!/usr/bin/env python3
# tools/reset_stuck_jobs.py
# Heimdall V-Scanner — Reset Stuck Jobs
#
# Finds jobs stuck in 'running' status and resets them back to 'pending'
# so they can be picked up again. Also marks jobs that have exceeded their
# max retries as failed.
#
# A job is considered stuck if it has been running longer than the threshold
# (default: 10 minutes). This is more generous than the server's built-in
# 120-second timeout because this tool runs manually and you may want to
# give long scans more time before intervening.
#
# Usage:
#   python tools/reset_stuck_jobs.py
#   python tools/reset_stuck_jobs.py --threshold 30   # 30 minute threshold
#   python tools/reset_stuck_jobs.py --dry-run        # preview without changing anything

import sys
import os
import argparse
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from backend.app.db import SessionLocal
    from backend.app.models import Job
except ImportError as e:
    print(f"[✗] Import error: {e}")
    print("    Run this script from the project root directory.")
    sys.exit(1)

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


def main():
    parser = argparse.ArgumentParser(description="Heimdall V-Scanner — Reset Stuck Jobs")
    parser.add_argument("--threshold", "-t", type=int, default=10,
                        help="Minutes a job must be running before it is considered stuck (default: 10)")
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="Preview what would be reset without making any changes")
    args = parser.parse_args()

    print(f"\n{BOLD}Heimdall V-Scanner — Reset Stuck Jobs{RESET}")
    print(f"  Threshold : {args.threshold} minute(s)")
    print(f"  Mode      : {'DRY RUN — no changes will be made' if args.dry_run else 'LIVE'}\n")

    db = SessionLocal()
    now = datetime.utcnow()
    cutoff = now - timedelta(minutes=args.threshold)

    try:
        running_jobs = db.query(Job).filter(Job.status == "running").all()

        if not running_jobs:
            print(f"  {GREEN}[✓]{RESET} No jobs currently in 'running' status. Nothing to do.\n")
            return

        print(f"  {CYAN}[→]{RESET} Found {len(running_jobs)} job(s) in 'running' status:\n")

        reset_count  = 0
        failed_count = 0
        ok_count     = 0

        for job in running_jobs:
            if job.started_at is None:
                elapsed_str = "unknown duration"
                is_stuck = True
            else:
                elapsed = now - job.started_at
                total_secs = int(elapsed.total_seconds())
                mins = total_secs // 60
                secs = total_secs % 60
                elapsed_str = f"{mins}m {secs}s"
                is_stuck = job.started_at < cutoff

            target_info = f"{job.type} → {job.target} ({job.profile})"
            agent_info  = f"agent #{job.agent_id}" if job.agent_id else "any agent"

            if not is_stuck:
                print(f"    {GREEN}[ok]{RESET}    Job #{job.id} — {target_info} — {elapsed_str} — still within threshold")
                ok_count += 1
                continue

            if job.retries >= job.max_retries:
                print(f"    {RED}[fail]{RESET}   Job #{job.id} — {target_info} — {elapsed_str} — exceeded max retries ({job.retries}/{job.max_retries}), marking failed")
                if not args.dry_run:
                    job.status = "failed"
                    job.started_at = None
                    job.completed_at = now
                failed_count += 1
            else:
                delay = (job.retries + 1) * 30
                print(f"    {YELLOW}[reset]{RESET}  Job #{job.id} — {target_info} — {elapsed_str} — retry {job.retries + 1}/{job.max_retries}, requeuing in {delay}s")
                if not args.dry_run:
                    job.retries += 1
                    job.status = "pending"
                    job.agent_id = None
                    job.started_at = None
                    job.next_run_at = now + timedelta(seconds=delay)
                reset_count += 1

        if not args.dry_run and (reset_count + failed_count) > 0:
            db.commit()

        print(f"\n  {'(dry run) ' if args.dry_run else ''}Results:")
        if ok_count:     print(f"    {GREEN}[✓]{RESET} {ok_count} job(s) still running within threshold — left alone")
        if reset_count:  print(f"    {YELLOW}[!]{RESET} {reset_count} job(s) {'would be' if args.dry_run else 'were'} reset to pending")
        if failed_count: print(f"    {RED}[✗]{RESET} {failed_count} job(s) {'would be' if args.dry_run else 'were'} marked failed (max retries exceeded)")

        if args.dry_run and (reset_count + failed_count) > 0:
            print(f"\n  Run without --dry-run to apply these changes.")

        print()

    finally:
        db.close()


if __name__ == "__main__":
    main()
