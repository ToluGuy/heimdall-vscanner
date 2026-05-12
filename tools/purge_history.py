#!/usr/bin/env python3
# tools/purge_history.py
# Heimdall V-Scanner — Purge Archived History
#
# Permanently deletes all cleared (archived) results and their associated jobs
# from the database. Useful for cleaning up after a large discovery sweep or
# before a scheduled maintenance window.
#
# Usage:
#   python tools/purge_history.py
#   python tools/purge_history.py --dry-run          # preview without deleting
#   python tools/purge_history.py --older-than 30    # only purge results older than 30 days
#   python tools/purge_history.py --yes              # skip confirmation prompt

import sys
import os
import argparse
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from backend.app.db import SessionLocal
    from backend.app.models import Result, Job
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
    parser = argparse.ArgumentParser(description="Heimdall V-Scanner — Purge Archived History")
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="Preview what would be deleted without making any changes")
    parser.add_argument("--older-than", type=int, default=None, metavar="DAYS",
                        help="Only purge results older than this many days (default: all history)")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Skip the confirmation prompt")
    args = parser.parse_args()

    print(f"\n{BOLD}Heimdall V-Scanner — Purge Archived History{RESET}")
    if args.dry_run:
        print(f"  {YELLOW}DRY RUN — no changes will be made{RESET}")
    if args.older_than:
        print(f"  Scope: results older than {args.older_than} day(s)")
    else:
        print(f"  Scope: all archived results")
    print()

    db = SessionLocal()

    try:
        query = db.query(Result).filter(Result.cleared == True)

        if args.older_than:
            cutoff = datetime.utcnow() - timedelta(days=args.older_than)
            query = query.filter(Result.created_at < cutoff)

        cleared_results = query.all()

        if not cleared_results:
            print(f"  {GREEN}[✓]{RESET} No archived results found matching criteria. Nothing to do.\n")
            return

        job_ids = [r.job_id for r in cleared_results]
        jobs_to_delete = db.query(Job).filter(Job.id.in_(job_ids)).all() if job_ids else []

        print(f"  {CYAN}[→]{RESET} Found:")
        print(f"       {len(cleared_results)} archived result(s)")
        print(f"       {len(jobs_to_delete)} associated job(s)")

        if args.dry_run:
            print(f"\n  {DIM}(dry run — the following would be deleted){RESET}")
            for r in cleared_results[:10]:
                created = r.created_at.strftime("%Y-%m-%d %H:%M") if r.created_at else "—"
                print(f"    Result #{r.id}  Job #{r.job_id}  created {created}")
            if len(cleared_results) > 10:
                print(f"    ... and {len(cleared_results) - 10} more")
            print(f"\n  Run without --dry-run to delete these records.\n")
            return

        if not args.yes:
            print()
            confirm = input(f"  {YELLOW}[!]{RESET} This will permanently delete {len(cleared_results)} result(s) and {len(jobs_to_delete)} job(s). Continue? [y/N]: ").strip().lower()
            if confirm != "y":
                print(f"\n  {CYAN}[→]{RESET} Aborted. No changes made.\n")
                return

        for r in cleared_results:
            db.delete(r)
        for j in jobs_to_delete:
            db.delete(j)

        db.commit()

        print(f"\n  {GREEN}[✓]{RESET} Deleted {len(cleared_results)} result(s) and {len(jobs_to_delete)} job(s).")
        print(f"  {GREEN}[✓]{RESET} History purge complete.\n")

    finally:
        db.close()


if __name__ == "__main__":
    main()
