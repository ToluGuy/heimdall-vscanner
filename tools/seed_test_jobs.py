#!/usr/bin/env python3
# tools/seed_test_jobs.py
# Heimdall V-Scanner — Seed Test Jobs
#
# Creates a set of test scan jobs against safe targets to verify that a fresh
# install is working end-to-end. All jobs target localhost (127.0.0.1) or a
# user-specified test IP. No real network scanning is performed unless you
# point it at a real target.
#
# After running this, open the dashboard and confirm the jobs appear,
# get picked up by the scanner, and produce results.
#
# Usage:
#   python tools/seed_test_jobs.py
#   python tools/seed_test_jobs.py --target 192.168.1.50
#   python tools/seed_test_jobs.py --target 127.0.0.1 --profile light
#   python tools/seed_test_jobs.py --count 5           # create 5 nmap jobs
#   python tools/seed_test_jobs.py --all-types         # one of each scan type

import sys
import os
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from backend.db import SessionLocal
    from backend.models import Job
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

def ok(msg):   print(f"  {GREEN}[✓]{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}[!]{RESET} {msg}")
def err(msg):  print(f"  {RED}[✗]{RESET} {msg}")
def info(msg): print(f"  {CYAN}[→]{RESET} {msg}")


SCAN_TYPES = {
    "nmap_scan": {
        "description": "Port scan with automatic Nikto follow-up on web ports",
        "port": None,
        "ports": None,
    },
    "nse_scan": {
        "description": "NSE vulnerability scan (non-web ports)",
        "port": None,
        "ports": None,
    },
    "nikto_scan": {
        "description": "Standalone web vulnerability scan on port 80",
        "port": 80,
        "ports": None,
    },
}


def create_job(db, job_type: str, target: str, profile: str, mode: str, priority: str, port=None, ports=None) -> Job:
    job = Job(
        type=job_type,
        target=target,
        status="pending",
        mode=mode,
        profile=profile,
        priority=priority,
        port=port,
        ports=ports,
    )
    db.add(job)
    db.flush()  # get the ID without committing
    return job


def main():
    parser = argparse.ArgumentParser(description="Heimdall V-Scanner — Seed Test Jobs")
    parser.add_argument("--target", default="127.0.0.1",
                        help="Target IP for test jobs (default: 127.0.0.1)")
    parser.add_argument("--profile", default="light",
                        choices=["light", "standard", "full"],
                        help="Scan profile (default: light — fastest for testing)")
    parser.add_argument("--mode", default="remote",
                        choices=["remote", "agent"],
                        help="Job mode (default: remote)")
    parser.add_argument("--priority", default="low",
                        choices=["high", "medium", "low"],
                        help="Job priority (default: low — test jobs shouldn't jump the queue)")
    parser.add_argument("--count", type=int, default=1,
                        help="Number of nmap_scan jobs to create (default: 1)")
    parser.add_argument("--all-types", action="store_true",
                        help="Create one job of each scan type instead of --count nmap jobs")
    args = parser.parse_args()

    print(f"\n{BOLD}Heimdall V-Scanner — Seed Test Jobs{RESET}")
    print(f"  Target  : {BOLD}{args.target}{RESET}")
    print(f"  Profile : {args.profile}")
    print(f"  Mode    : {args.mode}")
    print(f"  Priority: {args.priority}")
    print()

    if args.target == "127.0.0.1":
        info("Using localhost (127.0.0.1) — scanning the server itself")
        info("This is safe and just verifies the pipeline works end-to-end")
    else:
        warn(f"Targeting {args.target} — make sure you have authorisation to scan this host")

    print()

    db = SessionLocal()
    created = []

    try:
        if args.all_types:
            info("Creating one job of each scan type...")
            for job_type, cfg in SCAN_TYPES.items():
                job = create_job(
                    db,
                    job_type=job_type,
                    target=args.target,
                    profile=args.profile,
                    mode=args.mode,
                    priority=args.priority,
                    port=cfg["port"],
                    ports=cfg["ports"],
                )
                created.append((job.id, job_type, cfg["description"]))
        else:
            info(f"Creating {args.count} nmap_scan job(s)...")
            for i in range(args.count):
                job = create_job(
                    db,
                    job_type="nmap_scan",
                    target=args.target,
                    profile=args.profile,
                    mode=args.mode,
                    priority=args.priority,
                )
                created.append((job.id, "nmap_scan", SCAN_TYPES["nmap_scan"]["description"]))

        db.commit()

        print()
        for job_id, job_type, description in created:
            ok(f"Job #{job_id} — {job_type} — {description}")

        print(f"\n  {len(created)} job(s) created successfully.")
        print(f"\n  {CYAN}Next steps:{RESET}")
        print(f"  1. Open the dashboard and check the Jobs section")
        print(f"  2. Confirm the scanner picks up the job(s) within 10 seconds")
        print(f"  3. Check the Results section once complete")
        if args.mode == "remote":
            print(f"  4. If no results appear, check that vapt-scanner is running:")
            print(f"     {DIM}sudo systemctl status vapt-scanner{RESET}")
        else:
            print(f"  4. If no results appear, check that an agent is running with mode=agent")
        print()

    except Exception as e:
        db.rollback()
        err(f"Failed to create jobs: {e}")
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
