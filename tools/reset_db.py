#!/usr/bin/env python3
# tools/reset_db.py
# Heimdall V-Scanner — Database Reset
#
# Wipes all scan data (jobs, results, hosts, discovery sweeps) and resets
# all ID sequences back to 1. Agents and schedules are preserved.
#
# USE ONLY on development/test instances. This is irreversible.
#
# Usage:
#   python tools/reset_db.py
#   python tools/reset_db.py --yes        # skip confirmation prompt
#   python tools/reset_db.py --full       # also wipe agents and schedules

import sys
import os
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from backend.db import SessionLocal
    import sqlalchemy
except ImportError as e:
    print(f"[✗] Import error: {e}")
    print("    Run this script from the project root directory.")
    sys.exit(1)

RED    = "\033[0;31m"
GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN   = "\033[0;36m"
BOLD   = "\033[1m"
NC     = "\033[0m"

def ok(msg):    print(f"  {GREEN}[✓]{NC} {msg}")
def warn(msg):  print(f"  {YELLOW}[!]{NC} {msg}")
def err(msg):   print(f"  {RED}[✗]{NC} {msg}")
def info(msg):  print(f"  {CYAN}[→]{NC} {msg}")


def get_counts(db):
    counts = {}
    for table in ["jobs", "results", "hosts", "discovery_sweeps", "agents", "schedules"]:
        try:
            row = db.execute(sqlalchemy.text(f"SELECT COUNT(*) FROM {table}")).fetchone()
            counts[table] = row[0]
        except Exception:
            counts[table] = "?"
    return counts


def main():
    parser = argparse.ArgumentParser(
        description="Heimdall V-Scanner — Database Reset",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tools/reset_db.py              # interactive reset, preserves agents + schedules
  python tools/reset_db.py --yes        # skip confirmation
  python tools/reset_db.py --full       # also wipe agents and schedules
  python tools/reset_db.py --full --yes # fully non-interactive
        """
    )
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Skip the confirmation prompt")
    parser.add_argument("--full", action="store_true",
                        help="Also wipe agents and schedules (full factory reset)")
    args = parser.parse_args()

    print(f"\n{BOLD}{RED}━━━ Heimdall V-Scanner — Database Reset ━━━{NC}\n")
    print(f"  {YELLOW}WARNING: This permanently deletes scan data and resets ID sequences.{NC}")
    print(f"  {YELLOW}This action cannot be undone.{NC}\n")

    db = SessionLocal()

    try:
        # Show current counts
        counts = get_counts(db)
        print(f"  {BOLD}Current database state:{NC}")
        print(f"    Jobs              : {counts.get('jobs', '?')}")
        print(f"    Results           : {counts.get('results', '?')}")
        print(f"    Hosts             : {counts.get('hosts', '?')}")
        print(f"    Discovery sweeps  : {counts.get('discovery_sweeps', '?')}")
        print(f"    Agents            : {counts.get('agents', '?')} {'(will be wiped)' if args.full else '(preserved)'}")
        print(f"    Schedules         : {counts.get('schedules', '?')} {'(will be wiped)' if args.full else '(preserved)'}")
        print()

        if args.full:
            warn("Full reset selected — agents and schedules will also be deleted.")
            warn("All agent API keys will be invalidated. Agents will need to re-register.")
            print()

        if not args.yes:
            confirm = input(f"  {RED}Type 'reset' to confirm:{NC} ").strip().lower()
            if confirm != "reset":
                print(f"\n  {CYAN}[→]{NC} Aborted — nothing was changed.\n")
                return
            print()

        info("Beginning reset...")

        if args.full:
            # Full reset — wipe everything including agents and schedules
            db.execute(sqlalchemy.text(
                "TRUNCATE TABLE results, jobs, hosts, discovery_sweeps, schedules, agents "
                "RESTART IDENTITY CASCADE"
            ))
            ok("Wiped: results, jobs, hosts, discovery_sweeps, schedules, agents")
        else:
            # Standard reset — preserve agents and schedules
            # Must truncate in dependency order or use CASCADE
            db.execute(sqlalchemy.text(
                "TRUNCATE TABLE results, jobs, hosts, discovery_sweeps "
                "RESTART IDENTITY CASCADE"
            ))
            ok("Wiped: results, jobs, hosts, discovery_sweeps")
            ok("Preserved: agents, schedules")

        db.commit()

        # Verify counts are now zero
        print()
        info("Verifying reset...")
        after = get_counts(db)
        tables_reset = ["jobs", "results", "hosts", "discovery_sweeps"]
        if args.full:
            tables_reset += ["agents", "schedules"]

        all_zero = True
        for table in tables_reset:
            count = after.get(table, -1)
            if count == 0:
                ok(f"{table}: 0 rows")
            else:
                err(f"{table}: {count} rows remaining — reset may have partially failed")
                all_zero = False

        print()
        if all_zero:
            ok("Reset complete — all sequences restarted at 1")
            if not args.full:
                info(f"Agents preserved: {after.get('agents', '?')}")
                info(f"Schedules preserved: {after.get('schedules', '?')}")
        else:
            warn("Reset completed with errors — check output above")

        print()

    except Exception as e:
        db.rollback()
        err(f"Reset failed: {e}")
        print()
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
