#!/usr/bin/env python3
# tools/migrate_v2_1_plugins.py
# Heimdall V-Scanner — v2.1 migration (plugin mechanism)
#
# Base.metadata.create_all() only creates tables that don't exist yet — it
# never alters an existing table. The plugin mechanism added two brand new
# tables (plugins, target_authorizations), which create_all() handles fine
# on its own at every startup. But it also added a new column to the
# EXISTING jobs table (extra_params), which create_all() silently does
# nothing about. This script is the one-time fix for that column. Safe to
# run more than once — it checks before altering anything.
#
# Usage:
#   python tools/migrate_v2_1_plugins.py

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from sqlalchemy import text
    from backend.app.db import engine, Base
    import backend.app.models  # noqa: F401 — import registers all models on Base.metadata
except ImportError as e:
    print(f"[✗] Import error: {e}")
    print("    Run this script from the project root directory.")
    sys.exit(1)

GREEN, YELLOW, RED, RESET = "\033[92m", "\033[93m", "\033[91m", "\033[0m"


def ok(msg):   print(f"  {GREEN}[✓]{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}[!]{RESET} {msg}")
def err(msg):  print(f"  {RED}[✗]{RESET} {msg}")


def column_exists(conn, table: str, column: str) -> bool:
    result = conn.execute(text(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_name = :table AND column_name = :column"
    ), {"table": table, "column": column})
    return result.first() is not None


def main():
    print("Heimdall v2.1 migration — plugin mechanism\n")

    with engine.connect() as conn:
        if column_exists(conn, "jobs", "extra_params"):
            ok("jobs.extra_params already exists — nothing to do")
        else:
            print("  Adding jobs.extra_params ...")
            conn.execute(text("ALTER TABLE jobs ADD COLUMN extra_params TEXT"))
            conn.commit()
            ok("jobs.extra_params added")

    # plugins / target_authorizations are brand new tables — create_all is
    # the right tool for these (it only creates what's missing).
    print("  Ensuring plugins / target_authorizations tables exist ...")
    Base.metadata.create_all(bind=engine)
    ok("Done")

    print(f"\n{GREEN}Migration complete.{RESET} Safe to restart the server now.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        err(f"Migration failed: {e}")
        print("  Nothing else was changed — safe to fix the issue above and re-run.")
        sys.exit(1)
