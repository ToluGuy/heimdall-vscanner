# VAPT Scanner — Project Roadmap

A living reference for planned features and implementation priorities.
Both milestones and design decisions are tracked here so we stay aligned.

---

## Milestone 1 — NSE Integration ⬅ IN PROGRESS

**Goal:** Add a new `nse_scan` job type that runs Nmap Scripting Engine against
non-web ports, filling the gap between basic port discovery (Nmap) and web
vulnerability scanning (Nikto).

### Scope
- New job type: `nse_scan`
- Profile maps to NSE script intensity:
  - `light`    → `--script safe`
  - `standard` → `--script vuln`
  - `full`     → `--script vuln,exploit` ⚠️ intrusive — dashboard warns user
- Optional `ports` field (comma-separated string) on the job
  - If blank, uses the same default port range as the profile's Nmap flags
  - Web ports (80, 443, 8080, 8443, 8000, 8888) are automatically excluded
    because Nikto owns that surface
  - If the user specifies *only* web ports, show a warning instead of running
    silently with nothing to scan
- Output parsed from Nmap XML `<script>` elements
- Rendered as findings in the dashboard (`renderNseResult`)
- Included in JSON export

---

## Milestone 2 — Multiple Port Support for Nikto

**Goal:** Allow Nikto jobs to target more than one port at once via the dashboard.

- Reuse the `ports` field added in Milestone 1
- Dashboard port input accepts comma-separated values for `nikto_scan` jobs
- Agent/scanner iterate over all specified ports and run Nikto on each
- Results keyed by port (already the existing format — minimal change)

---

## Milestone 3 — Export

**Goal:** Structured, shareable output from scan results.

### Phase 1 — JSON export ✅ (basic version already exists)
- Improve structure: include NSE findings
- Per-result and bulk export from dashboard

### Phase 2 — PDF export
- "Generate Report" button per result
- Clean printable document: job metadata, open ports table, NSE/Nikto findings
  grouped by severity, summary section
- Useful for stakeholder reporting outside the dashboard

---

## Milestone 4 — Stale Agent Cleanup

**Goal:** Automatically remove or flag agents that have been offline too long.

- Configurable timeout threshold (e.g. 24 hours with no heartbeat)
- Soft-delete or archive stale agents in the dashboard
- Prevent stale agents from accumulating in the agents table

---

## Milestone 5 — Scheduling

**Goal:** Auto-create scan jobs on a configurable timer without manual dashboard
intervention.

- Schedule a job type + target + profile on a recurring interval (e.g. every 6h,
  daily, weekly)
- Schedules stored in the database
- Dashboard UI to create, view, pause, and delete schedules
- `next_run_at` field on `Job` already exists — will be reused

---

## Milestone 6 — Priority Queue Wiring

**Goal:** Make the `priority` field on jobs actually influence dispatch order.

- `high` priority jobs are picked up before `medium` and `low`
- `get_next_job` in `main.py` sorts eligible jobs by priority before selecting
- No schema changes needed — field already exists

---

## Design Notes

### Web port exclusion (NSE)
NSE and Nikto must not double-scan the same surface. Web ports are Nikto's
domain. NSE should focus on everything else — SSH, SMB, RDP, databases, etc.

### Exploit script warning
`full` profile + `nse_scan` triggers `--script vuln,exploit`. Exploit scripts
are intrusive and can disrupt services. The dashboard must display a prominent
warning before the job is created — not after.

### Risk scoring (future consideration)
Parse Nmap/Nikto/NSE output on ingest to assign severity levels
(Critical / High / Medium / Low / Info). Would unlock:
- Colour-coded result cards
- Severity-based filtering
- Alerting thresholds (email / webhook)

---

*Last updated: 2026-05-08*
