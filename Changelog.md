# Changelog

## [v3.1.1] - 17-07-2026

### Added
- Updated README and Changelog at project root, which were missing
  from v3.0 and v3.1

### Changed
- Renamed the plugin deployment directories to avoid confusion with the
  repo-root `plugins/` source folder:
  - `backend/app/plugins/` → `backend/app/installed_plugins/`
  - `agent/plugins/` → `agent/installed_plugins/`
- Updated everywhere that path was hardcoded: `scanner.py` and `agent.py`
  (`run_plugin()`), `services/hooks.py` (`HOOK_PLUGIN_DIR`),
  `install_plugin.sh`/`uninstall_plugin.sh` destination paths, the
  `.gitignore` pattern, and the README

### Action required
- Any scanner or agent that already has plugins deployed needs the
  folder moved by hand — nothing does this automatically across
  machines:
  ```bash
  mv backend/app/plugins backend/app/installed_plugins
  mv agent/plugins agent/installed_plugins   # if applicable
  ```
  Until this is done on a given machine, `run_plugin()` will report the
  job type as not installed there, even though the code is still on
  disk under the old path.

---

## [v3.1] - 17-07-2026

### Added
- Inline SVG icons on the six nav tabs (Dashboard, Discovery, Schedules,
  Insights, Network Map, Loki), matching the existing Plugins/Settings
  icon convention
- A Heimdall brand icon in the header, and a matching `favicon.svg`

### Fixed
- Light theme contrast: page, panel, and nested-element backgrounds were
  nearly indistinguishable (~1.1:1 contrast between page and panel), and
  two text-color tiers fell below readable contrast against white panels
  (2.56:1 and 1.48:1, against a ~4.5:1 baseline for body text). Panels
  now separate visibly from the page, both text tiers pass a real
  contrast check, and panels get a subtle shadow for extra depth.
- `favicon.svg` needed registering in the backend's static file
  allowlist (`STATIC_MEDIA_TYPES`) — it's not a generic file server, so
  the icon would have 404'd silently otherwise

---

## [v3.0] - 17-07-2026

### Added
- Renamed "Pen Test" to "Loki" throughout — nav tab, tab panel, settings copy
- Loki, Heimdall's Penetration testing suite (see README.md), now has its own dedicated screen:
  spacious Network/Web layout, a distinct header treatment, and inline
  recent-results per tool card so a job's outcome shows up without leaving
  the tab
- Generic `result_display` rendering: a plugin's manifest can now declare
  summary fields and table/list sections (with an optional nested-tags
  column) so results render as structured tables instead of a raw JSON
  dump — no plugin ever ships frontend code to make this happen
- Four Loki tool plugins, each with its own `plugin.json` / `run.py` /
  `setup.sh` / `NOTES.md`:
  - **ffuf** — directory/file fuzzing (intrusive)
  - **whatweb** — technology fingerprinting (intrusive)
  - **sqlmap** — SQL injection detection only, no enumeration or dumping
    (intrusive)
  - **hydra** — credential brute-force (high risk tier — the first job
    type that actually requires a live target authorization, not just a
    warning)
- `uninstall_plugin.sh` — the disk-side counterpart to `install_plugin.sh`,
  removes a plugin's deployed code and drops it from advertised
  capabilities

### Changed
- `install_plugin.sh` and `uninstall_plugin.sh` moved into `plugins/`;
  both now resolve the repo root one level above their own location
  instead of assuming repo root

### Fixed
- `install_plugin.sh` had its entire contents accidentally duplicated
  (an older and newer revision concatenated instead of one replacing the
  other), causing the installer to run every step — including the
  interactive prompts — twice. Merged into a single script.

---

## [v2.1.1] - 14-07-2026

### Fixed
- `install.sh` had its entire contents duplicated back-to-back (an
  older revision and a newer one concatenated instead of one replacing
  the other), causing the installer to run every step — including the
  interactive password prompts — twice. Merged into a single script:
  kept the newer revision's interactive password generation, and
  carried forward the `custom_scripts`/`sweep_id`/`nikto_tuning` column
  migrations and the scanner auto-spawn sudoers setup, both of which
  only existed in the older half.
- `install.sh`/`update.sh` were missing the `jobs.extra_params` column
  migration needed for v2.1's plugin mechanism. On an existing
  database, `create_all()` creates new tables (`plugins`,
  `target_authorizations`) but never alters an existing table, so any
  job carrying plugin `form_fields` values would have hit a
  missing-column error after an in-place upgrade.

### Internal
- Both scripts' schema-setup step now names `Plugin`/`TargetAuthorization`
  explicitly in the `create_all()` import, rather than relying on them
  being registered as a side effect of importing `models.py`.

---

## [v2.1] - 13-07-2026

### Added
- **Plugin extension mechanism**: manifest-based installation
  (`plugin.json`), risk-tiered job types (`none`/`read_only`/`intrusive`/
  `high`), a target authorization gate for high-risk job types (scoped to
  one exact target + job type, time-boxed, cap configurable in Settings),
  and per-plugin config storage rendered through the same generic field
  system as job creation.
- **Dedicated Plugins panel**, showing per-agent deployment status
  (auto-detected from reported capabilities) with a ready-to-copy
  `install_plugin.sh` command for anything not yet deployed.
- `install_plugin.sh` — local helper that deploys a plugin's code onto a
  scanner/agent and updates its capabilities in one step. Plugin code
  itself is never transmitted by the server — this only ever moves code
  that's already on the machine you run it from.
- **Hook plugin system** (`services/hooks.py`) — event-driven plugins,
  three events wired in: `job.completed`, `job.failed`, `host.new`.
- **Webhook Notifications plugin**, pre-installed — posts a JSON payload
  to a configured URL on any of the above events. Works directly with
  Slack/Discord incoming webhooks.
- **Asset Inventory plugin** — passive device fingerprinting and
  classification (router / printer / IoT / NAS / workstation / server),
  each with a confidence level and the signals behind it. Runs from the
  Discovery tab against a sweep's discovered hosts.
- Discovery sweeps can now target any installed job type, not just
  `nmap_scan`.
- `tools/migrations/` — a lightweight, numbered convention for schema
  changes that `Base.metadata.create_all()` can't handle on its own
  (altering an existing table rather than creating a new one).

### Changed
- Agent and scanner job execution now uses a 2-worker thread pool instead
  of running jobs strictly one at a time — matches the concurrency limit
  the server already enforced, previously unused in practice since a
  single long job blocked polling entirely.
- Sweep-spawned jobs and results are now hidden from the main Jobs/Results
  lists by default (`show_sweep_jobs`/`show_sweep_results` to opt back
  in) — they have their own consolidated view per sweep. This was
  pre-existing clutter, not something new in this release.
- High-risk job types can never be attached to a schedule — one-off jobs
  only, since a recurring schedule can't provide the fresh, explicit
  authorization the risk gate depends on.

### Fixed
- Plugin `form_fields` values had no path from the dashboard form into
  what an agent actually receives at execution time — added
  `Job.extra_params`, threaded through job creation, dispatch, and
  execution.
- A race condition where a hook event could fire, and its background
  thread open a fresh DB session, before the triggering transaction had
  actually committed — the row wasn't guaranteed visible yet.
- `install_plugin.sh` hard-failed when a scanner is run manually rather
  than via systemd; now degrades to a manual-restart reminder instead.

### Internal
- `VALID_JOB_TYPES` (a static set) replaced by `get_valid_job_types()`/
  `get_job_type_info()` in `core.py`, merging built-ins with whatever
  plugins are currently enabled.

---

## [v2.0] - 10-07-2026

### Changed
- Split the `main.py` monolith (~6,200 lines) into a modular structure:
  - Dashboard HTML/CSS/JS extracted from an embedded Python string into
    real files: `backend/app/static/{index.html,app.css,app.js}`.
  - Remaining route handlers split into `backend/app/core.py` (shared
    auth/config/validation), `backend/app/services/scheduler.py`
    (background threads), and one file per resource under
    `backend/app/routes/`.
  - `main.py` is now ~60 lines — app assembly only.
- `AI_PROVIDER` is now delivered via `GET /settings` instead of being
  server-templated into the dashboard's JS (necessary once the dashboard
  became a static file).

### Bug Fixes
- Restored a missing route decorator on `GET /sweeps/{sweep_id}/results` —
  the handler existed but was never wired to a route, making it fully
  unreachable (pre-existing bug, not introduced by the refactor above).

### Internal
- `_init_default_settings` renamed to `init_default_settings` (no longer
  private now that it's called across a module boundary).

---

## [v1.0] - 09/07/2026

**Stable Version of Heimdall V-Scanner released!, moving it out production stage**

### Added
- Optional `VAPT_REGISTRATION_TOKEN` shared secret to close the previously
  unauthenticated `/agents/register` endpoint.
- Startup warning if `DASHBOARD_PASSWORD` is left at its default value.
- Failed jobs now also submit a result containing the error message, so
  the reason is visible on the result card instead of a bare "failed"
  status.

### Changed
- Target/subnet validation added across job creation, schedule creation,
  and discovery/sweep endpoints — rejects values that could be
  misinterpreted as nmap/nikto command-line flags.
- Nmap and NSE scans now have profile-scaled timeouts, preventing a
  hung/filtered target from blocking a scanner indefinitely.

### Bug Fixes
- NSE "light" profile (`--script safe`) was timing out on every run —
  duration was incorrectly assumed to be fast, when `safe` is actually
  Nmap's broadest script category. Corrected timeout tiering.
- Long unbroken strings in Nikto/NSE findings (e.g. the CVE-2002-1078
  directory-listing check) overflowing outside the result card — added
  `break-all` to the relevant containers.
