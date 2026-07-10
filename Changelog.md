# Changelog

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
