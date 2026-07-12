# backend/app/routes/plugins.py
#
# Registers plugin METADATA only — see PLUGIN_ARCHITECTURE_PROPOSAL.md
# section 1. Nothing here ever transmits or executes plugin code; a
# plugin's actual run.py has to be placed on an agent by hand
# (install_plugin.sh helps with that locally) and that agent's
# VAPT_CAPABILITIES updated before it'll pick up jobs of that type.
#
# /plugins/install takes the manifest as a plain JSON body (same "data:
# dict" pattern every other route in this codebase already uses) rather
# than a multipart file upload — python-multipart isn't a dependency here,
# and it doesn't need to be: "upload a file" vs. "paste JSON" is purely a
# frontend distinction (FileReader vs a textarea), both end up POSTing the
# same JSON shape.

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Plugin, Job
from ..core import logger, require_auth, BUILTIN_JOB_TYPES

router = APIRouter()

REQUIRED_MANIFEST_FIELDS = {"name", "display_name", "version"}
VALID_RISK_TIERS = {"none", "read_only", "intrusive", "high"}

# The built-in job types, described in the same shape plugin job types are,
# so the dashboard has exactly one code path for "render a job type" rather
# than a hardcoded case plus a separate plugin case.
BUILTIN_JOB_TYPE_ENTRIES = [
    {
        "type": "nmap_scan", "label": "Port Scan", "risk_tier": "read_only",
        "tab": "scan", "section": None, "builtin": True,
        "form_fields": [
            {"name": "target", "type": "text", "required": True, "label": "Target"},
            {"name": "profile", "type": "select", "required": False, "label": "Profile",
             "options": ["light", "standard", "full"]},
        ],
    },
    {
        "type": "nikto_scan", "label": "Web Scan", "risk_tier": "read_only",
        "tab": "scan", "section": None, "builtin": True,
        "form_fields": [
            {"name": "target", "type": "text", "required": True, "label": "Target"},
            {"name": "port", "type": "number", "required": False, "label": "Port"},
        ],
    },
    {
        "type": "nse_scan", "label": "Vulnerability Scan", "risk_tier": "intrusive",
        "tab": "scan", "section": None, "builtin": True,
        "form_fields": [
            {"name": "target", "type": "text", "required": True, "label": "Target"},
            {"name": "profile", "type": "select", "required": False, "label": "Profile",
             "options": ["light", "standard", "full", "custom"]},
        ],
    },
]


def _validate_manifest(manifest: dict):
    if not isinstance(manifest, dict):
        raise HTTPException(status_code=400, detail="Manifest must be a JSON object")

    missing = REQUIRED_MANIFEST_FIELDS - manifest.keys()
    if missing:
        raise HTTPException(status_code=400, detail=f"Manifest missing required field(s): {sorted(missing)}")

    job_types = manifest.get("job_types", [])
    if not isinstance(job_types, list):
        raise HTTPException(status_code=400, detail="'job_types' must be a list")

    seen_types = set()
    for jt in job_types:
        if not isinstance(jt, dict) or "type" not in jt:
            raise HTTPException(status_code=400, detail="Each job_types entry needs a 'type'")
        if jt["type"] in BUILTIN_JOB_TYPES:
            raise HTTPException(status_code=400, detail=f"'{jt['type']}' collides with a built-in job type")
        if jt["type"] in seen_types:
            raise HTTPException(status_code=400, detail=f"Duplicate job type '{jt['type']}' within this manifest")
        seen_types.add(jt["type"])

        tier = jt.get("risk_tier", "high")
        if tier not in VALID_RISK_TIERS:
            raise HTTPException(
                status_code=400,
                detail=f"'{jt['type']}' has an invalid risk_tier '{tier}'. Valid: {sorted(VALID_RISK_TIERS)}"
            )
        # requires_target_auth is derived from risk_tier, not manifest-configurable —
        # a plugin can't opt itself out of the authorization gate by just omitting the field.
        jt["requires_target_auth"] = (tier == "high")

    hooks = manifest.get("hooks", [])
    if not isinstance(hooks, list):
        raise HTTPException(status_code=400, detail="'hooks' must be a list")


@router.get("/plugins")
def list_plugins(db: Session = Depends(get_db), username: str = Depends(require_auth)):
    plugins = db.query(Plugin).order_by(Plugin.installed_at).all()
    out = []
    for p in plugins:
        manifest = json.loads(p.manifest)
        out.append({
            "id": p.id,
            "name": p.name,
            "display_name": p.display_name,
            "version": p.version,
            "enabled": p.enabled,
            "installed_at": p.installed_at.isoformat() if p.installed_at else None,
            "job_types": manifest.get("job_types", []),
            "hooks": manifest.get("hooks", []),
        })
    return out


@router.post("/plugins/install")
def install_plugin(
    manifest: dict,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    _validate_manifest(manifest)

    name = manifest["name"]
    if db.query(Plugin).filter(Plugin.name == name).first():
        raise HTTPException(
            status_code=409,
            detail=f"A plugin named '{name}' is already installed. Uninstall it first to reinstall."
        )

    new_types = {jt["type"] for jt in manifest.get("job_types", [])}
    if new_types:
        for other in db.query(Plugin).filter(Plugin.enabled == True).all():
            other_types = {jt["type"] for jt in json.loads(other.manifest).get("job_types", [])}
            collision = new_types & other_types
            if collision:
                raise HTTPException(
                    status_code=409,
                    detail=f"Job type(s) {sorted(collision)} already registered by plugin '{other.name}'"
                )

    plugin = Plugin(
        name=name,
        display_name=manifest["display_name"],
        version=manifest["version"],
        manifest=json.dumps(manifest),
        enabled=True,
    )
    db.add(plugin)
    db.commit()
    db.refresh(plugin)

    logger.info(f"Plugin '{name}' installed (v{manifest['version']}) — job types: {sorted(new_types) or 'none'}")
    return {"ok": True, "id": plugin.id, "name": name}


@router.post("/plugins/{name}/enable")
def set_plugin_enabled(
    name: str,
    data: dict,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    plugin = db.query(Plugin).filter(Plugin.name == name).first()
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    plugin.enabled = bool(data.get("enabled", True))
    db.commit()
    logger.info(f"Plugin '{name}' {'enabled' if plugin.enabled else 'disabled'}")
    return {"ok": True, "enabled": plugin.enabled}


@router.delete("/plugins/{name}")
def uninstall_plugin(
    name: str,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    plugin = db.query(Plugin).filter(Plugin.name == name).first()
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")

    manifest = json.loads(plugin.manifest)
    job_types = {jt["type"] for jt in manifest.get("job_types", [])}

    # Cancel any still-pending jobs of this plugin's job types so they can't
    # be silently picked up later by an agent that still advertises the
    # capability. Anything already running or done is left untouched.
    cancelled = 0
    if job_types:
        pending = db.query(Job).filter(Job.type.in_(job_types), Job.status == "pending").all()
        for j in pending:
            j.status = "cancelled"
            j.completed_at = datetime.utcnow()
            cancelled += 1

    db.delete(plugin)
    db.commit()
    logger.info(f"Plugin '{name}' uninstalled — {cancelled} pending job(s) cancelled")
    return {"ok": True, "cancelled_pending_jobs": cancelled}


@router.get("/plugins/job-types")
def get_job_types_for_dashboard(db: Session = Depends(get_db), username: str = Depends(require_auth)):
    """
    Merged built-in + enabled-plugin job types, in the exact shape the
    dashboard's Create Job form and Pen Test tab render from. This is the
    one call the frontend needs to discover what's available right now.
    """
    plugin_types = []
    for plugin in db.query(Plugin).filter(Plugin.enabled == True).all():
        manifest = json.loads(plugin.manifest)
        for jt in manifest.get("job_types", []):
            plugin_types.append({
                **jt,
                "label": jt.get("label", jt["type"]),
                "tab": jt.get("tab", "scan"),
                "section": jt.get("section"),
                "builtin": False,
                "plugin_name": plugin.name,
            })

    return BUILTIN_JOB_TYPE_ENTRIES + plugin_types
