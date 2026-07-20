# backend/routes/settings.py

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Setting
from ..core import logger, require_auth, SETTING_DEFAULTS
from ..ai_analysis import AI_PROVIDER

router = APIRouter()


@router.get("/settings")
def get_settings(
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    """Return all server-side settings as a flat dict."""
    rows = db.query(Setting).all()
    result = {r.key: r.value for r in rows}
    # Fill in any missing keys with defaults
    for key, default in SETTING_DEFAULTS.items():
        if key not in result:
            result[key] = default
    # Deployment config (env-var driven, not a DB-editable Setting) — the
    # dashboard JS reads this to label AI analysis output. Previously
    # server-templated directly into the dashboard's embedded JS string;
    # moved here once the dashboard became a static file.
    result["ai_provider"] = AI_PROVIDER or "none"
    return result


@router.patch("/settings")
def update_settings(
    data: dict,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    """Update one or more settings. Unknown keys are ignored."""
    allowed_keys = set(SETTING_DEFAULTS.keys())
    updated = []
    for key, value in data.items():
        if key not in allowed_keys:
            continue
        row = db.query(Setting).filter(Setting.key == key).first()
        if row:
            row.value = str(value)
        else:
            db.add(Setting(key=key, value=str(value)))
        updated.append(key)

    db.commit()
    logger.info(f"Settings updated: {updated}")
    return {"ok": True, "updated": updated}
