# backend/app/routes/dashboard.py
#
# serve_static() is a small hand-written route rather than Starlette's
# StaticFiles mount: StaticFiles/FileResponse pull in aiofiles on some
# Starlette versions, which isn't in requirements.txt, and for three known
# files a plain synchronous read avoids that dependency question entirely.
# The one value that used to be templated into the JS server-side
# (AI_PROVIDER) is delivered through GET /settings instead, so index.html is
# served byte-for-byte unmodified.

import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, Response

router = APIRouter()

# static/ lives at backend/app/static — one level up from this routes/ package
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
STATIC_MEDIA_TYPES = {"app.js": "application/javascript", "app.css": "text/css", "favicon.svg": "image/svg+xml"}


@router.get("/")
def root():
    return {"message": "VAPT system running"}


@router.get("/static/{filename}")
def serve_static(filename: str):
    if filename not in STATIC_MEDIA_TYPES:
        raise HTTPException(status_code=404, detail="Not found")
    path = os.path.join(STATIC_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    return Response(content=content, media_type=STATIC_MEDIA_TYPES[filename])


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    with open(os.path.join(STATIC_DIR, "index.html"), "r", encoding="utf-8") as f:
        return f.read()
