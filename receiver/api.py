"""
UniFi Log Insight - REST API

FastAPI application serving log data to the frontend.
Route handlers live in the `routes/` package; shared state in `deps.py`.
"""

import logging
import os
import re
from pathlib import Path
from urllib.parse import unquote

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from deps import APP_VERSION
from routes.logs import router as logs_router
from routes.stats import router as stats_router
from routes.setup import router as setup_router
from routes.unifi import router as unifi_router
from routes.abuseipdb import router as abuseipdb_router
from routes.health import router as health_router
from routes.threats import router as threats_router
from routes.flows import router as flows_router
from routes.mcp import router as mcp_router
from routes.views import router as views_router

# ── Logging ──────────────────────────────────────────────────────────────────

_log_level_name = os.environ.get('LOG_LEVEL', 'INFO').upper()
if _log_level_name not in ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'):
    _log_level_name = 'INFO'

logging.basicConfig(
    level=getattr(logging, _log_level_name),
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger('api')

# ── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(title="UniFi Log Insight API", version=APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Uvicorn access log filter ────────────────────────────────────────────────

class _QuietAccessFilter(logging.Filter):
    """Suppress high-frequency polling endpoints from uvicorn access logs.

    /api/health (polled every 15s) and /api/logs (polled on page load)
    are only shown at DEBUG level. All other endpoints remain visible at INFO.
    """
    _QUIET_RE = re.compile(r'"GET /api/(health|logs)[\s?]')

    def filter(self, record):
        if self._QUIET_RE.search(record.getMessage()):
            return logging.getLogger().getEffectiveLevel() <= logging.DEBUG
        return True


@app.on_event("startup")
def _configure_access_logging():
    logging.getLogger("uvicorn.access").addFilter(_QuietAccessFilter())


# ── Route Registration ───────────────────────────────────────────────────────
# Order matters: API routers MUST be included before the SPA catch-all.

app.include_router(logs_router)
app.include_router(stats_router)
app.include_router(setup_router)
app.include_router(unifi_router)
app.include_router(abuseipdb_router)
app.include_router(health_router)
app.include_router(threats_router)
app.include_router(flows_router)
app.include_router(mcp_router)
app.include_router(views_router)


# ── Static file serving ──────────────────────────────────────────────────────

STATIC_DIR = '/app/static'

if os.path.exists(STATIC_DIR):
    # Mount static assets (JS, CSS, images)
    app.mount("/assets", StaticFiles(directory=os.path.join(STATIC_DIR, "assets")), name="assets")

    # SPA catch-all: serve index.html for any non-API route
    _static_root = Path(STATIC_DIR).resolve()
    _NO_CACHE = {"Cache-Control": "no-cache"}

    @app.get("/{path:path}")
    async def serve_spa(path: str):
        # URL-decode, resolve, and ensure the path stays inside STATIC_DIR
        decoded = unquote(path)
        resolved = (_static_root / decoded).resolve()
        if resolved != _static_root and not str(resolved).startswith(str(_static_root) + os.sep):
            return FileResponse(_static_root / "index.html", headers=_NO_CACHE)
        if decoded and resolved.is_file():
            return FileResponse(resolved)
        # Otherwise serve index.html for SPA routing
        return FileResponse(_static_root / "index.html", headers=_NO_CACHE)

    logger.info("Serving UI from %s", STATIC_DIR)
else:
    logger.warning("Static directory %s not found — UI not available", STATIC_DIR)
