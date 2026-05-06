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

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse

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
from routes.migration import router as migration_router
from routes.pihole import router as pihole_router
from routes.auth import (
    router as auth_router, require_auth,
    get_forwarded_proto, get_real_client_ip, _auth_enabled,
    AUTH_SESSION_PATHS, PUBLIC_PATHS, PUBLIC_PREFIXES,
    log_proxy_token,
)
from routes.tokens import router as tokens_router
from routes.adguard import router as adguard_router

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

class DualCORSMiddleware(BaseHTTPMiddleware):
    """Two-tier CORS: restricted for cookie-auth, permissive for token-auth.

    Cookie-auth: only reflect origin when it matches the Host header (same-origin).
    Token-auth (Bearer): allow any origin (no cookies involved).
    Auth disabled: allow any origin (open access).
    """

    @staticmethod
    def _is_same_origin(origin: str, request: StarletteRequest) -> bool:
        """Check if the Origin header matches the request's Host."""
        if not origin:
            return False
        # Origin is scheme://host[:port], Host is host[:port]
        host = request.headers.get('host', '')
        proto = get_forwarded_proto(request)
        expected = f"{proto}://{host}"
        return origin.rstrip('/') == expected.rstrip('/')

    async def dispatch(self, request: StarletteRequest, call_next):
        origin = request.headers.get('origin', '')
        is_preflight = request.method == 'OPTIONS'
        path = request.url.path

        # Determine if this is a token-auth request
        has_auth = bool(request.headers.get('authorization'))
        if is_preflight:
            acr_headers = request.headers.get('access-control-request-headers', '').lower()
            has_auth = 'authorization' in acr_headers

        # Public paths are accessible without auth — allow any origin
        is_public = path in PUBLIC_PATHS or any(path.startswith(p) for p in PUBLIC_PREFIXES)

        if is_preflight:
            headers = {
                'access-control-allow-methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
                'access-control-allow-headers': 'content-type, authorization, mcp-protocol-version',
                'access-control-max-age': '86400',
            }
            if origin and self._is_same_origin(origin, request):
                # Cookie-auth same-origin: restricted, with credentials
                headers['access-control-allow-origin'] = origin
                headers['access-control-allow-credentials'] = 'true'
            else:
                # All other cases: allow origin. Auth middleware enforces access;
                # CORS just needs to let the client read the response (including 401/403).
                # Cookie security is handled by SameSite=lax — browsers won't send
                # cookies cross-origin via fetch/XHR.
                headers['access-control-allow-origin'] = origin or '*'
            return StarletteResponse(status_code=204, headers=headers)

        response = await call_next(request)

        if origin and self._is_same_origin(origin, request):
            response.headers['access-control-allow-origin'] = origin
            response.headers['access-control-allow-credentials'] = 'true'
        else:
            response.headers['access-control-allow-origin'] = origin or '*'

        return response

class AuthMiddleware(BaseHTTPMiddleware):
    """Enforce authentication on all /api/ routes except public paths.

    Added BEFORE CORSMiddleware so that CORS wraps auth (Starlette LIFO):
    request → CORS → Auth → app. Auth 401 responses pass back through CORS
    and get proper Access-Control-Allow-Origin headers.
    """

    # Path prefix → (read_scope, write_scope | None)
    # write_scope=None means writes are allowed with just the read scope.
    # IMPORTANT: Every /api/ route must be covered here, in PUBLIC_PATHS,
    # or in _TOKEN_EXEMPT_PREFIXES. Unmatched routes are DENIED for token auth.
    _SCOPE_MAP = [
        # Order matters: more specific prefixes first
        ('/api/tokens',          None, None),             # handled separately (session-only)
        ('/api/settings/mcp',    'mcp.admin', 'mcp.admin'),
        ('/api/settings/',       'settings.read', 'settings.write'),
        ('/api/config/export',   'settings.read', None),
        ('/api/config/retention','settings.read', 'settings.write'),
        ('/api/config/adguard', 'settings.read', 'settings.write'),
        ('/api/adguard',        'settings.read', None),
        ('/api/config',          'settings.read', 'settings.write'),
        ('/api/setup/',          'settings.read', 'settings.write'),
        ('/api/firewall/',       'firewall.read', 'firewall.write'),
        ('/api/unifi/',          'unifi.read', None),
        ('/api/logs',            'logs.read', None),
        ('/api/export',          'logs.read', None),
        ('/api/services',        'logs.read', None),
        ('/api/protocols',       'logs.read', None),
        ('/api/stats',           'stats.read', None),
        ('/api/flows',           'flows.read', None),
        ('/api/threats',         'threats.read', None),
        ('/api/abuseipdb/',      'threats.read', None),
        ('/api/enrich/',         'threats.read', 'threats.read'),
        ('/api/dashboard',       'dashboard.read', None),
        ('/api/health',          'health.read', None),
        ('/api/system',          'system.read', None),
        ('/api/interfaces',      'system.read', None),
        ('/api/views',           'logs.read', 'logs.read'),
        ('/api/migration/',      'settings.write', 'settings.write'),
        ('/api/mcp',             None, None),             # MCP handles its own token auth internally
    ]

    @classmethod
    def _check_token_scopes(cls, path: str, is_write: bool, scopes: set) -> str | None:
        """Return an error message if the token lacks the required scope, else None."""
        for prefix, read_scope, write_scope in cls._SCOPE_MAP:
            if not path.startswith(prefix):
                continue
            if read_scope is None:
                return None  # no scope check needed (or handled elsewhere)
            needs_write = is_write and write_scope
            required = write_scope if needs_write else read_scope
            if required not in scopes:
                return f"Missing required scope: {required}"
            return None  # scope satisfied
        # No matching prefix — deny for token auth (fail closed).
        # Public paths (e.g. /api/auth/*) are handled before this check.
        return "Access denied: route not authorized for token authentication"

    async def dispatch(self, request: StarletteRequest, call_next):
        path = request.url.path

        # Initialise auth_info so route handlers can always read it
        request.state.auth_info = None

        # Only gate /api/ paths — static assets, SPA, etc. pass through
        if not path.startswith('/api/'):
            return await call_next(request)

        # OPTIONS preflight is handled by CORS middleware
        if request.method == 'OPTIONS':
            return await call_next(request)

        # Delegate to require_auth which knows about public paths, auth state, etc.
        try:
            auth_info = require_auth(request)
        except HTTPException as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
            )

        # Store auth result so route handlers never need to call require_auth again
        request.state.auth_info = auth_info

        # Authorization: enforce role/scope restrictions
        if auth_info:
            role = auth_info.get('role_name')
            is_write = request.method not in ('GET', 'HEAD', 'OPTIONS')

            # Session users: viewer role can only read
            if is_write and role == 'viewer':
                return JSONResponse(status_code=403, content={"detail": "Read-only role cannot perform this action"})

            # Token-auth: enforce scopes on both reads and writes
            is_token = bool(auth_info.get('token_id'))
            if is_token:
                # effective_scopes already computed by require_auth (token ∩ owner role)
                scopes = auth_info.get('effective_scopes') or set(auth_info.get('scopes') or [])

                # Token management is session-only — reject tokens entirely
                if path.startswith('/api/tokens'):
                    return JSONResponse(status_code=403, content={"detail": "Token management requires session authentication"})

                # Route → required scope mapping
                denied = self._check_token_scopes(path, is_write, scopes)
                if denied:
                    return JSONResponse(status_code=403, content={"detail": denied})

        return await call_next(request)

# Order matters: AuthMiddleware first, then CORS. Starlette is LIFO, so
# CORS (added second) wraps Auth (added first). This ensures 401 responses
# from auth always get CORS headers applied.
app.add_middleware(AuthMiddleware)
app.add_middleware(DualCORSMiddleware)


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
    log_proxy_token()


# ── Route Registration ───────────────────────────────────────────────────────
# Order matters: API routers MUST be included before the SPA catch-all.

app.include_router(auth_router)
app.include_router(tokens_router)
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
app.include_router(migration_router)
app.include_router(pihole_router)
app.include_router(adguard_router)


# ── Startup: verify all /api/ routes are covered by auth policy ─────────────

@app.on_event("startup")
def _verify_auth_route_coverage():
    """Fail-closed assertion: every /api/ route must be in the public allowlist,
    the auth-session-only set, or matched by the scope map.
    Uncovered routes would be denied at runtime, so catch misconfigurations early."""
    scope_prefixes = [prefix for prefix, _, _ in AuthMiddleware._SCOPE_MAP]
    public_paths = set(PUBLIC_PATHS)

    uncovered = []
    for route in app.routes:
        path = getattr(route, 'path', None)
        if not path or not path.startswith('/api/'):
            continue
        if path in public_paths or path in AUTH_SESSION_PATHS:
            continue
        if not any(path.startswith(prefix) for prefix in scope_prefixes):
            uncovered.append(path)

    if uncovered:
        raise RuntimeError(
            "AUTH ROUTE COVERAGE: The following /api/ routes are not covered by "
            "the scope map, public allowlist, or auth-session paths and will be "
            f"DENIED for token auth: {', '.join(sorted(set(uncovered)))}"
        )


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
