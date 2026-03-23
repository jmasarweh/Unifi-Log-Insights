"""Authentication endpoints."""

import hashlib
import hmac as _hmac
import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import APIRouter, HTTPException, Request, Response
from psycopg2.extras import RealDictCursor

from db import get_config, set_config
from deps import get_conn, put_conn, enricher_db

logger = logging.getLogger('api.auth')
router = APIRouter()

# ── Proxy Trust (shared-secret header) ────────────────────────────────────────
#
# Trust of X-Forwarded-Proto / X-Forwarded-For is gated by a shared secret.
# The app derives a deterministic token from SECRET_KEY, POSTGRES_PASSWORD,
# or DB_PASSWORD (first non-empty wins).
# The reverse proxy must send this token in the X-ULI-Proxy-Auth header.
# No IP/subnet configuration needed.

def _derive_proxy_token() -> str:
    """Derive a deterministic proxy-auth token from the app secret."""
    # @coderabbit: Fallback chain is intentional — SECRET_KEY is preferred, but
    # internal-DB users have POSTGRES_PASSWORD and external-DB users have DB_PASSWORD.
    # HMAC domain separation ('proxy-auth') prevents reuse as a DB credential.
    # Empty-string fallback is safe: POSTGRES_PASSWORD is always set (required by
    # PostgreSQL) for internal-DB, and DB_PASSWORD is required for external-DB.
    # The only scenario where all three are unset is a broken deployment that
    # can't connect to any database anyway — no HTTP traffic to protect.
    secret = (os.environ.get('SECRET_KEY')
              or os.environ.get('POSTGRES_PASSWORD')
              or os.environ.get('DB_PASSWORD', ''))
    return _hmac.new(secret.encode(), b'proxy-auth', hashlib.sha256).hexdigest()

PROXY_AUTH_TOKEN = _derive_proxy_token()


def log_proxy_token() -> None:
    """Log the proxy auth token.  Must be called after logging.basicConfig()."""
    logger.info(
        "Proxy auth token (X-ULI-Proxy-Auth): %s  — configure your reverse proxy with this value",
        PROXY_AUTH_TOKEN,
    )


def _is_trusted_proxy(request: Request) -> bool:
    """Check if the request carries a valid X-ULI-Proxy-Auth header."""
    header = request.headers.get('x-uli-proxy-auth')
    if not header:
        return False
    return _hmac.compare_digest(PROXY_AUTH_TOKEN, header)


AUTH_ENABLED = os.environ.get('AUTH_ENABLED', 'false').lower() in ('true', '1', 'yes')


def get_real_client_ip(request: Request) -> str:
    """Resolve client IP from X-Forwarded-For if from trusted proxy."""
    client_ip = request.client.host if request.client else '127.0.0.1'
    if not _is_trusted_proxy(request):
        return client_ip
    xff = request.headers.get('x-forwarded-for', '')
    if not xff:
        return client_ip
    parts = [p.strip() for p in xff.split(',')]
    # @coderabbit: Rightmost iteration is correct for our single-trusted-proxy model.
    # The nginx/Caddy/Traefik snippets we provide use $remote_addr (not
    # $proxy_add_x_forwarded_for), so XFF contains exactly one entry: the real client IP.
    # IP-based skipping of trusted proxies is unnecessary — trust is gated by the
    # X-ULI-Proxy-Auth shared secret, not by source IP.
    for ip in reversed(parts):
        if ip:
            return ip
    return client_ip


def get_forwarded_proto(request: Request) -> str:
    """Get protocol, trusting X-Forwarded-Proto only when proxy secret matches."""
    if _is_trusted_proxy(request):
        proto = request.headers.get('x-forwarded-proto', '').lower()
        if proto in ('http', 'https'):
            return proto
    return str(request.url.scheme)


def _require_https(request: Request):
    if get_forwarded_proto(request) != 'https':
        if not _is_trusted_proxy(request):
            raise HTTPException(403, "Unable to verify a secure connection. Your reverse proxy may not be sending the required X-ULI-Proxy-Auth header. See the authentication docs for proxy configuration.")
        raise HTTPException(403, "Authentication requires HTTPS. Please access the app through a reverse proxy with TLS enabled.")


def _auth_enabled() -> bool:
    if not AUTH_ENABLED:
        return False
    enabled = bool(get_config(enricher_db, 'auth_enabled', False))
    if not enabled and _has_admin():
        # AUTH_ENABLED env var is true and an admin exists, but the DB flag
        # is stale (e.g. toggled off then on).  Auto-sync to avoid showing
        # the setup form again.
        set_config(enricher_db, 'auth_enabled', True)
        logger.info("Auto-enabled auth: AUTH_ENABLED=true and admin user exists in DB")
        return True
    return enabled


def _has_users() -> bool:
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT EXISTS(SELECT 1 FROM users WHERE is_active = true)")
            return cur.fetchone()[0]
    finally:
        put_conn(conn)


def _has_admin() -> bool:
    """Check if an active admin user exists (by role name, not ID)."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT EXISTS(
                    SELECT 1 FROM users u
                    JOIN roles r ON r.id = u.role_id
                    WHERE r.name = 'admin' AND u.is_active = true
                )"""
            )
            return cur.fetchone()[0]
    finally:
        put_conn(conn)


# ── Rate Limiting ────────────────────────────────────────────────────────────

# In-memory rate limiter is intentional: this app runs as a single uvicorn worker
# inside a single Docker container, so process-local state is sufficient.
# Redis/DB-backed rate limiting would be overengineered for this deployment model.
_login_attempts = {}  # ip -> [timestamps]
_LOGIN_RATE_LIMIT = 5
_LOGIN_RATE_WINDOW = 60  # seconds
_login_check_count = 0
_LOGIN_PRUNE_EVERY = 100  # full GC sweep every N checks


def _check_rate_limit(ip: str):
    global _login_check_count
    now = datetime.now(timezone.utc).timestamp()

    # Periodic full sweep to prevent unbounded memory growth from stale IPs
    _login_check_count += 1
    if _login_check_count >= _LOGIN_PRUNE_EVERY:
        _login_check_count = 0
        stale = [k for k, v in _login_attempts.items() if not v or now - v[-1] >= _LOGIN_RATE_WINDOW]
        for k in stale:
            del _login_attempts[k]

    attempts = _login_attempts.get(ip, [])
    # Prune old entries for this IP
    attempts = [t for t in attempts if now - t < _LOGIN_RATE_WINDOW]
    _login_attempts[ip] = attempts
    if len(attempts) >= _LOGIN_RATE_LIMIT:
        raise HTTPException(429, "Too many login attempts. Please try again later.")


def _record_attempt(ip: str):
    now = datetime.now(timezone.utc).timestamp()
    if ip not in _login_attempts:
        _login_attempts[ip] = []
    _login_attempts[ip].append(now)


def _clear_attempts(ip: str):
    _login_attempts.pop(ip, None)


# ── Audit helper ─────────────────────────────────────────────────────────────

def _write_audit(user_id, token_id, action, detail, ip, user_agent):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO audit_log (user_id, token_id, action, detail, ip_address, user_agent)
                   VALUES (%s, %s, %s, %s, %s::inet, %s)""",
                [user_id, token_id, action,
                 json.dumps(detail) if detail else None,
                 ip, user_agent]
            )
        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception("Failed to write audit log")
    finally:
        put_conn(conn)


# ── Session helpers ──────────────────────────────────────────────────────────

def _create_session(user_id: int, request: Request) -> str:
    """Create a new session and return the raw token."""
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    ttl_hours = int(get_config(enricher_db, 'auth_session_ttl_hours', 168) or 168)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
    ip = get_real_client_ip(request)
    ua = request.headers.get('user-agent', '')[:500]

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO sessions (user_id, token_hash, expires_at, ip_address, user_agent)
                   VALUES (%s, %s, %s, %s::inet, %s)""",
                [user_id, token_hash, expires_at, ip, ua]
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        put_conn(conn)

    return token


def _validate_session(token: str) -> dict | None:
    """Validate session token. Returns user dict or None."""
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT s.user_id, s.expires_at, u.username, u.role_id, u.is_active,
                       r.name as role_name, r.permissions
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                JOIN roles r ON r.id = u.role_id
                WHERE s.token_hash = %s AND s.expires_at > NOW() AND u.is_active = true
            """, [token_hash])
            row = cur.fetchone()
        # Won't Fix: commit() on read-only SELECT closes the transaction cleanly,
        # preventing idle-in-transaction on long-lived connections from the pool.
        conn.commit()
        if row:
            return dict(row)
        return None
    except Exception:
        conn.rollback()
        return None
    finally:
        put_conn(conn)


# ── API Token validation ────────────────────────────────────────────────────

def _validate_api_token(token: str) -> dict | None:
    """Validate Bearer API token. Returns token+user dict or None."""
    if not token:
        return None
    # Extract prefix from random portion (after underscore) to match token creation logic.
    random_part = token.split('_', 1)[1] if '_' in token else token
    prefix = random_part[:8]
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT t.id as token_id, t.token_hash, t.token_salt, t.scopes, t.client_type,
                       t.owner_user_id, u.username, u.role_id, u.is_active,
                       r.name as role_name, r.permissions as user_permissions
                FROM api_tokens t
                LEFT JOIN users u ON u.id = t.owner_user_id
                LEFT JOIN roles r ON r.id = u.role_id
                WHERE t.token_prefix = %s AND t.disabled = false
                  AND (t.owner_user_id IS NULL OR u.is_active = true)
            """, [prefix])
            rows = cur.fetchall()
            for row in rows:
                expected = row.get('token_hash') or ''
                salt = row.get('token_salt') or ''
                if expected and salt:
                    computed = _hmac.new(salt.encode(), token.encode(), 'sha256').hexdigest()
                    if _hmac.compare_digest(computed, expected):
                        # Update last_used_at
                        cur.execute("UPDATE api_tokens SET last_used_at = NOW() WHERE id = %s", [row['token_id']])
                        conn.commit()
                        return dict(row)
        conn.commit()
        return None
    except Exception:
        conn.rollback()
        return None
    finally:
        put_conn(conn)


def validate_token_with_effective_scopes(token: str) -> dict | None:
    """Validate an API token and return context with effective scopes.

    Effective scopes = token scopes ∩ owner's role permissions.
    Ownerless tokens or admin wildcard use token scopes alone.
    Returns dict with: token_id, owner_user_id, username, role_name,
    scopes (raw), effective_scopes, client_type. Or None if invalid.
    """
    info = _validate_api_token(token)
    if not info:
        return None
    token_scopes = set(info.get('scopes') or [])
    owner_perms = set(info.get('user_permissions') or [])
    if info.get('owner_user_id') and owner_perms and '*' not in owner_perms:
        effective = token_scopes & owner_perms
    else:
        effective = token_scopes
    info['effective_scopes'] = effective
    return info


# ── Auth dependency ──────────────────────────────────────────────────────────

# Paths that never require auth
PUBLIC_PATHS = {
    '/api/health',
    '/api/auth/status',
    '/api/auth/login',
    '/api/auth/logout',
    '/api/auth/setup',
    '/api/setup/status',
}

PUBLIC_PREFIXES = (
    '/assets/',
)

# Auth routes that require session auth but don't need scope map coverage
# (handled by require_auth middleware, not token scopes).
# Defined here as single source of truth — also used by api.py startup verification.
AUTH_SESSION_PATHS = {
    '/api/auth/me',
    '/api/auth/session-ttl',
    '/api/auth/change-password',
    '/api/auth/proxy-token',
}


def require_auth(request: Request) -> dict | None:
    """Auth dependency. Returns user/token info or None if auth disabled.
    Raises 401 if auth enabled and no valid credentials."""
    if not _auth_enabled():
        return None

    path = request.url.path
    if path in PUBLIC_PATHS or any(path.startswith(p) for p in PUBLIC_PREFIXES):
        return None

    # Check Bearer token first
    auth_header = request.headers.get('authorization', '')
    if auth_header.lower().startswith('bearer '):
        token = auth_header[7:].strip()
        info = validate_token_with_effective_scopes(token)
        if info:
            return info
        raise HTTPException(401, "Invalid or expired API token")

    # Check session cookie
    session_token = request.cookies.get('uli_session')
    if session_token:
        info = _validate_session(session_token)
        if info:
            return info

    raise HTTPException(401, "Authentication required")


# ── Routes ───────────────────────────────────────────────────────────────────

@router.get("/api/auth/status")
def auth_status(request: Request):
    """Public bootstrap endpoint for SPA."""
    from routes.setup import setup_status as get_setup_status
    setup_result = get_setup_status()
    auth_enabled = _auth_enabled()
    result = {
        "auth_enabled_effective": auth_enabled,
        "has_users": _has_users(),
        "has_admin": _has_admin(),
        "is_https": get_forwarded_proto(request) == 'https',
        "proxy_trusted": _is_trusted_proxy(request),
        "setup_complete": setup_result.get('setup_complete', False),
        "session_ttl_hours": int(get_config(enricher_db, 'auth_session_ttl_hours', 168) or 168),
    }
    # Expose proxy token only when auth is not active — the app is already
    # fully unprotected at this point, so no additional risk.  Once auth is
    # enabled this field is omitted; users get it from the admin-only endpoint.
    if not auth_enabled:
        result["proxy_token"] = PROXY_AUTH_TOKEN
    return result


@router.get("/api/auth/proxy-token")
def get_proxy_token(request: Request):
    """Return the derived proxy-auth token. Requires admin session (not API tokens)."""
    info = getattr(request.state, 'auth_info', None)
    if not info or not info.get('user_id'):
        raise HTTPException(401, "Authentication required")
    # Reject API-token-backed auth — infrastructure-secret material,
    # only interactive admin sessions should retrieve it.
    if info.get('token_id'):
        raise HTTPException(403, "Session auth required — API tokens cannot retrieve proxy secret")
    if info.get('role_name') != 'admin':
        raise HTTPException(403, "Admin access required")
    return {
        "token": PROXY_AUTH_TOKEN,
        "header_name": "X-ULI-Proxy-Auth",
    }


@router.post("/api/auth/setup")
def auth_setup(request: Request, body: dict):
    """Create first user. Only works when no users exist."""
    _require_https(request)

    if _has_users():
        raise HTTPException(400, "Setup already completed. Users already exist.")

    username = (body.get('username') or '').strip()
    password = body.get('password') or ''

    if not username or len(username) < 2:
        raise HTTPException(400, "Username must be at least 2 characters")
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if len(password.encode('utf-8')) > 72:
        raise HTTPException(400, "Password must not exceed 72 bytes")

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # Get admin role id
            cur.execute("SELECT id FROM roles WHERE name = 'admin'")
            role_row = cur.fetchone()
            if not role_row:
                raise HTTPException(500, "Admin role not found. Database migration may be incomplete.")
            role_id = role_row[0]

            cur.execute(
                """INSERT INTO users (username, password_hash, role_id)
                   VALUES (%s, %s, %s) RETURNING id""",
                [username, password_hash, role_id]
            )
            user_id = cur.fetchone()[0]
        conn.commit()

        # Enable auth
        set_config(enricher_db, 'auth_enabled', True)

        # Audit
        _write_audit(user_id, None, 'auth_enabled', {'method': 'first_user_setup'}, get_real_client_ip(request), request.headers.get('user-agent', '')[:500])

        # Create session
        token = _create_session(user_id, request)
        response = Response(
            content=json.dumps({"success": True, "username": username}),
            media_type="application/json"
        )
        ttl_hours = int(get_config(enricher_db, 'auth_session_ttl_hours', 168) or 168)
        response.set_cookie(
            key='uli_session',
            value=token,
            httponly=True,
            secure=True,
            samesite='lax',
            max_age=ttl_hours * 3600,
            path='/',
        )
        return response

    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        logger.exception("Auth setup failed")
        raise HTTPException(500, "Setup failed") from None
    finally:
        put_conn(conn)


@router.post("/api/auth/login")
def auth_login(request: Request, body: dict):
    """Login with username/password."""
    _require_https(request)

    client_ip = get_real_client_ip(request)
    _check_rate_limit(client_ip)

    username = (body.get('username') or '').strip()
    password = body.get('password') or ''

    if not username or not password:
        raise HTTPException(400, "Username and password required")
    if len(password.encode('utf-8')) > 72:
        raise HTTPException(401, "Invalid username or password")

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT id, username, password_hash, is_active FROM users WHERE username = %s",
                [username]
            )
            user = cur.fetchone()
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        put_conn(conn)

    ua = request.headers.get('user-agent', '')[:500]

    if not user or not user['is_active']:
        _record_attempt(client_ip)
        _write_audit(None, None, 'login_failed', {'username': username, 'reason': 'user_not_found'}, client_ip, ua)
        raise HTTPException(401, "Invalid username or password")

    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        _record_attempt(client_ip)
        _write_audit(user['id'], None, 'login_failed', {'reason': 'wrong_password'}, client_ip, ua)
        raise HTTPException(401, "Invalid username or password")

    _clear_attempts(client_ip)

    token = _create_session(user['id'], request)
    _write_audit(user['id'], None, 'login', None, client_ip, ua)

    # Update last_login_at
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET last_login_at = NOW() WHERE id = %s", [user['id']])
        conn.commit()
    except Exception:
        conn.rollback()
    finally:
        put_conn(conn)

    response = Response(
        content=json.dumps({"success": True, "username": user['username']}),
        media_type="application/json"
    )
    ttl_hours = int(get_config(enricher_db, 'auth_session_ttl_hours', 168) or 168)
    response.set_cookie(
        key='uli_session',
        value=token,
        httponly=True,
        secure=True,
        samesite='lax',
        max_age=ttl_hours * 3600,
        path='/',
    )
    return response


@router.post("/api/auth/logout")
def auth_logout(request: Request):
    """Invalidate current session."""
    session_token = request.cookies.get('uli_session')
    if session_token:
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM sessions WHERE token_hash = %s", [token_hash])
            conn.commit()
        except Exception:
            conn.rollback()
        finally:
            put_conn(conn)

    response = Response(
        content=json.dumps({"success": True}),
        media_type="application/json"
    )
    response.delete_cookie('uli_session', path='/')
    return response


@router.put("/api/auth/session-ttl")
def update_session_ttl(request: Request, body: dict):
    """Update session duration. Requires auth (enforced by middleware)."""
    hours = body.get('hours')
    if not isinstance(hours, int) or hours < 1 or hours > 8760:
        raise HTTPException(400, "Session duration must be between 1 and 8760 hours")
    set_config(enricher_db, 'auth_session_ttl_hours', hours)
    return {"success": True, "session_ttl_hours": hours}


@router.get("/api/auth/me")
def auth_me(request: Request):
    """Return current user info. Auth enforced by middleware."""
    info = getattr(request.state, 'auth_info', None)
    if info is None:
        # Auth disabled
        return {"authenticated": False, "auth_enabled": False}

    return {
        "authenticated": True,
        "user_id": info.get('user_id'),
        "username": info.get('username'),
        "role": info.get('role_name'),
    }


@router.post("/api/auth/change-password")
def auth_change_password(request: Request, body: dict):
    """Change password. Auth enforced by middleware; requires HTTPS."""
    _require_https(request)
    info = getattr(request.state, 'auth_info', None)
    if not info or not info.get('user_id'):
        raise HTTPException(401, "Authentication required")

    current_password = body.get('current_password') or ''
    new_password = body.get('new_password') or ''

    if len(new_password) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")
    if len(new_password.encode('utf-8')) > 72:
        raise HTTPException(400, "New password must not exceed 72 bytes")

    user_id = info['user_id']
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE id = %s", [user_id])
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "User not found")

            if not bcrypt.checkpw(current_password.encode('utf-8'), row[0].encode('utf-8')):
                raise HTTPException(401, "Current password is incorrect")

            new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')
            cur.execute("UPDATE users SET password_hash = %s, updated_at = NOW() WHERE id = %s", [new_hash, user_id])

            # Invalidate all sessions except current
            session_token = request.cookies.get('uli_session')
            if session_token:
                current_hash = hashlib.sha256(session_token.encode()).hexdigest()
                cur.execute("DELETE FROM sessions WHERE user_id = %s AND token_hash != %s", [user_id, current_hash])
            else:
                cur.execute("DELETE FROM sessions WHERE user_id = %s", [user_id])

        conn.commit()
    except HTTPException:
        raise
    except Exception:
        conn.rollback()
        logger.exception("Password change failed")
        raise HTTPException(500, "Password change failed") from None
    finally:
        put_conn(conn)

    _write_audit(user_id, None, 'password_changed', None, get_real_client_ip(request), request.headers.get('user-agent', '')[:500])
    return {"success": True}


# ── Cleanup (called by scheduler) ───────────────────────────────────────────

def auth_cleanup():
    """Delete expired sessions and old audit log entries."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM sessions WHERE expires_at < NOW()")
            expired_sessions = cur.rowcount

            retention = int(get_config(enricher_db, 'audit_log_retention_days', 90) or 90)
            cur.execute(
                "DELETE FROM audit_log WHERE created_at < NOW() - make_interval(days => %s)",
                [retention]
            )
            old_audit = cur.rowcount
        conn.commit()
        if expired_sessions or old_audit:
            logger.info("Auth cleanup: %d expired sessions, %d old audit entries removed", expired_sessions, old_audit)
    except Exception:
        conn.rollback()
        logger.exception("Auth cleanup failed")
    finally:
        put_conn(conn)
