"""API token management endpoints.

Token management requires session-authenticated admin users.
Bearer token auth is explicitly rejected to prevent token-authenticated
clients from managing tokens (privilege escalation).
"""

import hmac
import logging
import secrets
import uuid

from fastapi import APIRouter, HTTPException, Request
from psycopg2.extras import RealDictCursor

from deps import get_conn, put_conn
from routes.auth import _require_https, get_real_client_ip, _write_audit

logger = logging.getLogger('api.tokens')
router = APIRouter()

_VALID_SCOPES = {
    'logs.read', 'stats.read', 'flows.read', 'threats.read', 'dashboard.read',
    'settings.read', 'settings.write', 'health.read',
    'firewall.read', 'firewall.write', 'firewall.syslog',
    'unifi.read', 'system.read', 'mcp.admin',
}

_VALID_CLIENT_TYPES = {'mcp', 'extension', 'api'}


def _format_token_timestamps(item: dict) -> dict:
    """Convert datetime fields to ISO strings for JSON serialization."""
    if item.get('created_at'):
        item['created_at'] = item['created_at'].isoformat()
    if item.get('last_used_at'):
        item['last_used_at'] = item['last_used_at'].isoformat()
    return item


def hash_token(token: str, salt: str) -> str:
    return hmac.new(salt.encode(), token.encode(), 'sha256').hexdigest()


def list_tokens_by_type(client_type: str) -> dict:
    """List API tokens filtered by client_type. Shared helper for MCP and token endpoints."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, name, token_prefix, scopes, client_type, owner_user_id,
                       created_at, last_used_at, disabled
                FROM api_tokens WHERE client_type = %s
                ORDER BY created_at DESC
            """, [client_type])
            rows = cur.fetchall()
        conn.commit()

        tokens = [_format_token_timestamps(dict(row)) for row in rows]
        return {"tokens": tokens, "total": len(tokens)}
    except Exception as e:
        conn.rollback()
        logger.exception("Failed to list API tokens")
        raise HTTPException(500, "Internal server error") from e
    finally:
        put_conn(conn)


def create_token_record(name: str, scopes: list, client_type: str,
                        valid_scopes: set, owner_user_id: int | None = None) -> dict:
    """Create a new API token record. Shared helper for MCP and token endpoints.

    Returns {"success": True, "token": <plaintext>, "id": <uuid>}.
    """
    if not isinstance(scopes, list) or not scopes:
        raise HTTPException(400, "scopes list is required")
    for scope in scopes:
        if scope not in valid_scopes:
            raise HTTPException(400, f"Invalid scope: {scope}")

    token = f"uli-{client_type}_{secrets.token_urlsafe(32)}"
    token_id = str(uuid.uuid4())
    # Extract prefix from the random portion (after underscore) so it's
    # not predictable from the fixed "uli-{client_type}_" header.
    random_part = token.split('_', 1)[1] if '_' in token else token
    prefix = random_part[:8]
    salt = secrets.token_hex(16)
    token_hash = hash_token(token, salt)

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO api_tokens (id, name, token_prefix, token_hash, token_salt, scopes, client_type, owner_user_id)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                [token_id, name, prefix, token_hash, salt, scopes, client_type, owner_user_id]
            )
        conn.commit()
        return {"success": True, "token": token, "id": token_id}
    except Exception as e:
        conn.rollback()
        logger.exception("Failed to create API token")
        raise HTTPException(500, "Internal server error") from e
    finally:
        put_conn(conn)


def revoke_token_by_id(token_id: str) -> dict:
    """Revoke (disable) an API token by ID. Shared helper."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE api_tokens SET disabled = true WHERE id = %s",
                [token_id]
            )
            if cur.rowcount == 0:
                raise HTTPException(404, "Token not found")
        conn.commit()
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        logger.exception("Failed to revoke API token")
        raise HTTPException(500, "Internal server error") from e
    finally:
        put_conn(conn)


def _require_session_admin(request: Request) -> dict:
    """Require session-authenticated admin user.

    Bearer tokens are already rejected by AuthMiddleware for /api/tokens paths.
    Auth is already enforced by middleware; this reads request.state.auth_info.

    When auth is disabled (single-user mode), returns an empty dict. Downstream
    callers (e.g. audit) will get None from .get('user_id') — this is expected
    since there is no authenticated user identity in no-auth mode.
    """
    auth_info = getattr(request.state, 'auth_info', None)
    if auth_info is None:
        # Auth disabled — allow (single-user mode, no identity to attribute)
        return {}

    if not auth_info.get('user_id'):
        raise HTTPException(401, "Session authentication required")

    if auth_info.get('role_name') != 'admin':
        raise HTTPException(403, "Admin role required for token management")

    return auth_info


@router.get("/api/tokens")
def list_tokens(request: Request, client_type: str | None = None):
    """List API tokens. Requires session-authenticated admin.

    No pagination: token lists are small (<20 in practice) for this
    single-container self-hosted deployment model."""
    _require_session_admin(request)

    if client_type:
        return list_tokens_by_type(client_type)

    # No filter — list all tokens
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, name, token_prefix, scopes, client_type, owner_user_id,
                       created_at, last_used_at, disabled
                FROM api_tokens
                ORDER BY created_at DESC
            """)
            rows = cur.fetchall()
        conn.commit()

        tokens = [_format_token_timestamps(dict(row)) for row in rows]
        return {"tokens": tokens, "total": len(tokens)}
    except Exception as e:
        conn.rollback()
        logger.exception("Failed to list API tokens")
        raise HTTPException(500, "Internal server error") from e
    finally:
        put_conn(conn)


@router.post("/api/tokens")
def create_token(request: Request, body: dict):
    """Create a new API token. Requires session-authenticated admin."""
    _require_https(request)
    auth_info = _require_session_admin(request)

    name = (body.get('name') or '').strip() or 'API Token'
    scopes = body.get('scopes') or []
    client_type = body.get('client_type') or 'api'

    if client_type not in _VALID_CLIENT_TYPES:
        raise HTTPException(400, f"Invalid client_type: {client_type}")

    result = create_token_record(name, scopes, client_type, _VALID_SCOPES,
                                 owner_user_id=auth_info.get('user_id'))

    _write_audit(auth_info.get('user_id'), result['id'], 'token_created',
                 {'name': name, 'client_type': client_type, 'scopes': scopes},
                 get_real_client_ip(request),
                 request.headers.get('user-agent', '')[:500])

    return result


@router.delete("/api/tokens/{token_id}")
def revoke_token(request: Request, token_id: str):
    """Revoke (disable) an API token. Requires session-authenticated admin."""
    _require_https(request)
    auth_info = _require_session_admin(request)

    result = revoke_token_by_id(token_id)

    _write_audit(
        auth_info.get('user_id'),
        token_id, 'token_revoked', None,
        get_real_client_ip(request),
        request.headers.get('user-agent', '')[:500]
    )
    return result
