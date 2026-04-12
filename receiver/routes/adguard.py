"""
AdGuard Home integration endpoints.

GET  /api/config/adguard        — read current configuration (password masked)
PUT  /api/config/adguard        — save configuration + signal receiver reload
POST /api/config/adguard/test   — test connection without saving
GET  /api/adguard/stats         — recent query log stats from adguard_logs table
"""

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from db import get_config, set_config, encrypt_api_key
from deps import enricher_db, signal_receiver, get_conn, put_conn

logger = logging.getLogger('api.adguard')

router = APIRouter()

_PASSWORD_PLACEHOLDER = '***'


# ── Pydantic models ───────────────────────────────────────────────────────────

class AdGuardConfig(BaseModel):
    """Payload for PUT /api/config/adguard."""
    enabled: bool = False
    host: str = ''
    username: str = 'admin'
    password: str = ''
    poll_interval: int = 30


class AdGuardTestRequest(BaseModel):
    """Payload for POST /api/config/adguard/test."""
    host: str
    username: str = 'admin'
    password: str


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/api/config/adguard")
def get_adguard_config():
    """Return the current AdGuard Home integration configuration.

    The password is always masked in the response; send the placeholder
    back in PUT to keep the existing password unchanged.
    """
    has_password = bool(get_config(enricher_db, 'adguard_password_enc', ''))
    return {
        'enabled':       get_config(enricher_db, 'adguard_enabled',       False),
        'host':          get_config(enricher_db, 'adguard_host',           ''),
        'username':      get_config(enricher_db, 'adguard_username',       'admin'),
        'password':      _PASSWORD_PLACEHOLDER if has_password else '',
        'poll_interval': get_config(enricher_db, 'adguard_poll_interval',  30),
    }


@router.put("/api/config/adguard")
def put_adguard_config(body: AdGuardConfig):
    """Save AdGuard Home configuration and signal the receiver to reload.

    Sending the password placeholder leaves the stored password unchanged.
    poll_interval must be between 15 and 86400 seconds.
    """
    if body.poll_interval < 15 or body.poll_interval > 86400:
        raise HTTPException(
            status_code=400,
            detail='poll_interval must be between 15 and 86400 seconds',
        )

    # Read stored host BEFORE writing so the comparison is against the old value.
    stored_host = (get_config(enricher_db, 'adguard_host', '') or '').rstrip('/')

    set_config(enricher_db, 'adguard_enabled',       body.enabled)
    set_config(enricher_db, 'adguard_host',          body.host.rstrip('/'))
    set_config(enricher_db, 'adguard_username',      body.username)
    set_config(enricher_db, 'adguard_poll_interval', body.poll_interval)

    if body.password and body.password != _PASSWORD_PLACEHOLDER:
        try:
            set_config(enricher_db, 'adguard_password_enc', encrypt_api_key(body.password))
        except ValueError as e:
            raise HTTPException(status_code=500, detail=f'Encryption failed: {e}')

    # Clear cursor when host changes so the poller re-fetches from the new instance.
    if body.host.rstrip('/') != stored_host:
        set_config(enricher_db, 'adguard_cursor', None)

    signal_receiver()
    return {'ok': True}


@router.post("/api/config/adguard/test")
def test_adguard_connection(body: AdGuardTestRequest):
    """Test connectivity to an AdGuard Home instance without saving credentials.

    Returns version and running status on success, or 400 with an error message.
    """
    from adguard_poller import test_connection
    try:
        info = test_connection(body.host, body.username, body.password)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f'Connection failed: {e}')
    return {'ok': True, 'version': info.get('version', ''), 'running': info.get('running', False)}


@router.get("/api/adguard/stats")
def get_adguard_stats():
    """Return summary statistics from the adguard_logs table.

    Includes total queries, blocked count, top queried domains, and
    top clients in the last 24 hours.
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # Check table exists before querying
            cur.execute("""
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = 'adguard_logs'
            """)
            if not cur.fetchone():
                # Table not yet created — return a consistent zero-state schema
                # so callers never need to handle a partial response.
                return {
                    'enabled':        bool(get_config(enricher_db, 'adguard_enabled', False)),
                    'total':          0,
                    'blocked':        0,
                    'cached':         0,
                    'avg_elapsed_ms': None,
                    'top_domains':    [],
                    'top_clients':    [],
                }

            cur.execute("""
                SELECT
                    COUNT(*)                                                                       AS total,
                    COUNT(*) FILTER (WHERE reason NOT LIKE 'NotFiltered%%')                        AS blocked,
                    COUNT(*) FILTER (WHERE cached = TRUE)                                          AS cached,
                    ROUND(AVG(elapsed_ms) FILTER (WHERE elapsed_ms IS NOT NULL)::numeric, 2)       AS avg_elapsed_ms
                FROM adguard_logs
                WHERE timestamp >= NOW() - INTERVAL '24 hours'
            """)
            row = cur.fetchone()
            total, blocked, cached_count, avg_ms = row if row else (0, 0, 0, None)

            cur.execute("""
                SELECT domain, COUNT(*) AS hits
                FROM adguard_logs
                WHERE timestamp >= NOW() - INTERVAL '24 hours'
                GROUP BY domain
                ORDER BY hits DESC
                LIMIT 10
            """)
            top_domains = [{'domain': r[0], 'hits': r[1]} for r in cur.fetchall()]

            cur.execute("""
                SELECT COALESCE(client_name, host(client_ip)::text, 'unknown') AS client,
                       COUNT(*) AS hits
                FROM adguard_logs
                WHERE timestamp >= NOW() - INTERVAL '24 hours'
                GROUP BY 1
                ORDER BY hits DESC
                LIMIT 10
            """)
            top_clients = [{'client': r[0], 'hits': r[1]} for r in cur.fetchall()]

        return {
            'enabled':      bool(get_config(enricher_db, 'adguard_enabled', False)),
            'total':        int(total or 0),
            'blocked':      int(blocked or 0),
            'cached':       int(cached_count or 0),
            'avg_elapsed_ms': float(avg_ms) if avg_ms is not None else None,
            'top_domains':  top_domains,
            'top_clients':  top_clients,
        }
    finally:
        put_conn(conn)
