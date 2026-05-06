"""
Shared dependencies for route modules.

Singletons (database pools, enrichers, UniFi client) are initialized here
at import time and imported by route modules via `from deps import ...`.
"""

import functools
import logging
import os
import subprocess
import threading
import time

from psycopg2 import extensions, pool

from db import Database, build_conn_params, wait_for_postgres
from enrichment import AbuseIPDBEnricher
from unifi_api import UniFiAPI
from pihole_api import PiHolePoller

logger = logging.getLogger('api')

# ── Version ──────────────────────────────────────────────────────────────────

def _read_version():
    for path in ('/app/VERSION', 'VERSION'):
        try:
            with open(path) as f:
                return f.read().strip()
        except FileNotFoundError:
            continue
    return 'unknown'

APP_VERSION = _read_version()

# ── Database ─────────────────────────────────────────────────────────────────

conn_params = build_conn_params()
wait_for_postgres(conn_params)

db_pool = pool.ThreadedConnectionPool(2, 10, **conn_params)


def get_conn(retries=3, wait=0.5):
    """Get a pooled connection with statement_timeout for API routes.

    Retries briefly on pool exhaustion instead of failing immediately.
    """
    last_err = None
    for attempt in range(retries):
        try:
            conn = db_pool.getconn()
        except pool.PoolError as e:
            last_err = e
            if attempt < retries - 1:
                logger.warning("Connection pool exhausted, retrying (%d/%d)", attempt + 1, retries)
                time.sleep(wait * (attempt + 1))
                continue
            raise
        try:
            with conn.cursor() as cur:
                cur.execute("SET statement_timeout = '30s'")
        except Exception:
            db_pool.putconn(conn, close=True)
            raise
        return conn
    raise last_err


def put_conn(conn):
    """Return connection to pool, discarding if broken.

    Rolls back non-IDLE connections (e.g. after statement_timeout) before
    returning them to the pool.  If rollback fails or the connection is
    still not IDLE afterward, the connection is discarded instead.
    """
    if conn.closed:
        db_pool.putconn(conn, close=True)
        return

    close_conn = False
    try:
        status = conn.info.transaction_status
        if status != extensions.TRANSACTION_STATUS_IDLE:
            conn.rollback()
            status = conn.info.transaction_status
        close_conn = status != extensions.TRANSACTION_STATUS_IDLE
    except Exception:
        close_conn = True

    db_pool.putconn(conn, close=close_conn)


# ── AbuseIPDB Enricher (for manual enrich endpoint) ─────────────────────────

enricher_db = Database(conn_params, min_conn=2, max_conn=8)
enricher_db.connect()
abuseipdb = AbuseIPDBEnricher(db=enricher_db)

# ── UniFi API Client ────────────────────────────────────────────────────────

unifi_api = UniFiAPI(db=enricher_db)

# ── Pi-hole Poller ─────────────────────────────────────────────────────────

pihole_poller = PiHolePoller(db=enricher_db, enricher=None)

# ── Caching ──────────────────────────────────────────────────────────────────

def ttl_cache(seconds=30):
    """Thread-safe TTL cache for expensive endpoint results."""
    def decorator(fn):
        lock = threading.Lock()
        cached = {'result': None, 'expires': 0}

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            now = time.monotonic()
            if cached['result'] is not None and now < cached['expires']:
                return cached['result']
            with lock:
                # Double-check after acquiring lock
                if cached['result'] is not None and now < cached['expires']:
                    return cached['result']
                result = fn(*args, **kwargs)
                cached['result'] = result
                cached['expires'] = time.monotonic() + seconds
                return result
        return wrapper
    return decorator


# ── Helpers ──────────────────────────────────────────────────────────────────

def get_config_source(db, key: str, env_map: dict, db_prefix: str) -> str:
    """Shared config-source resolver: returns 'env', 'db', or 'default'.

    Used by UniFi and Pi-hole integrations to report where each setting
    value came from (environment variable, database, or built-in default).
    """
    env_var = env_map.get(key)
    if env_var and os.environ.get(env_var):
        return 'env'
    db_key = f'{db_prefix}_{key}'
    val = db.get_config(db_key)
    if val is not None and val != '':
        return 'db'
    return 'default'


def signal_receiver() -> bool:
    """Signal the receiver process to reload config.

    Returns True when SIGUSR2 was delivered, False otherwise.
    """
    try:
        result = subprocess.run(['pkill', '-SIGUSR2', '-f', '/app/main.py'],
                                check=False, timeout=2)
        signaled = result.returncode == 0
        with open('/tmp/config_update_requested', 'w') as f:
            f.write(str(time.time()))
        if signaled:
            logger.info("Signaled receiver process to reload config")
        else:
            logger.warning(
                "signal_receiver: pkill found no matching process (exit %d) "
                "-- config saved but reload requires a service restart",
                result.returncode,
            )
        return signaled
    except Exception as e:
        logger.warning("Failed to signal receiver: %s", e)
        return False
