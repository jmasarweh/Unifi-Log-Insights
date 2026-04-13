"""
AdGuard Home v0.107+ query log poller.

Polls GET /control/querylog using a cursor (older_than) to fetch new DNS
queries since the last poll and stores them in the adguard_logs table.
Authentication uses HTTP Basic Auth (username:password, base64-encoded).

Client names are resolved from GET /control/clients and cached for 5 minutes.
Configured clients take priority over auto-detected clients.
"""

import base64
import logging
import re
import threading
import time
from datetime import datetime

import requests

from db import Database, decrypt_api_key, get_config

logger = logging.getLogger('adguard_poller')

_POLL_BATCH = 500           # max entries per API call
_CLIENT_CACHE_TTL = 300     # seconds between /control/clients refreshes


class AdGuardHomePoller:
    """Background thread that polls AdGuard Home query logs into adguard_logs."""

    def __init__(self, db: Database):
        """Initialise poller. Config is loaded from system_config via reload_config()."""
        self._db = db
        self._stop = threading.Event()
        self._thread = None
        self._clients: dict[str, str] = {}   # ip → display name
        self._clients_refreshed = 0.0
        self.reload_config()

    # ── Config ────────────────────────────────────────────────────────────────

    def reload_config(self):
        """Re-read AdGuard config from system_config. Safe to call from SIGUSR2 handler."""
        new_host = (get_config(self._db, 'adguard_host', '') or '').rstrip('/')
        if new_host != getattr(self, '_host', ''):
            # Host changed — invalidate client cache so _refresh_clients fetches
            # fresh names from the new instance rather than serving stale data.
            self._clients = {}
            self._clients_refreshed = 0.0

        self._enabled  = bool(get_config(self._db, 'adguard_enabled', False))
        self._host     = new_host
        self._username = get_config(self._db, 'adguard_username', 'admin') or 'admin'
        enc            = get_config(self._db, 'adguard_password_enc', '') or ''
        self._password = decrypt_api_key(enc) if enc else ''
        self._interval = max(15, min(86400, int(get_config(self._db, 'adguard_poll_interval', 30) or 30)))

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _auth_header(self) -> dict:
        """Build HTTP Basic Auth header from stored credentials."""
        token = base64.b64encode(
            f"{self._username}:{self._password}".encode()
        ).decode()
        return {'Authorization': f'Basic {token}'}

    # ── Client name cache ─────────────────────────────────────────────────────

    def _refresh_clients(self):
        """Fetch /control/clients and rebuild IP→name cache (TTL-gated)."""
        if time.time() - self._clients_refreshed < _CLIENT_CACHE_TTL:
            return
        try:
            r = requests.get(
                f"{self._host}/control/clients",
                headers=self._auth_header(),
                timeout=10,
            )
            r.raise_for_status()
            data = r.json()
            cache: dict[str, str] = {}
            # Auto-detected first (lower priority)
            for c in data.get('auto_clients', []):
                if c.get('name') and c.get('ip'):
                    cache[c['ip']] = c['name']
            # Configured clients override (higher priority)
            for c in data.get('clients', []):
                name = c.get('name', '')
                for cid in c.get('ids', []):
                    if name:
                        cache[cid] = name
            self._clients = cache
            self._clients_refreshed = time.time()
            logger.debug("AdGuard client cache refreshed: %d entries", len(cache))
        except (requests.RequestException, KeyError, ValueError) as e:
            logger.warning("AdGuard: client cache refresh failed: %s", e)

    # ── Poll ──────────────────────────────────────────────────────────────────

    def _poll(self):
        """Fetch all query log entries newer than the stored cursor and insert them.

        Pagination strategy: fetch pages newest-to-oldest using ``older_than``.
        Stop when a page is empty, the page's oldest entry is at/before the
        cursor, or there are no more pages.  A 100-page safety cap aborts the
        poll *without* advancing the cursor so no data is silently skipped.

        Config is snapshot into locals at the start so a concurrent
        ``reload_config()`` (SIGUSR2) cannot mix data from two different hosts.
        Timestamps are parsed to ``datetime`` objects for reliable comparison
        across RFC3339Nano format variations.
        """
        # ── Snapshot config to avoid race with reload_config() ────────────────
        poll_host    = self._host
        poll_headers = self._auth_header()
        cursor_str   = get_config(self._db, 'adguard_cursor', None)
        cursor_dt    = _parse_ts(cursor_str)

        all_entries: list[dict] = []
        older_than:  str | None = None
        pages        = 0
        _MAX_PAGES   = 100   # safety cap — aborts without advancing cursor

        while True:
            # Abort if host changed mid-poll (SIGUSR2 fired during pagination)
            if self._host != poll_host:
                logger.warning("AdGuard: host changed mid-poll — discarding batch")
                return

            pages += 1
            params: dict = {'limit': _POLL_BATCH, 'response_status': 'all'}
            if older_than:
                params['older_than'] = older_than

            try:
                r = requests.get(
                    f"{poll_host}/control/querylog",
                    headers=poll_headers,
                    params=params,
                    timeout=15,
                )
                r.raise_for_status()
            except requests.HTTPError as e:
                logger.error("AdGuard poll HTTP %s: %s",
                             e.response.status_code if e.response is not None else '?', e)
                return
            except requests.RequestException as e:
                logger.error("AdGuard poll connection error: %s", e)
                return

            data = r.json()
            page             = data.get('data') or []
            oldest_on_page   = data.get('oldest') or ''
            oldest_on_page_dt = _parse_ts(oldest_on_page)

            if not page:
                break

            all_entries.extend(page)

            # Stop when we've walked back to/past the cursor.
            if cursor_dt and oldest_on_page_dt and oldest_on_page_dt <= cursor_dt:
                break

            # No further pages available.
            if not oldest_on_page or len(page) < _POLL_BATCH:
                break

            # Safety cap: abort without touching cursor to prevent data loss.
            if pages >= _MAX_PAGES:
                logger.warning(
                    "AdGuard: poll reached %d-page safety cap without crossing cursor"
                    " — aborting this cycle; cursor unchanged", _MAX_PAGES,
                )
                return

            older_than = oldest_on_page

        if not all_entries:
            return

        # Keep only entries strictly newer than the stored cursor.
        if cursor_dt:
            all_entries = [
                e for e in all_entries
                if (_parse_ts(e.get('time') or '') or datetime.min.replace(tzinfo=cursor_dt.tzinfo)) > cursor_dt
            ]

        if not all_entries:
            return

        self._refresh_clients()
        batch = [_parse_entry(e, self._clients) for e in all_entries]

        # Advance cursor to the newest timestamp seen.
        valid_times = [_parse_ts(e.get('time') or '') for e in all_entries]
        new_cursor_dt = max(t for t in valid_times if t is not None)
        new_cursor = new_cursor_dt.isoformat()

        # Insert rows and advance the cursor atomically.
        inserted = self._db.insert_adguard_batch(batch, new_cursor=new_cursor)

        logger.debug("AdGuard: polled %d new entries, inserted %d, cursor=%s",
                     len(all_entries), inserted, new_cursor[:30])

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def run(self):
        """Main loop — runs in a daemon thread."""
        logger.info("AdGuard poller started (host=%s, interval=%ds)", self._host, self._interval)
        while not self._stop.is_set():
            if self._enabled and self._host:
                try:
                    self._poll()
                except Exception:
                    logger.exception("AdGuard poll unhandled error")
            self._stop.wait(self._interval)
        logger.info("AdGuard poller stopped")

    def start(self):
        """Start the poller in a background daemon thread."""
        self._thread = threading.Thread(
            target=self.run, daemon=True, name="adguard-poller"
        )
        self._thread.start()

    def stop(self):
        """Signal the polling loop to exit."""
        self._stop.set()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_ts(ts: str) -> datetime | None:
    """Parse an RFC3339/RFC3339Nano timestamp string to a timezone-aware datetime.

    AdGuard Home emits nanosecond-precision timestamps (e.g.
    ``2026-04-13T18:10:52.123456789+02:00``) which Python's
    ``fromisoformat`` cannot handle past microseconds.  Sub-microsecond
    digits are truncated before parsing.
    """
    if not ts:
        return None
    # Truncate sub-microsecond precision to 6 fractional digits.
    ts_norm = re.sub(r'(\.\d{6})\d+', r'\1', ts)
    try:
        return datetime.fromisoformat(ts_norm)
    except ValueError:
        return None

def _parse_entry(e: dict, clients: dict[str, str]) -> dict:
    """Map a raw AGH QueryLogItem dict to a flat dict for DB insert."""
    client_ip = e.get('client', '')
    q = e.get('question') or {}
    rules = e.get('rules') or []
    client_info = e.get('client_info') or {}
    return {
        'timestamp':      e.get('time'),
        'client_ip':      client_ip or None,
        'client_name':    clients.get(client_ip) or client_info.get('name') or None,
        'domain':         q.get('name', ''),
        'record_type':    q.get('type', ''),
        'reason':         e.get('reason', ''),
        'dns_status':     e.get('status', ''),
        'upstream':       e.get('upstream', '') or None,
        'elapsed_ms':     _safe_float(e.get('elapsedMs')),
        'cached':         bool(e.get('cached', False)),
        'answer_dnssec':  bool(e.get('answer_dnssec', False)),
        'rule_text':      rules[0].get('text') if rules else None,
        'filter_list_id': rules[0].get('filter_list_id') if rules else None,
    }


def _safe_float(v) -> float | None:
    """Convert a value to float, returning None on failure or None input."""
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def test_connection(host: str, username: str, password: str) -> dict:
    """Test connectivity to an AdGuard Home instance.

    Returns dict with 'version' and 'running' keys on success.
    Raises requests.RequestException or HTTPError on failure.
    """
    host = (host or '').rstrip('/')
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    headers = {'Authorization': f'Basic {token}'}
    r = requests.get(f"{host}/control/status", headers=headers, timeout=8)
    r.raise_for_status()
    data = r.json()
    return {'version': data.get('version', ''), 'running': bool(data.get('running', False))}
