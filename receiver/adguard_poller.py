"""
AdGuard Home v0.107+ query log poller.

Architecture
------------
``AdGuardHomePoller`` runs as a single daemon thread started by ``main.py``
alongside the Pi-hole and UniFi pollers.  On each cycle it:

1. Snapshots the current config (host, credentials, cursor) into locals so a
   concurrent ``reload_config()`` call triggered by SIGUSR2 cannot corrupt an
   in-flight poll.
2. Pages through ``GET /control/querylog`` newest-to-oldest, accumulating
   entries until it crosses the stored cursor timestamp or exhausts all pages.
3. Filters to entries strictly newer than the cursor, resolves client names
   from the ``/control/clients`` cache, then inserts the batch and atomically
   advances the cursor in the same DB transaction.

Cursor semantics
----------------
The cursor stores the ISO-8601 timestamp of the *newest* entry seen so far.
On each poll, pages are fetched without ``older_than`` (newest first) and
walked backwards using the ``oldest`` field returned per page.  This ensures
new queries are never missed: the cursor only moves forward.

Thread safety
-------------
``reload_config()`` is called from the main thread's SIGUSR2 handler while
``_poll()`` runs in the poller thread.  All mutable state accessed by both
paths is guarded by snapshotting into poll-local variables at the top of
``_poll()`` and by detecting host changes mid-pagination.
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

_POLL_BATCH      = 500    # max entries requested per /control/querylog call
_CLIENT_CACHE_TTL = 300   # seconds between /control/clients refreshes
_MAX_POLL_PAGES  = 100    # safety cap: abort without advancing cursor if hit


class AdGuardHomePoller:
    """Background thread that continuously polls AdGuard Home query logs.

    Instantiated once in ``main.py``.  Call ``start()`` to launch the thread,
    ``stop()`` to signal it to exit, and ``reload_config()`` to pick up
    settings changes without a restart.
    """

    def __init__(self, db: Database):
        """Initialise the poller.

        Config is read from ``system_config`` via ``reload_config()`` so no
        constructor arguments are needed beyond the DB handle.
        """
        self._db = db
        self._stop = threading.Event()
        self._thread = None
        # IP → display name cache populated by /control/clients
        self._clients: dict[str, str] = {}
        self._clients_refreshed = 0.0   # epoch seconds of last successful refresh
        self.reload_config()

    # ── Config ────────────────────────────────────────────────────────────────

    def reload_config(self):
        """Re-read all AdGuard settings from ``system_config``.

        Safe to call from a signal handler (SIGUSR2) while the poller thread
        is running.  When the host URL changes the client name cache is
        invalidated immediately so the next poll fetches names from the new
        instance instead of carrying over stale mappings.
        """
        new_host = (get_config(self._db, 'adguard_host', '') or '').rstrip('/')

        if new_host != getattr(self, '_host', ''):
            # Host changed — clear cache so _refresh_clients hits the new instance.
            self._clients = {}
            self._clients_refreshed = 0.0

        self._enabled  = bool(get_config(self._db, 'adguard_enabled', False))
        self._host     = new_host
        self._username = get_config(self._db, 'adguard_username', 'admin') or 'admin'
        enc            = get_config(self._db, 'adguard_password_enc', '') or ''
        self._password = decrypt_api_key(enc) if enc else ''
        # Clamp to [15, 86400] to mirror the API-level validation in routes/adguard.py.
        self._interval = max(15, min(86400, int(
            get_config(self._db, 'adguard_poll_interval', 30) or 30
        )))

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _auth_header(self) -> dict:
        """Return an HTTP Basic Auth header dict for the current credentials."""
        token = base64.b64encode(
            f"{self._username}:{self._password}".encode()
        ).decode()
        return {'Authorization': f'Basic {token}'}

    # ── Client name cache ─────────────────────────────────────────────────────

    def _refresh_clients(self, poll_host: str, poll_headers: dict):
        """Refresh the IP→name client cache from ``GET /control/clients``.

        The cache is TTL-gated (``_CLIENT_CACHE_TTL`` seconds) to avoid
        hammering the AdGuard API on every poll cycle.

        ``poll_host`` and ``poll_headers`` must be the snapshot values
        captured at the start of ``_poll()`` — **not** ``self._host`` — so
        that client names are always fetched from the same instance that
        provided the query log entries.  This prevents a concurrent
        ``reload_config()`` from causing client name mismatches.

        Priority: configured clients (``clients``) override auto-detected ones
        (``auto_clients``) because auto-detected names are less reliable.
        """
        if time.time() - self._clients_refreshed < _CLIENT_CACHE_TTL:
            return  # cache is still fresh

        try:
            r = requests.get(
                f"{poll_host}/control/clients",
                headers=poll_headers,
                timeout=10,
            )
            r.raise_for_status()
            data = r.json()
            cache: dict[str, str] = {}

            # Auto-detected clients — lower priority, populated first so they
            # can be overridden by configured entries below.
            for c in data.get('auto_clients', []):
                if c.get('name') and c.get('ip'):
                    cache[c['ip']] = c['name']

            # Configured clients — higher priority, one entry can have multiple
            # IDs (IPs, MACs, CIDRs) all mapped to the same display name.
            for c in data.get('clients', []):
                name = c.get('name', '')
                for cid in c.get('ids', []):
                    if name:
                        cache[cid] = name

            self._clients = cache
            self._clients_refreshed = time.time()
            logger.debug("AdGuard client cache refreshed: %d entries", len(cache))

        except (requests.RequestException, KeyError, ValueError) as e:
            # Non-fatal: log and continue with the existing cache.
            logger.warning("AdGuard: client cache refresh failed: %s", e)

    # ── Poll ──────────────────────────────────────────────────────────────────

    def _poll(self):
        """Fetch all query log entries newer than the stored cursor and insert them.

        Pagination
        ----------
        AdGuard's ``/control/querylog`` returns entries newest-first.  Each
        response includes an ``oldest`` field — the timestamp of the last
        (oldest) entry on that page — which we pass as ``older_than`` in the
        next request to walk backwards through history.  We stop when:

        * The API returns an empty page (no more data).
        * The page's oldest entry is at or before the cursor (we have caught up).
        * The page is shorter than ``_POLL_BATCH`` (last page in the log).
        * ``_MAX_POLL_PAGES`` is reached — safety cap to prevent infinite loops
          on very large backlogs; the cursor is **not** advanced so the next
          cycle retries from the same position without losing data.

        Concurrency safety
        ------------------
        Config is snapshotted into locals (``poll_host``, ``poll_headers``,
        ``cursor_str``/``cursor_dt``) before the loop starts.  If
        ``reload_config()`` fires mid-pagination and changes ``self._host``,
        the host-change check inside the loop detects the mismatch and aborts
        without writing anything to the DB.

        Timestamp handling
        ------------------
        All cursor and entry timestamp comparisons use timezone-aware
        ``datetime`` objects (via ``_parse_ts``) rather than raw strings to
        avoid subtle ordering bugs with RFC3339Nano format variations (e.g.
        differing fractional-second precision or ``+HH:MM`` vs ``Z`` suffixes).
        """
        # ── Snapshot config — isolates this poll from concurrent reload_config() calls
        poll_host    = self._host
        poll_headers = self._auth_header()
        cursor_str   = get_config(self._db, 'adguard_cursor', None)
        cursor_dt    = _parse_ts(cursor_str)

        all_entries: list[dict] = []
        older_than: str | None  = None   # walks backward through pages
        pages = 0

        while True:
            # ── Mid-poll host-change guard ─────────────────────────────────────
            # reload_config() may be called from a SIGUSR2 handler while we are
            # mid-pagination.  If the host changed, the entries collected so far
            # come from the old instance — discard them entirely.
            if self._host != poll_host:
                logger.warning(
                    "AdGuard: host changed mid-poll (%s → %s) — discarding batch",
                    poll_host, self._host,
                )
                return

            pages += 1
            params: dict = {'limit': _POLL_BATCH, 'response_status': 'all'}
            if older_than:
                # Walk backward: fetch entries older than the last page's oldest.
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
                logger.error(
                    "AdGuard poll HTTP %s: %s",
                    e.response.status_code if e.response is not None else '?', e,
                )
                return
            except requests.RequestException as e:
                logger.error("AdGuard poll connection error: %s", e)
                return

            data             = r.json()
            page             = data.get('data') or []
            oldest_on_page   = data.get('oldest') or ''
            oldest_on_page_dt = _parse_ts(oldest_on_page)

            if not page:
                # Empty page — no more entries available.
                break

            all_entries.extend(page)

            # Stop when we've walked back to or past the cursor.
            if cursor_dt and oldest_on_page_dt and oldest_on_page_dt <= cursor_dt:
                break

            # Last page: shorter than the batch size or no continuation cursor.
            if not oldest_on_page or len(page) < _POLL_BATCH:
                break

            # Safety cap — abort *without* advancing the cursor.
            # The next poll cycle will retry from the same position.
            if pages >= _MAX_POLL_PAGES:
                logger.warning(
                    "AdGuard: reached %d-page safety cap without crossing cursor "
                    "— aborting cycle; cursor unchanged (will retry next poll)",
                    _MAX_POLL_PAGES,
                )
                return

            older_than = oldest_on_page  # next page request

        if not all_entries:
            return

        # ── Deduplication: keep only entries strictly newer than the cursor ────
        # Entries equal to the cursor were already inserted in the previous cycle.
        if cursor_dt:
            all_entries = [
                e for e in all_entries
                if (
                    _parse_ts(e.get('time') or '')
                    or datetime.min.replace(tzinfo=cursor_dt.tzinfo)
                ) > cursor_dt
            ]

        if not all_entries:
            return  # nothing new since the last poll

        # ── Resolve client names then build the insert batch ──────────────────
        # Uses poll_host/poll_headers (not self._host) to avoid the same
        # reload_config() race for the /control/clients request.
        self._refresh_clients(poll_host, poll_headers)
        batch = [_parse_entry(e, self._clients) for e in all_entries]

        # ── Advance the cursor to the newest timestamp in this batch ──────────
        # If all entries have unparseable timestamps (shouldn't happen in
        # practice), fall back to the previous cursor to avoid regressing.
        valid_times = [
            t for t in (_parse_ts(e.get('time') or '') for e in all_entries)
            if t is not None
        ]
        new_cursor = max(valid_times).isoformat() if valid_times else cursor_str

        # ── Insert rows and advance cursor atomically ─────────────────────────
        # A crash between insert and cursor update would cause the next poll to
        # re-fetch (and attempt to re-insert) the same entries — acceptable
        # because the DB has no unique constraint on (timestamp, client_ip,
        # domain), so duplicates can occur only in this failure scenario.
        inserted = self._db.insert_adguard_batch(batch, new_cursor=new_cursor)

        logger.debug(
            "AdGuard: polled %d new entries, inserted %d, cursor=%s",
            len(all_entries), inserted, (new_cursor or '')[:30],
        )

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def run(self):
        """Main polling loop — runs in a daemon thread started by ``start()``.

        Sleeps for ``_interval`` seconds between cycles using a threading Event
        so that ``stop()`` can interrupt the sleep immediately rather than
        waiting for the full interval to elapse.
        """
        logger.info(
            "AdGuard poller started (host=%s, interval=%ds)",
            self._host, self._interval,
        )
        while not self._stop.is_set():
            if self._enabled and self._host:
                try:
                    self._poll()
                except Exception:
                    # Catch-all so a bug in _poll() never kills the thread.
                    logger.exception("AdGuard poll unhandled error")
            self._stop.wait(self._interval)
        logger.info("AdGuard poller stopped")

    def start(self):
        """Launch the poller in a background daemon thread."""
        self._thread = threading.Thread(
            target=self.run, daemon=True, name="adguard-poller",
        )
        self._thread.start()

    def stop(self):
        """Signal the run loop to exit at the end of the current sleep."""
        self._stop.set()


# ── Module-level helpers ──────────────────────────────────────────────────────

def _parse_ts(ts: str) -> datetime | None:
    """Parse an RFC3339/RFC3339Nano timestamp to a timezone-aware ``datetime``.

    AdGuard Home emits nanosecond-precision timestamps, e.g.::

        2026-04-13T18:10:52.123456789+02:00

    Python's ``datetime.fromisoformat()`` only handles up to microsecond
    precision, so we truncate any digits beyond the sixth decimal place before
    parsing.  Returns ``None`` for empty or unparseable strings rather than
    raising, so callers can safely filter or fall back.
    """
    if not ts:
        return None
    # Truncate sub-microsecond digits: keep at most 6 fractional-second digits.
    ts_norm = re.sub(r'(\.\d{6})\d+', r'\1', ts)
    try:
        return datetime.fromisoformat(ts_norm)
    except ValueError:
        return None


def _parse_entry(e: dict, clients: dict[str, str]) -> dict:
    """Map a raw AdGuard Home ``QueryLogItem`` to a flat dict for DB insert.

    Field mapping
    -------------
    ``e['client']``        → client_ip (INET)
    ``e['client_info']``   → client_name fallback when not in configured cache
    ``e['question']``      → domain + record_type (e.g. A, AAAA, CNAME)
    ``e['reason']``        → filter reason string (e.g. FilteredBlockList,
                             NotFilteredNotFound, Rewritten)
    ``e['status']``        → DNS response status (NOERROR, NXDOMAIN, …)
    ``e['upstream']``      → upstream resolver used (e.g. https://dns.cloudflare.com)
    ``e['elapsedMs']``     → query round-trip time in milliseconds (float string)
    ``e['cached']``        → True if the response was served from cache
    ``e['answer_dnssec']`` → True if the answer was DNSSEC-validated
    ``e['rules'][0]``      → first matching filter rule text and list ID
    """
    client_ip   = e.get('client', '')
    q           = e.get('question') or {}
    rules       = e.get('rules') or []
    client_info = e.get('client_info') or {}
    return {
        'timestamp':      e.get('time'),
        'client_ip':      client_ip or None,
        # Prefer the configured-client name; fall back to AdGuard's auto-resolved name.
        'client_name':    clients.get(client_ip) or client_info.get('name') or None,
        'domain':         q.get('name', ''),
        'record_type':    q.get('type', ''),
        'reason':         e.get('reason', ''),
        'dns_status':     e.get('status', ''),
        'upstream':       e.get('upstream', '') or None,
        'elapsed_ms':     _safe_float(e.get('elapsedMs')),
        'cached':         bool(e.get('cached', False)),
        'answer_dnssec':  bool(e.get('answer_dnssec', False)),
        'rule_text':      rules[0].get('text')          if rules else None,
        'filter_list_id': rules[0].get('filter_list_id') if rules else None,
    }


def _safe_float(v) -> float | None:
    """Convert ``v`` to ``float``, returning ``None`` on failure or ``None`` input."""
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def test_connection(host: str, username: str, password: str) -> dict:
    """Test connectivity and credentials against an AdGuard Home instance.

    Calls ``GET /control/status`` with HTTP Basic Auth.  Returns a dict with
    ``version`` (str) and ``running`` (bool) on success.  Raises
    ``requests.HTTPError`` on a non-2xx response (e.g. 401 for bad credentials)
    or ``requests.RequestException`` on network/timeout errors — callers should
    catch these and surface a user-friendly message.
    """
    host  = (host or '').rstrip('/')
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    r = requests.get(
        f"{host}/control/status",
        headers={'Authorization': f'Basic {token}'},
        timeout=8,
    )
    r.raise_for_status()
    data = r.json()
    return {
        'version': data.get('version', ''),
        'running': bool(data.get('running', False)),
    }
