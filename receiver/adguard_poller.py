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
import ipaddress
import logging
import re
import threading
import time
from datetime import datetime

import requests

from db import AdGuardHostMismatch, Database, decrypt_api_key, get_config

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
        # Structured client cache populated by /control/clients
        self._clients: '_ClientCache' = _ClientCache()
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
            # Host changed -- clear cache so _refresh_clients hits the new instance.
            self._clients = _ClientCache()
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

    def _refresh_clients(self, poll_host: str, poll_headers: dict) -> '_ClientCache | None':
        """Fetch a fresh client cache from ``GET /control/clients``.

        Returns a ``_ClientCache`` when the TTL has expired and the fetch
        succeeds, or ``None`` when the existing cache is still warm or the
        fetch fails.  The caller is responsible for publishing the returned
        cache to ``self._clients`` / ``self._clients_refreshed`` -- this method
        intentionally does **not** mutate shared state, so a discarded batch
        cannot poison the cache with stale data from the old host.

        ``poll_host`` and ``poll_headers`` must be the snapshot values
        captured at the start of ``_poll()`` -- **not** ``self._host`` -- so
        that client names are always fetched from the same instance that
        provided the query log entries.

        Priority: configured clients (``clients``) override auto-detected ones
        (``auto_clients``) because auto-detected names are less reliable.
        """
        if time.time() - self._clients_refreshed < _CLIENT_CACHE_TTL:
            return None  # cache is still fresh -- nothing to do

        try:
            r = requests.get(
                f"{poll_host}/control/clients",
                headers=poll_headers,
                timeout=10,
            )
            r.raise_for_status()
            data = r.json()

            exact:    dict[str, str]                         = {}  # IP string -> name
            networks: list[tuple[ipaddress.IPv4Network |
                                 ipaddress.IPv6Network, str]] = []  # (network, name)
            macs:     dict[str, str]                         = {}  # normalised MAC -> name

            # Auto-detected clients -- lower priority, exact IPs only.
            for c in data.get('auto_clients', []):
                if c.get('name') and c.get('ip'):
                    exact[c['ip']] = c['name']

            # Configured clients -- higher priority, IDs may be IPs, CIDRs, or MACs.
            for c in data.get('clients', []):
                name = c.get('name', '')
                if not name:
                    continue
                for cid in c.get('ids', []):
                    cid = cid.strip()
                    if '/' in cid:
                        # CIDR notation
                        try:
                            networks.append((ipaddress.ip_network(cid, strict=False), name))
                        except ValueError:
                            pass
                    elif (':' in cid or '-' in cid) and len(cid) == 17:
                        # MAC address: colon (aa:bb:cc:dd:ee:ff) or
                        # hyphen-delimited (aa-bb-cc-dd-ee-ff) — both exactly 17 chars.
                        macs[_norm_mac(cid)] = name
                    else:
                        # Plain IP
                        exact[cid] = name

            cache = _ClientCache(exact=exact, networks=networks, macs=macs)
            logger.debug(
                "AdGuard client cache refreshed: %d exact, %d networks, %d MACs",
                len(exact), len(networks), len(macs),
            )
            return cache

        except (requests.RequestException, KeyError, ValueError) as e:
            # Non-fatal: log and continue with the existing cache.
            logger.warning("AdGuard: client cache refresh failed: %s", e)
            return None

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
        ``cursor_str``/``cursor_dt``) before the loop starts.  Two guards
        protect against a concurrent ``reload_config()`` changing the host:

        1. **In-memory pre-poll check** — skips the cycle immediately if the
           DB host already differs from the snapshot (fast path).
        2. **In-loop check** — aborts without writing if ``self._host`` changes
           mid-pagination (detects SIGUSR2 reload during page fetches).
        3. **Transactional DB check** — ``insert_adguard_batch`` re-reads
           ``adguard_host`` *inside* the commit transaction; if it differs,
           ``AdGuardHostMismatch`` is raised and the transaction is rolled back,
           closing the TOCTOU window between the poll snapshot and the DB write.

        Timestamp handling
        ------------------
        ``_parse_ts`` returns ``(datetime, ns_int)`` tuples.  All ordering
        comparisons (pagination stop, dedup filter, cursor selection) use these
        tuples so entries differing only in sub-microsecond nanoseconds are
        ordered correctly.  The cursor is persisted as the original RFC3339Nano
        string to retain full precision across cycles.
        """
        # ── Snapshot config — isolates this poll from concurrent reload_config() calls
        # Read host, username, and password in one shot so reload_config() cannot
        # interleave and produce a mismatched (old host, new creds) combination.
        poll_host, poll_username, poll_password = (
            self._host, self._username, self._password
        )
        poll_headers = {
            'Authorization': 'Basic ' + base64.b64encode(
                f"{poll_username}:{poll_password}".encode()
            ).decode()
        }
        cursor_str   = get_config(self._db, 'adguard_cursor', None)
        cursor_dt    = _parse_ts(cursor_str)

        # ── DB host guard (pre-poll) ───────────────────────────────────────────
        # The DB is the authoritative source of config.  If the stored host
        # already differs from the snapshotted poll_host (e.g. a config change
        # landed between _host assignment above and the DB read), skip this
        # cycle entirely so we never mix entries from two different instances.
        db_host = (get_config(self._db, 'adguard_host', '') or '').strip().rstrip('/')
        if db_host != poll_host:
            logger.info(
                "AdGuard: DB host (%s) differs from snapshot (%s) — skipping cycle",
                db_host, poll_host,
            )
            return

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

            # Safety cap — commit what we have so far and stop paging.
            # Using `break` (not `return`) allows the already-accumulated entries
            # to be inserted and the cursor to advance, making forward progress
            # even when the backlog permanently exceeds MAX_POLL_PAGES * POLL_BATCH.
            if pages >= _MAX_POLL_PAGES:
                logger.warning(
                    "AdGuard: reached %d-page safety cap — committing partial batch "
                    "(%d entries so far) and advancing cursor; remaining entries will "
                    "be fetched on the next poll cycle",
                    _MAX_POLL_PAGES, len(all_entries),
                )
                break

            older_than = oldest_on_page  # next page request

        if not all_entries:
            return

        # ── Deduplication: keep only entries strictly newer than the cursor ────
        # Entries equal to the cursor were already inserted in the previous cycle.
        # Entries with unparseable timestamps fall back to datetime.min and are
        # filtered out; a debug log is emitted so they are visible during troubleshooting.
        if cursor_dt:
            pre_filter_count = len(all_entries)
            # _parse_ts returns (datetime, ns_int) tuples; the fallback sentinel
            # uses cursor_dt[0].tzinfo so the tuple comparison is timezone-aware.
            all_entries = [
                e for e in all_entries
                if (
                    _parse_ts(e.get('time') or '')
                    or (datetime.min.replace(tzinfo=cursor_dt[0].tzinfo), 0)
                ) > cursor_dt
            ]
            dropped = pre_filter_count - len(all_entries)
            if dropped > 0:
                logger.debug(
                    "AdGuard: filtered %d entries (at/before cursor or unparseable timestamp)",
                    dropped,
                )

        if not all_entries:
            return  # nothing new since the last poll

        # ── Resolve client names then build the insert batch ──────────────────
        # _refresh_clients returns a new _ClientCache (or None if still warm).
        # We hold it locally and only publish to self._clients after the insert
        # succeeds -- this prevents a discarded batch from marking the cache as
        # "fresh" with data fetched from the old host.
        new_clients = self._refresh_clients(poll_host, poll_headers)
        clients_to_use = new_clients if new_clients is not None else self._clients
        batch = [_parse_entry(e, clients_to_use) for e in all_entries]

        # ── Advance the cursor to the newest timestamp in this batch ──────────
        # We store the *original* RFC3339Nano string (not datetime.isoformat())
        # so nanosecond precision is preserved.  _parse_ts returns (datetime, ns_int)
        # tuples; max() on the tuple correctly orders entries that share the same
        # microsecond but differ in sub-microsecond nanoseconds.
        valid_pairs = [
            (t, raw)
            for e in all_entries
            if (raw := e.get('time') or '') and (t := _parse_ts(raw)) is not None
        ]
        new_cursor = max(valid_pairs, key=lambda p: p[0])[1] if valid_pairs else cursor_str

        # ── Insert rows, advance cursor, and verify host — all in one transaction
        # insert_adguard_batch re-reads adguard_host from the DB *inside* the
        # transaction before inserting, closing the TOCTOU window between the
        # poll snapshot and the DB write.  If the host changed, AdGuardHostMismatch
        # is raised, the transaction is rolled back, and we discard this batch.
        try:
            inserted = self._db.insert_adguard_batch(
                batch, new_cursor=new_cursor, expected_host=poll_host,
            )
        except AdGuardHostMismatch as e:
            logger.warning(
                "AdGuard: host changed before commit — discarding batch (%s)", e,
            )
            return

        # Host confirmed inside the transaction — safe to publish client cache.
        if new_clients is not None:
            self._clients = new_clients
            self._clients_refreshed = time.time()

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


def _norm_mac(mac: str) -> str:
    """Normalise a MAC address to lowercase hex without separators.

    Accepts common formats: ``aa:bb:cc:dd:ee:ff``, ``AA-BB-CC-DD-EE-FF``.
    Returns the 12-character lowercase hex string, e.g. ``aabbccddeeff``.
    """
    return re.sub(r'[:\-]', '', mac).lower()


class _ClientCache:
    """Resolved client name lookup supporting exact IPs, CIDRs, and MACs.

    AdGuard Home client IDs can be plain IPs, CIDR ranges, or MAC addresses.
    ``dict.get(client_ip)`` only handles exact IPs; this class adds CIDR
    and MAC resolution so configured names are matched correctly.
    """

    def __init__(
        self,
        exact:    dict[str, str] | None = None,
        networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] | None = None,
        macs:     dict[str, str] | None = None,
    ):
        """Store pre-parsed lookup tables for exact IPs, CIDR networks, and MAC addresses."""
        self._exact    = exact    or {}
        self._networks = networks or []
        self._macs     = macs     or {}

    def resolve(self, client_ip: str, client_mac: str = '') -> str | None:
        """Return the configured display name for *client_ip* or *client_mac*.

        Lookup order (highest to lowest priority):
        1. Exact IP match in configured clients.
        2. CIDR match in configured clients.
        3. Normalised MAC match in configured clients.
        4. Exact IP match in auto-detected clients (also stored in ``_exact``).
        Returns ``None`` when no match is found.
        """
        # Exact IP lookup (covers both configured and auto-detected IPs).
        if client_ip and client_ip in self._exact:
            return self._exact[client_ip]

        # CIDR lookup -- test client_ip against each configured network.
        if client_ip:
            try:
                addr = ipaddress.ip_address(client_ip)
                for net, name in self._networks:
                    if addr in net:
                        return name
            except ValueError:
                pass

        # MAC lookup.
        if client_mac:
            normed = _norm_mac(client_mac)
            if normed in self._macs:
                return self._macs[normed]

        return None


def _parse_ts(ts: str) -> tuple[datetime, int] | None:
    """Parse an RFC3339/RFC3339Nano timestamp to a ``(datetime, nanoseconds)`` pair.

    AdGuard Home emits nanosecond-precision timestamps, e.g.::

        2026-04-13T18:10:52.123456789+02:00

    Returns a ``(aware_datetime, ns_int)`` tuple where ``ns_int`` is the full
    fractional second expressed as nanoseconds (0-999 999 999).  Using the
    tuple for all ordering comparisons preserves sub-microsecond precision -
    two entries that share the same microsecond but differ only in later digits
    are correctly ordered by the ``ns_int`` component.

    Python's ``datetime.fromisoformat()`` only handles up to microsecond
    precision, so the fractional part is extracted separately for ``ns_int``
    and truncated to 6 digits before parsing.

    Returns ``None`` for empty or unparseable strings rather than raising, so
    callers can safely filter or fall back.
    """
    if not ts:
        return None
    # Extract fractional-second digits (may be absent, 1-9 digits).
    frac_match = re.search(r'\.(\d+)', ts)
    ns_int = 0
    if frac_match:
        frac_digits = frac_match.group(1)
        # Pad/truncate to exactly 9 digits for a nanosecond integer.
        ns_int = int(frac_digits[:9].ljust(9, '0'))
    # Truncate to 6 fractional digits for datetime parsing.
    ts_norm = re.sub(r'(\.\d{6})\d+', r'\1', ts)
    try:
        return (datetime.fromisoformat(ts_norm), ns_int)
    except ValueError:
        return None


def _parse_entry(e: dict, clients: '_ClientCache') -> dict:
    """Map a raw AdGuard Home ``QueryLogItem`` to a flat dict for DB insert.

    Field mapping
    -------------
    ``e['client']``        -> client_ip (INET)
    ``e['client_info']``   -> client_name fallback when not in configured cache
    ``e['question']``      -> domain + record_type (e.g. A, AAAA, CNAME)
    ``e['reason']``        -> filter reason string (e.g. FilteredBlockList,
                             NotFilteredNotFound, Rewritten)
    ``e['status']``        -> DNS response status (NOERROR, NXDOMAIN, ...)
    ``e['upstream']``      -> upstream resolver used (e.g. https://dns.cloudflare.com)
    ``e['elapsedMs']``     -> query round-trip time in milliseconds (float string)
    ``e['cached']``        -> True if the response was served from cache
    ``e['answer_dnssec']`` -> True if the answer was DNSSEC-validated
    ``e['rules'][0]``      -> first matching filter rule text and list ID
    """
    client_ip   = e.get('client', '')
    q           = e.get('question') or {}
    rules       = e.get('rules') or []
    client_info = e.get('client_info') or {}
    return {
        'timestamp':      e.get('time'),
        'client_ip':      client_ip or None,
        # Prefer the configured-client name (exact IP, CIDR, or MAC match);
        # fall back to AdGuard's auto-resolved name from client_info.
        # Note: the query log does not expose the client MAC — MAC resolution
        # only applies to IDs configured in AdGuard's client list.
        'client_name':    (
            clients.resolve(client_ip)
            or client_info.get('name')
            or None
        ),
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
