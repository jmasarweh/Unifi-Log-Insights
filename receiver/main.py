"""
UniFi Log Insight - Syslog Receiver

UDP syslog listener that receives logs from UDR, parses them,
and stores them in PostgreSQL.

Phase 1: Receive → Parse → Store
Phase 2 will add: IP enrichment (GeoIP, AbuseIPDB, rDNS)
"""

import os
import sys
import time
import socket
import signal
import logging
import threading
from collections import deque

import schedule

from parsers import parse_log
import parsers
from db import Database, get_config, set_config, build_conn_params, is_external_db, wait_for_postgres
from enrichment import Enricher
from backfill import BackfillTask
from blacklist import BlacklistFetcher
from unifi_api import UniFiAPI
from pihole_api import PiHolePoller
from routes.auth import auth_cleanup

# Set by the SIGUSR2 handler when retention_time may have changed.
# Consumed by the scheduler loop (single-writer, single-reader — safe).
# All `schedule` registry mutation stays on the scheduler thread.
_retention_reload_requested = threading.Event()

# ── Configuration ──────────────────────────────────────────────────────────────

SYSLOG_PORT = 514
SYSLOG_BUFFER_SIZE = 8192      # Max UDP packet size
BATCH_SIZE = 50                 # Insert logs in batches
BATCH_TIMEOUT = 2.0             # Flush batch after N seconds even if not full
STATS_INTERVAL_MINUTES = 15     # Log stats every N minutes

# ── Logging ────────────────────────────────────────────────────────────────────

_log_level_name = os.environ.get('LOG_LEVEL', 'INFO').upper()
if _log_level_name not in ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'):
    _log_level_name = 'INFO'

logging.basicConfig(
    level=getattr(logging, _log_level_name),
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout,
)
logger = logging.getLogger('receiver')


# ── Syslog Receiver ───────────────────────────────────────────────────────────

class SyslogReceiver:
    """UDP syslog receiver with batched database writes."""

    HEARTBEAT_INTERVAL = 60  # Log heartbeat every 60 seconds

    def __init__(self, db: Database, enricher: Enricher):
        """Create the receiver — does not open the socket until start() is called."""
        self.db = db
        self.enricher = enricher
        self.sock = None
        self.running = False
        self.batch: list[dict] = []
        self.batch_lock = threading.Lock()
        self.last_flush = time.time()
        self.last_heartbeat = time.time()
        self.last_receive_time = 0.0  # Track when we last received any packet
        self.consecutive_flush_errors = 0
        self.stats = {
            'received': 0,
            'parsed': 0,
            'filtered': 0,
            'failed': 0,
            'inserted': 0,
            'flush_errors': 0,
            'dropped': 0,
        }
        self._load_disabled_types()

    def _load_disabled_types(self):
        """Load set of log types that should be silently discarded."""
        disabled = set()
        if not get_config(self.db, 'wifi_processing_enabled', True):
            disabled.add('wifi')
        if not get_config(self.db, 'system_processing_enabled', True):
            disabled.add('system')
        self._disabled_log_types = disabled
        if disabled:
            logger.info("Log type filtering active: discarding %s", disabled)

    def start(self):
        """Start the UDP listener."""
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)  # dual-stack: accept IPv4 + IPv6
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Set receive buffer to 1MB to handle bursts
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
        actual_rcvbuf = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        logger.info("UDP socket SO_RCVBUF: requested=1048576, actual=%d", actual_rcvbuf)

        self.sock.bind(('::', SYSLOG_PORT))
        self.sock.settimeout(1.0)  # Allow periodic batch flushing
        self.running = True

        logger.info("Syslog receiver listening on UDP port %d", SYSLOG_PORT)

        while self.running:
            try:
                data, addr = self.sock.recvfrom(SYSLOG_BUFFER_SIZE)
                self.last_receive_time = time.time()
                self._handle_message(data, addr)
            except socket.timeout:
                pass
            except OSError as e:
                if self.running:
                    logger.error("Socket error (will retry): %s", e)
                    time.sleep(0.1)  # Brief pause to avoid tight error loop
            finally:
                # Check if batch needs flushing by timeout
                self._maybe_flush_batch()
                self._maybe_log_heartbeat()

    def stop(self):
        """Stop the receiver and flush remaining logs."""
        logger.info("Stopping syslog receiver...")
        self.running = False
        self._flush_batch()
        if self.sock:
            self.sock.close()
        logger.info("Syslog receiver stopped. Stats: %s", self.stats)

    def _handle_message(self, data: bytes, addr: tuple):
        """Process a single syslog message."""
        self.stats['received'] += 1

        try:
            raw_log = data.decode('utf-8', errors='replace').strip()
        except Exception as e:
            logger.warning("Failed to decode message from %s: %s", addr, e)
            self.stats['failed'] += 1
            return

        if not raw_log:
            return

        parsed = parse_log(raw_log)
        if parsed is None:
            self.stats['failed'] += 1
            logger.debug("Unparseable log from %s: %.100s...", addr, raw_log)
            return

        self.stats['parsed'] += 1

        # Filter disabled log types before enrichment
        log_type = parsed.get('log_type')
        if log_type in self._disabled_log_types:
            self.stats['filtered'] += 1
            return

        # Enrich with GeoIP, ASN, AbuseIPDB, rDNS
        parsed = self.enricher.enrich(parsed)

        with self.batch_lock:
            self.batch.append(parsed)
            if len(self.batch) >= BATCH_SIZE:
                self._flush_batch()

    def _maybe_flush_batch(self):
        """Flush batch if timeout elapsed."""
        if time.time() - self.last_flush >= BATCH_TIMEOUT:
            with self.batch_lock:
                if self.batch:
                    self._flush_batch()

    def _flush_batch(self):
        """Write current batch to database."""
        if not self.batch:
            self.last_flush = time.time()
            return

        to_insert = self.batch[:]
        self.batch = []
        self.last_flush = time.time()
        batch_len = len(to_insert)

        flush_start = time.time()
        try:
            self.db.insert_logs_batch(to_insert)
            flush_elapsed = time.time() - flush_start
            self.stats['inserted'] += batch_len
            if self.consecutive_flush_errors > 0:
                logger.info("DB insert recovered after %d consecutive failures", self.consecutive_flush_errors)
            self.consecutive_flush_errors = 0
            if flush_elapsed > 1.0:
                logger.warning("Slow DB flush: %d logs took %.2fs (>1s blocks UDP receive)", batch_len, flush_elapsed)
            else:
                logger.debug("Flushed %d logs in %.3fs", batch_len, flush_elapsed)
        except Exception as e:
            flush_elapsed = time.time() - flush_start
            self.stats['flush_errors'] += 1
            self.stats['dropped'] += batch_len
            self.consecutive_flush_errors += 1
            logger.error("DB insert failed (%d logs lost, %.2fs, consecutive=%d): %s",
                         batch_len, flush_elapsed, self.consecutive_flush_errors, e)
            if self.consecutive_flush_errors >= 5:
                logger.critical("DB insert failing repeatedly (%d consecutive). "
                                "UDP packets are likely being dropped. Check DB connectivity.",
                                self.consecutive_flush_errors)

    def _maybe_log_heartbeat(self):
        """Periodic heartbeat log to confirm the receiver is alive."""
        now = time.time()
        if now - self.last_heartbeat < self.HEARTBEAT_INTERVAL:
            return
        self.last_heartbeat = now

        silence = now - self.last_receive_time if self.last_receive_time else 0
        logger.debug("Heartbeat — received=%d parsed=%d filtered=%d inserted=%d dropped=%d flush_errors=%d silence=%.0fs",
                     self.stats['received'], self.stats['parsed'], self.stats['filtered'],
                     self.stats['inserted'], self.stats['dropped'], self.stats['flush_errors'], silence)

        # Warn if no packets received for a long time (gateway may have stopped sending)
        if self.last_receive_time and silence > 30:
            logger.warning("No UDP packets received for %.0fs — gateway may have stopped sending or port is unreachable", silence)


# ── Network identity gate ────────────────────────────────────────────────────

def _use_log_identity_detection(db: Database) -> bool:
    """Return True when log-based WAN/gateway detection should run."""
    return not bool(db.get_config('unifi_enabled', False))


def _refresh_network_identity_from_logs(db: Database):
    """Run log-based WAN/gateway detection only when UniFi is not authoritative."""
    if not _use_log_identity_detection(db):
        return
    try:
        db.detect_wan_ip()
    except Exception as e:
        logger.error("WAN IP detection failed: %s", e)
    try:
        db.detect_gateway_ips()
    except Exception as e:
        logger.error("Gateway IP detection failed: %s", e)


# ── Scheduler ─────────────────────────────────────────────────────────────────

def _retention_cleanup(db: Database):
    """Run a full retention cleanup pass. Called by the schedule library."""
    try:
        cfg = Database.resolve_retention_days(db)
        logger.info("Retention cleanup starting (general_retention=%d days, dns_retention=%d days)",
                    cfg.general, cfg.dns)
        result = db.run_retention_cleanup(cfg.general, cfg.dns)
        if result['status'] == 'partial':
            logger.warning("Retention cleanup partial: %d deleted, error: %s",
                           result['deleted_so_far'], result['error'])
        elif result['status'] == 'failed':
            logger.error("Retention cleanup failed: %s", result['error'])
    except Exception as e:
        logger.error("Retention cleanup failed: %s", e)


def _register_retention_job(db: Database):
    """(Re-)register the daily retention cleanup with the saved time.

    MUST only be called on the scheduler thread — mutates the `schedule`
    module's job registry, which is not thread-safe.

    Tagged 'retention' so we can clear and re-register without touching the
    other scheduled jobs (stats, blacklist, auth cleanup, wan refresh).
    """
    schedule.clear('retention')
    cfg = Database.resolve_retention_time(db)
    (schedule.every()
             .day
             .at(cfg.time)   # 'HH:MM' — schedule library's native format
             .do(_retention_cleanup, db=db)
             .tag('retention'))
    logger.info("Retention cleanup scheduled daily at %s (source=%s, container-local time)",
                cfg.time, cfg.source)


def _scheduler_tick(db: Database):
    """One iteration of the scheduler loop — extracted so tests can run it
    deterministically. Observes the retention-reload Event (set by the signal
    handler on another thread) and rebuilds the job before dispatching pending
    runs. All `schedule` registry mutation therefore stays on this thread.
    """
    if _retention_reload_requested.is_set():
        _retention_reload_requested.clear()
        _register_retention_job(db)
    schedule.run_pending()


def run_scheduler(db: Database, enricher: Enricher, blacklist_fetcher: BlacklistFetcher = None):
    """Background thread for scheduled tasks (retention cleanup, stats, blacklist)."""

    def log_stats():
        """Log current DB and enrichment statistics at DEBUG level."""
        try:
            db_stats = db.get_stats()
            enrich_stats = enricher.get_stats()
            logger.debug("DB stats — total: %s, last hour: %s", db_stats['total'], db_stats['last_hour'])
            logger.debug("Enrichment stats — %s", enrich_stats)
        except Exception as e:
            logger.error("Failed to get stats: %s", e)

    def pull_blacklist():
        """Fetch the latest IP blacklist and store it in the database."""
        if blacklist_fetcher:
            try:
                blacklist_fetcher.fetch_and_store()
            except Exception as e:
                logger.error("Blacklist pull failed: %s", e)

    def refresh_wan_ip():
        """Refresh WAN/gateway identity from recent log data (no-op when UniFi is active)."""
        _refresh_network_identity_from_logs(db)

    schedule.every(STATS_INTERVAL_MINUTES).minutes.do(log_stats)
    schedule.every(STATS_INTERVAL_MINUTES).minutes.do(refresh_wan_ip)
    _register_retention_job(db)
    schedule.every().day.at("04:00").do(pull_blacklist)
    # auth_cleanup has its own internal try/except — no wrapper needed here.
    schedule.every().day.at("03:30").do(auth_cleanup)

    logger.info("Scheduler started — stats every %dm, blacklist daily at 04:00, auth cleanup daily at 03:30",
                 STATS_INTERVAL_MINUTES)

    # Initial blacklist pull after 30s startup delay
    time.sleep(30)
    pull_blacklist()

    while True:
        _scheduler_tick(db)
        time.sleep(10)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    """Entrypoint: initialise the database, enricher, and syslog receiver."""
    # Build connection params from environment
    conn_params = build_conn_params()
    logger.info("Database: %s mode (host=%s:%s, db=%s)",
                "external" if is_external_db() else "embedded",
                conn_params['host'], conn_params['port'], conn_params['dbname'])

    # Wait for PostgreSQL
    wait_for_postgres(conn_params)

    # Initialize database
    db = Database(conn_params)
    db.connect()

    # Create performance indexes that require CONCURRENTLY (existing installs)
    db.ensure_post_boot_indexes()

    # Load system configuration and apply to parsers module
    # Check for existing user migration
    setup_complete = get_config(db, "setup_complete", None)
    if setup_complete is None:
        # Count firewall logs to detect existing installation
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM logs WHERE log_type = 'firewall'")
                log_count = cur.fetchone()[0]

        if log_count > 0:
            # Auto-migrate existing installation with safe defaults
            logger.info("Migrating existing installation to dynamic config...")
            set_config(db, "wan_interfaces", ["ppp0"])
            set_config(db, "interface_labels", {})  # Empty = use raw names
            set_config(db, "setup_complete", True)
            set_config(db, "config_version", 1)
            logger.info(
                "Migration complete with safe defaults (WAN=ppp0, labels=raw names). "
                "Users can customize via Settings → Reconfigure."
            )

    # Load config into parsers module
    parsers.reload_config_from_db(db)
    logger.info("Loaded config: WAN interfaces = %s", parsers.WAN_INTERFACES)

    # Detect and persist WAN IP + gateway IPs from existing log data
    # (skipped when UniFi API is authoritative — identity comes from poll)
    _refresh_network_identity_from_logs(db)

    # Check config version for future migrations
    current_version = get_config(db, 'config_version', 0)
    if current_version < 1:
        # Future: handle config schema migrations
        pass

    # Initialize UniFi API client (self-disables when not configured)
    unifi_api = UniFiAPI(db=db)

    # Initialize Pi-hole poller
    pihole = PiHolePoller(db=db, enricher=None)  # enricher set after creation

    # Initialize enrichment (with UniFi device name resolution)
    enricher = Enricher(db=db, unifi=unifi_api)

    # Wire enricher into Pi-hole poller (created before enricher for signal handler)
    pihole.set_enricher(enricher)

    # Start receiver
    receiver = SyslogReceiver(db, enricher)

    # Handle graceful shutdown
    def shutdown(signum, frame):
        """Handle SIGTERM/SIGINT: flush pending logs and exit cleanly."""
        logger.info("Received signal %d, shutting down...", signum)
        receiver.stop()
        unifi_api.stop_polling()
        pihole.stop_polling()
        enricher.close()
        db.close()
        sys.exit(0)

    # Handle GeoIP database reload
    def reload_geoip(signum, frame):
        """Handle SIGUSR1: hot-reload GeoIP databases without restarting."""
        logger.info("Received SIGUSR1, reloading GeoIP databases...")
        enricher.reload_geoip()

    # Handle config reload
    def reload_config(signum, frame):
        """Reload config from database when signaled by API process."""
        logger.info("Received SIGUSR2, reloading config from database...")
        parsers.reload_config_from_db(db)
        unifi_api.reload_config()
        pihole.reload_config()
        enricher.reload_config()
        receiver._load_disabled_types()
        # scheduler thread will rebuild the retention job on its next tick
        _retention_reload_requested.set()

        # Write timestamp to confirm reload completed
        try:
            from pathlib import Path
            Path('/tmp/config_reloaded').write_text(str(time.time()))
        except Exception as e:
            logger.debug("Failed to write reload timestamp: %s", e)

        logger.info("Config reloaded: WAN=%s", parsers.WAN_INTERFACES)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGUSR1, reload_geoip)
    signal.signal(signal.SIGUSR2, reload_config)

    # Start scheduler in background thread
    blacklist_fetcher = BlacklistFetcher(db)
    scheduler_thread = threading.Thread(target=run_scheduler, args=(db, enricher, blacklist_fetcher), daemon=True)
    scheduler_thread.start()

    # Start backfill daemon (queue-driven threat enrichment every 5 min)
    backfill = BackfillTask(db, enricher)
    backfill.start()

    # Start UniFi client/device polling (only runs if enabled)
    unifi_api.start_polling()

    # Start Pi-hole polling (only runs if enabled)
    pihole.start_polling()

    # Start receiving (blocks)
    try:
        receiver.start()
    except KeyboardInterrupt:
        receiver.stop()
        unifi_api.stop_polling()
        pihole.stop_polling()
        enricher.close()
        db.close()


if __name__ == '__main__':
    main()
