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

# ── Configuration ──────────────────────────────────────────────────────────────

SYSLOG_PORT = 514
SYSLOG_BUFFER_SIZE = 8192      # Max UDP packet size
BATCH_SIZE = 50                 # Insert logs in batches
BATCH_TIMEOUT = 2.0             # Flush batch after N seconds even if not full
STATS_INTERVAL_MINUTES = 15     # Log stats every N minutes
RETENTION_HOUR = "03:00"        # Run retention cleanup daily at this time

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

    def __init__(self, db: Database, enricher: Enricher):
        self.db = db
        self.enricher = enricher
        self.sock = None
        self.running = False
        self.batch: list[dict] = []
        self.batch_lock = threading.Lock()
        self.last_flush = time.time()
        self.stats = {
            'received': 0,
            'parsed': 0,
            'failed': 0,
            'inserted': 0,
        }

    def start(self):
        """Start the UDP listener."""
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)  # dual-stack: accept IPv4 + IPv6
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Set receive buffer to 1MB to handle bursts
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)

        self.sock.bind(('::', SYSLOG_PORT))
        self.sock.settimeout(1.0)  # Allow periodic batch flushing
        self.running = True

        logger.info("Syslog receiver listening on UDP port %d", SYSLOG_PORT)

        while self.running:
            try:
                data, addr = self.sock.recvfrom(SYSLOG_BUFFER_SIZE)
                self._handle_message(data, addr)
            except socket.timeout:
                pass
            except OSError as e:
                if self.running:
                    logger.error("Socket error: %s", e)
            finally:
                # Check if batch needs flushing by timeout
                self._maybe_flush_batch()

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

        try:
            self.db.insert_logs_batch(to_insert)
            self.stats['inserted'] += len(to_insert)
        except Exception as e:
            logger.error("Failed to insert batch of %d logs: %s", len(to_insert), e)
            self.stats['failed'] += len(to_insert)


# ── Scheduler ─────────────────────────────────────────────────────────────────

def run_scheduler(db: Database, enricher: Enricher, blacklist_fetcher: BlacklistFetcher = None):
    """Background thread for scheduled tasks (retention cleanup, stats, blacklist)."""

    def log_stats():
        try:
            db_stats = db.get_stats()
            enrich_stats = enricher.get_stats()
            logger.debug("DB stats — total: %s, last hour: %s", db_stats['total'], db_stats['last_hour'])
            logger.debug("Enrichment stats — %s", enrich_stats)
        except Exception as e:
            logger.error("Failed to get stats: %s", e)

    def retention_cleanup():
        try:
            # Resolution: system_config > env var > default
            general = get_config(db, 'retention_days')
            if general is None:
                general = int(os.environ.get('RETENTION_DAYS', '60'))
            else:
                general = int(general)
            dns = get_config(db, 'dns_retention_days')
            if dns is None:
                dns = int(os.environ.get('DNS_RETENTION_DAYS', '10'))
            else:
                dns = int(dns)
            db.run_retention_cleanup(general, dns)
        except Exception as e:
            logger.error("Retention cleanup failed: %s", e)

        # MCP audit retention (separate so log cleanup failures don't skip this, and vice versa)
        mcp_audit_days = 10
        try:
            mcp_audit_days = get_config(db, 'mcp_audit_retention_days', 10)
            try:
                mcp_audit_days = max(1, int(mcp_audit_days))
            except (ValueError, TypeError):
                mcp_audit_days = 10
            with db.get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM mcp_audit WHERE created_at < NOW() - (%s || ' days')::interval",
                        [mcp_audit_days]
                    )
                    if cur.rowcount > 0:
                        logger.info("MCP audit cleanup: deleted %d entries older than %d days", cur.rowcount, mcp_audit_days)
        except Exception as e:
            logger.error("MCP audit cleanup failed (retention=%s days): %s", mcp_audit_days, e)

    def pull_blacklist():
        if blacklist_fetcher:
            try:
                blacklist_fetcher.fetch_and_store()
            except Exception as e:
                logger.error("Blacklist pull failed: %s", e)

    def refresh_wan_ip():
        try:
            db.detect_wan_ip()
        except Exception as e:
            logger.error("WAN IP detection failed: %s", e)
        try:
            db.detect_gateway_ips()
        except Exception as e:
            logger.error("Gateway IP detection failed: %s", e)

    schedule.every(STATS_INTERVAL_MINUTES).minutes.do(log_stats)
    schedule.every(STATS_INTERVAL_MINUTES).minutes.do(refresh_wan_ip)
    schedule.every().day.at(RETENTION_HOUR).do(retention_cleanup)
    schedule.every().day.at("04:00").do(pull_blacklist)

    logger.info("Scheduler started — stats every %dm, retention daily at %s, blacklist daily at 04:00",
                 STATS_INTERVAL_MINUTES, RETENTION_HOUR)

    # Initial blacklist pull after 30s startup delay
    time.sleep(30)
    pull_blacklist()

    while True:
        schedule.run_pending()
        time.sleep(10)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
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
    try:
        db.detect_wan_ip()
    except Exception as e:
        logger.error("Startup WAN IP detection failed: %s", e)
    try:
        db.detect_gateway_ips()
    except Exception as e:
        logger.error("Startup gateway IP detection failed: %s", e)

    # Check config version for future migrations
    current_version = get_config(db, 'config_version', 0)
    if current_version < 1:
        # Future: handle config schema migrations
        pass

    # Initialize UniFi API client (self-disables when not configured)
    unifi_api = UniFiAPI(db=db)

    # Initialize enrichment (with UniFi device name resolution)
    enricher = Enricher(db=db, unifi=unifi_api)

    # Start receiver
    receiver = SyslogReceiver(db, enricher)

    # Handle graceful shutdown
    def shutdown(signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
        receiver.stop()
        unifi_api.stop_polling()
        enricher.close()
        db.close()
        sys.exit(0)

    # Handle GeoIP database reload
    def reload_geoip(signum, frame):
        logger.info("Received SIGUSR1, reloading GeoIP databases...")
        enricher.reload_geoip()

    # Handle config reload
    def reload_config(signum, frame):
        """Reload config from database when signaled by API process."""
        logger.info("Received SIGUSR2, reloading config from database...")
        parsers.reload_config_from_db(db)
        unifi_api.reload_config()

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

    # Start backfill daemon (patches NULL threat scores every 30 min)
    backfill = BackfillTask(db, enricher)
    backfill.start()

    # Start UniFi client/device polling (only runs if enabled)
    unifi_api.start_polling()

    # Start receiving (blocks)
    try:
        receiver.start()
    except KeyboardInterrupt:
        receiver.stop()
        unifi_api.stop_polling()
        enricher.close()
        db.close()


if __name__ == '__main__':
    main()
