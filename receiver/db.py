"""
UniFi Log Insight - Database Module

Handles PostgreSQL connection pooling, log insertion, and retention cleanup.
"""

import base64
import ipaddress
import os
import json
import logging
from contextlib import contextmanager

import psycopg2
import psycopg2.errors
from psycopg2 import pool, extras
from psycopg2.extras import Json

logger = logging.getLogger(__name__)


# ── API Key Encryption ────────────────────────────────────────────────────────

def _derive_fernet_key(postgres_password: str) -> bytes:
    """Derive a Fernet encryption key from POSTGRES_PASSWORD."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'unifi-log-insight-v1',
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(postgres_password.encode()))


def encrypt_api_key(api_key: str) -> str:
    """Encrypt API key for storage in system_config."""
    from cryptography.fernet import Fernet
    pg_pass = os.environ.get('POSTGRES_PASSWORD', '')
    if not pg_pass:
        raise ValueError("POSTGRES_PASSWORD required for encryption")
    f = Fernet(_derive_fernet_key(pg_pass))
    return f.encrypt(api_key.encode()).decode()


def decrypt_api_key(encrypted: str) -> str:
    """Decrypt API key from system_config. Returns empty string on failure."""
    from cryptography.fernet import Fernet, InvalidToken
    pg_pass = os.environ.get('POSTGRES_PASSWORD', '')
    if not pg_pass or not encrypted:
        return ''
    try:
        f = Fernet(_derive_fernet_key(pg_pass))
        return f.decrypt(encrypted.encode()).decode()
    except (InvalidToken, Exception) as e:
        logger.warning("Failed to decrypt API key (POSTGRES_PASSWORD may have changed): %s", e)
        return ''

# Column names matching the logs table
INSERT_COLUMNS = [
    'timestamp', 'log_type', 'direction',
    'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'service_name',
    'rule_name', 'rule_desc', 'rule_action',
    'interface_in', 'interface_out',
    'mac_address', 'hostname',
    'dns_query', 'dns_type', 'dns_answer',
    'dhcp_event', 'wifi_event',
    'geo_country', 'geo_city', 'geo_lat', 'geo_lon',
    'asn_number', 'asn_name',
    'threat_score', 'threat_categories', 'rdns',
    'abuse_usage_type', 'abuse_hostnames',
    'abuse_total_reports', 'abuse_last_reported',
    'abuse_is_whitelisted', 'abuse_is_tor',
    'src_device_name', 'dst_device_name',
    'raw_log',
]

INSERT_SQL = f"""
    INSERT INTO logs ({', '.join(INSERT_COLUMNS)})
    VALUES ({', '.join(['%s'] * len(INSERT_COLUMNS))})
"""


class Database:
    """PostgreSQL connection pool and operations."""

    def __init__(self, conn_params: dict | None = None, min_conn: int = 2, max_conn: int = 10):
        self.conn_params = conn_params or {
            'host': '127.0.0.1',
            'port': 5432,
            'dbname': 'unifi_logs',
            'user': 'unifi',
            'password': os.environ.get('POSTGRES_PASSWORD', 'changeme'),
        }
        self.pool = None
        self.min_conn = min_conn
        self.max_conn = max_conn

    def connect(self):
        """Initialize the connection pool."""
        logger.info("Connecting to PostgreSQL...")
        self.pool = pool.ThreadedConnectionPool(
            self.min_conn, self.max_conn, **self.conn_params
        )
        logger.info("PostgreSQL connection pool ready (min=%d, max=%d)", self.min_conn, self.max_conn)
        self._ensure_schema()

    def _ensure_schema(self):
        """Run idempotent schema migrations (safe on every boot)."""
        migrations = [
            # ip_threats persistent cache (added Phase 6)
            """CREATE TABLE IF NOT EXISTS ip_threats (
                ip              INET PRIMARY KEY,
                threat_score    INTEGER NOT NULL DEFAULT 0,
                threat_categories TEXT[],
                looked_up_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )""",
            "CREATE INDEX IF NOT EXISTS idx_ip_threats_looked_up ON ip_threats (looked_up_at)",
            # AbuseIPDB detail columns on logs (Phase 10)
            "ALTER TABLE logs ADD COLUMN IF NOT EXISTS abuse_usage_type TEXT",
            "ALTER TABLE logs ADD COLUMN IF NOT EXISTS abuse_hostnames TEXT",
            "ALTER TABLE logs ADD COLUMN IF NOT EXISTS abuse_total_reports INTEGER",
            "ALTER TABLE logs ADD COLUMN IF NOT EXISTS abuse_last_reported TIMESTAMPTZ",
            "ALTER TABLE logs ADD COLUMN IF NOT EXISTS abuse_is_whitelisted BOOLEAN",
            "ALTER TABLE logs ADD COLUMN IF NOT EXISTS abuse_is_tor BOOLEAN",
            # AbuseIPDB detail columns on ip_threats cache (Phase 10)
            "ALTER TABLE ip_threats ADD COLUMN IF NOT EXISTS abuse_usage_type TEXT",
            "ALTER TABLE ip_threats ADD COLUMN IF NOT EXISTS abuse_hostnames TEXT",
            "ALTER TABLE ip_threats ADD COLUMN IF NOT EXISTS abuse_total_reports INTEGER",
            "ALTER TABLE ip_threats ADD COLUMN IF NOT EXISTS abuse_last_reported TIMESTAMPTZ",
            "ALTER TABLE ip_threats ADD COLUMN IF NOT EXISTS abuse_is_whitelisted BOOLEAN",
            "ALTER TABLE ip_threats ADD COLUMN IF NOT EXISTS abuse_is_tor BOOLEAN",
            # IANA service name mapping (after protocol column)
            "ALTER TABLE logs ADD COLUMN IF NOT EXISTS service_name TEXT",
            "CREATE INDEX IF NOT EXISTS idx_logs_service_name ON logs (service_name) WHERE service_name IS NOT NULL",
            # Normalize protocol to lowercase for index optimization
            "UPDATE logs SET protocol = LOWER(protocol) WHERE protocol IS NOT NULL AND protocol != LOWER(protocol)",
            # System configuration table for dynamic settings
            """CREATE TABLE IF NOT EXISTS system_config (
                key TEXT PRIMARY KEY,
                value JSONB NOT NULL,
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            # MCP tokens and audit trail
            """CREATE TABLE IF NOT EXISTS mcp_tokens (
                id UUID PRIMARY KEY,
                name TEXT NOT NULL,
                token_prefix TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                token_salt TEXT NOT NULL,
                scopes TEXT[] NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_used_at TIMESTAMPTZ,
                disabled BOOLEAN NOT NULL DEFAULT FALSE
            )""",
            "CREATE INDEX IF NOT EXISTS idx_mcp_tokens_prefix ON mcp_tokens (token_prefix)",
            "CREATE INDEX IF NOT EXISTS idx_mcp_tokens_active ON mcp_tokens (disabled) WHERE disabled = false",
            """CREATE TABLE IF NOT EXISTS mcp_audit (
                id BIGSERIAL PRIMARY KEY,
                token_id UUID,
                tool_name TEXT NOT NULL,
                scope TEXT,
                success BOOLEAN NOT NULL,
                error TEXT,
                params JSONB,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )""",
            "CREATE INDEX IF NOT EXISTS idx_mcp_audit_created_at ON mcp_audit (created_at)",
            "CREATE INDEX IF NOT EXISTS idx_mcp_audit_token_id ON mcp_audit (token_id)",
            # One-time flag: re-enrich logs that were enriched on WAN IP instead of remote IP
            """INSERT INTO system_config (key, value, updated_at)
               VALUES ('enrichment_wan_fix_pending', 'true', NOW())
               ON CONFLICT (key) DO NOTHING""",
            # One-time flag: repair logs contaminated by WAN IP abuse data (issue #30)
            """INSERT INTO system_config (key, value, updated_at)
               VALUES ('abuse_hostname_fix_done', 'false', NOW())
               ON CONFLICT (key) DO NOTHING""",
            # Flow aggregation index (Sankey + IP Pairs)
            """CREATE INDEX IF NOT EXISTS idx_logs_flow_agg
                ON logs (timestamp DESC, src_ip, dst_ip, dst_port, protocol)
                WHERE log_type = 'firewall' AND src_ip IS NOT NULL AND dst_ip IS NOT NULL""",
            # Phase 2: Device name columns on logs
            "ALTER TABLE logs ADD COLUMN IF NOT EXISTS src_device_name TEXT",
            "ALTER TABLE logs ADD COLUMN IF NOT EXISTS dst_device_name TEXT",
            # Phase 2: UniFi client cache
            """CREATE TABLE IF NOT EXISTS unifi_clients (
                mac             MACADDR PRIMARY KEY,
                ip              INET,
                device_name     TEXT,
                hostname        TEXT,
                oui             TEXT,
                network         TEXT,
                essid           TEXT,
                vlan            INTEGER,
                is_fixed_ip     BOOLEAN DEFAULT FALSE,
                is_wired        BOOLEAN,
                last_seen       TIMESTAMPTZ,
                updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )""",
            "CREATE INDEX IF NOT EXISTS idx_unifi_clients_ip ON unifi_clients (ip)",
            "CREATE INDEX IF NOT EXISTS idx_unifi_clients_name ON unifi_clients (device_name) WHERE device_name IS NOT NULL",
            # Phase 2: UniFi infrastructure device cache
            """CREATE TABLE IF NOT EXISTS unifi_devices (
                mac             MACADDR PRIMARY KEY,
                ip              INET,
                device_name     TEXT,
                model           TEXT,
                shortname       TEXT,
                device_type     TEXT,
                firmware        TEXT,
                serial          TEXT,
                state           INTEGER,
                uptime          BIGINT,
                updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )""",
            "CREATE INDEX IF NOT EXISTS idx_unifi_devices_ip ON unifi_devices (ip)",
            # Saved views for Flow View filter presets
            """CREATE TABLE IF NOT EXISTS saved_views (
                id          SERIAL PRIMARY KEY,
                name        TEXT NOT NULL,
                filters     JSONB NOT NULL,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )""",
            # Zone matrix aggregation (interface-to-interface traffic)
            """CREATE INDEX IF NOT EXISTS idx_logs_zone_matrix
                ON logs (timestamp DESC, interface_in, interface_out, rule_action)
                WHERE log_type = 'firewall' AND interface_in IS NOT NULL AND interface_out IS NOT NULL""",
            # Parameterized retention cleanup function (replaces hardcoded 60/10 day version)
            """CREATE OR REPLACE FUNCTION cleanup_old_logs(
                general_days INTEGER DEFAULT 60,
                dns_days INTEGER DEFAULT 10
            ) RETURNS INTEGER AS $$
            DECLARE deleted INTEGER;
            BEGIN
                DELETE FROM logs
                WHERE (log_type = 'dns' AND timestamp < NOW() - (dns_days || ' days')::INTERVAL)
                   OR (log_type != 'dns' AND timestamp < NOW() - (general_days || ' days')::INTERVAL);
                GET DIAGNOSTICS deleted = ROW_COUNT;
                RETURN deleted;
            END;
            $$ LANGUAGE plpgsql""",
        ]
        # Fix function ownership BEFORE migrations so CREATE OR REPLACE
        # succeeds on the first boot after upgrade (not just the second).
        self._fix_function_ownership()

        try:
            with self.get_conn() as conn:
                with conn.cursor() as cur:
                    for i, sql in enumerate(migrations):
                        try:
                            cur.execute(f"SAVEPOINT sp_{i}")
                            cur.execute(sql)
                            cur.execute(f"RELEASE SAVEPOINT sp_{i}")
                        except psycopg2.errors.InsufficientPrivilege:
                            cur.execute(f"ROLLBACK TO SAVEPOINT sp_{i}")
                            logger.warning(
                                "Migration skipped (insufficient privilege): %.80s... "
                                "Check object ownership and grant privileges to the app DB user.",
                                sql,
                            )
                        except Exception:
                            cur.execute(f"ROLLBACK TO SAVEPOINT sp_{i}")
                            raise
            logger.info("Schema migrations applied.")
        except Exception:
            logger.exception("Schema migration failed")

        self._backfill_tz_timestamps()

    def _fix_function_ownership(self):
        """One-time fix: transfer function ownership from postgres to unifi.

        init.sql creates cleanup_old_logs() as the postgres superuser, so it's
        owned by postgres.  The app connects as unifi and can't CREATE OR REPLACE
        a function it doesn't own (fixes #24).  We connect as postgres via the
        local Unix socket (pg_hba.conf: local all all trust) to run the ALTER,
        then gate it so it only runs once.
        """
        try:
            if self.get_config('fn_ownership_fixed'):
                return
            fix_conn = psycopg2.connect(
                dbname='unifi_logs', user='postgres',
                host='/var/run/postgresql',
            )
            try:
                fix_conn.autocommit = True
                with fix_conn.cursor() as cur:
                    cur.execute(
                        "ALTER FUNCTION cleanup_old_logs(INTEGER, INTEGER) "
                        "OWNER TO unifi"
                    )
            finally:
                fix_conn.close()
            self.set_config('fn_ownership_fixed', True)
            logger.info("Fixed function ownership: cleanup_old_logs → unifi")
        except Exception:
            logger.debug(
                "Could not fix function ownership via superuser "
                "(may be a fresh install where system_config doesn't exist yet)",
                exc_info=True,
            )

    def _backfill_tz_timestamps(self):
        """One-time migration: fix historical timestamps stored with wrong timezone.

        Before v1.2.5, parse_syslog_timestamp() hardcoded UTC — syslog local times
        were labelled as UTC, creating an offset equal to the TZ difference.
        This re-interprets those timestamps in the container's actual TZ and
        converts them to correct UTC.  Reads TZ from os.environ (same source as
        the parser fix) and passes it to PostgreSQL's AT TIME ZONE, which
        handles DST per-row automatically.

        Gated by system_config 'tz_backfill_done' — runs once, then skips on
        every subsequent boot.  Uses a single pooled connection throughout so the
        advisory lock is acquired and released on the same session.
        """
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                lock_acquired = False
                try:
                    # Advisory lock prevents race between receiver and API processes
                    cur.execute("SELECT pg_try_advisory_lock(20250212)")
                    lock_acquired = cur.fetchone()[0]
                    if not lock_acquired:
                        return  # Another process is handling it

                    cur.execute("SELECT value FROM system_config WHERE key = 'tz_backfill_done'")
                    if cur.fetchone():
                        return  # Already migrated

                    tz_name = os.environ.get('TZ', 'UTC')
                    if tz_name in ('UTC', 'Etc/UTC', 'GMT', 'Etc/GMT', ''):
                        tz_label = tz_name or 'UTC'
                        logger.info("TZ backfill: timezone is %s, no correction needed.", tz_label)
                        self._set_config_with_cursor(cur, 'tz_backfill_done',
                                                     {'tz': tz_label, 'rows': 0, 'skipped': True})
                        return

                    # Validate that PostgreSQL recognises this timezone name
                    cur.execute("SELECT 1 FROM pg_timezone_names WHERE name = %s", [tz_name])
                    if not cur.fetchone():
                        logger.warning("TZ backfill: '%s' not recognised by PostgreSQL, skipping.", tz_name)
                        self._set_config_with_cursor(cur, 'tz_backfill_done',
                                                     {'tz': tz_name, 'rows': 0, 'skipped': True,
                                                      'reason': 'unknown_tz'})
                        return

                    # Re-interpret stored UTC-labelled timestamps as local TZ
                    cur.execute("""
                        UPDATE logs
                        SET timestamp = (timestamp AT TIME ZONE 'UTC') AT TIME ZONE %s
                    """, [tz_name])
                    fixed = cur.rowcount

                    logger.info("TZ backfill: corrected %d log timestamps from UTC to %s.", fixed, tz_name)
                    self._set_config_with_cursor(cur, 'tz_backfill_done',
                                                 {'tz': tz_name, 'rows': fixed, 'skipped': False})
                except Exception:
                    logger.exception("TZ backfill failed")
                    conn.rollback()
                finally:
                    if lock_acquired:
                        cur.execute("SELECT pg_advisory_unlock(20250212)")

    @staticmethod
    def _set_config_with_cursor(cur, key: str, value):
        """Write a system_config entry using an existing cursor."""
        cur.execute("""
            INSERT INTO system_config (key, value, updated_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (key) DO UPDATE
            SET value = EXCLUDED.value, updated_at = NOW()
        """, [key, Json(value)])

    def close(self):
        """Close all connections in the pool."""
        if self.pool:
            self.pool.closeall()
            logger.info("PostgreSQL connection pool closed.")

    @contextmanager
    def get_conn(self):
        """Get a connection from the pool."""
        conn = self.pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.pool.putconn(conn)

    def insert_log(self, parsed: dict):
        """Insert a single parsed log entry."""
        values = tuple(parsed.get(col) for col in INSERT_COLUMNS)

        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(INSERT_SQL, values)

    def insert_logs_batch(self, logs: list[dict]):
        """Insert multiple parsed log entries in a single transaction.
        
        If batch insert fails, falls back to row-by-row to isolate bad data.
        """
        if not logs:
            return

        rows = [
            tuple(log.get(col) for col in INSERT_COLUMNS)
            for log in logs
        ]

        try:
            with self.get_conn() as conn:
                with conn.cursor() as cur:
                    extras.execute_batch(cur, INSERT_SQL, rows, page_size=100)
            logger.debug("Batch inserted %d logs", len(logs))
        except Exception as batch_err:
            logger.warning("Batch insert failed (%s), falling back to row-by-row for %d logs",
                          batch_err, len(logs))
            inserted = 0
            dropped = 0
            for row in rows:
                try:
                    with self.get_conn() as conn:
                        with conn.cursor() as cur:
                            cur.execute(INSERT_SQL, row)
                    inserted += 1
                except Exception as row_err:
                    dropped += 1
                    logger.warning("Dropped bad log row: %s — raw: %.200s", row_err, row[-1] if row else '?')
            logger.info("Row-by-row fallback: %d inserted, %d dropped", inserted, dropped)

    def run_retention_cleanup(self, general_days: int = 60, dns_days: int = 10):
        """Run the retention cleanup function. Returns number of deleted rows."""
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT cleanup_old_logs(%s, %s)", [general_days, dns_days])
                deleted = cur.fetchone()[0]
        if deleted > 0:
            logger.info("Retention cleanup: deleted %d old logs (general=%dd, dns=%dd)",
                        deleted, general_days, dns_days)
        return deleted

    def get_stats(self) -> dict:
        """Get basic stats for health check / logging."""
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM logs")
                total = cur.fetchone()[0]
                cur.execute(
                    "SELECT log_type, COUNT(*) FROM logs "
                    "WHERE timestamp > NOW() - INTERVAL '1 hour' "
                    "GROUP BY log_type ORDER BY count DESC"
                )
                hourly = {row[0]: row[1] for row in cur.fetchall()}
        return {'total': total, 'last_hour': hourly}

    # ── Threat cache (ip_threats table) ──────────────────────────────────────

    def get_threat_cache(self, ip: str, max_age_days: int = 4) -> dict | None:
        """Look up a cached threat score. Returns dict or None if stale/missing."""
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT threat_score, threat_categories, "
                    "abuse_usage_type, abuse_hostnames, abuse_total_reports, "
                    "abuse_last_reported, abuse_is_whitelisted, abuse_is_tor "
                    "FROM ip_threats "
                    "WHERE ip = %s AND looked_up_at > NOW() - INTERVAL '%s days'",
                    [ip, max_age_days]
                )
                row = cur.fetchone()
                if row:
                    result = {
                        'threat_score': row[0],
                        'threat_categories': row[1] or [],
                    }
                    # Include extra fields if present
                    if row[2]:
                        result['abuse_usage_type'] = row[2]
                    if row[3]:
                        result['abuse_hostnames'] = row[3]
                    if row[4] is not None:
                        result['abuse_total_reports'] = row[4]
                    if row[5]:
                        result['abuse_last_reported'] = row[5].isoformat() if hasattr(row[5], 'isoformat') else row[5]
                    if row[6] is not None:
                        result['abuse_is_whitelisted'] = row[6]
                    if row[7] is not None:
                        result['abuse_is_tor'] = row[7]
                    return result
        return None

    def upsert_threat(self, ip: str, threat_data: dict):
        """Insert or update a threat entry for an IP.

        threat_data should contain at minimum: threat_score, threat_categories.
        May also contain: abuse_usage_type, abuse_hostnames, abuse_total_reports,
        abuse_last_reported, abuse_is_whitelisted, abuse_is_tor.
        """
        # Defense-in-depth: never store WAN/gateway IPs as threats
        try:
            normalized = str(ipaddress.ip_address(ip))
        except ValueError:
            normalized = ip
        excluded = set()
        for ip_str in get_wan_ips_from_config(self) + (self.get_config('gateway_ips') or []):
            try:
                excluded.add(str(ipaddress.ip_address(ip_str)))
            except ValueError:
                pass
        if normalized in excluded:
            logger.debug("Skipping upsert_threat for excluded IP %s", ip)
            return

        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO ip_threats (ip, threat_score, threat_categories, "
                    "abuse_usage_type, abuse_hostnames, abuse_total_reports, "
                    "abuse_last_reported, abuse_is_whitelisted, abuse_is_tor, "
                    "looked_up_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW()) "
                    "ON CONFLICT (ip) DO UPDATE SET "
                    "  threat_score = EXCLUDED.threat_score, "
                    "  threat_categories = EXCLUDED.threat_categories, "
                    "  abuse_usage_type = COALESCE(EXCLUDED.abuse_usage_type, ip_threats.abuse_usage_type), "
                    "  abuse_hostnames = COALESCE(EXCLUDED.abuse_hostnames, ip_threats.abuse_hostnames), "
                    "  abuse_total_reports = COALESCE(EXCLUDED.abuse_total_reports, ip_threats.abuse_total_reports), "
                    "  abuse_last_reported = COALESCE(EXCLUDED.abuse_last_reported, ip_threats.abuse_last_reported), "
                    "  abuse_is_whitelisted = COALESCE(EXCLUDED.abuse_is_whitelisted, ip_threats.abuse_is_whitelisted), "
                    "  abuse_is_tor = COALESCE(EXCLUDED.abuse_is_tor, ip_threats.abuse_is_tor), "
                    "  looked_up_at = NOW()",
                    [
                        normalized,
                        threat_data.get('threat_score', 0),
                        threat_data.get('threat_categories', []),
                        threat_data.get('abuse_usage_type'),
                        threat_data.get('abuse_hostnames'),
                        threat_data.get('abuse_total_reports'),
                        threat_data.get('abuse_last_reported'),
                        threat_data.get('abuse_is_whitelisted'),
                        threat_data.get('abuse_is_tor'),
                    ]
                )

    def bulk_upsert_threats(self, entries: list[tuple]) -> int:
        """Bulk upsert threat scores. entries = [(ip, score, categories), ...].
        
        Uses execute_batch for efficiency. Returns number of rows upserted.
        Only updates existing rows if the new score is >= the existing score,
        so a check-API result with categories won't be overwritten by a
        blacklist entry with just ["blacklist"].
        """
        if not entries:
            return 0

        sql = (
            "INSERT INTO ip_threats (ip, threat_score, threat_categories, looked_up_at) "
            "VALUES (%s, %s, %s, NOW()) "
            "ON CONFLICT (ip) DO UPDATE SET "
            "  threat_score = GREATEST(ip_threats.threat_score, EXCLUDED.threat_score), "
            "  threat_categories = CASE "
            "    WHEN array_length(ip_threats.threat_categories, 1) > 1 "
            "      THEN ip_threats.threat_categories "  # keep richer categories from check API
            "    ELSE EXCLUDED.threat_categories "
            "  END, "
            "  looked_up_at = NOW()"
        )

        try:
            with self.get_conn() as conn:
                with conn.cursor() as cur:
                    extras.execute_batch(cur, sql, entries, page_size=500)
            logger.info("Bulk upserted %d threat entries", len(entries))
            return len(entries)
        except Exception:
            logger.exception("Bulk upsert failed")
            return 0

    # ── System configuration ──────────────────────────────────────────────────

    def get_config(self, key: str, default=None):
        """Fetch a config value from system_config table.

        Returns the JSONB value as a Python object (dict/list/etc).
        Returns default if key doesn't exist.
        """
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT value FROM system_config WHERE key = %s", [key])
                row = cur.fetchone()
                return row[0] if row else default

    def set_config(self, key: str, value):
        """Upsert a config value to system_config table.

        Value is automatically converted to JSONB.
        """
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO system_config (key, value, updated_at)
                    VALUES (%s, %s, NOW())
                    ON CONFLICT (key) DO UPDATE
                    SET value = EXCLUDED.value, updated_at = NOW()
                """, [key, Json(value)])  # Use Json() for proper JSONB handling


    # ── UniFi client / device cache ──────────────────────────────────────────

    def upsert_unifi_clients(self, clients: list[dict]) -> int:
        """Bulk upsert UniFi clients. Returns count upserted."""
        if not clients:
            return 0
        sql = """
            INSERT INTO unifi_clients (mac, ip, device_name, hostname, oui,
                network, essid, vlan, is_fixed_ip, is_wired, last_seen, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (mac) DO UPDATE SET
                ip = EXCLUDED.ip,
                device_name = COALESCE(EXCLUDED.device_name, unifi_clients.device_name),
                hostname = COALESCE(EXCLUDED.hostname, unifi_clients.hostname),
                oui = COALESCE(EXCLUDED.oui, unifi_clients.oui),
                network = COALESCE(EXCLUDED.network, unifi_clients.network),
                essid = COALESCE(EXCLUDED.essid, unifi_clients.essid),
                vlan = COALESCE(EXCLUDED.vlan, unifi_clients.vlan),
                is_fixed_ip = COALESCE(EXCLUDED.is_fixed_ip, unifi_clients.is_fixed_ip),
                is_wired = COALESCE(EXCLUDED.is_wired, unifi_clients.is_wired),
                last_seen = GREATEST(EXCLUDED.last_seen, unifi_clients.last_seen),
                updated_at = NOW()
        """
        rows = [
            (c['mac'], c.get('ip'), c.get('device_name'), c.get('hostname'),
             c.get('oui'), c.get('network'), c.get('essid'), c.get('vlan'),
             c.get('is_fixed_ip'), c.get('is_wired'), c.get('last_seen'))
            for c in clients
        ]
        try:
            with self.get_conn() as conn:
                with conn.cursor() as cur:
                    extras.execute_batch(cur, sql, rows, page_size=200)
            return len(rows)
        except Exception:
            logger.exception("Failed to upsert UniFi clients")
            return 0

    def upsert_unifi_devices(self, devices: list[dict]) -> int:
        """Bulk upsert UniFi infrastructure devices. Returns count upserted."""
        if not devices:
            return 0
        sql = """
            INSERT INTO unifi_devices (mac, ip, device_name, model, shortname,
                device_type, firmware, serial, state, uptime, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (mac) DO UPDATE SET
                ip = EXCLUDED.ip,
                device_name = COALESCE(EXCLUDED.device_name, unifi_devices.device_name),
                model = COALESCE(EXCLUDED.model, unifi_devices.model),
                shortname = COALESCE(EXCLUDED.shortname, unifi_devices.shortname),
                device_type = COALESCE(EXCLUDED.device_type, unifi_devices.device_type),
                firmware = COALESCE(EXCLUDED.firmware, unifi_devices.firmware),
                serial = COALESCE(EXCLUDED.serial, unifi_devices.serial),
                state = EXCLUDED.state,
                uptime = EXCLUDED.uptime,
                updated_at = NOW()
        """
        rows = [
            (d['mac'], d.get('ip'), d.get('device_name'), d.get('model'),
             d.get('shortname'), d.get('device_type'), d.get('firmware'),
             d.get('serial'), d.get('state'), d.get('uptime'))
            for d in devices
        ]
        try:
            with self.get_conn() as conn:
                with conn.cursor() as cur:
                    extras.execute_batch(cur, sql, rows, page_size=200)
            return len(rows)
        except Exception:
            logger.exception("Failed to upsert UniFi devices")
            return 0

    def load_device_name_maps(self) -> tuple[dict, dict]:
        """Load IP-to-name and MAC-to-name maps from unifi_clients + unifi_devices.

        Name priority: device_name > hostname > oui.
        Returns (ip_to_name, mac_to_name) dicts.
        """
        ip_map = {}
        mac_map = {}
        try:
            with self.get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT mac, host(ip) as ip,
                               COALESCE(device_name, hostname, oui) as name
                        FROM unifi_clients
                        WHERE COALESCE(device_name, hostname, oui) IS NOT NULL
                        ORDER BY last_seen ASC NULLS FIRST, mac
                    """)
                    for mac, ip, name in cur.fetchall():
                        if mac:
                            mac_map[str(mac)] = name
                        if ip:
                            ip_map[ip] = name
                    cur.execute("""
                        SELECT mac, host(ip) as ip,
                               COALESCE(device_name, model) as name
                        FROM unifi_devices
                        WHERE COALESCE(device_name, model) IS NOT NULL
                        ORDER BY updated_at ASC NULLS FIRST, mac
                    """)
                    for mac, ip, name in cur.fetchall():
                        if mac:
                            mac_map[str(mac)] = name
                        if ip:
                            ip_map[ip] = name
        except Exception:
            logger.exception("Failed to load device name maps")
        return ip_map, mac_map

    # ── WAN IP detection ──────────────────────────────────────────────────────

    # Shared SQL filter for excluding private/non-routable dst_ip
    _PRIVATE_IP_FILTER = """
        NOT (dst_ip << '10.0.0.0/8'::inet
          OR dst_ip << '172.16.0.0/12'::inet
          OR dst_ip << '192.168.0.0/16'::inet
          OR dst_ip << '127.0.0.0/8'::inet
          OR dst_ip << 'fc00::/7'::inet
          OR dst_ip << 'fe80::/10'::inet
          OR dst_ip << '::1/128'::inet
          OR host(dst_ip) = '255.255.255.255')
    """

    def get_wan_ips_by_interface(self, interfaces: list) -> dict:
        """Detect WAN IP for each interface using the most common public dst_ip.

        Returns dict of {interface: wan_ip_str} for each interface that has one.
        """
        if not interfaces:
            return {}
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                placeholders = ','.join(['%s'] * len(interfaces))
                cur.execute(f"""
                    SELECT interface_in AS iface,
                           MODE() WITHIN GROUP (ORDER BY host(dst_ip)) FILTER (
                               WHERE dst_ip IS NOT NULL AND {self._PRIVATE_IP_FILTER}
                           ) AS wan_ip
                    FROM logs
                    WHERE log_type = 'firewall'
                      AND interface_in IN ({placeholders})
                    GROUP BY interface_in
                """, interfaces)
                return {row[0]: row[1] for row in cur.fetchall() if row[1]}

    def detect_wan_ip(self) -> str | None:
        """Detect WAN IPs and persist to system_config.

        When UniFi API is enabled AND wan_ip_by_iface exists, derives wan_ips
        from the map (no log computation). Otherwise computes per-interface
        WAN IPs from logs via get_wan_ips_by_interface() and stores
        wan_ip_by_iface automatically.

        Returns the primary detected WAN IP or None.
        """
        wan_interfaces = self.get_config('wan_interfaces', ['ppp0'])
        if not wan_interfaces:
            return None

        unifi_enabled = self.get_config('unifi_enabled', False)
        wan_ip_by_iface = self.get_config('wan_ip_by_iface')

        if unifi_enabled and wan_ip_by_iface:
            # UniFi API is authoritative — derive from map, don't compute from logs
            wan_ips = [wan_ip_by_iface[iface] for iface in wan_interfaces
                       if iface in wan_ip_by_iface and wan_ip_by_iface[iface]]
            primary = wan_ips[0] if wan_ips else None
        else:
            # Compute per-interface WAN IPs from logs
            iface_ips = self.get_wan_ips_by_interface(wan_interfaces)

            # Store wan_ip_by_iface (auto-populate for legacy installs)
            if iface_ips:
                current_map = self.get_config('wan_ip_by_iface')
                if current_map != iface_ips:
                    self.set_config('wan_ip_by_iface', iface_ips)
                    logger.info("wan_ip_by_iface auto-populated from logs: %s", iface_ips)

            # Derive ordered wan_ips following wan_interfaces order
            wan_ips = [iface_ips[iface] for iface in wan_interfaces
                       if iface in iface_ips and iface_ips[iface]]
            primary = wan_ips[0] if wan_ips else None

        # Persist primary wan_ip
        if primary:
            current = self.get_config('wan_ip')
            if primary != current:
                self.set_config('wan_ip', primary)
                logger.info("WAN IP detected and persisted: %s", primary)

        # Persist wan_ips list
        current_list = self.get_config('wan_ips') or []
        if sorted(wan_ips) != sorted(current_list):
            self.set_config('wan_ips', wan_ips)
            if len(wan_ips) > 1:
                logger.info("WAN IPs detected (multi-WAN): %s", wan_ips)

        return primary

    def detect_gateway_ips(self) -> list[str]:
        """Detect gateway internal IPs from _LOCAL firewall rule names.

        UniFi zone-based rules ending in '_LOCAL' target traffic destined for
        the gateway itself. The dst_ip on those rules (excluding broadcast/
        multicast) gives us the gateway's internal IP per VLAN.
        Stores result as 'gateway_ips' list in system_config.
        """
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT DISTINCT host(dst_ip) AS gateway_ip
                    FROM logs
                    WHERE log_type = 'firewall'
                      AND rule_name LIKE '%%\\_LOCAL%%'
                      AND (dst_ip << '10.0.0.0/8' OR dst_ip << '172.16.0.0/12'
                           OR dst_ip << '192.168.0.0/16'
                           OR dst_ip << 'fc00::/7')
                      AND host(dst_ip) NOT IN ('224.0.0.251', '255.255.255.255')
                """)
                detected = [row[0] for row in cur.fetchall()]

        current = self.get_config('gateway_ips', [])
        if sorted(detected) != sorted(current):
            self.set_config('gateway_ips', detected)
            logger.info("Gateway IPs detected: %s", detected)

        return detected

    def get_wan_ip_candidates(self) -> list[dict]:
        """Return non-bridge, non-VPN firewall interfaces with their WAN IPs.

        Used by the setup wizard to discover candidate WAN interfaces.
        """
        from parsers import VPN_INTERFACE_PREFIXES
        vpn_excludes = " ".join(
            f"AND interface_in NOT LIKE '{pfx}%%'" for pfx in VPN_INTERFACE_PREFIXES
        )
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(f"""
                    SELECT
                        interface_in AS interface,
                        COUNT(*)     AS event_count,
                        MODE() WITHIN GROUP (ORDER BY host(dst_ip)) FILTER (
                            WHERE dst_ip IS NOT NULL AND {self._PRIVATE_IP_FILTER}
                        ) AS wan_ip
                    FROM logs
                    WHERE log_type = 'firewall'
                      AND interface_in IS NOT NULL
                      AND interface_in NOT LIKE 'br%%'
                      {vpn_excludes}
                    GROUP BY interface_in
                    ORDER BY event_count DESC
                """)
                return [
                    {'interface': r[0], 'event_count': int(r[1]), 'wan_ip': r[2] or ''}
                    for r in cur.fetchall()
                ]


# ── Standalone helper functions ───────────────────────────────────────────────

def get_config(db, key: str, default=None):
    """Standalone helper: fetch config using Database instance."""
    return db.get_config(key, default)


def set_config(db, key: str, value):
    """Standalone helper: set config using Database instance."""
    return db.set_config(key, value)


def get_wan_ips_from_config(db) -> list[str]:
    """Derive ordered WAN IP list from wan_ip_by_iface + wan_interfaces.

    Falls back to legacy 'wan_ips' config key if 'wan_ip_by_iface' doesn't
    exist (pre-multi-WAN installs that haven't re-run the wizard).
    Returns list of WAN IP strings (may be empty).
    """
    wan_ip_by_iface = db.get_config('wan_ip_by_iface')
    if wan_ip_by_iface:
        wan_interfaces = db.get_config('wan_interfaces', [])
        # Derive ordered list following wan_interfaces order
        return [wan_ip_by_iface[iface] for iface in wan_interfaces
                if iface in wan_ip_by_iface and wan_ip_by_iface[iface]]
    # Legacy fallback: use wan_ips config key directly
    return db.get_config('wan_ips') or []


def count_logs(db, log_type='firewall'):
    """Count logs by type."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM logs WHERE log_type = %s", [log_type])
            return cur.fetchone()[0]
