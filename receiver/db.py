"""
UniFi Log Insight - Database Module

Handles PostgreSQL connection pooling, log insertion, and retention cleanup.
"""

import base64
import ipaddress
import os
import sys
import json
import logging
import time
from contextlib import contextmanager
from typing import NamedTuple, Optional

import psycopg2
import psycopg2.errors
from psycopg2 import pool, extras
from psycopg2.extras import Json

logger = logging.getLogger(__name__)


class AdGuardHostMismatch(Exception):
    """Raised by insert_adguard_batch when the DB host differs from the expected host.

    This indicates a config change landed between the start of _poll() and the
    DB commit — the batch is discarded to prevent cursor corruption.
    """


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


def _get_secret_key() -> str:
    """Return the encryption secret: SECRET_KEY > POSTGRES_PASSWORD > DB_PASSWORD."""
    return (os.environ.get('SECRET_KEY')
            or os.environ.get('POSTGRES_PASSWORD')
            or os.environ.get('DB_PASSWORD', ''))


def encrypt_api_key(api_key: str) -> str:
    """Encrypt API key for storage in system_config."""
    from cryptography.fernet import Fernet
    secret = _get_secret_key()
    if not secret:
        raise ValueError("SECRET_KEY or POSTGRES_PASSWORD required for encryption")
    f = Fernet(_derive_fernet_key(secret))
    return f.encrypt(api_key.encode()).decode()


def decrypt_api_key(encrypted: str) -> str:
    """Decrypt API key from system_config. Returns empty string on failure."""
    from cryptography.fernet import Fernet, InvalidToken
    secret = _get_secret_key()
    if not secret or not encrypted:
        return ''
    try:
        f = Fernet(_derive_fernet_key(secret))
        return f.decrypt(encrypted.encode()).decode()
    except (InvalidToken, Exception) as e:
        logger.warning("Failed to decrypt API key (SECRET_KEY/POSTGRES_PASSWORD may have changed): %s", e)
        return ''

# ── External Database Support ─────────────────────────────────────────────────

def _normalize_db_host(raw: str) -> str:
    """Normalize DB_HOST: strip leading/trailing whitespace, lowercase.
    Shared by build_conn_params() and is_external_db() to guarantee
    the same host value is used for detection and connection."""
    return raw.strip().lower()


def build_conn_params() -> dict:
    """Build PostgreSQL connection parameters from environment variables."""
    host = _normalize_db_host(os.environ.get('DB_HOST', '127.0.0.1'))
    params = {
        'host': host,
        'port': int(os.environ.get('DB_PORT', '5432')),
        'dbname': os.environ.get('DB_NAME', 'unifi_logs'),
        'user': os.environ.get('DB_USER', 'unifi'),
        'password': os.environ.get('DB_PASSWORD') or os.environ.get('POSTGRES_PASSWORD', 'changeme'),
        'connect_timeout': 10,
        'keepalives': 1,
        'keepalives_idle': 30,
        'keepalives_interval': 10,
        'keepalives_count': 3,
    }
    sslmode = os.environ.get('DB_SSLMODE')
    if sslmode:
        params['sslmode'] = sslmode
    sslrootcert = os.environ.get('DB_SSLROOTCERT')
    if sslrootcert:
        params['sslrootcert'] = sslrootcert
    sslcert = os.environ.get('DB_SSLCERT')
    if sslcert:
        params['sslcert'] = sslcert
    sslkey = os.environ.get('DB_SSLKEY')
    if sslkey:
        params['sslkey'] = sslkey
    return params


def is_external_db() -> bool:
    """Check if the app is configured to use an external database."""
    host = _normalize_db_host(os.environ.get('DB_HOST', '127.0.0.1'))
    return host not in ('127.0.0.1', 'localhost', 'localhost.localdomain', '::1', '')


def wait_for_postgres(conn_params: dict, max_retries: int = 30, delay: float = 2.0):
    """Wait for PostgreSQL to be ready. Used by both receiver and API."""
    for i in range(max_retries):
        try:
            conn = psycopg2.connect(**conn_params)
            conn.close()
            logger.info("PostgreSQL is ready.")
            return
        except psycopg2.OperationalError:
            logger.warning("Waiting for PostgreSQL... (%d/%d)", i + 1, max_retries)
            time.sleep(delay)
    logger.critical("PostgreSQL not available after %d retries. Check DB_HOST, DB_PORT, "
                    "DB_USER, DB_PASSWORD, network connectivity, and firewall rules.", max_retries)
    sys.exit(1)


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
    'remote_ip',
    'raw_log',
]

INSERT_SQL = f"""
    INSERT INTO logs ({', '.join(INSERT_COLUMNS)})
    VALUES ({', '.join(['%s'] * len(INSERT_COLUMNS))})
"""


# ── Retention configuration — parsers and result types ───────────────────────

def parse_retention_time(raw) -> str | None:
    """Parse and range-validate a retention_time input value.

    Returns a canonical 'HH:MM' string in the 00:00..23:59 range, or None for
    any non-coercible / out-of-range input. Accepts strings like '23:17',
    '3:5', '03:05' — the return value is always zero-padded two-digit form.

    Shared by Database.resolve_retention_time (for UI/env values) and the
    route handlers in routes/setup.py (for POST bodies and import payloads).
    Callers decide how to surface None — resolver falls through to the next
    precedence level, POST raises HTTPException, import pushes to failed_keys.

    The return value is directly consumable by `schedule.every().day.at(...)`
    so there's no format conversion needed in the scheduler.
    """
    if not isinstance(raw, str):
        return None
    parts = raw.strip().split(':')
    if len(parts) != 2:
        return None
    try:
        hour = int(parts[0])
        minute = int(parts[1])
    except ValueError:
        return None
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        return None
    return f"{hour:02d}:{minute:02d}"


class RetentionTimeConfig(NamedTuple):
    time: str    # 'HH:MM', 00:00..23:59
    source: str  # 'ui' | 'env' | 'default'


# Module-level flag so the legacy RETENTION_TIME deprecation warning fires
# once per process, not on every resolver call (the resolver runs on every
# GET /api/config/retention and every SIGUSR2 scheduler rebuild).
_legacy_retention_time_warned = False


def parse_retention_days(raw) -> int | None:
    """Parse and range-validate a retention-days input value.

    Returns positive int or None for any non-coercible / non-positive input.
    Accepts coercible values (including string digits) — this is for inputs
    from untrusted sources (API bodies, env vars, DB values).

    Related but distinct: `Database.validate_retention_days` is a stricter
    post-resolution invariant check (type: must already be `int`, not just
    coercible) used on values that have already been through a resolver.
    Both functions exist because they run at different points in the
    lifecycle — see that method's docstring for the scoping rule.
    """
    try:
        days = int(raw)
    except (ValueError, TypeError):
        return None
    return days if days > 0 else None


class RetentionDaysConfig(NamedTuple):
    general: int
    general_source: str   # 'ui' | 'env' | 'default'
    dns: int
    dns_source: str       # 'ui' | 'env' | 'default'


class Database:
    """PostgreSQL connection pool and operations."""

    # Heavyweight indexes created post-boot with CONCURRENTLY for upgrades.
    # Fresh installs get these from init.sql; this list handles existing installs.
    _POST_BOOT_INDEXES = [
        {
            'name': 'idx_logs_spgist_dst_ip_firewall',
            'sql': "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_logs_spgist_dst_ip_firewall "
                   "ON logs USING spgist (dst_ip) WHERE log_type = 'firewall'",
            'label': 'SP-GiST dst_ip for WAN detection',
        },
        {
            'name': 'idx_logs_type_id',
            'sql': "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_logs_type_id "
                   "ON logs (log_type, id)",
            'label': 'type+id for purge batches',
        },
        {
            'name': 'idx_logs_nondns_timestamp',
            'sql': "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_logs_nondns_timestamp "
                   "ON logs (timestamp DESC) WHERE log_type != 'dns'",
            'label': 'non-DNS retention cleanup',
        },
    ]

    # Redundant indexes dropped on upgrade. Each is a leftmost-prefix of an
    # existing composite so the planner loses nothing, but they incur write
    # amplification on every INSERT. DROP CONCURRENTLY IF EXISTS is idempotent.
    _POST_BOOT_DROPS = [
        ('idx_logs_type',        "DROP INDEX CONCURRENTLY IF EXISTS idx_logs_type"),
        ('idx_logs_rule_action', "DROP INDEX CONCURRENTLY IF EXISTS idx_logs_rule_action"),
    ]

    def __init__(self, conn_params: dict | None = None, min_conn: int = 2, max_conn: int = 10):
        self.conn_params = conn_params or build_conn_params()
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
        """Run idempotent schema migrations (safe on every boot).

        The full logs table DDL and indexes from init.sql are included here
        so external databases get the complete schema auto-provisioned.
        All statements use IF NOT EXISTS, so they are safe for embedded mode
        too (where init.sql already ran via entrypoint.sh).
        """
        migrations = [
            # ── Base schema (matches init.sql) ────────────────────────────
            """CREATE TABLE IF NOT EXISTS logs (
                id          BIGSERIAL PRIMARY KEY,
                timestamp   TIMESTAMPTZ NOT NULL,
                log_type    VARCHAR(20) NOT NULL,
                direction   VARCHAR(20),
                src_ip      INET,
                src_port    INTEGER,
                dst_ip      INET,
                dst_port    INTEGER,
                protocol    VARCHAR(10),
                service_name TEXT,
                rule_name   VARCHAR(100),
                rule_desc   VARCHAR(255),
                rule_action VARCHAR(20),
                interface_in  VARCHAR(20),
                interface_out VARCHAR(20),
                mac_address MACADDR,
                hostname    VARCHAR(255),
                dns_query   VARCHAR(255),
                dns_type    VARCHAR(10),
                dns_answer  VARCHAR(255),
                dhcp_event  VARCHAR(20),
                wifi_event  VARCHAR(50),
                geo_country VARCHAR(2),
                geo_city    VARCHAR(100),
                geo_lat     DECIMAL(9,6),
                geo_lon     DECIMAL(9,6),
                asn_number  INTEGER,
                asn_name    VARCHAR(255),
                threat_score    INTEGER,
                threat_categories TEXT[],
                rdns        VARCHAR(255),
                abuse_usage_type TEXT,
                abuse_hostnames TEXT,
                abuse_total_reports INTEGER,
                abuse_last_reported TIMESTAMPTZ,
                abuse_is_whitelisted BOOLEAN,
                abuse_is_tor BOOLEAN,
                src_device_name TEXT,
                dst_device_name TEXT,
                remote_ip   INET,
                raw_log     TEXT NOT NULL,
                created_at  TIMESTAMPTZ DEFAULT NOW()
            )""",
            # Performance indexes from init.sql
            "CREATE INDEX IF NOT EXISTS idx_logs_timestamp    ON logs (timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_logs_src_ip       ON logs (src_ip)",
            "CREATE INDEX IF NOT EXISTS idx_logs_dst_ip       ON logs (dst_ip)",
            "CREATE INDEX IF NOT EXISTS idx_logs_direction    ON logs (direction)",
            "CREATE INDEX IF NOT EXISTS idx_logs_threat_score ON logs (threat_score) WHERE threat_score IS NOT NULL",
            "CREATE INDEX IF NOT EXISTS idx_logs_type_time    ON logs (log_type, timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_logs_action_time  ON logs (rule_action, timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_logs_src_port     ON logs (src_port) WHERE src_port IS NOT NULL",
            "CREATE INDEX IF NOT EXISTS idx_logs_dst_port     ON logs (dst_port) WHERE dst_port IS NOT NULL",
            "CREATE INDEX IF NOT EXISTS idx_logs_protocol     ON logs (protocol) WHERE protocol IS NOT NULL",
            # ── Migrations (existing) ─────────────────────────────────────
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
            # System configuration table for dynamic settings
            # Must be created before any migration block that may reference it.
            """CREATE TABLE IF NOT EXISTS system_config (
                key TEXT PRIMARY KEY,
                value JSONB NOT NULL,
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            # Normalize protocol to lowercase for index optimization
            # Uses system_config marker to skip on subsequent boots (matches backfill pattern)
            """DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM system_config
    WHERE key = 'protocol_normalization_done'
      AND value = 'true'::jsonb
  ) THEN
    UPDATE logs SET protocol = LOWER(protocol)
    WHERE protocol IS NOT NULL AND protocol != LOWER(protocol);
    INSERT INTO system_config (key, value, updated_at)
    VALUES ('protocol_normalization_done', 'true'::jsonb, NOW())
    ON CONFLICT (key) DO UPDATE SET value = 'true'::jsonb, updated_at = NOW();
  END IF;
END $$;""",
            # Legacy MCP tables — only create if not already migrated to api_tokens
            """DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = '_mcp_tokens_backup' AND table_schema = 'public')
                   AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'api_tokens' AND table_schema = 'public') THEN
                    CREATE TABLE IF NOT EXISTS mcp_tokens (
                        id UUID PRIMARY KEY,
                        name TEXT NOT NULL,
                        token_prefix TEXT NOT NULL,
                        token_hash TEXT NOT NULL,
                        token_salt TEXT NOT NULL,
                        scopes TEXT[] NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        last_used_at TIMESTAMPTZ,
                        disabled BOOLEAN NOT NULL DEFAULT FALSE
                    );
                    CREATE INDEX IF NOT EXISTS idx_mcp_tokens_prefix ON mcp_tokens (token_prefix);
                    CREATE INDEX IF NOT EXISTS idx_mcp_tokens_active ON mcp_tokens (disabled) WHERE disabled = false;
                END IF;
            END $$""",
            """DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = '_mcp_audit_backup' AND table_schema = 'public')
                   AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_log' AND table_schema = 'public') THEN
                    CREATE TABLE IF NOT EXISTS mcp_audit (
                        id BIGSERIAL PRIMARY KEY,
                        token_id UUID,
                        tool_name TEXT NOT NULL,
                        scope TEXT,
                        success BOOLEAN NOT NULL,
                        error TEXT,
                        params JSONB,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    CREATE INDEX IF NOT EXISTS idx_mcp_audit_created_at ON mcp_audit (created_at);
                    CREATE INDEX IF NOT EXISTS idx_mcp_audit_token_id ON mcp_audit (token_id);
                END IF;
            END $$""",
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
            "ALTER TABLE logs ADD COLUMN IF NOT EXISTS remote_ip INET",
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
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_saved_views_name ON saved_views (name)",
            # Zone matrix aggregation (interface-to-interface traffic)
            """CREATE INDEX IF NOT EXISTS idx_logs_zone_matrix
                ON logs (timestamp DESC, interface_in, interface_out, rule_action)
                WHERE log_type = 'firewall' AND interface_in IS NOT NULL AND interface_out IS NOT NULL""",
            # cleanup_old_logs() SQL function removed — retention cleanup now
            # runs as a batched Python engine in run_retention_cleanup().
            # Drop the orphaned function from existing databases.
            "DROP FUNCTION IF EXISTS cleanup_old_logs(integer, integer)",
            # IP classification function — single source of truth for public/private
            """CREATE OR REPLACE FUNCTION is_public_inet(addr inet) RETURNS boolean AS $$
                SELECT addr IS NOT NULL
                    AND NOT (
                        addr << '10.0.0.0/8'
                        OR addr << '172.16.0.0/12'
                        OR addr << '192.168.0.0/16'
                        OR addr << 'fc00::/7'
                        OR addr << 'fe80::/10'
                    )
            $$ LANGUAGE sql IMMUTABLE""",
            # Auth: roles table
            """CREATE TABLE IF NOT EXISTS roles (
                id              SERIAL PRIMARY KEY,
                name            VARCHAR(50) UNIQUE NOT NULL,
                permissions     JSONB NOT NULL DEFAULT '[]',
                is_system       BOOLEAN DEFAULT FALSE,
                description     TEXT,
                created_at      TIMESTAMPTZ DEFAULT NOW()
            )""",
            # Auth: seed default roles
            """INSERT INTO roles (name, permissions, is_system, description) VALUES
                ('admin', '["*"]', TRUE, 'Full access to all features'),
                ('viewer', '["logs.read", "stats.read", "flows.read", "threats.read", "dashboard.read"]', TRUE, 'Read-only access to logs and dashboards')
            ON CONFLICT (name) DO NOTHING""",
            # Auth: users table
            """CREATE TABLE IF NOT EXISTS users (
                id              SERIAL PRIMARY KEY,
                username        VARCHAR(100) UNIQUE NOT NULL,
                password_hash   TEXT NOT NULL,
                role_id         INTEGER NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
                is_active       BOOLEAN DEFAULT TRUE,
                created_at      TIMESTAMPTZ DEFAULT NOW(),
                updated_at      TIMESTAMPTZ DEFAULT NOW(),
                last_login_at   TIMESTAMPTZ
            )""",
            # Auth: sessions table
            "CREATE EXTENSION IF NOT EXISTS pgcrypto",
            """CREATE TABLE IF NOT EXISTS sessions (
                id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
                token_hash      TEXT NOT NULL,
                expires_at      TIMESTAMPTZ NOT NULL,
                created_at      TIMESTAMPTZ DEFAULT NOW(),
                ip_address      INET,
                user_agent      TEXT
            )""",
            "CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)",
            # Auth: api_tokens table (replaces mcp_tokens)
            """CREATE TABLE IF NOT EXISTS api_tokens (
                id              UUID PRIMARY KEY,
                name            TEXT NOT NULL,
                token_prefix    TEXT NOT NULL,
                token_hash      TEXT NOT NULL,
                token_salt      TEXT NOT NULL,
                scopes          TEXT[] NOT NULL,
                client_type     VARCHAR(20) NOT NULL,
                owner_user_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
                created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_used_at    TIMESTAMPTZ,
                disabled        BOOLEAN NOT NULL DEFAULT FALSE
            )""",
            "CREATE INDEX IF NOT EXISTS idx_api_tokens_prefix ON api_tokens(token_prefix)",
            "CREATE INDEX IF NOT EXISTS idx_api_tokens_active ON api_tokens(disabled) WHERE disabled = false",
            "CREATE INDEX IF NOT EXISTS idx_api_tokens_owner ON api_tokens(owner_user_id)",
            # Auth: audit_log table (replaces mcp_audit)
            """CREATE TABLE IF NOT EXISTS audit_log (
                id              BIGSERIAL PRIMARY KEY,
                user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
                token_id        UUID REFERENCES api_tokens(id) ON DELETE SET NULL,
                action          VARCHAR(50) NOT NULL,
                detail          JSONB,
                ip_address      INET,
                user_agent      TEXT,
                created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )""",
            "CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_log_token_id ON audit_log(token_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action)",
            "CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at)",
            # Auth: system_config seed entries
            # Seed values use ::jsonb casts to store proper JSON types (boolean/number),
            # not strings — get_config() returns Python bool/int directly.
            """INSERT INTO system_config (key, value, updated_at) VALUES ('auth_enabled', 'false'::jsonb, NOW()) ON CONFLICT (key) DO NOTHING""",
            """INSERT INTO system_config (key, value, updated_at) VALUES ('auth_session_ttl_hours', '168'::jsonb, NOW()) ON CONFLICT (key) DO NOTHING""",
            """INSERT INTO system_config (key, value, updated_at) VALUES ('audit_log_retention_days', '90'::jsonb, NOW()) ON CONFLICT (key) DO NOTHING""",
            # Auth: migrate mcp_tokens data into api_tokens (guarded — table may not exist)
            """DO $$ BEGIN
                IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'mcp_tokens' AND table_schema = 'public') THEN
                    INSERT INTO api_tokens (id, name, token_prefix, token_hash, token_salt, scopes, client_type, owner_user_id, created_at, last_used_at, disabled)
                    SELECT id, name, token_prefix, token_hash, token_salt, scopes, 'mcp', NULL, created_at, last_used_at, disabled
                    FROM mcp_tokens
                    WHERE NOT EXISTS (SELECT 1 FROM api_tokens WHERE api_tokens.id = mcp_tokens.id);
                END IF;
            END $$""",
            # Auth: migrate mcp_audit data into audit_log (guarded — table may not exist).
            # Dedup uses created_at+token_id which is sufficient for this one-time migration
            # (source table is renamed to _mcp_audit_backup afterwards and never re-run).
            """DO $$ BEGIN
                IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'mcp_audit' AND table_schema = 'public') THEN
                    INSERT INTO audit_log (token_id, action, detail, created_at)
                    SELECT token_id, 'api_call', jsonb_build_object('tool_name', tool_name, 'scope', scope, 'success', success, 'error', error, 'params', params), created_at
                    FROM mcp_audit
                    WHERE NOT EXISTS (SELECT 1 FROM audit_log WHERE audit_log.created_at = mcp_audit.created_at AND audit_log.token_id IS NOT DISTINCT FROM mcp_audit.token_id);
                END IF;
            END $$""",
            # Auth: rename old mcp_tokens to backup
            """DO $$ BEGIN
                IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'mcp_tokens' AND table_schema = 'public')
                   AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = '_mcp_tokens_backup' AND table_schema = 'public') THEN
                    ALTER TABLE mcp_tokens RENAME TO _mcp_tokens_backup;
                END IF;
            END $$""",
            # Auth: rename old mcp_audit to backup
            """DO $$ BEGIN
                IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'mcp_audit' AND table_schema = 'public')
                   AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = '_mcp_audit_backup' AND table_schema = 'public') THEN
                    ALTER TABLE mcp_audit RENAME TO _mcp_audit_backup;
                END IF;
            END $$""",
            # Auth: migration version marker
            """INSERT INTO system_config (key, value, updated_at) VALUES ('mcp_migration_version', '1'::jsonb, NOW()) ON CONFLICT (key) DO NOTHING""",
            # ── Issue #67: queue-driven backfill (replaces sweep model) ────
            # 1. Queue for deferred threat enrichment
            """CREATE TABLE IF NOT EXISTS threat_backfill_queue (
                ip            INET PRIMARY KEY,
                source        TEXT NOT NULL DEFAULT 'live_miss',
                first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                next_retry_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                attempts      INTEGER NOT NULL DEFAULT 0,
                last_error    TEXT
            )""",
            """CREATE INDEX IF NOT EXISTS idx_threat_backfill_queue_due
                ON threat_backfill_queue (next_retry_at, last_seen_at DESC)""",
            # 2. Track recent activity on ip_threats (eliminates OR JOIN to logs)
            "ALTER TABLE ip_threats ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ DEFAULT NOW()",
            # Ensure default exists even if column was added by an earlier version without one
            "ALTER TABLE ip_threats ALTER COLUMN last_seen_at SET DEFAULT NOW()",
            """UPDATE ip_threats SET last_seen_at = COALESCE(last_seen_at, looked_up_at)
               WHERE last_seen_at IS NULL""",
            """CREATE INDEX IF NOT EXISTS idx_ip_threats_reenrich_candidates
                ON ip_threats (last_seen_at DESC, threat_score DESC)
                WHERE threat_score > 0
                  AND abuse_usage_type IS NULL AND abuse_hostnames IS NULL
                  AND abuse_total_reports IS NULL AND abuse_last_reported IS NULL
                  AND abuse_is_whitelisted IS NULL AND abuse_is_tor IS NULL""",
            # 3. Targeted log patch indexes for threat-score repair
            """CREATE INDEX IF NOT EXISTS idx_logs_fw_block_null_threat_src
                ON logs (src_ip)
                WHERE log_type = 'firewall'
                  AND rule_action = 'block'
                  AND threat_score IS NULL
                  AND src_ip IS NOT NULL""",
            """CREATE INDEX IF NOT EXISTS idx_logs_fw_block_null_threat_dst
                ON logs (dst_ip)
                WHERE log_type = 'firewall'
                  AND rule_action = 'block'
                  AND threat_score IS NULL
                  AND dst_ip IS NOT NULL""",
            # 4. Targeted log patch indexes for abuse-detail repair
            """CREATE INDEX IF NOT EXISTS idx_logs_fw_block_missing_abuse_src
                ON logs (src_ip)
                WHERE log_type = 'firewall'
                  AND rule_action = 'block'
                  AND threat_score IS NOT NULL
                  AND abuse_usage_type IS NULL
                  AND src_ip IS NOT NULL""",
            """CREATE INDEX IF NOT EXISTS idx_logs_fw_block_missing_abuse_dst
                ON logs (dst_ip)
                WHERE log_type = 'firewall'
                  AND rule_action = 'block'
                  AND threat_score IS NOT NULL
                  AND abuse_usage_type IS NULL
                  AND dst_ip IS NOT NULL""",
            # 5. One-shot service-name migration support (ID-cursor reads)
            """CREATE INDEX IF NOT EXISTS idx_logs_fw_service_name_null_id
                ON logs (id)
                WHERE log_type = 'firewall'
                  AND service_name IS NULL
                  AND dst_port IS NOT NULL""",
            # ── Issue #98: persistent rDNS cache (DB-backed cold tier) ─────
            """CREATE TABLE IF NOT EXISTS rdns_cache (
                ip            INET PRIMARY KEY,
                hostname      VARCHAR(255),
                status        VARCHAR(16) NOT NULL CHECK (status IN ('success', 'failure', 'transient')),
                looked_up_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )""",
            """CREATE INDEX IF NOT EXISTS idx_rdns_cache_looked_up_at
                ON rdns_cache (looked_up_at)""",
            # ── AdGuard Home integration ──────────────────────────────────────
            # adguard_logs is always a new table, so index builds are instantaneous
            # — ACCESS EXCLUSIVE lock risk is zero. Non-concurrent CREATE INDEX is
            # correct here because this block runs inside the advisory-lock transaction.
            """CREATE TABLE IF NOT EXISTS adguard_logs (
                id             BIGSERIAL PRIMARY KEY,
                timestamp      TIMESTAMPTZ NOT NULL,
                client_ip      INET,
                client_name    TEXT,
                domain         TEXT NOT NULL DEFAULT '',
                record_type    TEXT,
                reason         TEXT,
                dns_status     TEXT,
                upstream       TEXT,
                elapsed_ms     DOUBLE PRECISION,
                cached         BOOLEAN NOT NULL DEFAULT FALSE,
                answer_dnssec  BOOLEAN NOT NULL DEFAULT FALSE,
                rule_text      TEXT,
                filter_list_id INTEGER,
                inserted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )""",
            "CREATE INDEX IF NOT EXISTS idx_adguard_timestamp   ON adguard_logs (timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_adguard_client_ip   ON adguard_logs (client_ip)",
            "CREATE INDEX IF NOT EXISTS idx_adguard_domain      ON adguard_logs (domain)",
            "CREATE INDEX IF NOT EXISTS idx_adguard_reason      ON adguard_logs (reason)",
        ]
        try:
            with self.get_conn() as conn:
                with conn.cursor() as cur:
                    # Transaction-scoped advisory lock prevents race between
                    # receiver and API processes on first boot (#59).
                    # pg_advisory_xact_lock auto-releases on commit/rollback,
                    # so the lock is held until DDL is visible to other sessions.
                    cur.execute("SELECT pg_advisory_xact_lock(20250314)")
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
                        except psycopg2.errors.UniqueViolation as e:
                            cur.execute(f"ROLLBACK TO SAVEPOINT sp_{i}")
                            if e.diag.constraint_name and "pg_type" in e.diag.constraint_name:
                                logger.info("Schema type already exists, skipping: %s",
                                            e.diag.message_primary or e)
                            else:
                                raise
                        except psycopg2.errors.DuplicateObject as e:
                            cur.execute(f"ROLLBACK TO SAVEPOINT sp_{i}")
                            logger.info("Schema object already exists, skipping: %s",
                                        e.diag.message_primary or e)
                        except Exception:
                            cur.execute(f"ROLLBACK TO SAVEPOINT sp_{i}")
                            raise
                # ── Fail-fast validation ──────────────────────────────
                db_user = self.conn_params.get('user', '?')
                grant_hint = (
                    f"Run as DB superuser: GRANT ALL ON SCHEMA public TO {db_user}; "
                    f"GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO {db_user}; "
                    f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {db_user};"
                )

                with conn.cursor() as vcur:
                    vcur.execute("""SELECT 1 FROM information_schema.tables
                                   WHERE table_schema = 'public' AND table_name = 'logs'""")
                    if not vcur.fetchone():
                        logger.critical(
                            "FATAL: 'logs' table does not exist after schema migration. "
                            "The database user '%s' likely lacks CREATE TABLE privilege. %s",
                            db_user, grant_hint
                        )
                        sys.exit(1)

                    vcur.execute("""SELECT 1 FROM pg_indexes
                                   WHERE schemaname = 'public' AND indexname = 'idx_logs_timestamp'""")
                    if not vcur.fetchone():
                        logger.critical(
                            "FATAL: Critical index 'idx_logs_timestamp' missing after schema migration. "
                            "The database user '%s' likely lacks CREATE INDEX privilege. %s",
                            db_user, grant_hint
                        )
                        sys.exit(1)

                    # Issue #67: validate queue-driven backfill artifacts
                    vcur.execute("""SELECT 1 FROM information_schema.tables
                                   WHERE table_schema = 'public' AND table_name = 'threat_backfill_queue'""")
                    if not vcur.fetchone():
                        logger.critical(
                            "FATAL: 'threat_backfill_queue' table missing after schema migration. "
                            "The database user '%s' likely lacks CREATE TABLE privilege. %s",
                            db_user, grant_hint
                        )
                        sys.exit(1)

                    vcur.execute("""SELECT 1 FROM information_schema.columns
                                   WHERE table_schema = 'public' AND table_name = 'ip_threats'
                                     AND column_name = 'last_seen_at'""")
                    if not vcur.fetchone():
                        logger.critical(
                            "FATAL: 'ip_threats.last_seen_at' column missing after schema migration. "
                            "The database user '%s' likely lacks ALTER TABLE privilege. %s",
                            db_user, grant_hint
                        )
                        sys.exit(1)

                    # Verify DEFAULT exists — if SET DEFAULT was skipped due to
                    # InsufficientPrivilege, bulk_upsert_threats() would insert NULLs.
                    vcur.execute("""SELECT column_default FROM information_schema.columns
                                   WHERE table_schema = 'public' AND table_name = 'ip_threats'
                                     AND column_name = 'last_seen_at'""")
                    col_row = vcur.fetchone()
                    if not col_row or not col_row[0]:
                        logger.critical(
                            "FATAL: 'ip_threats.last_seen_at' has no DEFAULT after schema migration. "
                            "The database user '%s' likely lacks ALTER TABLE privilege to SET DEFAULT. %s",
                            db_user, grant_hint
                        )
                        sys.exit(1)

                    vcur.execute("""SELECT 1 FROM pg_indexes
                                   WHERE schemaname = 'public'
                                     AND indexname = 'idx_logs_fw_block_null_threat_src'""")
                    if not vcur.fetchone():
                        logger.critical(
                            "FATAL: Critical index 'idx_logs_fw_block_null_threat_src' missing after "
                            "schema migration. The database user '%s' likely lacks CREATE INDEX privilege. %s",
                            db_user, grant_hint
                        )
                        sys.exit(1)

                    # Issue #98: validate rdns_cache exists (loud failure if
                    # InsufficientPrivilege silently skipped the migration)
                    vcur.execute("""SELECT 1 FROM information_schema.tables
                                   WHERE table_schema = 'public' AND table_name = 'rdns_cache'""")
                    if not vcur.fetchone():
                        logger.critical(
                            "FATAL: 'rdns_cache' table missing after schema migration. "
                            "The database user '%s' likely lacks CREATE TABLE privilege. %s",
                            db_user, grant_hint
                        )
                        sys.exit(1)

                    # Validate AdGuard Home query log table and its primary index.
                    vcur.execute("""SELECT 1 FROM information_schema.tables
                                   WHERE table_schema = 'public'
                                     AND table_name = 'adguard_logs'""")
                    if not vcur.fetchone():
                        logger.critical(
                            "FATAL: 'adguard_logs' table missing after schema migration. "
                            "The database user '%s' likely lacks CREATE TABLE privilege. %s",
                            db_user, grant_hint
                        )
                        sys.exit(1)

                    vcur.execute("""SELECT 1 FROM pg_indexes
                                   WHERE schemaname = 'public'
                                     AND indexname = 'idx_adguard_timestamp'""")
                    if not vcur.fetchone():
                        logger.critical(
                            "FATAL: Critical index 'idx_adguard_timestamp' missing after schema "
                            "migration. The database user '%s' likely lacks CREATE INDEX privilege. %s",
                            db_user, grant_hint
                        )
                        sys.exit(1)
            logger.info("Schema migrations applied and validated.")
        except SystemExit:
            raise
        except Exception:
            logger.critical("Schema migration failed", exc_info=True)
            sys.exit(1)

        self._backfill_tz_timestamps()

    def ensure_post_boot_indexes(self):
        """Create heavyweight indexes and drop redundant ones for existing installs.

        Uses a dedicated autocommit connection (CONCURRENTLY cannot run inside
        a transaction).  Fresh installs get the create list from init.sql;
        this handles upgrades.  Skips creates for indexes that already exist
        and issues drops with IF EXISTS.

        A short lock_timeout is set before the drop loop so a stuck
        DROP CONCURRENTLY cannot stall receiver startup indefinitely — on
        timeout the drop retries on the next boot.

        Must be called from the receiver startup path only — not from
        Database.connect() — to avoid the API and receiver both racing on
        the same concurrent index creation.
        """
        try:
            conn = psycopg2.connect(**self.conn_params)
            conn.autocommit = True
        except Exception:
            logger.warning("Post-boot index maintenance failed (connect) — will retry next boot",
                           exc_info=True)
            return
        try:
            for idx in self._POST_BOOT_INDEXES:
                try:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT 1 FROM pg_indexes WHERE indexname = %s",
                            (idx['name'],),
                        )
                        if cur.fetchone():
                            continue  # already exists
                        logger.info("Creating %s concurrently (%s)...",
                                    idx['name'], idx['label'])
                        cur.execute(idx['sql'])
                        logger.info("Index %s created successfully", idx['name'])
                except Exception:
                    logger.warning("Could not create %s — will retry next boot",
                                   idx['name'], exc_info=True)

            # Drop redundant indexes (idempotent via IF EXISTS). Bound by a
            # short lock_timeout so a stuck DROP cannot stall receiver boot.
            # Note: lock_timeout only bounds the final ACCESS EXCLUSIVE phase;
            # a long-running query holding a snapshot that references the index
            # can still delay phase (a). The retry-next-boot loop is the real
            # safety net.
            try:
                with conn.cursor() as cur:
                    cur.execute("SET lock_timeout = '60s'")
            except Exception:
                logger.warning("Could not set lock_timeout — skipping post-boot drops, "
                               "will retry next boot", exc_info=True)
                return
            for name, sql in self._POST_BOOT_DROPS:
                try:
                    with conn.cursor() as cur:
                        logger.info("Dropping redundant index %s...", name)
                        cur.execute(sql)
                        logger.info("Index %s dropped (if it existed)", name)
                except Exception:
                    logger.warning("Could not drop %s — will retry next boot",
                                   name, exc_info=True)
        finally:
            conn.close()


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
        """Get a connection from the pool. Discards broken connections."""
        conn = self.pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception:
            if not conn.closed:
                conn.rollback()
            raise
        finally:
            self.pool.putconn(conn, close=bool(conn.closed))

    def insert_log(self, parsed: dict):
        """Insert a single parsed log entry."""
        values = tuple(parsed.get(col) for col in INSERT_COLUMNS)

        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(INSERT_SQL, values)

    def _execute_log_insert(self, cur, logs: list[dict]):
        """Shared insert helper: build rows and execute_batch on a caller-owned cursor.

        Does NOT commit, rollback, or manage connections — caller controls the
        transaction boundary.  Used by both syslog (with fallback) and Pi-hole
        (strict, no fallback) insert paths.
        """
        rows = [tuple(log.get(col) for col in INSERT_COLUMNS) for log in logs]
        cur.execute("SET LOCAL statement_timeout = '30s'")
        extras.execute_batch(cur, INSERT_SQL, rows, page_size=100)
        return len(rows)

    def insert_logs_batch(self, logs: list[dict]):
        """Insert multiple parsed log entries in a single transaction.

        If batch insert fails, falls back to row-by-row to isolate bad data.
        Sets a 30s statement timeout to prevent hung inserts from blocking the
        UDP receive loop (which causes silent packet loss).
        """
        if not logs:
            return

        try:
            with self.get_conn() as conn:
                with conn.cursor() as cur:
                    self._execute_log_insert(cur, logs)
            logger.debug("Batch inserted %d logs", len(logs))
        except Exception as batch_err:
            logger.warning("Batch insert failed (%s), falling back to row-by-row for %d logs",
                          batch_err, len(logs))
            inserted = 0
            dropped = 0
            rows = [tuple(log.get(col) for col in INSERT_COLUMNS) for log in logs]
            for row in rows:
                try:
                    with self.get_conn() as conn:
                        with conn.cursor() as cur:
                            cur.execute("SET LOCAL statement_timeout = '10s'")
                            cur.execute(INSERT_SQL, row)
                    inserted += 1
                except Exception as row_err:
                    dropped += 1
                    logger.warning("Dropped bad log row: %s — raw: %.200s", row_err, row[-1] if row else '?')
            logger.info("Row-by-row fallback: %d inserted, %d dropped", inserted, dropped)

    def insert_adguard_batch(
        self,
        entries: list[dict],
        new_cursor: str | None = None,
        expected_host: str | None = None,
    ) -> int:
        """Insert a batch of AdGuard Home query log entries and advance the cursor atomically.

        The cursor update (adguard_cursor in system_config) is committed in the
        same transaction as the row inserts, so only a transaction-commit failure
        can cause partial application — an extremely rare event.

        If ``expected_host`` is provided, the DB value of ``adguard_host`` is
        re-read *inside* the transaction and compared before any inserts occur.
        If they differ, ``AdGuardHostMismatch`` is raised and the transaction is
        rolled back, preventing cursor corruption when the config changes
        between the start of a poll cycle and the DB write.

        Returns the number of rows inserted.
        """
        if not entries:
            return 0
        sql = """
            INSERT INTO adguard_logs
                (timestamp, client_ip, client_name, domain, record_type,
                 reason, dns_status, upstream, elapsed_ms, cached,
                 answer_dnssec, rule_text, filter_list_id)
            VALUES
                (%(timestamp)s, %(client_ip)s, %(client_name)s, %(domain)s,
                 %(record_type)s, %(reason)s, %(dns_status)s, %(upstream)s,
                 %(elapsed_ms)s, %(cached)s, %(answer_dnssec)s,
                 %(rule_text)s, %(filter_list_id)s)
        """
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                if expected_host is not None:
                    # Re-read the host inside this transaction to close the TOCTOU
                    # window between the poll snapshot and the DB write.
                    cur.execute(
                        "SELECT value FROM system_config WHERE key = 'adguard_host'"
                    )
                    row = cur.fetchone()
                    db_host = (row[0] or '').strip().rstrip('/') if row else ''
                    expected_host_norm = expected_host.strip().rstrip('/')
                    if db_host != expected_host_norm:
                        raise AdGuardHostMismatch(
                            f"expected {expected_host_norm!r}, DB has {db_host!r}"
                        )
                extras.execute_batch(cur, sql, entries, page_size=100)
                # execute_batch runs multiple internal rounds; cur.rowcount only
                # reflects the last round. Use len(entries) — no ON CONFLICT clause
                # means every row is inserted unconditionally.
                inserted = len(entries)
                if new_cursor:
                    cur.execute(
                        """INSERT INTO system_config (key, value, updated_at)
                               VALUES ('adguard_cursor', %s::jsonb, NOW())
                               ON CONFLICT (key) DO UPDATE
                               SET value = EXCLUDED.value, updated_at = NOW()""",
                        [Json(new_cursor)],
                    )
        return inserted

    def insert_pihole_batch(self, logs: list[dict], new_cursor: int):
        """Atomic insert of Pi-hole logs + cursor update. No row-by-row fallback.

        Uses _execute_log_insert() for the shared insert logic, then updates
        the cursor in the same transaction.  On ANY failure the entire
        transaction rolls back — no partial inserts, no cursor drift.
        """
        if not logs:
            return
        conn = self.pool.getconn()
        failed = False
        try:
            with conn.cursor() as cur:
                self._execute_log_insert(cur, logs)
                cur.execute(
                    """INSERT INTO system_config (key, value, updated_at)
                       VALUES ('pihole_last_cursor', %s::jsonb, NOW())
                       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()""",
                    [str(new_cursor)]
                )
            conn.commit()
            logger.debug("Pi-hole batch: inserted %d logs, cursor=%d", len(logs), new_cursor)
        except Exception:
            failed = True
            conn.rollback()
            raise
        finally:
            self.pool.putconn(conn, close=failed)

    # ── Retention cleanup ────────────────────────────────────────────────────

    RETENTION_BATCH_SIZE = 5_000

    @staticmethod
    def validate_retention_days(general_days: int, dns_days: int):
        """Post-resolution invariant check: the given values must already be
        positive Python ints. Raises ValueError on bad input.

        This is stricter than `parse_retention_days` by design:
          - `parse_retention_days` is the input-validation entry point —
            accepts any coercible value (strings, ints), used by the resolver
            and the POST/import route handlers.
          - `validate_retention_days` is a post-resolution sanity check —
            used by `run_retention_cleanup` and `run_retention_cleanup_now`
            to catch wiring bugs where a non-int value somehow reached a
            code path that expected resolved, already-validated integers.

        If both functions still exist after this refactor, it is because
        they run at different lifecycle stages, not because the validation
        rules are duplicated — the parser owns the acceptance rules; this
        function owns the type-contract invariant.
        """
        if not isinstance(general_days, int) or not isinstance(dns_days, int):
            raise ValueError(
                f"retention days must be integers (general={general_days!r}, dns={dns_days!r})"
            )
        if general_days <= 0 or dns_days <= 0:
            raise ValueError(
                f"retention days must be positive (general={general_days}, dns={dns_days})"
            )

    @staticmethod
    def resolve_retention_days(db) -> RetentionDaysConfig:
        """Resolve general + DNS retention days from config > env > default.

        Invalid values at any level fall through to the next level. General and
        DNS resolve independently and may come from different sources in the
        same call. Uses the shared `parse_retention_days` helper so the parse
        and range logic lives in exactly one place.

        Returns a NamedTuple so callers write `cfg.general` / `cfg.dns_source`
        and never depend on field order. NamedTuples still compare equal to
        plain tuples, so existing test assertions that use positional literals
        (e.g. `== (60, 'default', 10, 'default')`) keep working unchanged.
        """
        def _resolve_one(ui_key: str, env_key: str, default: int) -> tuple[int, str]:
            ui = parse_retention_days(db.get_config(ui_key))
            if ui is not None:
                return (ui, 'ui')
            env = parse_retention_days(os.environ.get(env_key))
            if env is not None:
                return (env, 'env')
            return (default, 'default')

        general, general_source = _resolve_one('retention_days', 'RETENTION_DAYS', 60)
        dns, dns_source = _resolve_one('dns_retention_days', 'DNS_RETENTION_DAYS', 10)
        return RetentionDaysConfig(general, general_source, dns, dns_source)

    @staticmethod
    def resolve_retention_time(db) -> RetentionTimeConfig:
        """Resolve retention cleanup time (HH:MM) from config > env > default.

        Env precedence: RETENTION_CLEANUP_TIME (canonical) > RETENTION_TIME
        (deprecated — v3.6.2 introduced this name, v3.6.3 renamed it). The
        legacy name is still honored for one release so existing deployments
        don't silently revert to the default, but its use logs a WARNING
        (once per process) telling operators to rename.

        An invalid `system_config` value does NOT short-circuit to default —
        env is still consulted. Uses the shared `parse_retention_time` helper
        so the parse-and-range logic lives in exactly one place.

        Made a staticmethod (not instance method) because signal-handler code
        in main.py calls it with an arbitrary Database reference and a pure
        function is easier to test.
        """
        global _legacy_retention_time_warned

        ui = parse_retention_time(db.get_config('retention_time'))
        if ui is not None:
            return RetentionTimeConfig(ui, 'ui')

        # Canonical env var
        env = parse_retention_time(os.environ.get('RETENTION_CLEANUP_TIME'))
        if env is not None:
            return RetentionTimeConfig(env, 'env')

        # Legacy env var (deprecated in v3.6.3). Honour it but warn — once.
        legacy = parse_retention_time(os.environ.get('RETENTION_TIME'))
        if legacy is not None:
            if not _legacy_retention_time_warned:
                logger.warning(
                    "RETENTION_TIME env var is deprecated; rename to "
                    "RETENTION_CLEANUP_TIME. The fallback will be removed "
                    "in a future release."
                )
                _legacy_retention_time_warned = True
            return RetentionTimeConfig(legacy, 'env')

        return RetentionTimeConfig('03:00', 'default')

    def run_retention_cleanup(self, general_days: int = 60, dns_days: int = 10,
                              progress_cb=None) -> dict:
        """Delete expired logs in small batches to avoid long-held locks.

        Two separate passes (DNS / non-DNS) let each use its own index:
          - DNS pass:     idx_logs_type_time (log_type, timestamp DESC)
          - non-DNS pass: idx_logs_nondns_timestamp (timestamp DESC) WHERE log_type != 'dns'

        Each batch commits immediately so autovacuum can reclaim dead tuples
        incrementally.

        Args:
            general_days: Retention period for non-DNS logs.
            dns_days: Retention period for DNS logs.
            progress_cb: Optional callable(dict) invoked after each batch with
                         current progress state.  Used by the async job route.

        Returns:
            Structured result dict with keys: status, dns_deleted,
            non_dns_deleted, deleted_so_far, batches_completed, error.
        """
        from datetime import datetime, timezone, timedelta

        self.validate_retention_days(general_days, dns_days)

        batch_size = self.RETENTION_BATCH_SIZE
        now = datetime.now(timezone.utc)
        passes = [
            ("dns",     "log_type = 'dns'",  now - timedelta(days=dns_days)),
            ("non_dns", "log_type != 'dns'", now - timedelta(days=general_days)),
        ]

        result = {
            'status': 'complete',
            'dns_deleted': 0,
            'non_dns_deleted': 0,
            'deleted_so_far': 0,
            'batches_completed': 0,
            'error': None,
        }

        try:
            for label, type_filter, cutoff in passes:
                while True:
                    with self.get_conn() as conn:
                        with conn.cursor() as cur:
                            # type_filter is from the hardcoded passes list
                            # above — never user input. cutoff and batch_size
                            # remain bound parameters.
                            cur.execute(
                                f"DELETE FROM logs WHERE id IN ("
                                f"  SELECT id FROM logs"
                                f"  WHERE {type_filter} AND timestamp < %s"
                                f"  ORDER BY timestamp ASC"
                                f"  LIMIT %s"
                                f"  FOR UPDATE SKIP LOCKED"
                                f")",
                                [cutoff, batch_size],
                            )
                            n = cur.rowcount
                    if n == 0:
                        break
                    result[f'{label}_deleted'] += n
                    result['deleted_so_far'] += n
                    result['batches_completed'] += 1
                    logger.debug("Retention %s: batch %d — deleted %d rows",
                                 label, result['batches_completed'], n)
                    if progress_cb:
                        progress_cb({**result, 'phase': label})
        except Exception as exc:
            result['error'] = str(exc)
            result['status'] = 'partial' if result['deleted_so_far'] > 0 else 'failed'
            logger.error("Retention cleanup %s: %d rows deleted before error: %s",
                         result['status'], result['deleted_so_far'], exc)
            return result

        # Always log completion — including zero-row runs — so operators can
        # confirm the cleanup fired even on quiet days. Previously gated on
        # deleted_so_far > 0, which made successful no-op runs indistinguishable
        # from the job never firing at all.
        logger.info("Retention cleanup: deleted %d old logs "
                    "(dns_deleted=%d, non_dns_deleted=%d, "
                    "general_retention=%d days, dns_retention=%d days)",
                    result['deleted_so_far'], result['dns_deleted'],
                    result['non_dns_deleted'], general_days, dns_days)
        return result

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
                    "looked_up_at, last_seen_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW()) "
                    "ON CONFLICT (ip) DO UPDATE SET "
                    "  threat_score = EXCLUDED.threat_score, "
                    "  threat_categories = EXCLUDED.threat_categories, "
                    "  abuse_usage_type = COALESCE(EXCLUDED.abuse_usage_type, ip_threats.abuse_usage_type), "
                    "  abuse_hostnames = COALESCE(EXCLUDED.abuse_hostnames, ip_threats.abuse_hostnames), "
                    "  abuse_total_reports = COALESCE(EXCLUDED.abuse_total_reports, ip_threats.abuse_total_reports), "
                    "  abuse_last_reported = COALESCE(EXCLUDED.abuse_last_reported, ip_threats.abuse_last_reported), "
                    "  abuse_is_whitelisted = COALESCE(EXCLUDED.abuse_is_whitelisted, ip_threats.abuse_is_whitelisted), "
                    "  abuse_is_tor = COALESCE(EXCLUDED.abuse_is_tor, ip_threats.abuse_is_tor), "
                    "  looked_up_at = NOW(), "
                    "  last_seen_at = NOW()",
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
        The daily blacklist import is treated as a high-signal operator-facing
        classification. Existing multi-category check-API results are preserved,
        but rows with only 0/1 categories may be normalized back to
        ["blacklist"] so the cache keeps the stronger, less noisy label.
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
            "      THEN ip_threats.threat_categories "  # keep existing multi-category detail
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

    # ── Threat backfill queue (issue #67) ────────────────────────────────────

    def touch_threat_last_seen(self, ip: str):
        """Update last_seen_at on an existing ip_threats row (PK lookup)."""
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ip_threats SET last_seen_at = NOW() WHERE ip = %s",
                    [ip]
                )

    def enqueue_threat_backfill(self, ip: str, source: str = 'live_miss'):
        """Enqueue an IP for deferred AbuseIPDB lookup.

        Uses GREATEST on next_retry_at to preserve worker backoff: if the worker
        set a future retry time after a 429/timeout, a new sighting won't pull
        it back to NOW().
        """
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO threat_backfill_queue "
                    "(ip, source, first_seen_at, last_seen_at, next_retry_at) "
                    "VALUES (%s, %s, NOW(), NOW(), NOW()) "
                    "ON CONFLICT (ip) DO UPDATE "
                    "SET last_seen_at = NOW(), "
                    "    next_retry_at = GREATEST(threat_backfill_queue.next_retry_at, NOW())",
                    [ip, source]
                )

    def pull_due_queue_batch(self, limit: int = 50) -> list[str]:
        """Pull a batch of IPs due for backfill lookup.

        Returns bare IP strings (no /32 suffix). Uses FOR UPDATE SKIP LOCKED
        for single-worker safety.
        """
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "WITH due AS ("
                    "  SELECT ip FROM threat_backfill_queue "
                    "  WHERE next_retry_at <= NOW() "
                    "  ORDER BY next_retry_at ASC, last_seen_at DESC "
                    "  LIMIT %s "
                    "  FOR UPDATE SKIP LOCKED"
                    ") SELECT host(ip) FROM due",
                    [limit]
                )
                return [row[0] for row in cur.fetchall()]

    def delete_queue_rows(self, ips: list[str]):
        """Remove successfully processed IPs from the backfill queue."""
        if not ips:
            return
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM threat_backfill_queue WHERE ip = ANY(%s::inet[])",
                    [ips]
                )

    def fail_queue_rows(self, ips: list[str], error: str, base_delay: int = 300):
        """Mark queue rows as failed with exponential backoff.

        base_delay is in seconds (default 5 minutes). Backoff doubles per attempt,
        capped at 24 hours.
        """
        if not ips:
            return
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE threat_backfill_queue "
                    "SET attempts = attempts + 1, "
                    "    last_error = %s, "
                    "    next_retry_at = NOW() + LEAST("
                    "      make_interval(secs => %s * power(2, attempts)), "
                    "      INTERVAL '24 hours'"
                    "    ) "
                    "WHERE ip = ANY(%s::inet[])",
                    [error, base_delay, ips]
                )

    def patch_from_cache_for_ips(self, ips: list[str], wan_ips: list[str]):
        """Targeted: copy threat data from ip_threats to logs for specific IPs.

        Two passes (src_ip, dst_ip) with WAN IP exclusion.
        """
        if not ips:
            return 0
        total = 0
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                # Pass 1: src_ip
                cur.execute(
                    "UPDATE logs "
                    "SET threat_score = t.threat_score, "
                    "    threat_categories = t.threat_categories, "
                    "    abuse_usage_type = COALESCE(logs.abuse_usage_type, t.abuse_usage_type), "
                    "    abuse_hostnames = COALESCE(logs.abuse_hostnames, t.abuse_hostnames), "
                    "    abuse_total_reports = COALESCE(logs.abuse_total_reports, t.abuse_total_reports), "
                    "    abuse_last_reported = COALESCE(logs.abuse_last_reported, t.abuse_last_reported), "
                    "    abuse_is_whitelisted = COALESCE(logs.abuse_is_whitelisted, t.abuse_is_whitelisted), "
                    "    abuse_is_tor = COALESCE(logs.abuse_is_tor, t.abuse_is_tor) "
                    "FROM ip_threats t "
                    "WHERE logs.src_ip = t.ip "
                    "  AND t.ip = ANY(%s::inet[]) "
                    "  AND NOT (logs.src_ip = ANY(%s::inet[])) "
                    "  AND logs.threat_score IS NULL "
                    "  AND logs.log_type = 'firewall' "
                    "  AND logs.rule_action = 'block'",
                    [ips, wan_ips]
                )
                total += cur.rowcount
                # Pass 2: dst_ip
                cur.execute(
                    "UPDATE logs "
                    "SET threat_score = t.threat_score, "
                    "    threat_categories = t.threat_categories, "
                    "    abuse_usage_type = COALESCE(logs.abuse_usage_type, t.abuse_usage_type), "
                    "    abuse_hostnames = COALESCE(logs.abuse_hostnames, t.abuse_hostnames), "
                    "    abuse_total_reports = COALESCE(logs.abuse_total_reports, t.abuse_total_reports), "
                    "    abuse_last_reported = COALESCE(logs.abuse_last_reported, t.abuse_last_reported), "
                    "    abuse_is_whitelisted = COALESCE(logs.abuse_is_whitelisted, t.abuse_is_whitelisted), "
                    "    abuse_is_tor = COALESCE(logs.abuse_is_tor, t.abuse_is_tor) "
                    "FROM ip_threats t "
                    "WHERE logs.dst_ip = t.ip "
                    "  AND t.ip = ANY(%s::inet[]) "
                    "  AND NOT (logs.dst_ip = ANY(%s::inet[])) "
                    "  AND logs.threat_score IS NULL "
                    "  AND logs.log_type = 'firewall' "
                    "  AND logs.rule_action = 'block'",
                    [ips, wan_ips]
                )
                total += cur.rowcount
        return total

    def patch_abuse_fields_for_ips(self, ips: list[str], wan_ips: list[str]):
        """Targeted: copy abuse detail from ip_threats to logs for specific IPs.

        Only updates rows that have a threat_score but are missing abuse detail.
        Two passes (src_ip, dst_ip) with WAN IP exclusion.
        """
        if not ips:
            return 0
        total = 0
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                # Pass 1: src_ip
                cur.execute(
                    "UPDATE logs "
                    "SET abuse_usage_type = t.abuse_usage_type, "
                    "    abuse_hostnames = t.abuse_hostnames, "
                    "    abuse_total_reports = t.abuse_total_reports, "
                    "    abuse_last_reported = t.abuse_last_reported, "
                    "    abuse_is_whitelisted = t.abuse_is_whitelisted, "
                    "    abuse_is_tor = t.abuse_is_tor, "
                    "    threat_categories = CASE "
                    "        WHEN t.threat_categories IS NOT NULL "
                    "             AND array_length(t.threat_categories, 1) > 0 "
                    "             AND (logs.threat_categories IS NULL "
                    "                  OR array_length(logs.threat_categories, 1) IS NULL "
                    "                  OR array_length(logs.threat_categories, 1) = 0) "
                    "        THEN t.threat_categories "
                    "        ELSE logs.threat_categories "
                    "    END "
                    "FROM ip_threats t "
                    "WHERE logs.src_ip = t.ip "
                    "  AND t.ip = ANY(%s::inet[]) "
                    "  AND NOT (logs.src_ip = ANY(%s::inet[])) "
                    "  AND logs.threat_score IS NOT NULL "
                    "  AND logs.abuse_usage_type IS NULL "
                    "  AND (t.abuse_usage_type IS NOT NULL OR t.abuse_hostnames IS NOT NULL "
                    "       OR t.abuse_total_reports IS NOT NULL OR t.abuse_last_reported IS NOT NULL "
                    "       OR t.abuse_is_whitelisted IS NOT NULL OR t.abuse_is_tor IS NOT NULL) "
                    "  AND logs.log_type = 'firewall' "
                    "  AND logs.rule_action = 'block'",
                    [ips, wan_ips]
                )
                total += cur.rowcount
                # Pass 2: dst_ip
                cur.execute(
                    "UPDATE logs "
                    "SET abuse_usage_type = t.abuse_usage_type, "
                    "    abuse_hostnames = t.abuse_hostnames, "
                    "    abuse_total_reports = t.abuse_total_reports, "
                    "    abuse_last_reported = t.abuse_last_reported, "
                    "    abuse_is_whitelisted = t.abuse_is_whitelisted, "
                    "    abuse_is_tor = t.abuse_is_tor, "
                    "    threat_categories = CASE "
                    "        WHEN t.threat_categories IS NOT NULL "
                    "             AND array_length(t.threat_categories, 1) > 0 "
                    "             AND (logs.threat_categories IS NULL "
                    "                  OR array_length(logs.threat_categories, 1) IS NULL "
                    "                  OR array_length(logs.threat_categories, 1) = 0) "
                    "        THEN t.threat_categories "
                    "        ELSE logs.threat_categories "
                    "    END "
                    "FROM ip_threats t "
                    "WHERE logs.dst_ip = t.ip "
                    "  AND t.ip = ANY(%s::inet[]) "
                    "  AND NOT (logs.dst_ip = ANY(%s::inet[])) "
                    "  AND logs.threat_score IS NOT NULL "
                    "  AND logs.abuse_usage_type IS NULL "
                    "  AND (t.abuse_usage_type IS NOT NULL OR t.abuse_hostnames IS NOT NULL "
                    "       OR t.abuse_total_reports IS NOT NULL OR t.abuse_last_reported IS NOT NULL "
                    "       OR t.abuse_is_whitelisted IS NOT NULL OR t.abuse_is_tor IS NOT NULL) "
                    "  AND logs.log_type = 'firewall' "
                    "  AND logs.rule_action = 'block'",
                    [ips, wan_ips]
                )
                total += cur.rowcount
        return total

    def get_stale_threat_candidates(self, limit: int = 10) -> list[str]:
        """Select IPs from ip_threats that need re-enrichment.

        Prioritizes recently-seen, high-score IPs missing ALL abuse detail.
        IPs that already have any detail field populated are considered complete.
        No logs join — uses last_seen_at directly.
        """
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT host(ip) FROM ip_threats "
                    "WHERE threat_score > 0 "
                    "  AND abuse_usage_type IS NULL "
                    "  AND abuse_hostnames IS NULL "
                    "  AND abuse_total_reports IS NULL "
                    "  AND abuse_last_reported IS NULL "
                    "  AND abuse_is_whitelisted IS NULL "
                    "  AND abuse_is_tor IS NULL "
                    "  AND looked_up_at < NOW() - INTERVAL '7 days' "
                    "ORDER BY last_seen_at DESC NULLS LAST, threat_score DESC "
                    "LIMIT %s",
                    [limit]
                )
                return [row[0] for row in cur.fetchall()]

    def service_name_backfill_batch(self, last_id: int, batch_size: int = 1000):
        """Read a batch of firewall logs missing service_name for one-shot migration.

        Returns list of (id, dst_port, protocol) tuples.
        """
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, dst_port, protocol FROM logs "
                    "WHERE id > %s "
                    "  AND log_type = 'firewall' "
                    "  AND service_name IS NULL "
                    "  AND dst_port IS NOT NULL "
                    "ORDER BY id LIMIT %s",
                    [last_id, batch_size]
                )
                return cur.fetchall()

    def patch_service_names(self, updates: list[tuple]):
        """Batch update service_name for specific log IDs.

        updates = [(id, service_name), ...]
        """
        if not updates:
            return 0
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                extras.execute_batch(
                    cur,
                    "UPDATE logs SET service_name = %s WHERE id = %s AND service_name IS NULL",
                    [(name, log_id) for log_id, name in updates],
                    page_size=500
                )
                return len(updates)

    def get_queue_stats(self) -> dict:
        """Return queue statistics for logging/monitoring."""
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*), "
                    "  COUNT(*) FILTER (WHERE next_retry_at <= NOW()), "
                    "  COUNT(*) FILTER (WHERE attempts > 0) "
                    "FROM threat_backfill_queue"
                )
                row = cur.fetchone()
                return {
                    'total': row[0],
                    'due': row[1],
                    'retried': row[2],
                }

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


    # ── rDNS cache (issue #98) ───────────────────────────────────────────────

    def get_rdns_cache(self, ip: str) -> Optional[dict]:
        """Read-through DB cache for reverse-DNS results.

        Returns {'hostname': str|None, 'status': 'success'|'failure'|'transient',
        'age_seconds': int} or None if no row exists. Age is computed inline so
        the caller can compare against per-status TTLs without a second query.
        """
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT hostname, status, "
                    "       EXTRACT(EPOCH FROM NOW() - looked_up_at)::bigint AS age_seconds "
                    "FROM rdns_cache WHERE ip = %s",
                    [ip]
                )
                row = cur.fetchone()
                if not row:
                    return None
                return {
                    'hostname': row[0],
                    'status': row[1],
                    'age_seconds': int(row[2]),
                }

    def set_rdns_cache(self, ip: str, hostname: Optional[str], status: str):
        """Upsert an rDNS cache entry. Always refreshes looked_up_at."""
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO rdns_cache (ip, hostname, status, looked_up_at) "
                    "VALUES (%s, %s, %s, NOW()) "
                    "ON CONFLICT (ip) DO UPDATE SET "
                    "  hostname = EXCLUDED.hostname, "
                    "  status = EXCLUDED.status, "
                    "  looked_up_at = NOW()",
                    [ip, hostname, status]
                )

    def cleanup_rdns_cache(self) -> int:
        """Delete rdns_cache rows older than the longest TTL + 1d slack.

        Returns deleted row count. 8 days = 7d (longest TTL = failure) + 1d slack.
        Any row older than that is expired by every status policy and unreachable
        for read-through hits. Cheap — uses idx_rdns_cache_looked_up_at.
        """
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM rdns_cache "
                    "WHERE looked_up_at < NOW() - INTERVAL '8 days'"
                )
                return cur.rowcount


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
    def persist_network_identity(
        self,
        *,
        wan_ip_by_iface: dict[str, str] | None = None,
        gateway_ip_vlans: dict[str, dict] | None = None,
    ) -> None:
        """Persist WAN/gateway identity derived from UniFi API data.

        Writes only non-empty values.  Missing/empty inputs do not clear
        last-known-good persisted values.  wan_ip_names stays outside this
        helper (poll-specific).
        """
        if wan_ip_by_iface:
            self.set_config('wan_ip_by_iface', wan_ip_by_iface)
            # Derive ordered wan_ips following configured wan_interfaces order
            cfg_wan_ifaces = self.get_config('wan_interfaces') or []
            wan_ips = [wan_ip_by_iface[iface] for iface in cfg_wan_ifaces
                       if iface in wan_ip_by_iface]
            if wan_ips:
                self.set_config('wan_ips', wan_ips)
                self.set_config('wan_ip', wan_ips[0])

        if gateway_ip_vlans:
            self.set_config('gateway_ip_vlans', gateway_ip_vlans)
            self.set_config('gateway_ips', sorted(gateway_ip_vlans.keys()))

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
                           MODE() WITHIN GROUP (ORDER BY host(dst_ip)) AS wan_ip
                    FROM logs
                    WHERE log_type = 'firewall'
                      AND interface_in IN ({placeholders})
                      AND dst_ip IS NOT NULL
                      AND {self._PRIVATE_IP_FILTER}
                    GROUP BY interface_in
                """, interfaces)
                return {row[0]: row[1] for row in cur.fetchall() if row[1]}

    def detect_wan_ip(self) -> str | None:
        """Detect WAN IPs from logs and persist to system_config.

        Only called when unifi_enabled is false (gated by caller).
        Computes per-interface WAN IPs from logs via
        get_wan_ips_by_interface() and stores wan_ip_by_iface automatically.

        Returns the primary detected WAN IP or None.

        .. deprecated:: Phase 1 transition
            Retained for phase-1 transition only (non-UniFi installs).
            Removal target: phase 2 log-detection decommission.
        """
        wan_interfaces = self.get_config('wan_interfaces', ['ppp0'])
        if not wan_interfaces:
            return None

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

        .. deprecated:: Phase 1 transition
            Retained for phase-1 transition only (non-UniFi installs).
            Removal target: phase 2 log-detection decommission.

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

        .. deprecated:: Phase 1 transition
            Retained for phase-1 transition only (log-detection wizard).
            Removal target: phase 2 log-detection decommission.
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


def parse_vpn_config(raw) -> dict:
    """Parse vpn_networks config value into a dict, handling all storage forms."""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, ValueError):
            return {}
    return {}


def count_logs(db, log_type='firewall'):
    """Count logs by type."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM logs WHERE log_type = %s", [log_type])
            return cur.fetchone()[0]
