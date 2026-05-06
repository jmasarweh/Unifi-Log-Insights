-- UniFi Log Insight schema

CREATE TABLE IF NOT EXISTS logs (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL,
    log_type    VARCHAR(20) NOT NULL,  -- firewall, dhcp, dns, wifi, ids
    direction   VARCHAR(20),           -- inbound, outbound, inter_vlan, nat
    src_ip      INET,
    src_port    INTEGER,
    dst_ip      INET,
    dst_port    INTEGER,
    protocol    VARCHAR(10),
    service_name TEXT,
    rule_name   VARCHAR(100),
    rule_desc   VARCHAR(255),
    rule_action VARCHAR(20),           -- allow, block, redirect
    interface_in  VARCHAR(20),
    interface_out VARCHAR(20),
    mac_address MACADDR,
    hostname    VARCHAR(255),
    dns_query   VARCHAR(255),
    dns_type    VARCHAR(10),
    dns_answer  VARCHAR(255),
    dhcp_event  VARCHAR(20),           -- DHCPACK, DHCPDISCOVER, DHCPOFFER, DHCPREQUEST
    wifi_event  VARCHAR(50),
    geo_country VARCHAR(2),
    geo_city    VARCHAR(100),
    geo_lat     DECIMAL(9,6),
    geo_lon     DECIMAL(9,6),
    asn_number  INTEGER,
    asn_name    VARCHAR(255),
    threat_score    INTEGER,           -- 0-100 from AbuseIPDB
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
    raw_log     TEXT NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_logs_timestamp    ON logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_src_ip       ON logs (src_ip);
CREATE INDEX IF NOT EXISTS idx_logs_dst_ip       ON logs (dst_ip);
CREATE INDEX IF NOT EXISTS idx_logs_direction    ON logs (direction);
CREATE INDEX IF NOT EXISTS idx_logs_threat_score ON logs (threat_score) WHERE threat_score IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_logs_service_name ON logs (service_name) WHERE service_name IS NOT NULL;

-- Composite index for common filtered queries
CREATE INDEX IF NOT EXISTS idx_logs_type_time    ON logs (log_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_action_time  ON logs (rule_action, timestamp DESC);

-- Partial index for non-DNS retention cleanup batches.
-- run_retention_cleanup() deletes WHERE log_type != 'dns' AND timestamp < cutoff.
-- Without this index the non-DNS pass cannot use idx_logs_type_time (equality-only
-- on log_type) and falls back to a sequential scan on 165M rows.
-- With this index each LIMIT-N batch resolves as a constant O(N) range scan.
CREATE INDEX IF NOT EXISTS idx_logs_nondns_timestamp
    ON logs (timestamp DESC)
    WHERE log_type != 'dns';

-- Composite index for flow aggregation (Sankey + IP Pairs)
CREATE INDEX IF NOT EXISTS idx_logs_flow_agg
    ON logs (timestamp DESC, src_ip, dst_ip, dst_port, protocol)
    WHERE log_type = 'firewall' AND src_ip IS NOT NULL AND dst_ip IS NOT NULL;

-- Zone matrix aggregation (interface-to-interface traffic)
CREATE INDEX IF NOT EXISTS idx_logs_zone_matrix
    ON logs (timestamp DESC, interface_in, interface_out, rule_action)
    WHERE log_type = 'firewall' AND interface_in IS NOT NULL AND interface_out IS NOT NULL;

-- Indexes for newly exposed filters
CREATE INDEX IF NOT EXISTS idx_logs_src_port     ON logs (src_port) WHERE src_port IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_logs_dst_port     ON logs (dst_port) WHERE dst_port IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_logs_protocol     ON logs (protocol) WHERE protocol IS NOT NULL;

-- Targeted backfill indexes (issue #67: avoid full-table scans)
CREATE INDEX IF NOT EXISTS idx_logs_fw_block_null_threat_src
    ON logs (src_ip)
    WHERE log_type = 'firewall' AND rule_action = 'block'
      AND threat_score IS NULL AND src_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_logs_fw_block_null_threat_dst
    ON logs (dst_ip)
    WHERE log_type = 'firewall' AND rule_action = 'block'
      AND threat_score IS NULL AND dst_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_logs_fw_block_missing_abuse_src
    ON logs (src_ip)
    WHERE log_type = 'firewall' AND rule_action = 'block'
      AND threat_score IS NOT NULL AND abuse_usage_type IS NULL AND src_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_logs_fw_block_missing_abuse_dst
    ON logs (dst_ip)
    WHERE log_type = 'firewall' AND rule_action = 'block'
      AND threat_score IS NOT NULL AND abuse_usage_type IS NULL AND dst_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_logs_fw_service_name_null_id
    ON logs (id)
    WHERE log_type = 'firewall' AND service_name IS NULL AND dst_port IS NOT NULL;

-- SP-GiST index for WAN IP detection queries (Issue 72 fallback)
CREATE INDEX IF NOT EXISTS idx_logs_spgist_dst_ip_firewall
    ON logs USING spgist (dst_ip)
    WHERE log_type = 'firewall';

-- Composite index for type-scoped purge batches and COUNT/MAX snapshots.
-- Enables O(N) batch scans for DELETE … WHERE log_type = X AND id <= Y LIMIT N
-- instead of O(total-rows-of-type) heap-sorts on large tables.
CREATE INDEX IF NOT EXISTS idx_logs_type_id ON logs (log_type, id);

-- AbuseIPDB threat score cache (persistent across restarts)
CREATE TABLE IF NOT EXISTS ip_threats (
    ip              INET PRIMARY KEY,
    threat_score    INTEGER NOT NULL DEFAULT 0,
    threat_categories TEXT[],
    looked_up_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    abuse_usage_type TEXT,
    abuse_hostnames TEXT,
    abuse_total_reports INTEGER,
    abuse_last_reported TIMESTAMPTZ,
    abuse_is_whitelisted BOOLEAN,
    abuse_is_tor BOOLEAN,
    last_seen_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_threats_looked_up ON ip_threats (looked_up_at);
CREATE INDEX IF NOT EXISTS idx_ip_threats_reenrich_candidates
    ON ip_threats (last_seen_at DESC, threat_score DESC)
    WHERE threat_score > 0
      AND abuse_usage_type IS NULL AND abuse_hostnames IS NULL
      AND abuse_total_reports IS NULL AND abuse_last_reported IS NULL
      AND abuse_is_whitelisted IS NULL AND abuse_is_tor IS NULL;

-- Deferred threat enrichment queue (issue #67: replaces sweep-style backfill)
CREATE TABLE IF NOT EXISTS threat_backfill_queue (
    ip            INET PRIMARY KEY,
    source        TEXT NOT NULL DEFAULT 'live_miss',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    next_retry_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempts      INTEGER NOT NULL DEFAULT 0,
    last_error    TEXT
);
CREATE INDEX IF NOT EXISTS idx_threat_backfill_queue_due
    ON threat_backfill_queue (next_retry_at, last_seen_at DESC);

-- UniFi client cache (Phase 2: IP-to-device-name enrichment)
CREATE TABLE IF NOT EXISTS unifi_clients (
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
);
CREATE INDEX IF NOT EXISTS idx_unifi_clients_ip ON unifi_clients (ip);
CREATE INDEX IF NOT EXISTS idx_unifi_clients_name ON unifi_clients (device_name) WHERE device_name IS NOT NULL;

-- UniFi infrastructure device cache (Phase 2)
CREATE TABLE IF NOT EXISTS unifi_devices (
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
);
CREATE INDEX IF NOT EXISTS idx_unifi_devices_ip ON unifi_devices (ip);

-- Dynamic configuration store (setup wizard, interface labels, etc.)
CREATE TABLE IF NOT EXISTS system_config (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── Authentication ──────────────────────────────────────────────────────────

-- pgcrypto for gen_random_uuid() used by sessions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- RBAC roles
CREATE TABLE IF NOT EXISTS roles (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(50) UNIQUE NOT NULL,
    permissions     JSONB NOT NULL DEFAULT '[]',
    is_system       BOOLEAN DEFAULT FALSE,
    description     TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO roles (name, permissions, is_system, description) VALUES
    ('admin', '["*"]', TRUE, 'Full access to all features'),
    ('viewer', '["logs.read", "stats.read", "flows.read", "threats.read", "dashboard.read"]', TRUE, 'Read-only access to logs and dashboards')
ON CONFLICT (name) DO NOTHING;

-- Users
CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(100) UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    role_id         INTEGER NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ
);

-- Sessions (login cookies)
CREATE TABLE IF NOT EXISTS sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    ip_address      INET,
    user_agent      TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- API tokens (MCP, browser extension, generic API access)
CREATE TABLE IF NOT EXISTS api_tokens (
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
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_prefix ON api_tokens(token_prefix);
CREATE INDEX IF NOT EXISTS idx_api_tokens_active ON api_tokens(disabled) WHERE disabled = false;
CREATE INDEX IF NOT EXISTS idx_api_tokens_owner ON api_tokens(owner_user_id);

-- Audit log (login events, API calls, admin actions)
CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL PRIMARY KEY,
    user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    token_id        UUID REFERENCES api_tokens(id) ON DELETE SET NULL,
    action          VARCHAR(50) NOT NULL,
    detail          JSONB,
    ip_address      INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_token_id ON audit_log(token_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);

-- Auth configuration defaults
INSERT INTO system_config (key, value, updated_at) VALUES
    ('auth_enabled', 'false'::jsonb, NOW()),
    ('auth_session_ttl_hours', '168'::jsonb, NOW()),
    ('audit_log_retention_days', '90'::jsonb, NOW())
ON CONFLICT (key) DO NOTHING;
