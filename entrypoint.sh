#!/bin/bash
set -e

PGDATA="/var/lib/postgresql/data"

# ── External database mode detection ─────────────────────────────────────────
# Normalize DB_HOST: trim leading/trailing whitespace + lowercase
# Must match Python's _normalize_db_host() exactly — do NOT use `tr -d '[:space:]'`
# (that strips interior whitespace, diverging from Python's .strip())
_db_host_lower=$(echo "${DB_HOST:-127.0.0.1}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr '[:upper:]' '[:lower:]')
_external_db=false
if [ "$_db_host_lower" != "127.0.0.1" ] && [ "$_db_host_lower" != "localhost" ] && [ "$_db_host_lower" != "::1" ] && [ -n "$_db_host_lower" ]; then
    _external_db=true
fi

if [ "$_external_db" = "true" ]; then
    echo "[entrypoint] External database mode (DB_HOST=$DB_HOST), skipping embedded PostgreSQL"
    # Disable PostgreSQL in supervisord (targeted: only [program:postgresql])
    sed -i '/\[program:postgresql\]/,/^\[/{s/autostart=true/autostart=false/; s/autorestart=true/autorestart=false/}' /etc/supervisor/conf.d/supervisord.conf
else

# Initialize PostgreSQL if data directory is empty
if [ ! -s "$PGDATA/PG_VERSION" ]; then
    echo "[entrypoint] Initializing PostgreSQL..."
    chown -R postgres:postgres "$PGDATA"
    su - postgres -c "/usr/lib/postgresql/16/bin/initdb -D $PGDATA"

    # Start PostgreSQL temporarily to create database and schema
    su - postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D $PGDATA -w start"

    # Create user and database
    su - postgres -c "psql -c \"CREATE USER unifi WITH PASSWORD '${POSTGRES_PASSWORD}';\""
    su - postgres -c "psql -c \"CREATE DATABASE unifi_logs OWNER unifi;\""
    su - postgres -c "psql -d unifi_logs -f /app/init.sql"
    su - postgres -c "psql -d unifi_logs -c \"GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO unifi;\""
    su - postgres -c "psql -d unifi_logs -c \"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO unifi;\""

    # Transfer table ownership so the unifi user can run ALTER TABLE migrations
    su - postgres -c "psql -d unifi_logs -c \"ALTER TABLE logs OWNER TO unifi;\""
    su - postgres -c "psql -d unifi_logs -c \"ALTER TABLE ip_threats OWNER TO unifi;\""
    su - postgres -c "psql -d unifi_logs -c \"ALTER SEQUENCE logs_id_seq OWNER TO unifi;\""
    su - postgres -c "psql -d unifi_logs -c \"ALTER FUNCTION cleanup_old_logs(INTEGER, INTEGER) OWNER TO unifi;\""

    # Defensive: transfer ownership of app-created tables if they exist
    su - postgres -c "psql -d unifi_logs -c \"DO \\\$\\\$ BEGIN IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename='system_config') THEN ALTER TABLE system_config OWNER TO unifi; END IF; END \\\$\\\$;\""
    su - postgres -c "psql -d unifi_logs -c \"DO \\\$\\\$ BEGIN IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename='unifi_clients') THEN ALTER TABLE unifi_clients OWNER TO unifi; END IF; END \\\$\\\$;\""
    su - postgres -c "psql -d unifi_logs -c \"DO \\\$\\\$ BEGIN IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename='unifi_devices') THEN ALTER TABLE unifi_devices OWNER TO unifi; END IF; END \\\$\\\$;\""

    # Configure PostgreSQL to accept connections from the app
    echo "host all all 127.0.0.1/32 md5" >> "$PGDATA/pg_hba.conf"
    echo "local all all trust" >> "$PGDATA/pg_hba.conf"

    # Tune for logging workload
    cat >> "$PGDATA/postgresql.conf" <<EOF

# UniFi Log Insight tuning
listen_addresses = '127.0.0.1'
shared_buffers = 128MB
work_mem = 8MB
maintenance_work_mem = 64MB
effective_cache_size = 256MB
wal_buffers = 8MB
checkpoint_completion_target = 0.9
max_wal_size = 512MB
synchronous_commit = off
EOF

    su - postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D $PGDATA -w stop"
    echo "[entrypoint] PostgreSQL initialized."
else
    echo "[entrypoint] PostgreSQL data directory exists, skipping init."
    chown -R postgres:postgres "$PGDATA"

fi
fi  # end external_db else block

echo "[entrypoint] Starting services via supervisord..."

# Configure MaxMind GeoIP auto-update if credentials are provided
if [ -n "$MAXMIND_ACCOUNT_ID" ] && [ -n "$MAXMIND_LICENSE_KEY" ]; then
    echo "[entrypoint] Configuring MaxMind GeoIP auto-update..."
    cat > /etc/GeoIP.conf <<GEOEOF
AccountID $MAXMIND_ACCOUNT_ID
LicenseKey $MAXMIND_LICENSE_KEY
EditionIDs GeoLite2-City GeoLite2-ASN
DatabaseDirectory /app/maxmind
GEOEOF

    # Schedule: Wednesday 07:00 UTC and Saturday 07:00 UTC
    echo "0 7 * * 3,6 /app/geoip-update.sh >> /var/log/geoip-update.log 2>&1" > /etc/cron.d/geoipupdate
    chmod 0644 /etc/cron.d/geoipupdate

    # Run an initial update if databases are missing
    if [ ! -f /app/maxmind/GeoLite2-City.mmdb ]; then
        echo "[entrypoint] No GeoLite2 databases found, running initial download..."
        /app/geoip-update.sh
    fi

    echo "[entrypoint] GeoIP auto-update configured (Wed & Sat @ 07:00 UTC)"
else
    echo "[entrypoint] MaxMind credentials not set, skipping GeoIP auto-update"
fi

# Derive lowercase log level for uvicorn (defaults to info)
UVICORN_LOG_LEVEL=$(echo "${LOG_LEVEL:-INFO}" | tr '[:upper:]' '[:lower:]')
export UVICORN_LOG_LEVEL
echo "[entrypoint] Log level: ${LOG_LEVEL:-INFO} (uvicorn: $UVICORN_LOG_LEVEL)"

exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
