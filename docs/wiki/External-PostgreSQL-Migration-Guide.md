This guide explains how to migrate UniFi Log Insight from the embedded PostgreSQL database to an external PostgreSQL server, with focus on Docker connectivity pitfalls.

Use this with the in-app migration wizard: **Settings > Data & Backups > Database Migration**.

## What This Guide Covers

- Choosing the correct `DB_HOST` for your topology
- Docker Desktop vs Linux Docker host routing differences
- Resolving "Test Connection" timeouts and failures
- SSL mode setup (`disable`, `require`, `verify-ca`, `verify-full`)
- Post-migration compose file updates and rollout
- SECRET_KEY setup for API key encryption

## Quick Topology Matrix

Pick the `DB_HOST` value based on where PostgreSQL runs:

| Topology | `DB_HOST` | Notes |
|---|---|---|
| Same compose project | `postgres` (service name) | Only works when both services share the same compose network |
| Different compose projects on same host | Host-routable address | Use host IP or `host.docker.internal` (Desktop) |
| Docker Desktop (Windows/Mac) to host-mapped Postgres | `host.docker.internal` | Works by default |
| Linux Docker to host-mapped Postgres | Host gateway IP (e.g. `172.17.0.1`) or `host.docker.internal` with host-gateway mapping | `host.docker.internal` is not automatic on many Linux setups |
| Cloud PostgreSQL (RDS/Aurora/Cloud SQL/etc.) | Cloud hostname | Usually requires `DB_SSLMODE=require` or stricter |

> [!WARNING]
> Do not use random container bridge IPs like `172.18.x.x` unless both containers are intentionally on that same routable network. Prefer host-mapped ports and host-routable addresses for separate compose projects.

## Prerequisites

- PostgreSQL 14+
- Dedicated database (recommended: `unifi_logs`)
- User with schema/table/index/function privileges
- Network/firewall allows container → target DB on `DB_PORT` (default `5432`)

Minimum SQL setup:

```sql
CREATE USER unifi WITH PASSWORD 'your_password';
CREATE DATABASE unifi_logs OWNER unifi;

GRANT ALL ON SCHEMA public TO unifi;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO unifi;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO unifi;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO unifi;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO unifi;
```

## Connectivity Checks Before Wizard

### 1) Confirm Postgres is reachable on host

If Postgres container is mapped as `-p 5432:5432`, confirm on host:

```bash
psql -h 127.0.0.1 -p 5432 -U unifi -d unifi_logs -c "SELECT 1;"
```

### 2) Confirm reachability from UniFi Log Insight container

Use the same host/port you plan to enter in the wizard:

```bash
docker exec -it unifi-log-insight sh -lc "nc -zv <DB_HOST> <DB_PORT>"
```

> [!IMPORTANT]
> If this fails, the wizard's Test Connection will also fail.

### Linux-specific note

On Linux Docker, if you want to use `host.docker.internal`, add this to the `unifi-log-insight` service in your `docker-compose.yml`:

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

Then use:
- `DB_HOST=host.docker.internal`
- `DB_PORT=<mapped-port>`

> [!NOTE]
> Without this mapping, `host.docker.internal` will not resolve on Linux.

## Migration Wizard Steps

The wizard has 3 steps: **Configure → Migration → Required Manual Tasks**.

### Step 1: Configure

In **Settings > Data & Backups > Database Migration**, enter:
- **Host** — the DB_HOST for your topology (see matrix above)
- **Port** — default `5432`
- **Database Name** — default `unifi_logs`
- **Username** — the PostgreSQL user
- **Password** — the PostgreSQL password
- **SSL Mode** — see [SSL Mode Guidance](#ssl-mode-guidance) below

Click **Test Connection** to verify connectivity. On success:
- "Connection successful" with server version shown
- If the target database already contains tables not owned by UniFi Log Insight, a warning is shown and migration is blocked (use a dedicated database)
- The **Start Migration** button appears

If you get **timeout/connection refused**:
- Verify `DB_HOST` is routable from the app container (see connectivity checks above)
- Verify DB port mapping and firewall rules
- Do not use non-routable bridge IPs from unrelated Docker networks

If you get **authentication failed**:
- Verify username/password for the target DB user
- Check `pg_hba.conf` if using host-based authentication rules

If you get **database does not exist**:
- Create the target database first (see Prerequisites)

### Step 2: Migration

Click **Start Migration**. The app:
1. Validates the target database is safe (no foreign tables)
2. Counts source rows in the embedded database
3. Creates a `pg_dump` of the embedded database
4. Restores the dump to the external database via `pg_restore`
5. Validates row counts match between source and target

> [!CAUTION]
> Do not restart the container while migration is running. Large datasets may take several minutes to transfer.

If migration fails, click **Back to Configuration** to review settings and retry.

When migration completes, a validation table compares source and target row counts for each table. Click **Continue** to proceed.

### Step 3: Required Manual Tasks

This step helps you update your `docker-compose.yml` for external database mode.

**Generate updated compose file:**
1. Paste your current `docker-compose.yml` into the text area
2. Click **Generate Updated Compose**
3. The patcher finds the `unifi-log-insight` service (by service name or `container_name`) and updates:
   - `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER` environment variables
   - `DB_PASSWORD` as `${DB_PASSWORD}` (reads from `.env` file — never embedded)
   - `DB_SSLMODE` and `DB_SSLROOTCERT` if SSL is configured
   - Healthcheck swapped from `pg_isready` to HTTP check (embedded PostgreSQL is disabled in external mode)
   - Removes the `pgdata` volume mount (no longer needed)
   - All other settings (ports, labels, other env vars, etc.) are preserved

**After generating, follow the numbered steps shown in the wizard:**
1. Copy and save the generated output as your `docker-compose.yml`
2. Set `DB_PASSWORD=<your_password>` in your `.env` file — use the **Check Environment** button to verify
3. Rename `POSTGRES_PASSWORD` to `SECRET_KEY` in your `.env` file (keep the same value — it encrypts stored API keys for AbuseIPDB, UniFi, and MaxMind)
4. Run `docker compose up -d`

> [!NOTE]
> YAML comments from your original file are not preserved (PyYAML limitation). If you need to re-paste, click **Paste Different Compose File**.

## SSL Mode Guidance

| SSL Mode | Use When |
|---|---|
| `disable` | Local trusted network, no TLS required |
| `require` | TLS required, cert chain verification not enforced |
| `verify-ca` | TLS with CA certificate verification |
| `verify-full` | TLS with CA verification + hostname validation (strictest) |

### Setting up `verify-ca` or `verify-full`

1. Place your CA certificate file in a `certs/` directory next to your `docker-compose.yml`
2. The compose patcher automatically adds a `./certs:/certs:ro` volume mount and sets `DB_SSLROOTCERT=/certs/ca-certificate.crt`
3. Rename your CA cert to `ca-certificate.crt` or update the `DB_SSLROOTCERT` path to match your filename

> [!WARNING]
> For `verify-full`, the certificate's CN or SAN must match the `DB_HOST` value exactly. If they don't match, the connection will be rejected.

> [!TIP]
> If your provider requires mutual TLS (client certificate authentication), manually add `DB_SSLCERT` and `DB_SSLKEY` to your compose environment after patching.

## Common Failures and Fixes

| Error | Likely Cause | Fix |
|---|---|---|
| Could not connect / timeout | Wrong host routing | Use host-routable address and mapped port (see topology matrix) |
| Could not translate host name `host.docker.internal` | Linux host-gateway mapping missing | Add `extra_hosts` mapping or use gateway IP directly |
| Connection refused | DB not listening/not port-mapped | Confirm `-p` mapping and Postgres `listen_addresses`/`pg_hba.conf` |
| Password authentication failed | Wrong credentials | Verify `DB_USER`/`DB_PASSWORD`; check `pg_hba.conf` auth method |
| Database does not exist | Target DB not created | Run `CREATE DATABASE unifi_logs OWNER unifi;` |
| Target has unknown tables | Shared/wrong database | Use a dedicated DB for UniFi Log Insight |
| SSL required by server | Server enforces TLS | Set `DB_SSLMODE=require` or stricter |
| pg_dump timed out | Very large dataset | Retry — dump has a 10-minute timeout |
| pg_restore error | Permission or schema conflict | Check target user has full privileges (see Prerequisites) |
| Could not find 'unifi-log-insight' service | Compose patcher can't find the service | Ensure your compose file has a service named `unifi-log-insight` or with `container_name: unifi-log-insight` |
| Partial restore detected | Network interruption during restore | Retry migration — target is cleaned before restore |

## Post-Migration Checklist

After restarting with the updated compose file:

1. Dashboard and Log Stream load normally
2. New syslog messages are being ingested (check Log Stream for fresh entries)
3. `/api/health` reports healthy status
4. Historical data (filters, date ranges) returns expected results
5. API keys (AbuseIPDB, UniFi, MaxMind) still work

> [!IMPORTANT]
> If API keys stop working after migration, verify that `SECRET_KEY` in your `.env` file matches your old `POSTGRES_PASSWORD`. This value is used to encrypt/decrypt stored API keys.

## Removing the Old Embedded Volume

> [!WARNING]
> Your old embedded database volume (`pgdata`) remains on disk as a safety net after migration. Only remove it after confirming the external database is working correctly.

To remove just the old volume:

```bash
docker volume rm unifi-log-insight-pgdata
```

If your volume has a different name, find it with:

```bash
docker volume ls | grep pgdata
```

> [!CAUTION]
> Do not use `docker compose down -v` as this removes **all** volumes, not just `pgdata`.

## Rollback Plan

> [!IMPORTANT]
> Your embedded `pgdata` volume still has all your data until you explicitly remove it.

If external DB setup fails after migration:
- Remove the `DB_HOST` and other `DB_*` variables from your compose file to revert to embedded mode
- Run `docker compose up -d` to restart with the embedded database
- Do not delete `pgdata` until external operation is confirmed working

## Recommended Compose Patterns

### External DB in different compose project (host-mapped port)

```yaml
services:
  unifi-log-insight:
    image: ghcr.io/jmasarweh/unifi-log-insight:latest
    ports:
      - "514:514/udp"
      - "8090:8000"
    environment:
      DB_HOST: "host.docker.internal"
      DB_PORT: "5432"
      DB_NAME: "unifi_logs"
      DB_USER: "unifi"
      DB_PASSWORD: "${DB_PASSWORD}"
      SECRET_KEY: "${SECRET_KEY}"
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"]
      interval: 15s
      timeout: 10s
      retries: 5
      start_period: 45s
```

> [!NOTE]
> On Linux, add `extra_hosts` if using `host.docker.internal`:

```yaml
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

### Shared Docker network (different compose projects)

When both containers are in separate compose projects but need to communicate directly:

```yaml
services:
  unifi-log-insight:
    image: ghcr.io/jmasarweh/unifi-log-insight:latest
    environment:
      DB_HOST: "postgres-container-name"
      DB_PORT: "5432"
      DB_NAME: "unifi_logs"
      DB_USER: "unifi"
      DB_PASSWORD: "${DB_PASSWORD}"
      SECRET_KEY: "${SECRET_KEY}"
    networks:
      - default
      - shared-db-net

networks:
  shared-db-net:
    external: true
```

> [!TIP]
> Create the shared network first: `docker network create shared-db-net`, then add the same network to your Postgres compose project.

### Same compose file

```yaml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: unifi
      POSTGRES_PASSWORD: "${DB_PASSWORD}"
      POSTGRES_DB: unifi_logs
    volumes:
      - pgdata:/var/lib/postgresql/data

  unifi-log-insight:
    image: ghcr.io/jmasarweh/unifi-log-insight:latest
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DB_HOST: "postgres"
      DB_PORT: "5432"
      DB_NAME: "unifi_logs"
      DB_USER: "unifi"
      DB_PASSWORD: "${DB_PASSWORD}"
      SECRET_KEY: "${SECRET_KEY}"
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"]
      interval: 15s
      timeout: 10s
      retries: 5
      start_period: 45s

volumes:
  pgdata:
```

### Cloud PostgreSQL with SSL

```yaml
services:
  unifi-log-insight:
    image: ghcr.io/jmasarweh/unifi-log-insight:latest
    environment:
      DB_HOST: "mydb.us-east-1.rds.amazonaws.com"
      DB_PORT: "5432"
      DB_NAME: "unifi_logs"
      DB_USER: "unifi"
      DB_PASSWORD: "${DB_PASSWORD}"
      DB_SSLMODE: "verify-ca"
      DB_SSLROOTCERT: "/certs/ca-certificate.crt"
      SECRET_KEY: "${SECRET_KEY}"
    volumes:
      - ./certs:/certs:ro
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"]
      interval: 15s
      timeout: 10s
      retries: 5
      start_period: 45s
```

## Support

> [!TIP]
> Before opening an issue, collect the following:
- The exact error message from the wizard
- Output of `docker logs unifi-log-insight` (last 50 lines)
- Your target topology (same compose, different compose, shared network, cloud DB)
- Sanitized DB env config (`DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_SSLMODE` — never share passwords)
- Output of `docker exec -it unifi-log-insight sh -lc "nc -zv <DB_HOST> <DB_PORT>"` for connectivity issues
