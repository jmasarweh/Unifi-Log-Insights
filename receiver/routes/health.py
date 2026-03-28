"""Health check endpoint."""

import logging
import os
import shutil
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException

from db import get_config, is_external_db
from enrichment import get_abuseipdb_stats
from deps import get_conn, put_conn, enricher_db, APP_VERSION

logger = logging.getLogger('api.health')

router = APIRouter()


@router.get("/api/health")
def health():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # Use pg_class catalog estimate instead of COUNT(*) full scan.
            # On large tables (100M+ rows) the exact COUNT takes 5-7s per call and
            # causes persistent /api/health 503 errors via statement_timeout.
            # reltuples is updated by autovacuum and accurate to ~1% on active tables.
            cur.execute("""
                SELECT
                    COALESCE(GREATEST(c.reltuples::bigint, 0), 0) AS count,
                    NULL::timestamptz  AS min_timestamp,
                    NULL::timestamptz  AS max_timestamp
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relname = 'logs'
                  AND n.nspname = 'public'
            """)
            row = cur.fetchone()
            if row is None:
                total, oldest, latest = 0, None, None
            else:
                total, oldest, latest = row[0], row[1], row[2]
        conn.commit()

        # Retention days: system_config > env > default
        retention_val = get_config(enricher_db, 'retention_days')
        if retention_val is not None:
            retention_days = int(retention_val)
        else:
            try:
                retention_days = int(os.environ.get('RETENTION_DAYS', '60'))
            except (ValueError, TypeError):
                retention_days = 60

        # AbuseIPDB rate limit stats (written by receiver process)
        abuseipdb = get_abuseipdb_stats(enricher_db)

        # MaxMind database info
        maxmind_last_update = None
        mmdb_path = '/app/maxmind/GeoLite2-City.mmdb'
        try:
            if os.path.exists(mmdb_path):
                mtime = os.path.getmtime(mmdb_path)
                maxmind_last_update = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
        except Exception:
            pass

        # Calculate next MaxMind update (Wed=2, Sat=5 at 07:00 local)
        maxmind_next_update = None
        try:
            now = datetime.now().astimezone()
            target_time = now.replace(hour=7, minute=0, second=0, microsecond=0)
            # Find next Wed(2) or Sat(5)
            for days_ahead in range(1, 8):
                candidate = target_time + timedelta(days=days_ahead)
                if candidate.weekday() in (2, 5):  # Wed=2, Sat=5
                    maxmind_next_update = candidate.isoformat()
                    break
            # Edge case: today is Wed/Sat and it's before 07:00
            if now.weekday() in (2, 5) and now < target_time:
                maxmind_next_update = target_time.isoformat()
        except Exception:
            pass

        # Storage: database size + volume disk usage
        storage = {}
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_database_size(current_database())")
                storage['db_size_bytes'] = cur.fetchone()[0]
            conn.commit()
        except Exception:
            conn.rollback()
        if not is_external_db():
            try:
                usage = shutil.disk_usage('/var/lib/postgresql/data')
                storage['volume_total_bytes'] = usage.total
                storage['volume_used_bytes'] = usage.used
                storage['volume_available_bytes'] = usage.free
            except Exception as e:
                logger.warning("Failed to read disk usage for /var/lib/postgresql/data: %s", e)

        return {
            'status': 'ok',
            'version': APP_VERSION,
            'total_logs': total,
            'oldest_log_at': oldest.isoformat() if oldest else None,
            'latest_log': latest.isoformat() if latest else None,
            'retention_days': retention_days,
            'abuseipdb': abuseipdb,
            'maxmind_last_update': maxmind_last_update,
            'maxmind_next_update': maxmind_next_update,
            'storage': storage,
        }
    except Exception as e:
        conn.rollback()
        logger.exception("Health check failed")
        raise HTTPException(status_code=503, detail="Service unavailable") from None
    finally:
        put_conn(conn)
