"""Health check endpoint."""

import json
import logging
import os
import shutil
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException

from db import get_config, is_external_db
from deps import get_conn, put_conn, enricher_db, APP_VERSION

logger = logging.getLogger('api.health')

router = APIRouter()


@router.get("/api/health")
def health():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM logs")
            row = cur.fetchone()
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
        abuseipdb = None
        try:
            with open('/tmp/abuseipdb_stats.json', 'r') as f:
                abuseipdb = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        # Fallback: tmp file missing, corrupt, or lacks useful data
        if not abuseipdb or abuseipdb.get('limit') is None:
            try:
                db_stats = get_config(enricher_db, 'abuseipdb_rate_limit')
                if db_stats:
                    paused = db_stats.get('paused_until')
                    pause_active = False
                    if paused:
                        try:
                            pause_active = time.time() < float(paused)
                        except (ValueError, TypeError):
                            pass
                    if db_stats.get('limit') is not None or pause_active:
                        abuseipdb = db_stats
            except Exception:
                pass

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
