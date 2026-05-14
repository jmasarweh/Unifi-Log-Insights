"""AbuseIPDB status and manual enrichment endpoints."""

import ipaddress
import logging
import time

from fastapi import APIRouter, HTTPException

from db import get_config, get_wan_ips_from_config
from enrichment import is_public_ip, get_abuseipdb_stats
from deps import abuseipdb, enricher_db

logger = logging.getLogger('api.abuseipdb')

router = APIRouter()


@router.get("/api/abuseipdb/status")
def abuseipdb_status():
    stats = get_abuseipdb_stats(enricher_db)
    if not stats:
        return {"remaining": None, "limit": None}
    reset_at = stats.get('reset_at')
    remaining = stats.get('remaining', 0) or 0
    if reset_at is not None and remaining <= 0:
        try:
            if time.time() > float(reset_at):
                stats['quota_reset_pending'] = True
        except (ValueError, TypeError):
            pass
    return stats


@router.post("/api/enrich/{ip}")
def enrich_ip(ip: str):
    if not is_public_ip(ip):
        raise HTTPException(status_code=400, detail="Not a public IP")

    # Reject WAN/gateway IPs — enriching these contaminates log rows
    wan_ips = get_wan_ips_from_config(enricher_db)
    gateway_ips = get_config(enricher_db, 'gateway_ips') or []
    excluded = set()
    for ip_str in wan_ips + gateway_ips:
        try:
            excluded.add(str(ipaddress.ip_address(ip_str)))
        except ValueError:
            pass
    try:
        normalized_ip = str(ipaddress.ip_address(ip))
    except ValueError:
        normalized_ip = ip
    if normalized_ip in excluded:
        raise HTTPException(status_code=400, detail="Cannot enrich WAN/gateway IP")

    if not abuseipdb.enabled:
        raise HTTPException(status_code=400, detail="AbuseIPDB not configured")

    # Budget check: use centralized AbuseIPDB stats from enricher DB
    budget_stats = get_abuseipdb_stats(enricher_db)
    if budget_stats:
        # Bootstrap rule: when no /check call has ever populated rate-limit
        # state (limit/remaining both None) and no active 429 pause, allow one
        # call through so subsequent callers see populated state.
        paused_active = False
        paused_until_val = budget_stats.get('paused_until')
        if paused_until_val:
            try:
                paused_active = time.time() < float(paused_until_val)
            except (ValueError, TypeError):
                paused_active = False
        is_bootstrap = (
            budget_stats.get('limit') is None
            and budget_stats.get('remaining') is None
            and not paused_active
        )
        if is_bootstrap:
            logger.info("Manual enrich: bootstrap call (no prior /check rate-limit state)")
        else:
            # Block if actively paused (429 back-off)
            if paused_active:
                raise HTTPException(status_code=429, detail="AbuseIPDB paused (rate limited) — try later")
            remaining = budget_stats.get('remaining', 0) or 0
            if remaining <= 0:
                # Check if quota has renewed since stats were written
                reset_at = budget_stats.get('reset_at')
                quota_renewed = False
                if reset_at is not None:
                    try:
                        quota_renewed = time.time() > float(reset_at)
                    except (ValueError, TypeError):
                        pass
                if not quota_renewed:
                    raise HTTPException(status_code=429, detail="No API budget remaining — resets daily")
                logger.info("Manual enrich: quota reset detected (reset_at %s passed), allowing call", reset_at)

    # Clear from memory cache
    abuseipdb.cache.delete(ip)

    # Backdate ip_threats entry so lookup() treats it as expired
    try:
        with enricher_db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE ip_threats
                    SET looked_up_at = NOW() - INTERVAL '30 days'
                    WHERE ip = %s::inet
                """, [ip])
    except Exception:
        logger.debug("Could not backdate ip_threats for %s (may not exist yet)", ip, exc_info=True)

    # Call lookup — hits the API, writes back to ip_threats + memory cache
    result = abuseipdb.lookup(ip)
    if not result or 'threat_score' not in result:
        raise HTTPException(status_code=502, detail="AbuseIPDB lookup failed")

    # Patch log rows — two-pass direction-aware to avoid cross-contamination
    logs_patched = 0
    patch_sql = """
        UPDATE logs
        SET threat_score = COALESCE(t.threat_score, logs.threat_score),
            abuse_usage_type = t.abuse_usage_type,
            abuse_hostnames = t.abuse_hostnames,
            abuse_total_reports = t.abuse_total_reports,
            abuse_last_reported = t.abuse_last_reported,
            abuse_is_whitelisted = t.abuse_is_whitelisted,
            abuse_is_tor = t.abuse_is_tor,
            threat_categories = COALESCE(
                CASE WHEN array_length(t.threat_categories, 1) > 0
                     THEN t.threat_categories ELSE NULL END,
                logs.threat_categories
            )
        FROM ip_threats t
        WHERE logs.{side}_ip = t.ip
          AND NOT (logs.{side}_ip = ANY(%s::inet[]))
          AND t.ip = %s::inet
          AND logs.log_type = 'firewall'
          AND logs.rule_action = 'block'
    """
    excluded_ips = wan_ips + gateway_ips
    try:
        with enricher_db.get_conn() as conn:
            with conn.cursor() as cur:
                # Pass 1: patch where this IP is src
                cur.execute(patch_sql.format(side='src'), [excluded_ips, ip])
                logs_patched += cur.rowcount
                # Pass 2: patch where this IP is dst
                cur.execute(patch_sql.format(side='dst'), [excluded_ips, ip])
                logs_patched += cur.rowcount
    except Exception:
        logger.exception("Failed to patch logs for %s", ip)

    return {
        'ip': ip,
        'threat_score': result.get('threat_score'),
        'threat_categories': result.get('threat_categories', []),
        'abuse_usage_type': result.get('abuse_usage_type'),
        'abuse_hostnames': result.get('abuse_hostnames'),
        'abuse_total_reports': result.get('abuse_total_reports'),
        'abuse_last_reported': result.get('abuse_last_reported'),
        'abuse_is_whitelisted': result.get('abuse_is_whitelisted'),
        'abuse_is_tor': result.get('abuse_is_tor'),
        'logs_patched': logs_patched,
        'remaining_budget': abuseipdb.remaining_budget,
    }
