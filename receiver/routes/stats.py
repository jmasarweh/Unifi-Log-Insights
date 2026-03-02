"""Dashboard statistics endpoint."""

import csv
import io
import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import StreamingResponse
from psycopg2.extras import RealDictCursor

from db import get_config, get_wan_ips_from_config
from deps import get_conn, put_conn, enricher_db
from query_helpers import parse_time_range, build_log_query, validate_time_params, VALID_TIME_RANGES

logger = logging.getLogger('api.stats')

router = APIRouter()


def _apply_ip_filters(where, params, src_ip, dst_ip, interface_in, interface_out):
    """Validate and append IP/interface exact-match filters to a WHERE clause."""
    if src_ip:
        try:
            ipaddress.ip_address(src_ip)
        except ValueError as err:
            raise HTTPException(status_code=400, detail="Invalid src_ip") from err
        where += " AND src_ip = %s::inet"
        params.append(src_ip)
    if dst_ip:
        try:
            ipaddress.ip_address(dst_ip)
        except ValueError as err:
            raise HTTPException(status_code=400, detail="Invalid dst_ip") from err
        where += " AND dst_ip = %s::inet"
        params.append(dst_ip)
    if interface_in:
        where += " AND interface_in = %s"
        params.append(interface_in)
    if interface_out:
        where += " AND interface_out = %s"
        params.append(interface_out)
    return where, params


@router.get("/api/stats")
def get_stats(
    time_range: str = Query("24h", description="1h,6h,24h,7d,30d,60d"),
):
    cutoff = parse_time_range(time_range)
    if not cutoff:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    bucket_map = {
        '1h': 'hour', '6h': 'hour', '24h': 'hour',
        '7d': 'day', '30d': 'day', '60d': 'day',
        '90d': 'week',
        '180d': 'month', '365d': 'month',
    }
    bucket = bucket_map.get(time_range, 'day')
    if bucket not in ('hour', 'day', 'week', 'month'):
        bucket = 'day'

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Total logs
            cur.execute("SELECT COUNT(*) as total FROM logs WHERE timestamp >= %s", [cutoff])
            total = cur.fetchone()['total']

            # By type
            cur.execute(
                "SELECT log_type, COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s GROUP BY log_type ORDER BY count DESC",
                [cutoff]
            )
            by_type = {r['log_type']: r['count'] for r in cur.fetchall()}

            # Blocked count
            cur.execute(
                "SELECT COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND rule_action = 'block'",
                [cutoff]
            )
            blocked = cur.fetchone()['count']

            # Threat count (score > 50)
            cur.execute(
                "SELECT COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND threat_score > 50",
                [cutoff]
            )
            threats = cur.fetchone()['count']

            # Top blocked countries
            cur.execute(
                "SELECT geo_country as country, COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND rule_action = 'block' AND geo_country IS NOT NULL "
                "GROUP BY geo_country ORDER BY count DESC LIMIT 10",
                [cutoff]
            )
            top_blocked_countries = [dict(r) for r in cur.fetchall()]

            # Top blocked external IPs (public src_ip only, exclude WAN IPs)
            wan_ips = get_wan_ips_from_config(enricher_db)
            exclude_ips = ['0.0.0.0']
            for ip in wan_ips:
                if ip not in exclude_ips:
                    exclude_ips.append(ip)
            cur.execute(
                "SELECT host(src_ip) as ip, COUNT(*) as count, "
                "MAX(geo_country) as country, MAX(asn_name) as asn, "
                "MAX(threat_score) as threat_score "
                "FROM logs "
                "WHERE timestamp >= %s AND rule_action = 'block' AND src_ip IS NOT NULL "
                "AND host(src_ip) != ALL(%s) "
                "AND NOT (src_ip << '10.0.0.0/8' OR src_ip << '172.16.0.0/12' "
                "    OR src_ip << '192.168.0.0/16' OR src_ip << '127.0.0.0/8' "
                "    OR src_ip << 'fe80::/10' OR src_ip << 'fc00::/7') "
                "GROUP BY src_ip ORDER BY count DESC LIMIT 10",
                [cutoff, exclude_ips]
            )
            top_blocked_ips = [dict(r) for r in cur.fetchall()]

            # Top blocked internal IPs (private src_ip only — inter-VLAN / outbound blocks)
            # Recency guard: cutoff-anchored (scales with time range, not fixed to NOW())
            cur.execute(
                "WITH top_ips AS ("
                "  SELECT src_ip, host(src_ip) as ip, COUNT(*) as count "
                "  FROM logs "
                "  WHERE timestamp >= %s AND rule_action = 'block' AND src_ip IS NOT NULL "
                "  AND (src_ip << '10.0.0.0/8' OR src_ip << '172.16.0.0/12' "
                "      OR src_ip << '192.168.0.0/16') "
                "  GROUP BY src_ip ORDER BY count DESC LIMIT 10"
                ") SELECT t.ip, t.count, c.device_name "
                "FROM top_ips t "
                "LEFT JOIN LATERAL ("
                "    SELECT COALESCE(device_name, hostname, oui) as device_name "
                "    FROM unifi_clients "
                "    WHERE ip = t.src_ip AND last_seen >= %s - INTERVAL '1 day' "
                "    ORDER BY last_seen DESC NULLS LAST LIMIT 1"
                ") c ON true "
                "ORDER BY t.count DESC",
                [cutoff, cutoff]
            )
            top_blocked_internal_ips = [dict(r) for r in cur.fetchall()]

            # Top threat IPs (enriched — categories from ip_threats for reliability)
            cur.execute(
                "SELECT host(l.src_ip) as ip, COUNT(*) as count, "
                "MAX(l.geo_country) as country, MAX(l.asn_name) as asn, "
                "MAX(l.geo_city) as city, MAX(l.rdns) as rdns, "
                "MAX(l.threat_score) as threat_score, "
                "COALESCE(MAX(l.threat_categories), MAX(t.threat_categories)) as threat_categories, "
                "MAX(l.timestamp) as last_seen "
                "FROM logs l "
                "LEFT JOIN ip_threats t ON l.src_ip = t.ip "
                "WHERE l.timestamp >= %s AND l.threat_score > 50 AND l.src_ip IS NOT NULL "
                "AND host(l.src_ip) != ALL(%s) "
                "GROUP BY l.src_ip ORDER BY max(l.threat_score) DESC, count DESC LIMIT 10",
                [cutoff, exclude_ips]
            )
            top_threat_ips = []
            for r in cur.fetchall():
                row = dict(r)
                if row.get('last_seen'):
                    row['last_seen'] = row['last_seen'].isoformat()
                top_threat_ips.append(row)

            # Logs over time (adaptive bucketing)
            cur.execute(
                f"SELECT date_trunc('{bucket}', timestamp) as period, COUNT(*) as count "
                "FROM logs WHERE timestamp >= %s "
                "GROUP BY period ORDER BY period",
                [cutoff]
            )
            logs_over_time = [
                {'period': r['period'].isoformat(), 'count': r['count']}
                for r in cur.fetchall()
            ]

            # Traffic by action over time
            cur.execute(
                f"SELECT date_trunc('{bucket}', timestamp) as period, "
                "rule_action, COUNT(*) as count "
                "FROM logs WHERE timestamp >= %s AND log_type = 'firewall' "
                "AND rule_action IS NOT NULL "
                "GROUP BY period, rule_action ORDER BY period",
                [cutoff]
            )
            action_map = {}
            for r in cur.fetchall():
                p = r['period'].isoformat()
                if p not in action_map:
                    action_map[p] = {'period': p, 'allow': 0, 'block': 0, 'redirect': 0}
                action = r['rule_action']
                if action in ('allow', 'block', 'redirect'):
                    action_map[p][action] = r['count']
            traffic_by_action = sorted(action_map.values(), key=lambda x: x['period'])

            # Direction breakdown
            cur.execute(
                "SELECT direction, COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND direction IS NOT NULL "
                "GROUP BY direction ORDER BY count DESC",
                [cutoff]
            )
            by_direction = {r['direction']: r['count'] for r in cur.fetchall()}

            # Top DNS queries
            cur.execute(
                "SELECT dns_query, COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND log_type = 'dns' AND dns_query IS NOT NULL "
                "GROUP BY dns_query ORDER BY count DESC LIMIT 10",
                [cutoff]
            )
            top_dns = [dict(r) for r in cur.fetchall()]

            # Top blocked services
            cur.execute(
                "SELECT service_name, COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND rule_action = 'block' AND service_name IS NOT NULL "
                "GROUP BY service_name ORDER BY count DESC LIMIT 10",
                [cutoff]
            )
            top_blocked_services = [dict(r) for r in cur.fetchall()]

            # Allowed count
            cur.execute(
                "SELECT COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND log_type = 'firewall' AND rule_action = 'allow'",
                [cutoff]
            )
            allowed = cur.fetchone()['count']

            # Top allowed destinations (external dst_ip, exclude WAN IPs)
            cur.execute(
                "SELECT host(dst_ip) as ip, COUNT(*) as count, "
                "MAX(geo_country) as country, MAX(asn_name) as asn "
                "FROM logs "
                "WHERE timestamp >= %s AND rule_action = 'allow' AND dst_ip IS NOT NULL "
                "AND host(dst_ip) != ALL(%s) "
                "AND NOT (dst_ip << '10.0.0.0/8' OR dst_ip << '172.16.0.0/12' "
                "    OR dst_ip << '192.168.0.0/16' OR dst_ip << '127.0.0.0/8' "
                "    OR dst_ip << '0.0.0.0/8' OR dst_ip << '169.254.0.0/16' "
                "    OR dst_ip << '224.0.0.0/4' OR dst_ip << '240.0.0.0/4' "
                "    OR dst_ip << 'fe80::/10' OR dst_ip << 'fc00::/7' "
                "    OR dst_ip << 'ff00::/8' OR dst_ip << '::1/128') "
                "GROUP BY dst_ip ORDER BY count DESC LIMIT 10",
                [cutoff, exclude_ips]
            )
            top_allowed_destinations = [dict(r) for r in cur.fetchall()]

            # Top allowed countries (outbound destinations)
            cur.execute(
                "SELECT geo_country as country, COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND rule_action = 'allow' "
                "AND geo_country IS NOT NULL AND direction = 'outbound' "
                "GROUP BY geo_country ORDER BY count DESC LIMIT 10",
                [cutoff]
            )
            top_allowed_countries = [dict(r) for r in cur.fetchall()]

            # Top allowed services
            cur.execute(
                "SELECT service_name, COUNT(*) as count FROM logs "
                "WHERE timestamp >= %s AND rule_action = 'allow' AND service_name IS NOT NULL "
                "GROUP BY service_name ORDER BY count DESC LIMIT 10",
                [cutoff]
            )
            top_allowed_services = [dict(r) for r in cur.fetchall()]

            # Top active internal IPs (most allowed traffic by source, exclude gateway IPs)
            gateway_ips = get_config(enricher_db, 'gateway_ips') or []
            gw_filter = "  AND host(src_ip) != ALL(%s) " if gateway_ips else ""
            # Params: [cutoff (WHERE), gateway_ips (gw_filter), cutoff (LATERAL recency)]
            params = [cutoff, gateway_ips, cutoff] if gateway_ips else [cutoff, cutoff]
            cur.execute(
                "WITH top_ips AS ("
                "  SELECT src_ip, host(src_ip) as ip, COUNT(*) as count "
                "  FROM logs "
                "  WHERE timestamp >= %s AND rule_action = 'allow' AND src_ip IS NOT NULL "
                "  AND (src_ip << '10.0.0.0/8' OR src_ip << '172.16.0.0/12' "
                "      OR src_ip << '192.168.0.0/16') "
                + gw_filter +
                "  GROUP BY src_ip ORDER BY count DESC LIMIT 10"
                ") SELECT t.ip, t.count, c.device_name "
                "FROM top_ips t "
                "LEFT JOIN LATERAL ("
                "    SELECT COALESCE(device_name, hostname, oui) as device_name "
                "    FROM unifi_clients "
                "    WHERE ip = t.src_ip AND last_seen >= %s - INTERVAL '1 day' "
                "    ORDER BY last_seen DESC NULLS LAST LIMIT 1"
                ") c ON true "
                "ORDER BY t.count DESC",
                params
            )
            top_active_internal_ips = [dict(r) for r in cur.fetchall()]

            # Annotate gateway/WAN IPs with device names
            gateway_vlans = get_config(enricher_db, 'gateway_ip_vlans') or {}
            wan_ip_names = get_config(enricher_db, 'wan_ip_names') or {}
            for ip_list in (top_blocked_internal_ips, top_active_internal_ips):
                for item in ip_list:
                    if not item.get('device_name'):
                        if item['ip'] in gateway_vlans:
                            item['device_name'] = 'Gateway'
                            item['vlan'] = gateway_vlans[item['ip']].get('vlan')
                        elif item['ip'] in wan_ip_names:
                            item['device_name'] = wan_ip_names[item['ip']]

        conn.commit()
        return {
            'time_range': time_range,
            'total': total,
            'by_type': by_type,
            'blocked': blocked,
            'threats': threats,
            'allowed': allowed,
            'by_direction': by_direction,
            'top_blocked_countries': top_blocked_countries,
            'top_blocked_ips': top_blocked_ips,
            'top_blocked_internal_ips': top_blocked_internal_ips,
            'top_threat_ips': top_threat_ips,
            'top_blocked_services': top_blocked_services,
            'top_allowed_destinations': top_allowed_destinations,
            'top_allowed_countries': top_allowed_countries,
            'top_allowed_services': top_allowed_services,
            'top_active_internal_ips': top_active_internal_ips,
            'top_dns': top_dns,
            'logs_per_hour': logs_over_time,  # backward-compat alias for logs_over_time
            'logs_over_time': logs_over_time,
            'traffic_by_action': traffic_by_action,
        }
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching stats")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/stats/ip-pairs")
def get_ip_pairs(
    time_range: Optional[str] = Query("24h"),
    time_from: Optional[str] = Query(None),
    time_to: Optional[str] = Query(None),
    log_type: Optional[str] = Query("firewall"),
    rule_action: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    interface: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    dst_port: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    interface_in: Optional[str] = Query(None),
    interface_out: Optional[str] = Query(None),
    limit: int = Query(25, ge=1, le=100),
):
    time_range, time_from, time_to = validate_time_params(time_range, time_from, time_to)

    # Pass dst_port and protocol through build_log_query (they use = matching)
    where, params = build_log_query(
        log_type=log_type, time_range=time_range, time_from=time_from, time_to=time_to,
        src_ip=None, dst_ip=None, ip=None, direction=direction,
        rule_action=rule_action, rule_name=None, country=None, threat_min=None,
        search=None, service=service, interface=interface,
        dst_port=dst_port, protocol=protocol,
    )

    # Exact-match filters for cross-filtering (NOT through build_log_query LIKE path)
    where, params = _apply_ip_filters(where, params, src_ip, dst_ip, interface_in, interface_out)

    sql = f"""
    WITH pair_counts AS (
        SELECT
            src_ip, dst_ip, dst_port, LOWER(protocol) AS protocol,
            MODE() WITHIN GROUP (ORDER BY service_name) AS service_name,
            COUNT(*) AS total_count,
            COUNT(*) FILTER (WHERE rule_action = 'allow') AS allow_count,
            COUNT(*) FILTER (WHERE rule_action = 'block') AS block_count,
            MAX(threat_score) AS max_threat_score,
            MODE() WITHIN GROUP (ORDER BY asn_name) FILTER (WHERE asn_name IS NOT NULL) AS asn_name,
            MODE() WITHIN GROUP (ORDER BY direction) FILTER (WHERE direction IS NOT NULL) AS direction
        FROM logs
        WHERE {where}
          AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
          AND dst_port IS NOT NULL AND protocol IS NOT NULL
        GROUP BY src_ip, dst_ip, dst_port, LOWER(protocol)
        ORDER BY total_count DESC
        LIMIT %s
    )
    SELECT
        host(p.src_ip) AS src_ip, host(p.dst_ip) AS dst_ip,
        p.dst_port, p.protocol, p.service_name,
        p.total_count, p.allow_count, p.block_count, p.max_threat_score, p.asn_name, p.direction,
        COALESCE(cs.device_name, ds.device_name) AS src_device_name,
        COALESCE(cd.device_name, dd.device_name) AS dst_device_name
    FROM pair_counts p
    LEFT JOIN LATERAL (
        SELECT COALESCE(device_name, hostname, oui) AS device_name
        FROM unifi_clients WHERE ip = p.src_ip
        ORDER BY last_seen DESC NULLS LAST LIMIT 1
    ) cs ON true
    LEFT JOIN LATERAL (
        SELECT COALESCE(device_name, model) AS device_name
        FROM unifi_devices WHERE ip = p.src_ip
        ORDER BY updated_at DESC NULLS LAST LIMIT 1
    ) ds ON true
    LEFT JOIN LATERAL (
        SELECT COALESCE(device_name, hostname, oui) AS device_name
        FROM unifi_clients WHERE ip = p.dst_ip
        ORDER BY last_seen DESC NULLS LAST LIMIT 1
    ) cd ON true
    LEFT JOIN LATERAL (
        SELECT COALESCE(device_name, model) AS device_name
        FROM unifi_devices WHERE ip = p.dst_ip
        ORDER BY updated_at DESC NULLS LAST LIMIT 1
    ) dd ON true
    ORDER BY p.total_count DESC
    """
    params.append(limit)

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            pairs = [dict(r) for r in cur.fetchall()]
        conn.commit()
        return {"pairs": pairs}
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching IP pairs")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/stats/ip-pairs/csv")
def get_ip_pairs_csv(
    time_range: Optional[str] = Query("24h"),
    time_from: Optional[str] = Query(None),
    time_to: Optional[str] = Query(None),
    log_type: Optional[str] = Query("firewall"),
    rule_action: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    interface: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    dst_port: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    interface_in: Optional[str] = Query(None),
    interface_out: Optional[str] = Query(None),
):
    """Stream all filtered IP pairs as CSV (hard cap 10,000 rows)."""
    time_range, time_from, time_to = validate_time_params(time_range, time_from, time_to)

    where, params = build_log_query(
        log_type=log_type, time_range=time_range, time_from=time_from, time_to=time_to,
        src_ip=None, dst_ip=None, ip=None, direction=direction,
        rule_action=rule_action, rule_name=None, country=None, threat_min=None,
        search=None, service=service, interface=interface,
        dst_port=dst_port, protocol=protocol,
    )

    where, params = _apply_ip_filters(where, params, src_ip, dst_ip, interface_in, interface_out)

    sql = f"""
    SELECT
        host(src_ip) AS source_ip, host(dst_ip) AS destination_ip,
        dst_port AS port, LOWER(protocol) AS protocol,
        MODE() WITHIN GROUP (ORDER BY service_name) AS service,
        COUNT(*) FILTER (WHERE rule_action = 'allow') AS allow_count,
        COUNT(*) FILTER (WHERE rule_action = 'block') AS block_count
    FROM logs
    WHERE {where}
      AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
      AND dst_port IS NOT NULL AND protocol IS NOT NULL
    GROUP BY src_ip, dst_ip, dst_port, LOWER(protocol)
    ORDER BY (COUNT(*)) DESC
    LIMIT 10000
    """

    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')

    def generate():
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                cols = [desc[0] for desc in cur.description]
                # Header row
                buf = io.StringIO()
                writer = csv.writer(buf)
                writer.writerow(cols)
                yield buf.getvalue()
                # Data rows
                for row in cur:
                    buf = io.StringIO()
                    writer = csv.writer(buf)
                    writer.writerow(row)
                    yield buf.getvalue()
            conn.commit()
        except Exception:
            conn.rollback()
            logger.exception("Error streaming CSV export")
            raise
        finally:
            put_conn(conn)

    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=ip_pairs_{timestamp}.csv"},
    )
