"""Log CRUD, export, and service endpoints."""

import csv
import io
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from psycopg2.extras import RealDictCursor

from db import get_config, get_wan_ips_from_config
from deps import get_conn, put_conn, enricher_db, ttl_cache
from ip_identity import load_identity_config, annotate_record, annotate_ip
from query_helpers import (build_log_query, validate_time_params,
                          device_name_client_lateral, device_name_device_lateral,
                          device_name_coalesce)
from services import get_service_description



logger = logging.getLogger('api.logs')

router = APIRouter()


@router.get("/api/logs")
def get_logs(
    log_type: Optional[str] = Query(None, description="Comma-separated: firewall,dns,dhcp,wifi,system"),
    time_range: Optional[str] = Query(None, description="1h,6h,24h,7d,30d,60d"),
    time_from: Optional[str] = Query(None, description="ISO datetime"),
    time_to: Optional[str] = Query(None, description="ISO datetime"),
    src_ip: Optional[str] = Query(None, description="Source IP search (prefix with ! to negate)"),
    dst_ip: Optional[str] = Query(None, description="Dest IP search (prefix with ! to negate)"),
    ip: Optional[str] = Query(None, description="Search both src and dst (prefix with ! to negate)"),
    direction: Optional[str] = Query(None, description="Comma-separated: inbound,outbound,inter_vlan,nat"),
    rule_action: Optional[str] = Query(None, description="Comma-separated: allow,block,redirect (prefix with ! to negate)"),
    rule_name: Optional[str] = Query(None, description="Rule name search (prefix with ! to negate)"),
    country: Optional[str] = Query(None, description="Comma-separated country codes (prefix with ! to negate)"),
    threat_min: Optional[int] = Query(None, description="Minimum threat score"),
    search: Optional[str] = Query(None, description="Full-text search in raw_log (prefix with ! to negate)"),
    service: Optional[str] = Query(None, description="Comma-separated service names (prefix with ! to negate)"),
    interface: Optional[str] = Query(None, description="Comma-separated interface names"),
    vpn_only: bool = Query(False, description="Show only VPN traffic"),
    asn: Optional[str] = Query(None, description="ASN name search"),
    dst_port: Optional[str] = Query(None, description="Destination port (prefix with ! to negate)"),
    src_port: Optional[str] = Query(None, description="Source port (prefix with ! to negate)"),
    protocol: Optional[str] = Query(None, description="Comma-separated: TCP,UDP,ICMP (prefix with ! to negate)"),
    sort: str = Query("timestamp", description="Sort field"),
    order: str = Query("desc", description="asc or desc"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
):
    time_range, time_from, time_to = validate_time_params(time_range, time_from, time_to)
    where, params = build_log_query(
        log_type, time_range, time_from, time_to,
        src_ip, dst_ip, ip, direction, rule_action,
        rule_name, country, threat_min, search, service,
        interface, vpn_only, asn=asn,
        dst_port=dst_port, src_port=src_port, protocol=protocol,
    )

    # Whitelist sort columns
    allowed_sorts = {
        'timestamp', 'log_type', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
        'protocol', 'service_name', 'direction', 'rule_action', 'rule_name',
        'geo_country', 'threat_score', 'hostname', 'created_at',
    }
    sort_col = sort if sort in allowed_sorts else 'timestamp'
    sort_dir = 'ASC' if order.lower() == 'asc' else 'DESC'
    offset = (page - 1) * per_page

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Count total
            cur.execute(f"SELECT COUNT(*) as total FROM logs WHERE {where}", params)
            total = cur.fetchone()['total']

            # Fetch page, enriching with live device names from unifi_clients + unifi_devices
            cur.execute(
                f"""WITH page AS (
                        SELECT * FROM logs WHERE {where}
                        ORDER BY {sort_col} {sort_dir} LIMIT %s OFFSET %s
                    )
                    SELECT page.*,
                        {device_name_coalesce('c1', 'd1', 'src_device_name', 'page.src_device_name')},
                        {device_name_coalesce('c2', 'd2', 'dst_device_name', 'page.dst_device_name')}
                    FROM page
                    LEFT JOIN unifi_clients c1 ON c1.mac = page.mac_address
                    {device_name_client_lateral('page.dst_ip', 'c2')}
                    LEFT JOIN unifi_devices d1 ON d1.mac = page.mac_address
                    {device_name_device_lateral('page.dst_ip', 'd2')}
                    ORDER BY page.{sort_col} {sort_dir}""",
                params + [per_page, offset]
            )
            rows = cur.fetchall()

        logs = [_serialize_log(row) for row in rows]
        _annotate_logs(logs)

        conn.commit()
        return {
            'data': logs,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page if per_page else 0,
        }
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching logs")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


# ── Aggregation ──────────────────────────────────────────────────────────────

# Maps user-facing group_by values to SQL expressions and column aliases.
_GROUP_BY_MAP = {
    'src_ip':    ('src_ip::text',       'src_ip'),
    'dst_ip':    ('dst_ip::text',       'dst_ip'),
    'country':   ('geo_country',        'geo_country'),
    'asn':       ('asn_name',           'asn_name'),
    'rule_name': ('rule_name',          'rule_name'),
    'service':   ('service_name',       'service_name'),
}

_VALID_PREFIXES = {8, 16, 22, 24}

# Whitelist mapping group_by values to the actual SQL column name for CIDR collapsing.
_CIDR_COLUMN = {'src_ip': 'src_ip', 'dst_ip': 'dst_ip'}


@router.get("/api/logs/aggregate")
def get_logs_aggregate(
    group_by: str = Query(..., description="Group by: src_ip, dst_ip, country, asn, rule_name, service"),
    prefix_length: Optional[int] = Query(None, description=f"CIDR prefix for IP grouping: {', '.join(str(p) for p in sorted(_VALID_PREFIXES))}"),
    having_min_total: Optional[int] = Query(None, ge=1, description="Min row count per group"),
    having_min_unique_ips: Optional[int] = Query(None, ge=1, description="Min distinct src_ip per group"),
    limit: int = Query(100, ge=1, le=500),
    # ── All standard log filters ──
    log_type: Optional[str] = Query(None),
    time_range: Optional[str] = Query(None),
    time_from: Optional[str] = Query(None),
    time_to: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    rule_action: Optional[str] = Query(None),
    rule_name: Optional[str] = Query(None),
    country: Optional[str] = Query(None),
    threat_min: Optional[int] = Query(None),
    search: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    interface: Optional[str] = Query(None),
    vpn_only: bool = Query(False),
    asn: Optional[str] = Query(None),
    dst_port: Optional[str] = Query(None, description="Destination port (prefix with ! to negate)"),
    src_port: Optional[str] = Query(None, description="Source port (prefix with ! to negate)"),
    protocol: Optional[str] = Query(None, description="Comma-separated: TCP,UDP,ICMP (prefix with ! to negate)"),
):
    """Aggregate logs by a dimension, returning grouped counts and optional metrics."""
    if group_by not in _GROUP_BY_MAP:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid group_by. Must be one of: {', '.join(sorted(_GROUP_BY_MAP))}"
        )

    if prefix_length is not None:
        if group_by not in ('src_ip', 'dst_ip'):
            raise HTTPException(status_code=400, detail="prefix_length only applies to src_ip or dst_ip grouping")
        if prefix_length not in _VALID_PREFIXES:
            raise HTTPException(status_code=400, detail=f"prefix_length must be one of: {sorted(_VALID_PREFIXES)}")

    # having_min_unique_ips counts distinct src_ips per group.  When group_by='src_ip'
    # without prefix_length, each group IS a single src_ip, so "min unique IPs" is
    # always 1 — the filter would be meaningless.  With prefix_length it aggregates
    # into CIDR blocks where unique-IP counts vary.  For group_by='dst_ip' (no prefix),
    # unique src_ip counts per dst_ip are naturally variable, so no prefix is needed.
    if having_min_unique_ips is not None and group_by == 'src_ip' and prefix_length is None:
        raise HTTPException(status_code=400, detail="having_min_unique_ips requires prefix_length when grouping by src_ip")

    time_range, time_from, time_to = validate_time_params(time_range, time_from, time_to)
    where, params = build_log_query(
        log_type, time_range, time_from, time_to,
        src_ip, dst_ip, ip, direction, rule_action,
        rule_name, country, threat_min, search, service,
        interface, vpn_only, asn=asn,
        dst_port=dst_port, src_port=src_port, protocol=protocol,
    )

    # Build GROUP BY expression and per-clause param lists
    sql_expr, alias = _GROUP_BY_MAP[group_by]
    collapsing_cidrs = prefix_length is not None
    select_params = []   # params referenced in SELECT
    group_params = []    # params referenced in GROUP BY

    if collapsing_cidrs:
        ip_col = _CIDR_COLUMN[group_by]  # KeyError if group_by not in whitelist
        sql_expr = f"network(set_masklen({ip_col}, %s))::text"
        alias = f"{group_by}_cidr"
        select_params.append(prefix_length)
        group_params.append(prefix_length)

    # Distinct-IP counts are omitted only when every row in the group is
    # already a single IP (group_by=src_ip/dst_ip without prefix_length).
    # With CIDR collapsing, each group contains many IPs so the counts
    # remain useful.
    is_grouping_individual_ips = not collapsing_cidrs
    select_parts = [f"{sql_expr} AS {alias}", "COUNT(*) AS total"]
    if not (group_by == 'src_ip' and is_grouping_individual_ips):
        select_parts.append("COUNT(DISTINCT src_ip) AS unique_src_ips")
    if not (group_by == 'dst_ip' and is_grouping_individual_ips):
        select_parts.append("COUNT(DISTINCT dst_ip) AS unique_dst_ips")

    # When collapsing IPs into CIDRs, surface the most common country / ASN
    if collapsing_cidrs:
        # PostgreSQL-specific MODE() ordered-set aggregate: returns the most
        # frequently occurring value in the group (top country / ASN here).
        select_parts.append("MODE() WITHIN GROUP (ORDER BY geo_country) AS top_country")
        select_parts.append("MODE() WITHIN GROUP (ORDER BY asn_name) AS top_asn")

    # HAVING clauses
    having_parts = []
    having_params = []
    if having_min_total is not None:
        having_parts.append("COUNT(*) >= %s")
        having_params.append(having_min_total)
    if having_min_unique_ips is not None:
        having_parts.append("COUNT(DISTINCT src_ip) >= %s")
        having_params.append(having_min_unique_ips)

    having_sql = f"HAVING {' AND '.join(having_parts)}" if having_parts else ""

    sql = f"""
        SELECT {', '.join(select_parts)}
        FROM logs
        WHERE {where}
        GROUP BY {sql_expr}
        {having_sql}
        ORDER BY total DESC
        LIMIT %s
    """

    # Assemble params in SQL clause order to match the %s placeholders:
    #   SELECT → WHERE → GROUP BY → HAVING → LIMIT
    final_params = select_params + params + group_params + having_params + [limit]

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, final_params)
            rows = [dict(r) for r in cur.fetchall()]
        conn.commit()
        return {
            'group_by': group_by,
            'prefix_length': prefix_length,
            'count': len(rows),
            'data': rows,
        }
    except Exception as e:
        conn.rollback()
        logger.exception("Error in log aggregation")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


# ── Shared helpers for detailed log queries ──────────────────────────────────

# Join ip_threats on both src and dst to fill abuse fields for logs not yet
# patched by the backfill daemon.  WAN IPs excluded via params.
_LOG_DETAIL_SQL = """
    SELECT l.*,
        COALESCE(l.abuse_usage_type,
            CASE WHEN l.direction IN ('inbound', 'in') THEN t1.abuse_usage_type
                 WHEN l.direction IN ('outbound', 'out') THEN t2.abuse_usage_type
                 WHEN t1.ip IS NOT NULL THEN t1.abuse_usage_type
                 ELSE t2.abuse_usage_type END) as abuse_usage_type,
        COALESCE(l.abuse_hostnames,
            CASE WHEN l.direction IN ('inbound', 'in') THEN t1.abuse_hostnames
                 WHEN l.direction IN ('outbound', 'out') THEN t2.abuse_hostnames
                 WHEN t1.ip IS NOT NULL THEN t1.abuse_hostnames
                 ELSE t2.abuse_hostnames END) as abuse_hostnames,
        COALESCE(l.abuse_total_reports,
            CASE WHEN l.direction IN ('inbound', 'in') THEN t1.abuse_total_reports
                 WHEN l.direction IN ('outbound', 'out') THEN t2.abuse_total_reports
                 WHEN t1.ip IS NOT NULL THEN t1.abuse_total_reports
                 ELSE t2.abuse_total_reports END) as abuse_total_reports,
        COALESCE(l.abuse_last_reported,
            CASE WHEN l.direction IN ('inbound', 'in') THEN t1.abuse_last_reported
                 WHEN l.direction IN ('outbound', 'out') THEN t2.abuse_last_reported
                 WHEN t1.ip IS NOT NULL THEN t1.abuse_last_reported
                 ELSE t2.abuse_last_reported END) as abuse_last_reported,
        COALESCE(l.abuse_is_whitelisted,
            CASE WHEN l.direction IN ('inbound', 'in') THEN t1.abuse_is_whitelisted
                 WHEN l.direction IN ('outbound', 'out') THEN t2.abuse_is_whitelisted
                 WHEN t1.ip IS NOT NULL THEN t1.abuse_is_whitelisted
                 ELSE t2.abuse_is_whitelisted END) as abuse_is_whitelisted,
        COALESCE(l.abuse_is_tor,
            CASE WHEN l.direction IN ('inbound', 'in') THEN t1.abuse_is_tor
                 WHEN l.direction IN ('outbound', 'out') THEN t2.abuse_is_tor
                 WHEN t1.ip IS NOT NULL THEN t1.abuse_is_tor
                 ELSE t2.abuse_is_tor END) as abuse_is_tor,
        COALESCE(
            CASE WHEN array_length(l.threat_categories, 1) > 0 THEN l.threat_categories END,
            CASE WHEN l.direction IN ('inbound', 'in') THEN
                     CASE WHEN array_length(t1.threat_categories, 1) > 0 THEN t1.threat_categories END
                 WHEN l.direction IN ('outbound', 'out') THEN
                     CASE WHEN array_length(t2.threat_categories, 1) > 0 THEN t2.threat_categories END
                 WHEN t1.ip IS NOT NULL THEN
                     CASE WHEN array_length(t1.threat_categories, 1) > 0 THEN t1.threat_categories END
                 ELSE
                     CASE WHEN array_length(t2.threat_categories, 1) > 0 THEN t2.threat_categories END
            END
        ) as threat_categories,
        """ + device_name_coalesce('c1', 'd1', 'src_device_name', 'l.src_device_name') + """,
        """ + device_name_coalesce('c2', 'd2', 'dst_device_name', 'l.dst_device_name') + """
    FROM logs l
    LEFT JOIN ip_threats t1 ON t1.ip = l.src_ip
        AND NOT (l.src_ip = ANY(%s::inet[]))
    LEFT JOIN ip_threats t2 ON t2.ip = l.dst_ip
        AND NOT (l.dst_ip = ANY(%s::inet[]))
    LEFT JOIN unifi_clients c1 ON c1.mac = l.mac_address
    """ + device_name_client_lateral('l.dst_ip', 'c2') + """
    LEFT JOIN unifi_devices d1 ON d1.mac = l.mac_address
    """ + device_name_device_lateral('l.dst_ip', 'd2') + """
"""


def _serialize_log(row):
    """Convert a raw log DB row to API-friendly dict."""
    log = dict(row)
    for key in ('timestamp', 'created_at', 'abuse_last_reported'):
        if log.get(key):
            log[key] = log[key].isoformat()
    for key in ('src_ip', 'dst_ip', 'remote_ip', 'mac_address'):
        if log.get(key):
            log[key] = str(log[key])
    if log.get('geo_lat') is not None:
        log['geo_lat'] = float(log['geo_lat'])
    if log.get('geo_lon') is not None:
        log['geo_lon'] = float(log['geo_lon'])
    return log


def _annotate_logs(logs):
    """Annotate logs with gateway/VPN device names and service descriptions."""
    cfg = load_identity_config(enricher_db)
    for log in logs:
        annotate_record(cfg, log)
        desc = get_service_description(log.get('dst_port'), log.get('protocol'))
        if desc:
            log['service_description'] = desc


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/api/logs/{log_id}")
def get_log(log_id: int):
    wan_ips = get_wan_ips_from_config(enricher_db)
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                _LOG_DETAIL_SQL + " WHERE l.id = %s",
                [wan_ips, wan_ips, log_id]
            )
            row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Log not found")
        log = _serialize_log(row)
        _annotate_logs([log])
        conn.commit()
        return log
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching log detail")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


class LogBatchRequest(BaseModel):
    ids: list[int] = Field(..., min_length=1, max_length=50)


@router.post("/api/logs/batch")
def get_logs_batch(payload: LogBatchRequest):
    """Fetch multiple logs by ID (max 50). Used by threat map sidebar."""
    ids = payload.ids
    wan_ips = get_wan_ips_from_config(enricher_db)
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                _LOG_DETAIL_SQL + " WHERE l.id = ANY(%s) ORDER BY l.timestamp DESC",
                [wan_ips, wan_ips, ids]
            )
            rows = cur.fetchall()
        logs = [_serialize_log(row) for row in rows]
        _annotate_logs(logs)
        conn.commit()
        return logs
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching log batch")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/export")
def export_csv_endpoint(
    log_type: Optional[str] = Query(None),
    time_range: Optional[str] = Query(None),
    time_from: Optional[str] = Query(None),
    time_to: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    rule_action: Optional[str] = Query(None),
    rule_name: Optional[str] = Query(None),
    country: Optional[str] = Query(None),
    threat_min: Optional[int] = Query(None),
    search: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    interface: Optional[str] = Query(None),
    vpn_only: bool = Query(False),
    asn: Optional[str] = Query(None),
    dst_port: Optional[str] = Query(None),
    src_port: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    limit: int = Query(10000, ge=1, le=100000),
):
    time_range, time_from, time_to = validate_time_params(time_range, time_from, time_to)
    where, params = build_log_query(
        log_type, time_range, time_from, time_to,
        src_ip, dst_ip, ip, direction, rule_action,
        rule_name, country, threat_min, search, service, interface, vpn_only, asn=asn,
        dst_port=dst_port, src_port=src_port, protocol=protocol,
    )

    export_columns = [
        'timestamp', 'log_type', 'direction', 'src_ip', 'src_port',
        'dst_ip', 'dst_port', 'protocol', 'service_name', 'rule_name', 'rule_desc',
        'rule_action', 'interface_in', 'interface_out', 'mac_address',
        'hostname', 'dns_query', 'dns_type', 'dns_answer',
        'geo_country', 'geo_city', 'asn_name', 'threat_score',
        'threat_categories', 'rdns',
        'abuse_usage_type', 'abuse_total_reports', 'abuse_last_reported',
        'abuse_is_tor', 'remote_ip',
    ]

    # CSV header includes device name + VLAN + VPN network columns resolved via live JOIN
    csv_columns = export_columns + [
        'src_device_name', 'dst_device_name',
        'src_device_vlan', 'dst_device_vlan',
        'src_device_network', 'dst_device_network',
    ]

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"""WITH filtered AS (
                        SELECT * FROM logs WHERE {where}
                        ORDER BY timestamp DESC LIMIT %s
                    )
                    SELECT {', '.join('f.' + c for c in export_columns)},
                        {device_name_coalesce('c1', 'd1', 'src_device_name', 'f.src_device_name')},
                        {device_name_coalesce('c2', 'd2', 'dst_device_name', 'f.dst_device_name')}
                    FROM filtered f
                    LEFT JOIN unifi_clients c1 ON c1.mac = f.mac_address
                    {device_name_client_lateral('f.dst_ip', 'c2')}
                    LEFT JOIN unifi_devices d1 ON d1.mac = f.mac_address
                    {device_name_device_lateral('f.dst_ip', 'd2')}
                    ORDER BY f.timestamp DESC""",
                params + [limit]
            )
            rows = cur.fetchall()

        # Annotate gateway/WAN IPs and VPN badges in CSV rows
        cfg = load_identity_config(enricher_db)
        src_ip_idx = export_columns.index('src_ip')
        dst_ip_idx = export_columns.index('dst_ip')
        src_name_idx = len(export_columns)      # first appended column
        dst_name_idx = len(export_columns) + 1

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(csv_columns)
        for row in rows:
            # append vlan + network columns (4 total)
            row = list(row) + [None, None, None, None]
            src_vlan_idx = src_name_idx + 2
            dst_vlan_idx = src_name_idx + 3
            src_net_idx = src_name_idx + 4
            dst_net_idx = src_name_idx + 5
            for ip_idx, name_idx, vlan_idx, net_idx in [
                (src_ip_idx, src_name_idx, src_vlan_idx, src_net_idx),
                (dst_ip_idx, dst_name_idx, dst_vlan_idx, dst_net_idx),
            ]:
                ip_str = str(row[ip_idx] or '').split('/')[0]
                name, vlan, vpn_badge = annotate_ip(cfg, ip_str, row[name_idx])
                if name and not row[name_idx]:
                    row[name_idx] = name
                if vlan is not None:
                    row[vlan_idx] = vlan
                if vpn_badge and name == 'Gateway':
                    row[net_idx] = vpn_badge
            writer.writerow([str(v) if v is not None else '' for v in row])

        output.seek(0)
        conn.commit()
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=unifi_logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            }
        )
    except Exception as e:
        conn.rollback()
        logger.exception("Error exporting CSV")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/services")
@ttl_cache(seconds=30)
def get_services():
    """Return distinct service names for autocomplete filtering."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT service_name
                FROM logs
                WHERE service_name IS NOT NULL
                  AND timestamp > now() - interval '36 hours'
                ORDER BY service_name
            """)
            services = [row[0] for row in cur.fetchall()]
        conn.commit()
        return {'services': services}
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching services")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/protocols")
@ttl_cache(seconds=30)
def get_protocols():
    """Return distinct protocols seen in logs for dropdown filtering."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT protocol
                FROM logs
                WHERE protocol IS NOT NULL
                  AND timestamp > now() - interval '36 hours'
                ORDER BY protocol
            """)
            protocols = [row[0] for row in cur.fetchall()]
        conn.commit()
        return {'protocols': protocols}
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching protocols")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)
