"""Flow graph, zone matrix, and host detail endpoints."""

import ipaddress
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Query, HTTPException
from psycopg2.extras import RealDictCursor

from db import get_config
from deps import get_conn, put_conn, enricher_db
from ip_identity import load_identity_config, annotate_ip
from query_helpers import (build_log_query, validate_time_params, ALLOWED_DIMENSIONS,
                          device_name_client_lateral, device_name_device_lateral,
                          device_name_coalesce)

logger = logging.getLogger('api.flows')

router = APIRouter()

# SQL expressions for each dimension — never interpolate user input directly
DIMENSION_EXPRS = {
    'src_ip': "host(src_ip)",
    'dst_ip': "host(dst_ip)",
    'dst_port': "COALESCE(dst_port::text, 'Unknown')",
    'protocol': "COALESCE(LOWER(protocol), 'unknown')",
    'service_name': "COALESCE(service_name, 'Unknown')",
    'direction': "COALESCE(direction, 'unknown')",
    'interface_in': "COALESCE(interface_in, 'unknown')",
    'interface_out': "COALESCE(interface_out, 'unknown')",
}

MAX_NODES = 200
MAX_LINKS = 400
MIN_TOP_N = 3



def _build_sankey(rows, dims, requested_top_n, applied_top_n):
    """Convert aggregated rows into nodes + links for the Sankey chart."""
    node_values = {}  # id -> total value
    link_map = {}     # (source_id, target_id) -> value

    dim_a, dim_b, dim_c = dims

    for row in rows:
        a_val, b_val, c_val, value = row['a'], row['b'], row['c'], row['value']
        a_id = f"{dim_a}:{a_val}"
        b_id = f"{dim_b}:{b_val}"
        c_id = f"{dim_c}:{c_val}"

        # Accumulate node values
        node_values[a_id] = node_values.get(a_id, 0) + value
        node_values[b_id] = node_values.get(b_id, 0) + value
        node_values[c_id] = node_values.get(c_id, 0) + value

        # Accumulate link values (a→b and b→c)
        ab = (a_id, b_id)
        link_map[ab] = link_map.get(ab, 0) + value
        bc = (b_id, c_id)
        link_map[bc] = link_map.get(bc, 0) + value

    nodes = [
        {"id": nid, "label": nid.split(":", 1)[1], "type": nid.split(":", 1)[0], "value": val}
        for nid, val in node_values.items()
    ]
    links = [
        {"source": src, "target": tgt, "value": val}
        for (src, tgt), val in link_map.items()
    ]

    capped = requested_top_n != applied_top_n
    return nodes, links, capped


def _lookup_ip_info(conn, nodes):
    """Bulk lookup device names, VLAN, and network badges for IP nodes."""
    ip_set = {n['label'] for n in nodes
              if n['type'] in ('src_ip', 'dst_ip') and n['label'] != 'Other'}
    if not ip_set:
        return {}, {}, {}

    device_names = {}
    ip_list = list(ip_set)
    placeholders = ','.join(['%s::inet'] * len(ip_list))

    # Track VLAN per IP from unifi_clients
    client_vlans = {}

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(f"""
            SELECT DISTINCT ON (ip) host(ip) AS ip_str,
                   COALESCE(device_name, hostname, oui) AS device_name,
                   vlan
            FROM unifi_clients
            WHERE ip IN ({placeholders})
            ORDER BY ip, last_seen DESC NULLS LAST
        """, ip_list)
        for row in cur.fetchall():
            if row['device_name']:
                device_names[row['ip_str']] = row['device_name']
            if row['vlan'] is not None:
                client_vlans[row['ip_str']] = row['vlan']

        missing = [i for i in ip_list if i not in device_names]
        if missing:
            ph = ','.join(['%s::inet'] * len(missing))
            cur.execute(f"""
                SELECT DISTINCT ON (ip) host(ip) AS ip_str,
                       COALESCE(device_name, model) AS device_name
                FROM unifi_devices
                WHERE ip IN ({ph})
                ORDER BY ip, updated_at DESC NULLS LAST
            """, missing)
            for row in cur.fetchall():
                if row['device_name']:
                    device_names[row['ip_str']] = row['device_name']

    # Annotate from identity config (gateway, WAN, VPN)
    gateway_vlans = {}
    vpn_badges = {}
    cfg = load_identity_config(enricher_db)
    for ip_str in ip_set:
        name, vlan, vpn_badge = annotate_ip(cfg, ip_str, device_names.get(ip_str))
        if name and not device_names.get(ip_str):
            device_names[ip_str] = name
        if vlan is not None:
            gateway_vlans[ip_str] = vlan
        elif ip_str in client_vlans:
            gateway_vlans[ip_str] = client_vlans[ip_str]
        if vpn_badge:
            vpn_badges[ip_str] = vpn_badge

    return device_names, gateway_vlans, vpn_badges


@router.get("/api/flows/graph")
def get_flow_graph(
    time_range: Optional[str] = Query("24h"),
    time_from: Optional[str] = Query(None),
    time_to: Optional[str] = Query(None),
    dimensions: str = Query("src_ip,dst_port,dst_ip"),
    top_n: int = Query(15, ge=3, le=50),
    log_type: Optional[str] = Query("firewall"),
    rule_action: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    interface: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
):
    # Validate dimensions
    dims = [d.strip() for d in dimensions.split(',')]
    if len(dims) != 3 or len(set(dims)) != 3:
        raise HTTPException(status_code=400, detail="dimensions must be exactly 3 unique values")
    for d in dims:
        if d not in ALLOWED_DIMENSIONS:
            raise HTTPException(status_code=400, detail=f"Invalid dimension: {d}. Allowed: {sorted(ALLOWED_DIMENSIONS)}")

    # Validate IP filter
    ip_filter = ""
    ip_params_extra = []
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError as err:
            raise HTTPException(status_code=400, detail="Invalid IP address") from err
        ip_filter = " AND (src_ip = %s::inet OR dst_ip = %s::inet)"
        ip_params_extra = [ip, ip]

    time_range, time_from, time_to = validate_time_params(time_range, time_from, time_to)

    where, params = build_log_query(
        log_type=log_type, time_range=time_range, time_from=time_from, time_to=time_to,
        src_ip=None, dst_ip=None, ip=None, direction=direction,
        rule_action=rule_action, rule_name=None, country=None, threat_min=None,
        search=None, service=None, interface=interface,
    )

    dim_a_expr = DIMENSION_EXPRS[dims[0]]
    dim_b_expr = DIMENSION_EXPRS[dims[1]]
    dim_c_expr = DIMENSION_EXPRS[dims[2]]

    requested_top_n = top_n
    base_params = params + ip_params_extra

    # Try with current top_n, reduce if node/link caps exceeded
    conn = get_conn()
    try:
        while top_n >= MIN_TOP_N:
            sql = f"""
            WITH filtered AS (
                SELECT src_ip, dst_ip, dst_port, LOWER(protocol) AS protocol,
                       service_name, direction, interface_in, interface_out
                FROM logs
                WHERE {where}
                  AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
                  {ip_filter}
            ),
            top_a AS (SELECT {dim_a_expr} AS val FROM filtered GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT %s),
            top_b AS (SELECT {dim_b_expr} AS val FROM filtered GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT %s),
            top_c AS (SELECT {dim_c_expr} AS val FROM filtered GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT %s),
            mapped AS (
                SELECT
                    CASE WHEN {dim_a_expr} IN (SELECT val FROM top_a) THEN ({dim_a_expr})::text ELSE 'Other' END AS a,
                    CASE WHEN {dim_b_expr} IN (SELECT val FROM top_b) THEN ({dim_b_expr})::text ELSE 'Other' END AS b,
                    CASE WHEN {dim_c_expr} IN (SELECT val FROM top_c) THEN ({dim_c_expr})::text ELSE 'Other' END AS c
                FROM filtered
            )
            SELECT a, b, c, COUNT(*) AS value
            FROM mapped
            GROUP BY a, b, c
            ORDER BY value DESC
            """
            query_params = base_params + [top_n, top_n, top_n]

            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, query_params)
                rows = cur.fetchall()

            nodes, links, _ = _build_sankey(rows, dims, requested_top_n, top_n)

            if len(nodes) <= MAX_NODES and len(links) <= MAX_LINKS:
                device_names, gateway_vlans, vpn_badges = _lookup_ip_info(conn, nodes)
                labels = get_config(enricher_db, 'interface_labels', {}) or {}
                wan = list(get_config(enricher_db, 'wan_interfaces', []) or [])
                conn.commit()
                return {
                    "nodes": nodes,
                    "links": links,
                    "device_names": device_names,
                    "gateway_vlans": gateway_vlans,
                    "vpn_badges": vpn_badges,
                    "interface_labels": labels,
                    "wan_interfaces": wan,
                    "meta": {
                        "requested_top_n": requested_top_n,
                        "applied_top_n": top_n,
                        "capped": top_n != requested_top_n,
                    }
                }

            top_n -= 1

        # Even at MIN_TOP_N, still exceeded caps — reject
        conn.commit()
        raise HTTPException(
            status_code=400,
            detail=f"Flow graph too dense even at top_n={MIN_TOP_N} "
                   f"({len(nodes)} nodes/{len(links)} links exceeds {MAX_NODES}/{MAX_LINKS}). "
                   "Try narrowing filters or changing dimensions."
        )
    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching flow graph")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/flows/zone-matrix")
def get_zone_matrix(
    time_range: Optional[str] = Query("24h"),
    time_from: Optional[str] = Query(None),
    time_to: Optional[str] = Query(None),
    log_type: Optional[str] = Query("firewall"),
    rule_action: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
):
    time_range, time_from, time_to = validate_time_params(time_range, time_from, time_to)

    where, params = build_log_query(
        log_type=log_type, time_range=time_range, time_from=time_from, time_to=time_to,
        src_ip=None, dst_ip=None, ip=None, direction=direction,
        rule_action=rule_action, rule_name=None, country=None, threat_min=None,
        search=None, service=None, interface=None,
    )

    sql = f"""
    SELECT
        interface_in, interface_out,
        COUNT(*) AS total,
        COUNT(*) FILTER (WHERE rule_action = 'allow') AS allow_count,
        COUNT(*) FILTER (WHERE rule_action = 'block') AS block_count,
        COUNT(DISTINCT (host(src_ip) || '-' || host(dst_ip))) AS unique_pairs
    FROM logs
    WHERE {where}
      AND interface_in IS NOT NULL AND interface_out IS NOT NULL
    GROUP BY interface_in, interface_out
    ORDER BY total DESC
    """

    labels = get_config(enricher_db, 'interface_labels', {}) or {}

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        conn.commit()

        interfaces = sorted({r['interface_in'] for r in rows} | {r['interface_out'] for r in rows})
        cells = [
            {
                "interface_in": r['interface_in'],
                "interface_out": r['interface_out'],
                "in_label": labels.get(r['interface_in'], r['interface_in']),
                "out_label": labels.get(r['interface_out'], r['interface_out']),
                "total": r['total'],
                "allow_count": r['allow_count'],
                "block_count": r['block_count'],
                "unique_pairs": r['unique_pairs'],
            }
            for r in rows
        ]

        return {
            "cells": cells,
            "interfaces": interfaces,
            "labels": {iface: labels.get(iface, iface) for iface in interfaces},
        }
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching zone matrix")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/flows/host-detail")
def get_host_detail(
    ip: str = Query(...),
    time_range: Optional[str] = Query("24h"),
    time_from: Optional[str] = Query(None),
    time_to: Optional[str] = Query(None),
    log_type: Optional[str] = Query("firewall"),
    rule_action: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
):
    # Validate IP
    try:
        ipaddress.ip_address(ip)
    except ValueError as err:
        raise HTTPException(status_code=400, detail="Invalid IP address") from err

    time_range, time_from, time_to = validate_time_params(time_range, time_from, time_to)

    where, params = build_log_query(
        log_type=log_type, time_range=time_range, time_from=time_from, time_to=time_to,
        src_ip=None, dst_ip=None, ip=None, direction=direction,
        rule_action=rule_action, rule_name=None, country=None, threat_min=None,
        search=None, service=None, interface=None,
    )

    # All host queries use parenthesized OR to prevent precedence bugs with base filters
    host_where = f"{where} AND (src_ip = %s::inet OR dst_ip = %s::inet)"
    host_params = params + [ip, ip]

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # 1. Summary
            cur.execute(f"""
                SELECT
                    COUNT(*) AS total_events,
                    COUNT(*) FILTER (WHERE rule_action = 'allow') AS allow_count,
                    COUNT(*) FILTER (WHERE rule_action = 'block') AS block_count,
                    COUNT(DISTINCT CASE WHEN src_ip = %s::inet THEN host(dst_ip) ELSE host(src_ip) END) AS unique_peers,
                    MIN(timestamp) AS first_seen,
                    MAX(timestamp) AS last_seen
                FROM logs
                WHERE {host_where}
            """, [ip] + host_params)
            summary = dict(cur.fetchone())
            # Convert timestamps to ISO strings
            for k in ('first_seen', 'last_seen'):
                if summary[k]:
                    summary[k] = summary[k].isoformat()

            # 2. Device info
            cur.execute("""
                SELECT COALESCE(device_name, hostname, oui) AS device_name,
                       network, vlan, mac
                FROM unifi_clients WHERE ip = %s::inet
                ORDER BY last_seen DESC NULLS LAST LIMIT 1
            """, [ip])
            device = cur.fetchone()
            if not device:
                cur.execute("""
                    SELECT COALESCE(device_name, model) AS device_name,
                           NULL AS network, NULL AS vlan, mac
                    FROM unifi_devices WHERE ip = %s::inet
                    ORDER BY updated_at DESC NULLS LAST LIMIT 1
                """, [ip])
                device = cur.fetchone()
            device = dict(device) if device else {"device_name": None, "network": None, "vlan": None, "mac": None}

            # Identity annotation (gateway/WAN/VPN) — mirrors _lookup_ip_info precedence
            cfg = load_identity_config(enricher_db)
            name, vlan, vpn_badge = annotate_ip(cfg, ip, device.get('device_name'))
            if name and not device.get('device_name'):
                device['device_name'] = name
            if vlan is not None:
                device['vlan'] = vlan
            if vpn_badge and not device.get('network'):
                device['network'] = vpn_badge

            # 3. Top outbound peers (this IP as source)
            src_where = f"{where} AND src_ip = %s::inet"
            src_params = params + [ip]
            cur.execute(f"""
                SELECT host(dst_ip) AS peer_ip,
                       COUNT(*) AS count,
                       COUNT(*) FILTER (WHERE rule_action = 'allow') AS allow_count,
                       COUNT(*) FILTER (WHERE rule_action = 'block') AS block_count
                FROM logs
                WHERE {src_where} AND dst_ip IS NOT NULL
                GROUP BY dst_ip
                ORDER BY count DESC
                LIMIT 10
            """, src_params)
            peers_out_raw = [dict(r) for r in cur.fetchall()]

            # 4. Top inbound peers (this IP as destination)
            dst_where = f"{where} AND dst_ip = %s::inet"
            dst_params = params + [ip]
            cur.execute(f"""
                SELECT host(src_ip) AS peer_ip,
                       COUNT(*) AS count,
                       COUNT(*) FILTER (WHERE rule_action = 'allow') AS allow_count,
                       COUNT(*) FILTER (WHERE rule_action = 'block') AS block_count
                FROM logs
                WHERE {dst_where} AND src_ip IS NOT NULL
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT 10
            """, dst_params)
            peers_in_raw = [dict(r) for r in cur.fetchall()]

            # Bulk-enrich peer device names (single query for all peers)
            all_peer_ips = list({p['peer_ip'] for p in peers_out_raw + peers_in_raw})
            peer_name_map = {}
            if all_peer_ips:
                cur.execute(f"""
                    SELECT host(p.ip) AS peer_ip,
                           {device_name_coalesce('c', 'd')}
                    FROM unnest(%s::inet[]) AS p(ip)
                    {device_name_client_lateral('p.ip', 'c')}
                    {device_name_device_lateral('p.ip', 'd')}
                """, [all_peer_ips])
                peer_name_map = {r['peer_ip']: r['device_name'] for r in cur.fetchall()}
            for peer in peers_out_raw + peers_in_raw:
                peer['device_name'] = peer_name_map.get(peer['peer_ip'])

            # 5. Port/service breakdown
            cur.execute(f"""
                SELECT dst_port, COALESCE(service_name, 'Unknown') AS service_name,
                       COALESCE(LOWER(protocol), 'unknown') AS protocol,
                       COUNT(*) AS count
                FROM logs
                WHERE {host_where}
                  AND dst_port IS NOT NULL
                GROUP BY dst_port, service_name, protocol
                ORDER BY count DESC
                LIMIT 15
            """, host_params)
            ports = [dict(r) for r in cur.fetchall()]

        conn.commit()

        return {
            "ip": ip,
            "device_name": device.get("device_name"),
            "network": device.get("network"),
            "vlan": device.get("vlan"),
            "mac": device.get("mac"),
            "summary": summary,
            "peers_as_source": peers_out_raw,
            "peers_as_destination": peers_in_raw,
            "ports": ports,
        }
    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching host detail for %s", ip)
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)
