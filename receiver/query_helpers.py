"""
Query building helpers shared by log and export endpoints.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Single source of truth for valid time ranges and their deltas
_TIME_RANGE_DELTAS = {
    '1h': timedelta(hours=1),
    '6h': timedelta(hours=6),
    '24h': timedelta(hours=24),
    '7d': timedelta(days=7),
    '30d': timedelta(days=30),
    '60d': timedelta(days=60),
    '90d': timedelta(days=90),
    '180d': timedelta(days=180),
    '365d': timedelta(days=365),
}
VALID_TIME_RANGES = set(_TIME_RANGE_DELTAS)


def validate_time_params(
    time_range: Optional[str],
    time_from: Optional[str],
    time_to: Optional[str],
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Validate and sanitize time parameters."""
    if time_range and time_range not in VALID_TIME_RANGES:
        time_range = '24h'
    if not time_range and not time_from:
        time_range = '24h'
    if time_from:
        try:
            datetime.fromisoformat(time_from.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            time_from = None
    if time_to:
        try:
            datetime.fromisoformat(time_to.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            time_to = None
    # Re-apply default: time_from may have been supplied but failed validation above
    if not time_range and not time_from:
        time_range = '24h'
    return time_range, time_from, time_to


def _parse_negation(value: str) -> tuple[bool, str]:
    """Check if a filter value is negated (prefixed with '!').
    Returns (is_negated, clean_value).
    """
    if value.startswith('!'):
        return True, value[1:]
    return False, value


def _parse_port(value: str) -> tuple[bool, int | None]:
    """Parse a port filter value, supporting '!' prefix for negation.
    Returns (is_negated, port_int_or_None).
    """
    negated, clean = _parse_negation(value)
    try:
        port = int(clean)
        if 1 <= port <= 65535:
            return negated, port
        logger.debug("Port value out of range (1-65535): %r", value)
    except (ValueError, TypeError):
        logger.debug("Non-numeric port value: %r", value)
    return negated, None


def parse_time_range(time_range: str) -> Optional[datetime]:
    """Convert time range string to a datetime cutoff."""
    now = datetime.now(timezone.utc)
    delta = _TIME_RANGE_DELTAS.get(time_range)
    return now - delta if delta else None


def build_log_query(
    log_type: Optional[str],
    time_range: Optional[str],
    time_from: Optional[str],
    time_to: Optional[str],
    src_ip: Optional[str],
    dst_ip: Optional[str],
    ip: Optional[str],
    direction: Optional[str],
    rule_action: Optional[str],
    rule_name: Optional[str],
    country: Optional[str],
    threat_min: Optional[int],
    search: Optional[str],
    service: Optional[str],
    interface: Optional[str],
    vpn_only: bool = False,
    asn: Optional[str] = None,
    dst_port: Optional[str] = None,
    src_port: Optional[str] = None,
    protocol: Optional[str] = None,
) -> tuple[str, list]:
    """Build WHERE clause and params from filters."""
    conditions = []
    params = []

    if log_type:
        types = [t.strip() for t in log_type.split(',')]
        placeholders = ','.join(['%s'] * len(types))
        conditions.append(f"log_type IN ({placeholders})")
        params.extend(types)

    if time_range:
        cutoff = parse_time_range(time_range)
        if cutoff:
            conditions.append("timestamp >= %s")
            params.append(cutoff)

    if time_from:
        conditions.append("timestamp >= %s")
        params.append(time_from)

    if time_to:
        conditions.append("timestamp <= %s")
        params.append(time_to)

    if src_ip:
        negated, val = _parse_negation(src_ip)
        op = "NOT LIKE" if negated else "LIKE"
        if negated:
            conditions.append(f"(src_ip::text {op} %s ESCAPE '\\' OR src_ip IS NULL)")
        else:
            conditions.append(f"src_ip::text {op} %s ESCAPE '\\'") 
        params.append(f"%{_escape_like(val)}%")

    if dst_ip:
        negated, val = _parse_negation(dst_ip)
        op = "NOT LIKE" if negated else "LIKE"
        if negated:
            conditions.append(f"(dst_ip::text {op} %s ESCAPE '\\' OR dst_ip IS NULL)")
        else:
            conditions.append(f"dst_ip::text {op} %s ESCAPE '\\'") 
        params.append(f"%{_escape_like(val)}%")

    if ip:
        negated, val = _parse_negation(ip)
        escaped_ip = _escape_like(val)
        if negated:
            conditions.append(
                "((src_ip::text NOT LIKE %s ESCAPE '\\' OR src_ip IS NULL)"
                " AND (dst_ip::text NOT LIKE %s ESCAPE '\\' OR dst_ip IS NULL))"
            )
        else:
            conditions.append("(src_ip::text LIKE %s ESCAPE '\\' OR dst_ip::text LIKE %s ESCAPE '\\')")
        params.extend([f"%{escaped_ip}%", f"%{escaped_ip}%"])

    if direction:
        directions = [d.strip() for d in direction.split(',')]
        # When VPN filter is active, always include 'vpn' direction so
        # VPN↔LAN traffic isn't excluded by the direction filter.
        if vpn_only and 'vpn' not in directions:
            directions.append('vpn')
        placeholders = ','.join(['%s'] * len(directions))
        conditions.append(f"direction IN ({placeholders})")
        params.extend(directions)

    if rule_action:
        negated, val = _parse_negation(rule_action)
        actions = [a.strip() for a in val.split(',')]
        placeholders = ','.join(['%s'] * len(actions))
        if negated:
            conditions.append(f"(rule_action NOT IN ({placeholders}) OR rule_action IS NULL)")
        else:
            conditions.append(f"rule_action IN ({placeholders})")
        params.extend(actions)

    if rule_name:
        negated, val = _parse_negation(rule_name)
        escaped = _escape_like(val)
        # The UI adds a space after ']' for display (e.g. "[WAN_LOCAL] Allow All Traffic")
        # but the DB stores it without the space ("[WAN_LOCAL]Allow All Traffic").
        # Normalize by also trying the value with '] ' collapsed to ']'.
        escaped_norm = _escape_like(val.replace('] ', ']'))
        if negated:
            conditions.append(
                "(rule_name NOT ILIKE %s ESCAPE '\\' OR rule_name IS NULL)"
                " AND (rule_desc NOT ILIKE %s ESCAPE '\\' OR rule_desc IS NULL)"
                " AND (rule_desc NOT ILIKE %s ESCAPE '\\' OR rule_desc IS NULL)"
            )
            params.extend([f"%{escaped}%", f"%{escaped}%", f"%{escaped_norm}%"])
        else:
            conditions.append(
                "(rule_name ILIKE %s ESCAPE '\\'"
                " OR rule_desc ILIKE %s ESCAPE '\\'"
                " OR rule_desc ILIKE %s ESCAPE '\\')"
            )
            params.extend([f"%{escaped}%", f"%{escaped}%", f"%{escaped_norm}%"])

    if country:
        negated, val = _parse_negation(country)
        countries = [c.strip().upper() for c in val.split(',')]
        placeholders = ','.join(['%s'] * len(countries))
        keyword = "NOT IN" if negated else "IN"
        condition = f"geo_country {keyword} ({placeholders})"
        if negated:
            condition = f"({condition} OR geo_country IS NULL)"
        conditions.append(condition)
        params.extend(countries)

    if threat_min is not None:
        conditions.append("threat_score >= %s")
        params.append(threat_min)

    if search:
        negated, val = _parse_negation(search)
        op = "NOT ILIKE" if negated else "ILIKE"
        escaped = _escape_like(val)
        conditions.append(f"raw_log {op} %s ESCAPE '\\'")
        params.append(f"%{escaped}%")

    if service:
        negated, val = _parse_negation(service)
        services = [s.strip() for s in val.split(',')]
        placeholders = ','.join(['%s'] * len(services))
        keyword = "NOT IN" if negated else "IN"
        condition = f"service_name {keyword} ({placeholders})"
        if negated:
            condition = f"({condition} OR service_name IS NULL)"
        conditions.append(condition)
        params.extend(services)

    if interface:
        ifaces = [i.strip() for i in interface.split(',')]
        placeholders = ','.join(['%s'] * len(ifaces))
        conditions.append(f"(interface_in IN ({placeholders}) OR interface_out IN ({placeholders}))")
        params.extend(ifaces)
        params.extend(ifaces)  # Twice: once for interface_in, once for interface_out

    if asn:
        negated, val = _parse_negation(asn)
        escaped_asn = _escape_like(val)
        op = "NOT ILIKE" if negated else "ILIKE"
        if negated:
            conditions.append(f"(asn_name {op} %s ESCAPE '\\' OR asn_name IS NULL)")
        else:
            conditions.append(f"asn_name {op} %s ESCAPE '\\'") 
        params.append(f"%{escaped_asn}%")

    if dst_port:
        negated, port_val = _parse_port(dst_port)
        if port_val is not None:
            if negated:
                conditions.append("(dst_port != %s OR dst_port IS NULL)")
            else:
                conditions.append("dst_port = %s")
            params.append(port_val)

    if src_port:
        negated, port_val = _parse_port(src_port)
        if port_val is not None:
            if negated:
                conditions.append("(src_port != %s OR src_port IS NULL)")
            else:
                conditions.append("src_port = %s")
            params.append(port_val)

    if protocol:
        negated, val = _parse_negation(protocol)
        protocols = [p.strip().lower() for p in val.split(',')]
        placeholders = ','.join(['%s'] * len(protocols))
        keyword = "NOT IN" if negated else "IN"
        condition = f"LOWER(protocol) {keyword} ({placeholders})"
        if negated:
            condition = f"({condition} OR protocol IS NULL)"
        conditions.append(condition)
        params.extend(protocols)

    if vpn_only:
        from parsers import VPN_INTERFACE_PREFIXES
        vpn_parts = []
        for pfx in VPN_INTERFACE_PREFIXES:
            vpn_parts.append("interface_in LIKE %s")
            vpn_parts.append("interface_out LIKE %s")
            params.extend([f"{pfx}%", f"{pfx}%"])
        conditions.append(f"({' OR '.join(vpn_parts)})")

    where = " AND ".join(conditions) if conditions else "1=1"
    return where, params


def _escape_like(value: str) -> str:
    """Escape LIKE wildcard characters in user input."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# ── Saved view filter validation ─────────────────────────────────────────────

# Canonical dimension set — single source of truth for flows + saved view validation
ALLOWED_DIMENSIONS = {
    'src_ip', 'dst_ip', 'dst_port', 'protocol',
    'service_name', 'direction', 'interface_in', 'interface_out',
}
_VALID_ACTIONS = {'allow', 'block'}
_VALID_DIRECTIONS = {'inbound', 'outbound', 'inter_vlan', 'nat', 'local', 'vpn'}


def validate_view_filters(filters: dict) -> str | None:
    """Validate saved view filters against canonical backend enums.

    Returns None if valid, or an error message string if invalid.
    Shared by routes/views.py and routes/setup.py (config import).
    """
    if not isinstance(filters, dict):
        return "filters must be a JSON object"

    dims = filters.get('dims')
    if not isinstance(dims, list) or len(dims) != 3:
        return "dims must be an array of exactly 3 values"
    if len(set(dims)) != 3:
        return "dims must contain 3 unique values"
    for d in dims:
        if d not in ALLOWED_DIMENSIONS:
            return f"Invalid dimension: {d}. Allowed: {sorted(ALLOWED_DIMENSIONS)}"

    top_n = filters.get('topN')
    if not isinstance(top_n, int) or top_n < 3 or top_n > 50:
        return "topN must be an integer between 3 and 50"

    actions = filters.get('activeActions')
    if not isinstance(actions, list) or not actions:
        return "activeActions must be a non-empty array"
    if not set(actions).issubset(_VALID_ACTIONS):
        return f"activeActions must be a subset of {sorted(_VALID_ACTIONS)}"

    directions = filters.get('activeDirections')
    if not isinstance(directions, list) or not directions:
        return "activeDirections must be a non-empty array"
    if not set(directions).issubset(_VALID_DIRECTIONS):
        return f"activeDirections must be a subset of {sorted(_VALID_DIRECTIONS)}"

    time_range = filters.get('timeRange')
    if time_range is not None and time_range not in VALID_TIME_RANGES:
        return f"timeRange must be one of {sorted(VALID_TIME_RANGES)} or null"

    return None
