"""Firewall policy matcher — zone map building, snapshot caching, and log-to-policy matching.

This module is the single home for:
- Building the interface-to-zone map from raw UniFi API data
- Matching a firewall log entry to a policy candidate
- 5-minute snapshot caching with invalidation

It calls unifi_api for raw data but owns all derived/enrichment logic.
unifi_api.py must NOT contain any of this.
"""

import logging
import re
import time
import threading

logger = logging.getLogger('api.firewall_matcher')

# ── Zone chain name mapping (iptables convention) ────────────────────────────

_ZONE_CHAIN_MAP = {
    'internal': 'LAN',
    'external': 'WAN',
    'gateway': 'LOCAL',
    'hotspot': 'GUEST',
    'vpn': 'VPN',
    'dmz': 'DMZ',
}

# ── Rule name parsing ────────────────────────────────────────────────────────

_LEGACY_RE = re.compile(r'^(.+?)-(A|B|D|R)-(\d+)(?:-[A-Z])?$')
_ZONE_INDEX_RE = re.compile(r'^([A-Z][A-Z0-9]*_[A-Z][A-Z0-9]*)-(\d+)$')
_DESC_ACTION_RE = re.compile(r'\b(block|drop|reject|allow)\b', re.IGNORECASE)

_ACTION_CODE_MAP = {'A': 'allow', 'B': 'block', 'D': 'block', 'R': 'block'}
_ACTION_CODE_TO_POLICY = {'A': 'ALLOW', 'B': 'BLOCK', 'D': 'BLOCK'}
_DESC_ACTION_MAP = {'block': 'block', 'drop': 'block', 'reject': 'block', 'allow': 'allow'}


def _action_from_desc(rule_desc):
    """Extract action from rule description text (e.g. 'Block Unauthorized Traffic').

    Used as a last-resort fallback for zone_index rules where the rule name
    has no embedded action code. The description is user-editable, so the
    policy metadata lookup via resolve_rule_action() is preferred when available.
    """
    if not rule_desc:
        return None
    m = _DESC_ACTION_RE.search(rule_desc)
    if m:
        return _DESC_ACTION_MAP[m.group(1).lower()]
    return None


def parse_firewall_rule(rule_name, rule_desc=None):
    """Parse a firewall rule reference into structured metadata.

    Understands two formats:
    - Legacy:     CHAIN-A-123  (action code embedded)
    - Zone-index: ZONE_ZONE-123 (action from description fallback or policy lookup)

    For zone_index rules, if rule_desc is provided, the action keyword
    ('Block', 'Allow', etc.) is extracted as a best-effort fallback.
    The authoritative source remains the UniFi API policy metadata
    via resolve_rule_action().

    Returns dict with format, chain, index, action_code, resolved_action,
    action_source. Returns None if rule_name doesn't match either format.
    """
    if not rule_name:
        return None

    # Check for DNAT/PREROUTING first
    if 'DNAT' in rule_name or 'PREROUTING' in rule_name:
        return {
            'format': 'redirect',
            'chain': rule_name,
            'index': None,
            'action_code': None,
            'resolved_action': 'redirect',
            'action_source': 'rule_name',
        }

    # Legacy format: CHAIN-A-123
    m = _LEGACY_RE.match(rule_name)
    if m:
        code = m.group(2)
        return {
            'format': 'legacy',
            'chain': m.group(1),
            'index': int(m.group(3)),
            'action_code': code,
            'resolved_action': _ACTION_CODE_MAP.get(code, 'allow'),
            'action_source': 'rule_name',
        }

    # Zone-index format: ZONE_ZONE-123
    m = _ZONE_INDEX_RE.match(rule_name)
    if m:
        return {
            'format': 'zone_index',
            'chain': m.group(1),
            'index': int(m.group(2)),
            'action_code': None,
            'resolved_action': None,
            'action_source': 'default',
            'desc_hint': _action_from_desc(rule_desc),
        }

    return None


# ── Snapshot cache ───────────────────────────────────────────────────────────
# Scoped to log-to-policy matching only.  GET /api/firewall/policies (the
# FirewallRules matrix) intentionally bypasses this cache and fetches live
# data — users managing policies need real-time state.

_CACHE_TTL = 300  # 5 minutes

_cache_lock = threading.Lock()
_cached_snapshot = None  # {'zone_data': ..., 'policies': ..., 'expires_at': float}


def invalidate_cache():
    """Invalidate the firewall snapshot cache.

    Called after successful PATCH, bulk logging, SSE completion, or settings reload.
    """
    global _cached_snapshot
    with _cache_lock:
        _cached_snapshot = None
    logger.debug("Firewall snapshot cache invalidated")


def _vpn_cache_key(vpn_networks):
    """Build a hashable key from vpn_networks for cache comparison."""
    if not vpn_networks:
        return ()
    return tuple(sorted(vpn_networks.items(), key=lambda kv: kv[0]))


def _get_snapshot(unifi_api, vpn_networks=None):
    """Return cached snapshot or build a fresh one.

    Thread-safe. The snapshot contains zone_data (zone map) and policies
    (raw firewall data from the Integration API). TTL is 5 minutes.
    The cache is keyed on both TTL and vpn_networks so callers with
    different VPN configs don't get stale zone data.
    """
    global _cached_snapshot

    vpn_key = _vpn_cache_key(vpn_networks)

    with _cache_lock:
        if (_cached_snapshot
                and time.monotonic() < _cached_snapshot['expires_at']
                and _cached_snapshot.get('vpn_key') == vpn_key):
            return _cached_snapshot

    # Build outside the lock to avoid blocking other threads during API calls.
    # Multiple threads may race to build; the last write wins (safe — all produce
    # equivalent data from the same UniFi state).
    zone_data = build_zone_map(unifi_api, vpn_networks=vpn_networks)
    fw_data = unifi_api.get_firewall_data()

    snapshot = {
        'zone_data': zone_data,
        'policies': fw_data.get('policies', []),
        'zones': fw_data.get('zones', []),
        'expires_at': time.monotonic() + _CACHE_TTL,
        'vpn_key': vpn_key,
    }

    with _cache_lock:
        _cached_snapshot = snapshot

    logger.debug("Firewall snapshot cache refreshed (%d policies, %d zones)",
                 len(snapshot['policies']), len(snapshot['zones']))
    return snapshot


# ── Zone resolution helper ────────────────────────────────────────────────────

def _resolve_zone_pair(zone_data, interface_in, interface_out):
    """Map interface pair to (src_zone_id, dst_zone_id).

    Empty interface_out maps to the gateway zone.
    Returns (None, None) if zone_data is missing or interfaces unknown.
    """
    iface_to_zone = {}
    gateway_zone_id = None
    for z in zone_data.get('zone_map', []):
        if z['zone_name'].lower() == 'gateway':
            gateway_zone_id = z['zone_id']
        for iface in z['interfaces']:
            iface_to_zone[iface['interface']] = z['zone_id']

    src_zone_id = iface_to_zone.get(interface_in)
    dst_zone_id = gateway_zone_id if not interface_out else iface_to_zone.get(interface_out)
    return src_zone_id, dst_zone_id


# ── Action resolution ─────────────────────────────────────────────────────────

def resolve_rule_action(parsed_rule, unifi_api, interface_in, interface_out,
                        vpn_networks=None):
    """Resolve rule_action from policy metadata for zone_index format rules.

    Resolution order:
    1. Policy metadata lookup (authoritative — from UniFi controller)
    2. Description hint (best-effort fallback — from rule_desc keyword)

    Mutates parsed_rule in place: sets resolved_action and action_source.
    Uses the cached snapshot to avoid repeated API calls.

    Returns the resolved action string ('allow'/'block') or None if unresolvable.
    """
    if not parsed_rule or parsed_rule.get('resolved_action') is not None:
        return parsed_rule.get('resolved_action') if parsed_rule else None

    # Try authoritative policy metadata lookup first
    if unifi_api:
        try:
            snapshot = _get_snapshot(unifi_api, vpn_networks=vpn_networks)
            zone_data = snapshot['zone_data']
            src_zone_id, dst_zone_id = _resolve_zone_pair(zone_data, interface_in, interface_out)
            if src_zone_id and dst_zone_id:
                rule_index = parsed_rule['index']
                for p in snapshot['policies']:
                    if (p.get('source', {}).get('zoneId') == src_zone_id
                            and p.get('destination', {}).get('zoneId') == dst_zone_id
                            and p.get('index') == rule_index):
                        action = p.get('action', {}).get('type', '').lower()
                        if action in ('allow', 'block'):
                            parsed_rule['resolved_action'] = action
                            parsed_rule['action_source'] = 'policy_lookup'
                            return action
        except Exception:
            logger.debug("Snapshot fetch failed for rule action resolution", exc_info=True)

    # Fall back to description hint (user-editable, best-effort)
    desc_hint = parsed_rule.get('desc_hint')
    if desc_hint:
        parsed_rule['resolved_action'] = desc_hint
        parsed_rule['action_source'] = 'rule_desc'
        return desc_hint

    return None


# ── Zone map builder ─────────────────────────────────────────────────────────

def build_zone_map(unifi_api, vpn_networks=None):
    """Build zone-to-interface mapping by combining zones, networks, and WAN config.

    Calls raw unifi_api methods for data, then assembles the derived mapping.

    Args:
        unifi_api: UniFiAPI instance (raw data access only).
        vpn_networks: dict of {interface: label_or_dict} from system_config.

    Returns:
        dict with 'zone_map', 'wan_interfaces', 'vpn_interfaces'.
    """
    if vpn_networks is None:
        vpn_networks = {}

    zones = unifi_api.get_firewall_zones()
    net_config = unifi_api.get_network_config()

    # Build network_id -> interface from get_network_config() networks. When the
    # firewall policy view is backed by UniFi's v2 API, zones may not carry
    # networkIds. Classic /rest/networkconf still exposes firewall_zone_id in the
    # same v2 namespace, so keep a second index for that direct zone join.
    network_id_to_info = {}
    zone_id_to_network_infos = {}
    for net in net_config.get('networks', []):
        nid = net.get('id')
        info = {
            'name': net.get('name', ''),
            'interface': net.get('interface'),
            'vlan': net.get('vlan'),
        }
        if nid:
            network_id_to_info[nid] = info
        firewall_zone_id = net.get('firewall_zone_id')
        if firewall_zone_id:
            zone_id_to_network_infos.setdefault(firewall_zone_id, []).append(info)

    # WAN physical interfaces
    wan_interfaces = []
    for w in net_config.get('wan_interfaces', []):
        name = w.get('name')
        phys = w.get('physical_interface')
        if not name or not phys:
            continue
        wan_interfaces.append({
            'name': name,
            'interface': phys,
            'active': w.get('active', False),
            'wan_ip': w.get('wan_ip'),
        })

    # Build the zone map
    zone_map = []
    custom_idx = 0
    for z in zones:
        zone_id = z.get('id')
        if not zone_id:
            continue
        zname = z.get('name', '')
        zname_lower = zname.lower()

        # Determine chain name
        chain = _ZONE_CHAIN_MAP.get(zname_lower)
        if chain is None:
            custom_idx += 1
            chain = f'CUSTOM{custom_idx}'

        # Resolve interfaces from networkIds. If v2 zones omit networkIds, fall
        # back to the direct network.firewall_zone_id mapping prepared above.
        interfaces = []
        seen_interfaces = set()

        def add_interface(info):
            """Append one network interface once, preserving the existing shape."""
            iface = info.get('interface')
            if not iface or iface in seen_interfaces:
                return
            interfaces.append({
                'interface': iface,
                'network_name': info.get('name', ''),
                'vlan': info.get('vlan'),
            })
            seen_interfaces.add(iface)

        for nid in z.get('networkIds', []):
            info = network_id_to_info.get(nid)
            if info:
                add_interface(info)

        for info in zone_id_to_network_infos.get(zone_id, []):
            add_interface(info)

        # External zone — add WAN interfaces
        if zname_lower == 'external' and not interfaces:
            for wi in wan_interfaces:
                interfaces.append({
                    'interface': wi['interface'],
                    'network_name': wi['name'],
                    'wan_ip': wi.get('wan_ip'),
                })

        # VPN zone — add VPN interfaces
        if zname_lower == 'vpn':
            for vpn_iface, vpn_label in vpn_networks.items():
                if isinstance(vpn_label, dict):
                    name = vpn_label.get('badge', vpn_iface)
                    cidr = vpn_label.get('cidr', '')
                else:
                    name = vpn_label or vpn_iface
                    cidr = ''
                interfaces.append({
                    'interface': vpn_iface,
                    'network_name': name,
                    'vpn': True,
                    'cidr': cidr or None,
                })

        # Gateway zone has no interfaces (it's the gateway itself)

        zone_map.append({
            'zone_id': zone_id,
            'zone_name': zname,
            'chain_name': chain,
            'origin': z.get('metadata', {}).get('origin', 'UNKNOWN'),
            'interfaces': interfaces,
        })

    return {
        'zone_map': zone_map,
        'wan_interfaces': wan_interfaces,
        'vpn_interfaces': [{'interface': k, 'label': v} for k, v in vpn_networks.items()],
    }


# ── Policy matching ──────────────────────────────────────────────────────────

def match_log_to_policy(unifi_api, interface_in, interface_out, rule_name,
                        vpn_networks=None):
    """Match a firewall log entry to a single firewall policy.

    Uses the cached snapshot to avoid repeated UniFi API calls.
    Supports both legacy (CHAIN-A-123) and zone-index (ZONE_ZONE-123) formats.

    Args:
        unifi_api: UniFiAPI instance.
        interface_in: Source interface from the log (e.g. 'br50', 'eth3').
        interface_out: Destination interface from the log (e.g. 'eth3', '' for Gateway).
        rule_name: Syslog rule_name (e.g. 'CUSTOM2_WAN-A-2147483647', 'GUEST_WAN-30004').
        vpn_networks: dict from system_config.

    Returns:
        dict with 'status' and optional 'policy'/'message' keys.
        Statuses: matched, unmatched, ambiguous, uncontrollable, unsupported, error.
    """
    parsed = parse_firewall_rule(rule_name)
    if not parsed:
        return {"status": "unsupported", "message": "Could not parse rule name."}

    fmt = parsed['format']
    rule_index = parsed['index']

    # Redirect rules have no matchable policy
    if fmt == 'redirect':
        return {"status": "unsupported",
                "message": "Redirect rules are not supported for log matching."}

    # Legacy: R (reject) is unsupported until verified against live payloads
    if fmt == 'legacy' and parsed['action_code'] == 'R':
        return {"status": "unsupported",
                "message": "Reject rules are not yet supported for log matching."}

    # Get cached snapshot (zone map + policies)
    try:
        snapshot = _get_snapshot(unifi_api, vpn_networks=vpn_networks)
    except Exception as e:
        logger.exception("Failed to build firewall snapshot for matching")
        return {"status": "error", "message": str(e)}

    zone_data = snapshot['zone_data']

    # Resolve zone pair via shared helper
    src_zone_id, dst_zone_id = _resolve_zone_pair(zone_data, interface_in, interface_out)

    # Build zone_id -> zone_name lookup (only needed here for the response)
    zone_id_to_name = {}
    for z in zone_data.get('zone_map', []):
        zone_id_to_name[z['zone_id']] = z['zone_name']

    if not src_zone_id:
        return {"status": "unmatched",
                "message": f"Unknown source interface: {interface_in}"}
    if not dst_zone_id:
        return {"status": "unmatched",
                "message": f"Unknown destination interface: {interface_out or '(empty)'}"}

    policies = snapshot['policies']

    # For legacy format, filter by expected action; for zone_index, match by zone pair + index only
    if fmt == 'legacy':
        expected_action = _ACTION_CODE_TO_POLICY.get(parsed['action_code'])
    else:
        expected_action = None  # zone_index: action comes from matched policy

    all_matches = []
    for p in policies:
        if p.get('source', {}).get('zoneId') != src_zone_id:
            continue
        if p.get('destination', {}).get('zoneId') != dst_zone_id:
            continue
        if expected_action and p.get('action', {}).get('type') != expected_action:
            continue
        if p.get('index') != rule_index:
            continue
        all_matches.append(p)

    if len(all_matches) == 0:
        return {"status": "unmatched",
                "message": "No matching policy found"}

    # Build controllable candidate set — filter DERIVED and disabled BEFORE
    # deciding ambiguity, so an uncontrollable twin doesn't block a valid match.
    controllable = [p for p in all_matches
                    if p.get('metadata', {}).get('origin', '') != 'DERIVED'
                    and p.get('enabled') is not False]

    if len(controllable) == 0:
        # All matches are uncontrollable
        policy = all_matches[0]
        origin = policy.get('metadata', {}).get('origin', '')
        if origin == 'DERIVED':
            return {
                "status": "uncontrollable",
                "message": "This rule is auto-generated and cannot be modified.",
                "policy": {"id": policy['id'], "name": policy.get('name', '')}
            }
        return {
            "status": "uncontrollable",
            "message": "This rule is disabled and cannot be toggled.",
            "policy": {"id": policy['id'], "name": policy.get('name', '')}
        }

    if len(controllable) > 1:
        return {"status": "ambiguous",
                "message": "Multiple matching policies found."}

    policy = controllable[0]
    origin = policy.get('metadata', {}).get('origin', '')
    policy_action = policy.get('action', {}).get('type', '').lower() or None

    return {
        "status": "matched",
        "policy": {
            "id": policy['id'],
            "name": policy.get('name', ''),
            "loggingEnabled": policy.get('loggingEnabled', False),
            "origin": origin,
            "action": policy_action,
            "srcZone": zone_id_to_name.get(src_zone_id, ''),
            "dstZone": zone_id_to_name.get(dst_zone_id, ''),
        }
    }
