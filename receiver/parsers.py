"""
UniFi Log Insight - Syslog Parsers

Parses UDR syslog messages into structured data.
Log types: firewall, dns, dhcp, wifi
"""

import os
import re
import ipaddress
import logging
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from services import get_service_name

logger = logging.getLogger(__name__)

# ── WAN IP auto-detection ────────────────────────────────────────────────────
_wan_ip = None
WAN_IPS = set()  # All known WAN IPs (derived from config); replaces single _wan_ip for exclusion
_wan_ip_by_iface_present = False  # True when authoritative wan_ip_by_iface exists


def get_wan_ip() -> str:
    return _wan_ip


def _is_broadcast_or_multicast(ip: str) -> bool:
    """Check if IP is broadcast (255.255.255.255) or multicast (224.0.0.0/4)."""
    if not ip:
        return False
    if ip == '255.255.255.255':
        return True
    try:
        return ipaddress.ip_address(ip).is_multicast
    except ValueError:
        return False

# ── Syslog header ──────────────────────────────────────────────────────────────
# Matches: "Feb  8 16:43:49 UDR-UK ..."
SYSLOG_HEADER = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<body>.+)$'
)

# ── Firewall (iptables/netfilter) ──────────────────────────────────────────────
FW_RULE     = re.compile(r'\[([^\]]+)\]')
FW_DESC     = re.compile(r'DESCR="([^"]*)"')
FW_IN       = re.compile(r'IN=(\S*)')
FW_OUT      = re.compile(r'OUT=(\S*)')
FW_SRC      = re.compile(r'SRC=([0-9a-fA-F:.]+)')
FW_DST      = re.compile(r'DST=([0-9a-fA-F:.]+)')
FW_PROTO    = re.compile(r'PROTO=([A-Z]+)')
FW_SPT      = re.compile(r'SPT=(\d+)')
FW_DPT      = re.compile(r'DPT=(\d+)')
FW_MAC      = re.compile(r'MAC=([0-9a-f:]+)')

# ── DNS (dnsmasq) ─────────────────────────────────────────────────────────────
DNS_QUERY   = re.compile(r'query\[([A-Z]+)\]\s+(\S+)\s+from\s+([0-9a-fA-F:.]+)')
DNS_REPLY   = re.compile(r'reply\s+(\S+)\s+is\s+(.+)')
DNS_FORWARD = re.compile(r'forwarded\s+(\S+)\s+to\s+([0-9a-fA-F:.]+)')
DNS_CACHED  = re.compile(r'cached\s+(\S+)\s+is\s+(.+)')

# ── DHCP (dnsmasq-dhcp) ───────────────────────────────────────────────────────
MAC_PATTERN = r'[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}'
MAC_RE      = re.compile(MAC_PATTERN)
DHCP_ACK     = re.compile(rf'DHCPACK\((\S+)\)\s+([0-9a-fA-F:.]+)\s+({MAC_PATTERN})\s*(\S*)')
DHCP_DISC    = re.compile(rf'DHCPDISCOVER\((\S+)\)\s+(?:([0-9a-fA-F:.]+)\s+)?({MAC_PATTERN})')
DHCP_OFFER   = re.compile(rf'DHCPOFFER\((\S+)\)\s+([0-9a-fA-F:.]+)\s+({MAC_PATTERN})')
DHCP_REQ     = re.compile(rf'DHCPREQUEST\((\S+)\)\s+([0-9a-fA-F:.]+)\s+({MAC_PATTERN})')

# ── WiFi (stamgr / hostapd) ───────────────────────────────────────────────────
WIFI_EVENT  = re.compile(r'(\w+):\s+STA\s+([0-9a-f:]+)')
WIFI_ASSOC  = re.compile(r'STA\s+([0-9a-f:]+)\s+.*?(associated|disassociated|deauthenticated|authenticated)')

# Module-level config (set by main.py after DB initialization)
WAN_INTERFACES = {'ppp0'}  # Default fallback
INTERFACE_LABELS = {}  # Default to empty (raw names)

# VPN interface prefix → auto-detected badge abbreviation (max 8 chars)
VPN_PREFIX_BADGES = {
    'wgsrv': 'WGD SRV',
    'wgclt': 'WGD CLT',
    'wgsts': 'S MAGIC',
    'tlprt': 'TELEPORT',
    'vti':   'S2S IPSEC',
    'tunovpnc': 'OVPN CLT',
    'tun':   'OVPN TUN',
    'vtun':  'OVPN VTN',
    'l2tp':  'L2TP SRV',
}
# All known VPN interface prefixes (including ones without auto-detection).
# Order matters: longer prefixes before shorter overlapping ones (tunovpnc before tun)
# because startswith() matching uses first-match semantics. Keep VPN_PREFIX_BADGES
# and VPN_PREFIX_DESCRIPTIONS in the same order.
VPN_INTERFACE_PREFIXES = ('wgsrv', 'wgclt', 'wgsts', 'tlprt', 'vti', 'tunovpnc', 'tun', 'vtun', 'l2tp')
# Badge abbreviation → human-readable full name (for UI dropdowns)
VPN_BADGE_LABELS = {
    'WGD SRV':   'WireGuard Server',
    'WGD CLT':   'WireGuard Client',
    'OVPN SRV':  'OpenVPN Server',
    'OVPN CLT':  'OpenVPN Client',
    'OVPN TUN':  'OpenVPN / Tunnel 1',
    'OVPN VTN':  'OpenVPN / Tunnel 2',
    'L2TP SRV':  'L2TP Server',
    'TELEPORT':  'Teleport',
    'S MAGIC':   'Site Magic',
    'S2S IPSEC': 'Site-to-Site IPsec',
}
# Ordered list of badge choices for UI dropdowns
VPN_BADGE_CHOICES = [
    'WGD SRV', 'WGD CLT', 'OVPN SRV', 'OVPN CLT', 'OVPN TUN', 'OVPN VTN', 'L2TP SRV', 'TELEPORT', 'S MAGIC', 'S2S IPSEC',
]
# Interface prefix → human-readable description (shown under interface name)
VPN_PREFIX_DESCRIPTIONS = {
    'wgsrv': 'WireGuard Server',
    'wgclt': 'WireGuard Client',
    'wgsts': 'Site Magic',
    'tlprt': 'Teleport',
    'vti':   'Site-to-Site IPsec',
    'tunovpnc': 'OpenVPN Client',
    'tun':   'OpenVPN / Tunnel 1',
    'vtun':  'OpenVPN / Tunnel 2',
    'l2tp':  'L2TP Server',
}


def build_vpn_cidr_map(vpn_networks):
    """Pre-parse VPN CIDRs into (network_obj, gateway_ip, badge, type_name) tuples.

    The first usable IP in each CIDR is the VPN gateway (e.g. .1 in a /24).
    """
    result = []
    for iface, cfg in vpn_networks.items():
        cidr, badge = cfg.get('cidr', ''), cfg.get('badge', '')
        if cidr and badge:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                gw_ip = net.network_address + 1
                type_name = next(
                    (d for p, d in VPN_PREFIX_DESCRIPTIONS.items() if iface.startswith(p)),
                    badge
                )
                result.append((net, gw_ip, badge, type_name))
            except ValueError:
                pass
    return result


def match_vpn_ip(ip_str, vpn_cidrs, exclude_ips=None):
    """Check if an IP falls within a VPN CIDR.

    Returns (badge, device_name) if matched, else None.
    Gateway IPs (.1) get device_name='Gateway'; other IPs get the VPN type name.
    """
    if not vpn_cidrs or not ip_str:
        return None
    if exclude_ips and ip_str in exclude_ips:
        return None
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net, gw_ip, badge, type_name in vpn_cidrs:
            if ip_obj in net:
                if ip_obj == gw_ip:
                    return (badge, 'Gateway')
                return (badge, type_name)
    except ValueError:
        pass
    return None


MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12,
}


def _get_syslog_tz():
    """Return the timezone for interpreting syslog timestamps.

    Uses TZ env var (matching the gateway's local time). Falls back to UTC.
    """
    tz_name = os.environ.get('TZ', 'UTC')
    try:
        return ZoneInfo(tz_name)
    except Exception:
        logger.warning("Invalid TZ=%r, falling back to UTC for syslog timestamps", tz_name)
        return timezone.utc


def parse_syslog_timestamp(month: str, day: str, time_str: str) -> datetime | None:
    """Parse syslog timestamp. Syslog doesn't include year, so we use current year.

    Syslog RFC3164 timestamps carry no timezone — they are in the sender's
    local time.  We interpret them in the container's TZ (which should match
    the gateway) and convert to UTC for storage.

    Year-rollover guard: only subtract a year when the parsed month is
    significantly ahead of the current month (e.g. a Dec log arriving in Jan).
    A simple ``ts > now`` check is too aggressive — if the gateway clock is
    even a few seconds ahead of the container clock, same-day logs get stamped
    with the previous year.

    Returns None when the components don't form a valid datetime — an attacker
    on the LAN can send a syslog packet with ``Feb 99 99:99:99`` that passes
    the header regex but fails ``datetime()`` construction, and an unhandled
    ValueError here would crash the receiver thread.
    """
    local_tz = _get_syslog_tz()
    now = datetime.now(local_tz)
    month_num = MONTHS.get(month, 1)
    try:
        h, m, s = time_str.split(':')
        year = now.year
        if month_num - now.month > 6:
            year -= 1
        ts = datetime(year, month_num, int(day), int(h), int(m), int(s), tzinfo=local_tz)
        return ts.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def derive_direction(iface_in: str, iface_out: str, rule_name: str, src_ip: str = None, dst_ip: str = None) -> str:
    """Derive traffic direction from interfaces, rule name, and IPs."""
    global _wan_ip

    if not iface_in and not iface_out:
        return None

    # Auto-learn WAN IP from WAN_LOCAL rules (IN=WAN interface, public DST)
    # Only when UniFi API is unavailable and no wan_ip_by_iface is present
    if (not _wan_ip_by_iface_present
            and iface_in in WAN_INTERFACES and 'WAN_LOCAL' in (rule_name or '') and dst_ip):
        try:
            ip = ipaddress.ip_address(dst_ip)
            if ip.is_global and not ip.is_multicast:
                ip_str = str(ip)
                if ip_str != _wan_ip:
                    _wan_ip = ip_str
                    WAN_IPS.add(ip_str)
                    logger.info("Auto-detected WAN IP: %s", _wan_ip)
        except ValueError:
            pass

    # Broadcast/multicast → local (not real inbound/outbound traffic)
    if _is_broadcast_or_multicast(dst_ip):
        return 'local'

    # Traffic from the router's own WAN IP staying local (not going out WAN)
    if src_ip and src_ip in WAN_IPS and iface_out not in WAN_INTERFACES:
        return 'local'

    # NAT rules (explicit DNAT/PREROUTING)
    if 'DNAT' in (rule_name or '') or 'PREROUTING' in (rule_name or ''):
        return 'nat'

    is_wan_in = iface_in in WAN_INTERFACES

    # No OUT interface = traffic destined to the router itself
    if not iface_out:
        return 'inbound' if is_wan_in else 'local'

    is_wan_out = iface_out in WAN_INTERFACES

    if is_wan_in and not is_wan_out:
        return 'inbound'
    if not is_wan_in and is_wan_out:
        return 'outbound'
    if not is_wan_in and not is_wan_out and iface_in != iface_out:
        # VPN tunnel ↔ LAN is VPN traffic, not inter-VLAN
        is_vpn = any(
            (iface_in or '').startswith(p) or (iface_out or '').startswith(p)
            for p in VPN_INTERFACE_PREFIXES
        )
        return 'vpn' if is_vpn else 'inter_vlan'

    return 'local'


def derive_action(rule_name: str, rule_desc: str = None) -> str | None:
    """Derive firewall action from rule name and optional description.

    Returns 'allow'/'block'/'redirect' for legacy format,
    desc_hint for zone_index format (e.g. 'block' from 'Block Unauthorized Traffic'),
    None for zone_index with no description match (needs policy lookup later),
    'allow' for unrecognized names, None for empty/None input.
    """
    if not rule_name:
        return None
    from firewall_policy_matcher import parse_firewall_rule
    parsed = parse_firewall_rule(rule_name, rule_desc=rule_desc)
    if parsed is None:
        return 'allow'  # unrecognized → default allow (backward compat)
    # For zone_index: resolved_action is None here; use desc_hint as best-effort.
    # The enricher will later call resolve_rule_action() to upgrade from policy metadata.
    return parsed['resolved_action'] or parsed.get('desc_hint')


def extract_mac(mac_raw: str) -> str:
    """Extract the source MAC from the iptables MAC field.
    
    Format: dest_mac:src_mac:ethertype (6:6:2 bytes)
    We want bytes 7-12 (the source MAC).
    """
    if not mac_raw:
        return None
    parts = mac_raw.split(':')
    if len(parts) >= 12:
        return ':'.join(parts[6:12])
    return mac_raw


def parse_firewall(body: str) -> dict:
    """Parse a firewall (iptables/netfilter) log line."""
    result = {'log_type': 'firewall'}

    m = FW_RULE.search(body)
    result['rule_name'] = m.group(1) if m else None

    m = FW_DESC.search(body)
    result['rule_desc'] = m.group(1) if m else None

    m = FW_IN.search(body)
    result['interface_in'] = m.group(1) if m and m.group(1) else None

    m = FW_OUT.search(body)
    result['interface_out'] = m.group(1) if m and m.group(1) else None

    m = FW_SRC.search(body)
    result['src_ip'] = m.group(1) if m else None

    m = FW_DST.search(body)
    result['dst_ip'] = m.group(1) if m else None

    m = FW_PROTO.search(body)
    result['protocol'] = m.group(1).lower() if m else None

    m = FW_SPT.search(body)
    result['src_port'] = int(m.group(1)) if m else None

    m = FW_DPT.search(body)
    result['dst_port'] = int(m.group(1)) if m else None

    # Map destination port to IANA service name
    result['service_name'] = get_service_name(result.get('dst_port'), result.get('protocol'))

    m = FW_MAC.search(body)
    result['mac_address'] = extract_mac(m.group(1)) if m else None

    result['rule_action'] = derive_action(result['rule_name'], result.get('rule_desc'))
    result['direction'] = derive_direction(
        result['interface_in'], result['interface_out'], result['rule_name'],
        result.get('src_ip'), result.get('dst_ip')
    )

    return result


def parse_dns(body: str) -> dict:
    """Parse a DNS (dnsmasq) log line."""
    result = {'log_type': 'dns'}

    m = DNS_QUERY.search(body)
    if m:
        result['dns_type'] = m.group(1)
        result['dns_query'] = m.group(2)
        result['src_ip'] = m.group(3)
        return result

    m = DNS_REPLY.search(body)
    if m:
        result['dns_query'] = m.group(1)
        result['dns_answer'] = m.group(2)
        return result

    m = DNS_FORWARD.search(body)
    if m:
        result['dns_query'] = m.group(1)
        result['dst_ip'] = m.group(2)
        return result

    m = DNS_CACHED.search(body)
    if m:
        result['dns_query'] = m.group(1)
        result['dns_answer'] = m.group(2)
        return result

    return result


def parse_dhcp(body: str) -> dict:
    """Parse a DHCP (dnsmasq-dhcp) log line."""
    result = {'log_type': 'dhcp'}

    m = DHCP_ACK.search(body)
    if m:
        result['interface_in'] = m.group(1)
        result['src_ip'] = m.group(2)
        result['mac_address'] = m.group(3)
        result['hostname'] = m.group(4) if m.group(4) else None
        result['dhcp_event'] = 'DHCPACK'
        return result

    m = DHCP_REQ.search(body)
    if m:
        result['interface_in'] = m.group(1)
        result['src_ip'] = m.group(2)
        result['mac_address'] = m.group(3)
        result['dhcp_event'] = 'DHCPREQUEST'
        return result

    m = DHCP_OFFER.search(body)
    if m:
        result['interface_in'] = m.group(1)
        result['src_ip'] = m.group(2)
        result['mac_address'] = m.group(3)
        result['dhcp_event'] = 'DHCPOFFER'
        return result

    m = DHCP_DISC.search(body)
    if m:
        result['interface_in'] = m.group(1)
        if m.group(2):
            result['src_ip'] = m.group(2)
        result['mac_address'] = m.group(3)
        result['dhcp_event'] = 'DHCPDISCOVER'
        return result

    return result


def parse_wifi(body: str) -> dict:
    """Parse a WiFi (stamgr/hostapd/stahtd) log line."""
    result = {'log_type': 'wifi'}

    # stahtd STA tracker JSON events
    if 'stahtd' in body and '{' in body:
        json_start = body.index('{')
        try:
            import json
            data = json.loads(body[json_start:])
            result['mac_address'] = data.get('mac')
            result['wifi_event'] = data.get('event_type', data.get('message_type', 'stahtd'))
            return result
        except (json.JSONDecodeError, ValueError):
            result['wifi_event'] = 'stahtd'
            return result

    m = WIFI_ASSOC.search(body)
    if m:
        result['mac_address'] = m.group(1)
        result['wifi_event'] = m.group(2)
        return result

    m = WIFI_EVENT.search(body)
    if m:
        result['wifi_event'] = m.group(1)
        result['mac_address'] = m.group(2)
        return result

    return result


def parse_system(body: str) -> dict:
    """Parse a system log line. Stores raw log only."""
    return {'log_type': 'system'}


def detect_log_type(body: str) -> str:
    """Detect log type from the syslog message body."""
    # Firewall: contains iptables-style fields
    if 'SRC=' in body and 'DST=' in body and 'PROTO=' in body:
        return 'firewall'
    if body.startswith('[') and 'DESCR=' in body:
        return 'firewall'

    # DHCP: dnsmasq-dhcp messages
    if 'dnsmasq-dhcp' in body or 'DHCPACK' in body or 'DHCPDISCOVER' in body or 'DHCPREQUEST' in body or 'DHCPOFFER' in body:
        return 'dhcp'

    # DNS: dnsmasq query/reply/forwarded/cached
    if 'dnsmasq' in body and ('query[' in body or 'reply ' in body or 'forwarded ' in body or 'cached ' in body):
        return 'dns'

    # WiFi: stamgr, hostapd, or stahtd (STA tracker)
    if 'stamgr' in body or 'hostapd' in body or 'stahtd' in body:
        return 'wifi'
    if 'STA ' in body and ('associated' in body or 'authenticated' in body):
        return 'wifi'

    # System: earlyoom, systemd, ubios-udapi, other UDR internals
    return 'system'


def parse_log(raw_log: str) -> dict | None:
    """Parse a raw syslog line into a structured dict.
    
    Returns None if the log can't be parsed (header doesn't match).
    """
    original_raw = raw_log

    m = SYSLOG_HEADER.match(raw_log)
    if not m:
        # Strip RFC3164 priority prefix (e.g. <13>, <14>) and retry
        stripped = re.sub(r'^<\d+>', '', raw_log)
        m = SYSLOG_HEADER.match(stripped)
        if not m:
            return None
        raw_log = stripped

    timestamp = parse_syslog_timestamp(m.group('month'), m.group('day'), m.group('time'))
    if timestamp is None:
        return None
    body = m.group('body')

    log_type = detect_log_type(body)

    if log_type == 'firewall':
        parsed = parse_firewall(body)
    elif log_type == 'dns':
        parsed = parse_dns(body)
    elif log_type == 'dhcp':
        parsed = parse_dhcp(body)
    elif log_type == 'wifi':
        parsed = parse_wifi(body)
    elif log_type == 'system':
        parsed = parse_system(body)
    else:
        parsed = {'log_type': 'unknown'}

    parsed['timestamp'] = timestamp
    parsed['raw_log'] = original_raw

    # Validate IP fields — reject invalid inet values before DB insert
    for ip_field in ('src_ip', 'dst_ip'):
        ip_val = parsed.get(ip_field)
        if ip_val:
            try:
                ipaddress.ip_address(ip_val)
            except ValueError:
                logger.warning("Invalid %s '%s' in log: %.300s", ip_field, ip_val, original_raw)
                parsed[ip_field] = None

    # Validate MAC field — reject invalid macaddr values before DB insert
    mac_val = parsed.get('mac_address')
    if mac_val and not MAC_RE.fullmatch(mac_val):
        logger.warning("Invalid mac_address '%s' in log: %.300s", mac_val, original_raw)
        parsed['mac_address'] = None

    return parsed


def reload_config_from_db(db):
    """Reload WAN interfaces, labels, and WAN IPs from system_config table.

    Called by main.py on startup and via SIGUSR2 signal after reconfiguration.
    Updates module-level WAN_INTERFACES, INTERFACE_LABELS, WAN_IPS, and _wan_ip.
    """
    global WAN_INTERFACES, INTERFACE_LABELS, _wan_ip, WAN_IPS, _wan_ip_by_iface_present
    from db import get_config, get_wan_ips_from_config

    wan_list = get_config(db, 'wan_interfaces', ['ppp0'])
    WAN_INTERFACES = set(wan_list)
    INTERFACE_LABELS = get_config(db, 'interface_labels', {})

    # Populate WAN_IPS from wan_ip_by_iface (preferred) or legacy wan_ips
    wan_ips_list = get_wan_ips_from_config(db)
    WAN_IPS = set(wan_ips_list)

    # Track whether authoritative wan_ip_by_iface exists
    _wan_ip_by_iface_present = bool(get_config(db, 'wan_ip_by_iface'))

    saved_wan_ip = get_config(db, 'wan_ip')
    if saved_wan_ip:
        _wan_ip = saved_wan_ip
        WAN_IPS.add(saved_wan_ip)
    logger.info("Config reloaded: WAN=%s, WAN_IPS=%s, Labels=%d",
                WAN_INTERFACES, WAN_IPS, len(INTERFACE_LABELS))
