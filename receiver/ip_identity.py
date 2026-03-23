"""IP identity annotation — single resolver for gateway, WAN, and VPN labeling."""

import logging
from dataclasses import dataclass
from typing import Optional

from db import get_config
from parsers import build_vpn_cidr_map, match_vpn_ip

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IdentityConfig:
    """Immutable snapshot of IP identity configuration."""
    gateway_vlans: dict       # ip_str -> {vlan, ...}
    wan_ip_names: dict        # ip_str -> display_name
    vpn_cidrs: list           # [(network, gw_ip, badge, type_name), ...]
    exclude_ips: set          # WAN + gateway IPs excluded from VPN matching


def load_identity_config(db) -> IdentityConfig:
    """Load identity configuration from system_config table.

    Returns a frozen snapshot safe to pass across function boundaries.
    """
    gateway_vlans = get_config(db, 'gateway_ip_vlans') or {}
    if not isinstance(gateway_vlans, dict):
        logger.warning("Expected dict for gateway_ip_vlans, got %s — using empty", type(gateway_vlans).__name__)
        gateway_vlans = {}
    wan_ip_names = get_config(db, 'wan_ip_names') or {}
    if not isinstance(wan_ip_names, dict):
        logger.warning("Expected dict for wan_ip_names, got %s — using empty", type(wan_ip_names).__name__)
        wan_ip_names = {}
    vpn_networks = get_config(db, 'vpn_networks') or {}
    if not isinstance(vpn_networks, dict):
        logger.warning("Expected dict for vpn_networks, got %s — using empty", type(vpn_networks).__name__)
        vpn_networks = {}
    vpn_cidrs = build_vpn_cidr_map(vpn_networks) if vpn_networks else []
    exclude_ips = set(wan_ip_names.keys()) | set(gateway_vlans.keys())
    return IdentityConfig(
        gateway_vlans=gateway_vlans,
        wan_ip_names=wan_ip_names,
        vpn_cidrs=vpn_cidrs,
        exclude_ips=exclude_ips,
    )


def annotate_ip(cfg: IdentityConfig, ip_str: str, existing_name: Optional[str] = None):
    """Resolve identity for a single IP.

    Precedence: existing device name > gateway > WAN > VPN inferred type.

    Returns (name, vlan, vpn_badge) tuple. Any field may be None.
    """
    ip_clean = ip_str.split('/')[0] if ip_str else ''
    name = existing_name
    vlan = None
    vpn_badge = None

    if ip_clean in cfg.gateway_vlans:
        if not name:
            name = 'Gateway'
        vlan = cfg.gateway_vlans[ip_clean].get('vlan')
    elif not name and ip_clean in cfg.wan_ip_names:
        name = cfg.wan_ip_names[ip_clean]

    if cfg.vpn_cidrs and not name:
        vpn_result = match_vpn_ip(ip_clean, cfg.vpn_cidrs, cfg.exclude_ips)
        if vpn_result:
            vpn_badge, name = vpn_result

    return name, vlan, vpn_badge


def annotate_record(cfg: IdentityConfig, record: dict):
    """Annotate a log/stats dict in place for both src and dst IPs.

    Sets {prefix}_device_name, {prefix}_device_vlan, and {prefix}_device_network
    matching the existing annotation pattern used by routes.
    """
    for prefix in ('src', 'dst'):
        # Skip if already has vlan or network badge (same guard as _annotate_vpn_badges)
        if record.get(f'{prefix}_device_vlan') is not None:
            continue
        if record.get(f'{prefix}_device_network'):
            continue

        ip_str = str(record.get(f'{prefix}_ip', '') or '')
        existing = record.get(f'{prefix}_device_name')
        name, vlan, vpn_badge = annotate_ip(cfg, ip_str, existing)

        if name and not existing:
            record[f'{prefix}_device_name'] = name
        if vlan is not None:
            record[f'{prefix}_device_vlan'] = vlan
        if vpn_badge and name == 'Gateway':
            record[f'{prefix}_device_network'] = vpn_badge
