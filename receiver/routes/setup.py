"""Setup wizard and configuration endpoints."""

import ipaddress as _ipaddress
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException
from psycopg2.extras import RealDictCursor, Json

from db import Database, get_config, set_config, count_logs, encrypt_api_key, decrypt_api_key, parse_retention_time
from deps import get_conn, put_conn, enricher_db, unifi_api, signal_receiver, APP_VERSION, ttl_cache
from unifi_api import UniFiAPI
from firewall_policy_matcher import invalidate_cache as invalidate_fw_cache
from parsers import (
    VPN_PREFIX_BADGES, VPN_INTERFACE_PREFIXES, VPN_BADGE_CHOICES,
    VPN_BADGE_LABELS, VPN_PREFIX_DESCRIPTIONS,
)
from query_helpers import validate_view_filters

logger = logging.getLogger('api.setup')

router = APIRouter()


def _read_dismissed_list(config_key: str) -> list:
    """Read a toast-dismissal list, coercing legacy boolean True → []."""
    val = get_config(enricher_db, config_key, [])
    return val if isinstance(val, list) else []


def _prune_dismissed(config_key: str, configured_ifaces: set) -> None:
    """Remove configured interfaces from a toast-dismissal list.

    Legacy note: vpn_toast_dismissed was previously a boolean (True = dismiss
    all). It now stores a list of interface names. If we read back True or any
    non-list value, we treat it as [] (no per-interface dismissals) so the old
    global dismiss is silently dropped and new VPNs can trigger the toast again.
    """
    dismissed = get_config(enricher_db, config_key, []) or []
    if not isinstance(dismissed, list):
        dismissed = []
    pruned = [i for i in dismissed if i not in configured_ifaces]
    if pruned != dismissed:
        set_config(enricher_db, config_key, pruned)


@router.get("/api/config")
def get_current_config():
    """Return current system configuration."""
    return {
        "wan_interfaces": get_config(enricher_db, "wan_interfaces", ["ppp0"]),
        "interface_labels": get_config(enricher_db, "interface_labels", {}),
        "setup_complete": get_config(enricher_db, "setup_complete", False),
        "config_version": get_config(enricher_db, "config_version", 1),
        "upgrade_v2_dismissed": get_config(enricher_db, "upgrade_v2_dismissed", False),
        "unifi_enabled": unifi_api.enabled,
        "wizard_path": get_config(enricher_db, "wizard_path", None),
        "vpn_networks": get_config(enricher_db, "vpn_networks", {}),
        "wan_ip_by_iface": get_config(enricher_db, "wan_ip_by_iface", {}),
        # vpn_toast_dismissed was previously a boolean (True = dismiss all).
        # It now stores a list of dismissed interface names. If the stored
        # value is the old boolean True, we expose [] so the frontend sees
        # "nothing dismissed" and new VPNs trigger the toast again.
        "vpn_toast_dismissed": _read_dismissed_list("vpn_toast_dismissed"),
        **{k: get_config(enricher_db, k, v) for k, v in _UI_SETTINGS_DEFAULTS.items()},
        "mcp_enabled": get_config(enricher_db, "mcp_enabled", False),
        "mcp_audit_enabled": get_config(enricher_db, "mcp_audit_enabled", False),
        "mcp_audit_retention_days": get_config(enricher_db, "mcp_audit_retention_days", 10),
        "mcp_allowed_origins": get_config(enricher_db, "mcp_allowed_origins", []),
    }


@router.get("/api/setup/status")
def setup_status():
    """Check if setup wizard is complete."""
    return {
        "setup_complete": get_config(enricher_db, "setup_complete", False),
        "logs_count": count_logs(enricher_db, 'firewall'),
    }


@router.get("/api/setup/wan-candidates")
def wan_candidates():
    """Return non-bridge firewall interfaces with their associated WAN IP.

    Phase-1 transition: retained for log-detection wizard path only.
    Removal target: phase 2 log-detection decommission.
    """
    return {
        'candidates': enricher_db.get_wan_ip_candidates(),
    }


@router.get("/api/setup/network-segments")
def network_segments(wan_interfaces: Optional[str] = None):
    """Discover ALL network interfaces with sample local IPs and suggested labels.

    wan_interfaces: comma-separated list from Step 1. Auto-labelled WAN/WAN1/WAN2.
    """
    wan_list = wan_interfaces.split(',') if wan_interfaces else []

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get ALL interfaces with sample local IPs (no exclusions)
            cur.execute("""
                WITH interface_ips AS (
                    SELECT interface_in as iface, src_ip
                    FROM logs
                    WHERE log_type = 'firewall'
                      AND interface_in IS NOT NULL
                      AND NOT is_public_inet(src_ip)
                    UNION
                    SELECT interface_out as iface, dst_ip as src_ip
                    FROM logs
                    WHERE log_type = 'firewall'
                      AND interface_out IS NOT NULL
                      AND NOT is_public_inet(dst_ip)
                )
                SELECT
                    iface,
                    ARRAY_AGG(DISTINCT host(src_ip) ORDER BY host(src_ip)) as sample_ips
                FROM interface_ips
                GROUP BY iface
                ORDER BY iface
                LIMIT 30
            """)
            interfaces = cur.fetchall()
    except Exception as e:
        logger.exception("Error querying network segments")
        raise HTTPException(status_code=500, detail="Failed to query network segments") from e
    finally:
        put_conn(conn)

    # For WAN interfaces, fetch their public IP instead of a local IP
    wan_ips = enricher_db.get_wan_ips_by_interface(wan_list) if wan_list else {}

    # Fetch VPN configs from UniFi API (if enabled) for auto-fill
    vpn_by_iface = {}
    if unifi_api.enabled:
        try:
            for vpn in unifi_api.get_vpn_networks():
                iface = vpn.get('interface')
                if iface:
                    vpn_by_iface[iface] = vpn
        except Exception as e:
            logger.debug("Could not fetch VPN configs from UniFi API: %s", e)

    # Inject API-discovered VPN interfaces not yet seen in logs
    log_ifaces = {row['iface'] for row in interfaces}
    for iface, vpn in vpn_by_iface.items():
        if iface and iface not in log_ifaces:
            interfaces.append({'iface': iface, 'sample_ips': []})

    # Generate suggested labels
    segments = []
    for row in interfaces:
        iface = row['iface']
        ips = row['sample_ips'] or []
        is_wan = iface in wan_list
        is_vpn_iface = any(iface.startswith(p) for p in VPN_INTERFACE_PREFIXES)

        # WAN interfaces auto-labelled from Step 1
        if is_wan:
            if len(wan_list) == 1:
                suggested = 'WAN'
            else:
                suggested = f'WAN{wan_list.index(iface) + 1}'
            # Show WAN IP, not a random local IP
            display_ip = wan_ips.get(iface, '')
        elif iface == 'br0':
            suggested = 'Main LAN'
            display_ip = ips[0] if ips else ''
        elif iface.startswith('br'):
            num = iface[2:]
            suggested = f'VLAN {num}' if num.isdigit() else iface
            display_ip = ips[0] if ips else ''
        elif iface.startswith('vlan'):
            num = iface[4:]
            suggested = f'VLAN {num}' if num.isdigit() else iface
            display_ip = ips[0] if ips else ''
        elif iface.startswith('eth'):
            num = iface[3:]
            suggested = f'Ethernet {num}' if num.isdigit() else iface
            display_ip = ips[0] if ips else ''
        else:
            suggested = 'VPN' if is_vpn_iface else ''
            display_ip = ips[0] if ips else ''

        seg = {
            'interface': iface,
            'sample_local_ip': display_ip,
            'suggested_label': suggested,
            'is_wan': is_wan,
        }
        # Tag VPN interfaces with badge metadata for the UI
        if not is_wan and is_vpn_iface:
            seg['is_vpn'] = True
            seg['suggested_badge'] = next(
                (b for p, b in VPN_PREFIX_BADGES.items() if iface.startswith(p)), None
            )
            seg['badge_choices'] = VPN_BADGE_CHOICES
            seg['badge_labels'] = VPN_BADGE_LABELS
            seg['prefix_description'] = next(
                (d for p, d in VPN_PREFIX_DESCRIPTIONS.items() if iface.startswith(p)), None
            )
            # Overlay UniFi API data when available (user can still override)
            unifi_vpn = vpn_by_iface.get(iface)
            if unifi_vpn:
                if unifi_vpn.get('name'):
                    seg['suggested_label'] = unifi_vpn['name']
                if unifi_vpn.get('cidr'):
                    seg['suggested_cidr'] = unifi_vpn['cidr']
                if unifi_vpn.get('badge'):
                    seg['suggested_badge'] = unifi_vpn['badge']
        segments.append(seg)

    return {'segments': segments}


@router.post("/api/setup/complete")
def complete_setup(body: dict):
    """Save wizard configuration and trigger receiver reload."""
    if not body.get('wan_interfaces'):
        raise HTTPException(status_code=400, detail="wan_interfaces required")

    # Read current WAN config before overwriting (for backfill comparison)
    current_wan = set(get_config(enricher_db, "wan_interfaces", ["ppp0"]))

    set_config(enricher_db, "wan_interfaces", body["wan_interfaces"])
    set_config(enricher_db, "interface_labels", body.get("interface_labels", {}))
    if "vpn_networks" in body:
        set_config(enricher_db, "vpn_networks", body["vpn_networks"])
        _prune_dismissed("vpn_toast_dismissed",
                         set((body.get("vpn_networks") or {}).keys()))
    set_config(enricher_db, "setup_complete", True)
    set_config(enricher_db, "config_version", 2)

    # Save wizard path (unifi_api or log_detection)
    wizard_path = body.get("wizard_path", "log_detection")
    set_config(enricher_db, "wizard_path", wizard_path)

    # Enable UniFi API if wizard used the API path, and seed identity
    if wizard_path == "unifi_api":
        set_config(enricher_db, "unifi_enabled", True)
        unifi_api.reload_config()
        # Seed WAN/gateway identity from UniFi API (best-effort)
        try:
            net_config = unifi_api.get_network_config()
            wan_ip_by_iface, gateway_ip_vlans = (
                UniFiAPI.extract_network_identity_from_net_config(net_config))
            enricher_db.persist_network_identity(
                wan_ip_by_iface=wan_ip_by_iface,
                gateway_ip_vlans=gateway_ip_vlans,
            )
        except Exception:
            logger.warning("Setup: UniFi identity seed incomplete — "
                           "poll will refresh", exc_info=True)
    elif wizard_path == "log_detection":
        # Log-detection path: compute wan_ip_by_iface from logs
        # Phase-1 transition: removal target phase 2 log-detection decommission
        iface_ips = enricher_db.get_wan_ips_by_interface(body["wan_interfaces"])
        if iface_ips:
            set_config(enricher_db, "wan_ip_by_iface", iface_ips)
            wan_ips = [iface_ips[iface] for iface in body["wan_interfaces"]
                       if iface in iface_ips and iface_ips[iface]]
            if wan_ips:
                set_config(enricher_db, "wan_ips", wan_ips)
                set_config(enricher_db, "wan_ip", wan_ips[0])

    # Trigger direction backfill if WAN interfaces actually changed
    new_wan = set(body["wan_interfaces"])
    if new_wan != current_wan:
        set_config(enricher_db, "direction_backfill_pending", True)

    # Invalidate firewall snapshot cache — VPN/WAN config affects zone map
    invalidate_fw_cache()

    # Signal receiver process to reload config
    signal_receiver()

    return {"success": True}


def _get_configured_interfaces(labels, wan_list, vpn_networks):
    """Return interface names from persisted config only."""
    return set(wan_list) | set(labels.keys()) | set(vpn_networks.keys())


def _get_unifi_discovered_interfaces():
    """Return interface names from UniFi API topology."""
    ifaces = set()
    try:
        net_config = unifi_api.get_network_config()
        for wan in net_config.get('wan_interfaces', []):
            if wan.get('physical_interface'):
                ifaces.add(wan['physical_interface'])
        for net in net_config.get('networks', []):
            if net.get('interface'):
                ifaces.add(net['interface'])
        for vpn in unifi_api.get_vpn_networks():
            if vpn.get('interface'):
                ifaces.add(vpn['interface'])
    except Exception:
        logger.warning("Could not fetch UniFi interfaces for /api/interfaces",
                       exc_info=True)
    return ifaces


def _get_recent_log_interfaces():
    """Return interface names from the last 36 hours of firewall logs.

    Legacy supplement — retained for phase-1 transition only when
    unifi_enabled is false.  Removal target: phase 2 log-detection
    decommission.
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT unnest(ARRAY[interface_in, interface_out]) as iface
                FROM logs
                WHERE log_type = 'firewall'
                  AND timestamp > now() - interval '36 hours'
                  AND (interface_in IS NOT NULL OR interface_out IS NOT NULL)
            """)
            return {row[0] for row in cur.fetchall() if row[0]}
    except Exception as e:
        logger.exception("Error querying interfaces")
        raise HTTPException(status_code=500,
                            detail="Failed to query interfaces") from e
    finally:
        put_conn(conn)


@router.get("/api/interfaces")
@ttl_cache(seconds=30)
def list_interfaces():
    """Return all discovered interfaces with their labels and type metadata."""
    labels = get_config(enricher_db, "interface_labels", {})
    if not isinstance(labels, dict):
        logger.warning("Expected dict for interface_labels config, got %s — using empty", type(labels).__name__)
        labels = {}
    raw_wans = get_config(enricher_db, "wan_interfaces", ["ppp0"])
    if not isinstance(raw_wans, (list, tuple, set)):
        logger.warning("Expected list for wan_interfaces config, got %s — using default", type(raw_wans).__name__)
        raw_wans = ["ppp0"]
    wan_list = set(raw_wans)
    vpn_networks = get_config(enricher_db, "vpn_networks", {})
    if not isinstance(vpn_networks, dict):
        logger.warning("Expected dict for vpn_networks config, got %s — using empty", type(vpn_networks).__name__)
        vpn_networks = {}

    config_ifaces = _get_configured_interfaces(labels, wan_list, vpn_networks)

    # Gate on persisted unifi_enabled, not unifi_api.enabled, so that
    # degraded credentials don't silently fall back to the log scan.
    if get_config(enricher_db, "unifi_enabled", False):
        discovered = _get_unifi_discovered_interfaces()
    else:
        discovered = _get_recent_log_interfaces()

    interfaces = config_ifaces | discovered

    result = []
    for iface in sorted(interfaces):
        entry = {
            'name': iface,
            'label': labels.get(iface, iface),
        }
        if iface in wan_list:
            entry['iface_type'] = 'wan'
        elif any(iface.startswith(p) for p in VPN_INTERFACE_PREFIXES):
            entry['iface_type'] = 'vpn'
            vpn_cfg = vpn_networks.get(iface, {})
            if vpn_cfg.get('badge'):
                entry['vpn_badge'] = vpn_cfg['badge']
            entry['description'] = next(
                (d for p, d in VPN_PREFIX_DESCRIPTIONS.items() if iface.startswith(p)), None
            )
        elif iface.startswith('br'):
            entry['iface_type'] = 'vlan'
            num = iface[2:]
            if iface == 'br0':
                entry['vlan_id'] = 1
            elif num.isdigit():
                entry['vlan_id'] = int(num)
        elif iface.startswith('eth'):
            entry['iface_type'] = 'eth'
        result.append(entry)

    return {'interfaces': result}


# ── UI Settings (defaults & validation) ──────────────────────────────────────

_UI_SETTINGS_DEFAULTS = {
    'ui_country_display': 'flag_name',
    'ui_ip_subline': 'none',
    'ui_theme': 'dark',
    'ui_block_highlight': 'on',
    'ui_block_highlight_threshold': 0,
    'wifi_processing_enabled': True,
    'system_processing_enabled': True,
}

_UI_SETTINGS_VALID = {
    'ui_country_display': {'flag_name', 'flag_only', 'name_only'},
    'ui_ip_subline': {'asn_or_abuse', 'none'},
    'ui_theme': {'dark', 'light'},
    'ui_block_highlight': {'on', 'off'},
    'ui_block_highlight_threshold': (0, 100),
    'wifi_processing_enabled': {True, False},
    'system_processing_enabled': {True, False},
}

# Keys that trigger a receiver reload (SIGUSR2) when changed via PUT /api/settings/ui
_PROCESSING_KEYS = {'wifi_processing_enabled', 'system_processing_enabled'}


# ── Config Export/Import ─────────────────────────────────────────────────────

# Keys that are always exported (user-configured settings)
_EXPORTABLE_KEYS = [
    'wan_interfaces', 'interface_labels', 'vpn_networks',
    'setup_complete', 'config_version',
    'wizard_path', 'unifi_enabled', 'unifi_host', 'unifi_site',
    'unifi_verify_ssl', 'unifi_poll_interval', 'unifi_features',
    'unifi_controller_name', 'unifi_controller_type',
    'retention_days', 'dns_retention_days', 'retention_time',
    'mcp_enabled', 'mcp_audit_enabled', 'mcp_audit_retention_days', 'mcp_allowed_origins',
    'auth_session_ttl_hours', 'audit_log_retention_days',
    *_UI_SETTINGS_DEFAULTS.keys(),
]
# NOTE: unifi_username, unifi_password, and unifi_site_id are NEVER exported
# (security + site_id is controller-specific and would break on import).

# Key that is only exported when explicitly requested
_API_KEY_CONFIG_KEY = 'unifi_api_key'


@router.get("/api/config/export")
def export_config(include_api_key: bool = False):
    """Export user configuration as JSON.

    Query params:
        include_api_key: if true, decrypts and includes the UniFi API key in plaintext.
    """
    config = {}
    for key in _EXPORTABLE_KEYS:
        val = get_config(enricher_db, key)
        if val is not None:
            config[key] = val

    includes_api_key = False
    if include_api_key:
        encrypted = get_config(enricher_db, _API_KEY_CONFIG_KEY, '')
        if encrypted:
            decrypted = decrypt_api_key(encrypted)
            if decrypted:
                config[_API_KEY_CONFIG_KEY] = decrypted
                includes_api_key = True

    # Export saved views
    views_list = []
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT name, filters FROM saved_views ORDER BY created_at DESC")
            for row in cur.fetchall():
                views_list.append({"name": row["name"], "filters": row["filters"]})
        conn.commit()
    except Exception:
        conn.rollback()
        logger.debug("Could not export saved_views (table may not exist yet)", exc_info=True)
    finally:
        put_conn(conn)

    return {
        "version": APP_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "includes_api_key": includes_api_key,
        "config": config,
        "saved_views": views_list,
    }


@router.post("/api/config/import")
def import_config(body: dict):
    """Import configuration from a previously exported JSON.

    If the payload contains unifi_api_key (plaintext), it is re-encrypted before storage.
    If unifi_api_key is absent, the existing key is left untouched.
    """
    config = body.get("config")
    if not config or not isinstance(config, dict):
        raise HTTPException(status_code=400, detail="Invalid config format — expected {config: {...}}")

    imported_keys = []
    failed_keys = []
    for key in _EXPORTABLE_KEYS:
        if key not in config:
            continue
        val = config[key]
        # Validate MCP-specific keys before storing
        if key == 'mcp_audit_retention_days':
            try:
                val = max(1, min(365, int(val)))
            except (ValueError, TypeError):
                failed_keys.append(key)
                continue
        elif key == 'mcp_allowed_origins':
            if isinstance(val, str):
                val = [v.strip() for v in val.split(',') if v.strip()]
            elif not isinstance(val, list):
                failed_keys.append(key)
                continue
        elif key == 'vpn_networks':
            if not isinstance(val, dict):
                failed_keys.append(key)
                continue
        elif key == 'interface_labels':
            if not isinstance(val, dict):
                failed_keys.append(key)
                continue
        elif key == 'wan_interfaces':
            if not isinstance(val, list):
                failed_keys.append(key)
                continue
        elif key == 'auth_session_ttl_hours':
            try:
                val = max(1, min(8760, int(val)))
            except (ValueError, TypeError):
                failed_keys.append(key)
                continue
        elif key == 'audit_log_retention_days':
            try:
                val = max(1, min(365, int(val)))
            except (ValueError, TypeError):
                failed_keys.append(key)
                continue
        elif key == 'retention_time':
            parsed = parse_retention_time(val)
            if parsed is None:
                failed_keys.append(key)
                continue
            val = parsed
        set_config(enricher_db, key, val)
        imported_keys.append(key)

    # Handle API key separately — re-encrypt for storage
    if _API_KEY_CONFIG_KEY in config and config[_API_KEY_CONFIG_KEY]:
        try:
            encrypted = encrypt_api_key(config[_API_KEY_CONFIG_KEY])
            set_config(enricher_db, _API_KEY_CONFIG_KEY, encrypted)
            imported_keys.append(_API_KEY_CONFIG_KEY)
        except Exception as e:
            logger.warning("Failed to encrypt imported API key: %s", e)
            failed_keys.append(_API_KEY_CONFIG_KEY)

    # Import saved views (if present)
    failed_saved_views = []
    imported_views_count = 0
    if "saved_views" in body and isinstance(body["saved_views"], list):
        valid_views = []
        for i, view in enumerate(body["saved_views"]):
            name = view.get("name", "").strip() if isinstance(view.get("name"), str) else ""
            filters = view.get("filters")
            if not name or not filters:
                failed_saved_views.append({"index": i, "name": name or "(empty)", "reason": "missing name or filters"})
                continue
            error = validate_view_filters(filters)
            if error:
                failed_saved_views.append({"index": i, "name": name, "reason": error})
                continue
            valid_views.append((name, filters))

        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM saved_views")
                for name, filters in valid_views:
                    cur.execute(
                        "INSERT INTO saved_views (name, filters) VALUES (%s, %s)",
                        [name, Json(filters)]
                    )
            conn.commit()
            imported_views_count = len(valid_views)
        except Exception as e:
            conn.rollback()
            logger.warning("Failed to import saved views: %s", e)
        finally:
            put_conn(conn)

    # Signal receiver to reload config
    signal_receiver()

    # Reload UniFi API if any unifi settings changed
    has_unifi_key = any(k.startswith('unifi_') for k in imported_keys)
    if has_unifi_key:
        unifi_api.reload_config()

    # Invalidate firewall cache if any imported key affects zone/policy behavior
    _FW_RELEVANT_KEYS = {'wan_interfaces', 'interface_labels', 'vpn_networks'}
    if _FW_RELEVANT_KEYS & set(imported_keys) or has_unifi_key:
        invalidate_fw_cache()

    result = {"success": True, "imported_keys": imported_keys}
    if failed_keys:
        result["failed_keys"] = failed_keys
    if imported_views_count:
        result["imported_saved_views"] = imported_views_count
    if failed_saved_views:
        result["failed_saved_views"] = failed_saved_views
    return result


# ── VPN Network Configuration ────────────────────────────────────────────────

@router.post("/api/config/vpn-networks")
def save_vpn_networks(body: dict):
    """Save VPN network configuration from Settings page."""
    vpn = body.get('vpn_networks', {})
    for iface, cfg in vpn.items():
        cidr = cfg.get('cidr', '')
        if cidr:
            try:
                _ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid CIDR for {iface}: {cidr}") from None
    # Read old config before overwriting, so we can clean up stale labels
    old_vpn = get_config(enricher_db, 'vpn_networks') or {}
    set_config(enricher_db, 'vpn_networks', vpn)
    # Clean up labels for removed VPN interfaces, then merge new ones
    labels = get_config(enricher_db, 'interface_labels') or {}
    for iface in old_vpn:
        if iface not in vpn:
            labels.pop(iface, None)
    vpn_labels = body.get('vpn_labels', {})
    for iface, label in vpn_labels.items():
        if label:
            labels[iface] = label
        else:
            labels.pop(iface, None)
    set_config(enricher_db, 'interface_labels', labels)
    _prune_dismissed("vpn_toast_dismissed", set(vpn.keys()))
    invalidate_fw_cache()
    signal_receiver()
    return {"success": True}


# ── Retention Configuration ──────────────────────────────────────────────────

@router.get("/api/config/retention")
def get_retention():
    """Return current retention configuration with effective values and source."""
    days = Database.resolve_retention_days(enricher_db)
    time_cfg = Database.resolve_retention_time(enricher_db)

    return {
        'retention_days': days.general,
        'dns_retention_days': days.dns,
        'retention_time': time_cfg.time,
        'general_source': days.general_source,
        'dns_source': days.dns_source,
        'time_source': time_cfg.source,
    }


@router.post("/api/config/retention")
def update_retention(body: dict):
    """Update retention configuration. Values saved to system_config (overrides env vars)."""
    days = body.get('retention_days')
    dns_days = body.get('dns_retention_days')

    if days is not None:
        try:
            days = int(days)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="retention_days must be an integer") from None
        if not (1 <= days <= 3650):
            raise HTTPException(status_code=400, detail="retention_days must be between 1 and 3650")
        set_config(enricher_db, 'retention_days', days)

    if dns_days is not None:
        try:
            dns_days = int(dns_days)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="dns_retention_days must be an integer") from None
        if not (1 <= dns_days <= 3650):
            raise HTTPException(status_code=400, detail="dns_retention_days must be between 1 and 3650")
        set_config(enricher_db, 'dns_retention_days', dns_days)

    raw_time = body.get('retention_time')
    time_changed = False
    if raw_time is not None:
        parsed_time = parse_retention_time(raw_time)
        if parsed_time is None:
            raise HTTPException(
                status_code=400,
                detail="retention_time must be a 'HH:MM' string in 00:00..23:59"
            )
        # Compare against the *effective* value (UI > env > default), not the
        # raw DB key. The UI sends retention_time on every save (part of the
        # combined dirty check), so a days-only edit always arrives with the
        # current effective time in the payload.
        #
        # Comparing against get_config('retention_time') alone would treat
        # env/default-sourced times as "not present in DB, needs writing",
        # which silently flips the precedence source from env/default to ui
        # and pins the current time against future env overrides. The
        # resolver-based comparison only writes on a genuine user-initiated
        # change.
        effective = Database.resolve_retention_time(enricher_db).time
        if effective != parsed_time:
            set_config(enricher_db, 'retention_time', parsed_time)
            time_changed = True

    # Only signal the receiver when the *time* actually changes — days are
    # re-resolved from the DB on every scheduled run, so they don't need a
    # reload. Scheduler rebuild is an OS-level signal + SIGUSR2 handler chain,
    # so avoiding no-op reloads keeps the system quiet.
    if time_changed:
        signal_receiver()

    return {"success": True}


# ── Retention cleanup (async job) ────────────────────────────────────────────

_CLEANUP_RESULT_TTL = 60  # seconds to keep terminal status before clearing
_cleanup_job: dict | None = None
_cleanup_lock = threading.Lock()


def _cleanup_gc():
    """Clear finished cleanup job older than TTL.  Caller must hold _cleanup_lock."""
    global _cleanup_job
    if _cleanup_job and _cleanup_job['status'] in ('complete', 'partial', 'failed'):
        finished = _cleanup_job.get('finished_at')
        if finished:
            elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(finished)).total_seconds()
            if elapsed > _CLEANUP_RESULT_TTL:
                _cleanup_job = None


def _resolve_retention_days():
    """Return (general_days, dns_days) via the shared DB resolver.

    Drops the source fields — callers in this module only need the integers.
    The GET endpoint calls the full resolver directly.
    """
    cfg = Database.resolve_retention_days(enricher_db)
    return (cfg.general, cfg.dns)


def _run_cleanup_worker(general_days: int, dns_days: int):
    """Background worker for retention cleanup."""
    global _cleanup_job

    def on_progress(state):
        with _cleanup_lock:
            if _cleanup_job:
                _cleanup_job.update(
                    phase=state.get('phase', 'dns'),
                    dns_deleted=state['dns_deleted'],
                    non_dns_deleted=state['non_dns_deleted'],
                    deleted_so_far=state['deleted_so_far'],
                    batches_completed=state['batches_completed'],
                    last_updated_at=_now_ts(),
                )

    logger.info("Retention cleanup started (general_retention=%d days, dns_retention=%d days)",
                general_days, dns_days)
    result = enricher_db.run_retention_cleanup(general_days, dns_days,
                                                progress_cb=on_progress)
    logger.info("Retention cleanup finished: status=%s, deleted=%d",
                result['status'], result['deleted_so_far'])
    now = _now_ts()
    with _cleanup_lock:
        if _cleanup_job:
            _cleanup_job.update(
                status=result['status'],
                phase='done',
                dns_deleted=result['dns_deleted'],
                non_dns_deleted=result['non_dns_deleted'],
                deleted_so_far=result['deleted_so_far'],
                batches_completed=result['batches_completed'],
                error=result['error'],
                last_updated_at=now,
                finished_at=now,
            )


@router.post("/api/config/retention/cleanup")
def run_retention_cleanup_now():
    """Start background retention cleanup using current saved settings.

    Returns immediately.  Poll GET /api/config/retention/cleanup-status for progress.
    """
    global _cleanup_job
    general, dns = _resolve_retention_days()
    try:
        Database.validate_retention_days(general, dns)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None

    with _cleanup_lock:
        _cleanup_gc()
        if _cleanup_job and _cleanup_job['status'] == 'running':
            raise HTTPException(status_code=409, detail="Retention cleanup already in progress")
        now = _now_ts()
        _cleanup_job = {
            'status': 'running',
            'general_days': general,
            'dns_days': dns,
            'batch_size': Database.RETENTION_BATCH_SIZE,
            'phase': 'dns',
            'dns_deleted': 0,
            'non_dns_deleted': 0,
            'deleted_so_far': 0,
            'batches_completed': 0,
            'error': None,
            'started_at': now,
            'last_updated_at': now,
            'finished_at': None,
        }
    t = threading.Thread(target=_run_cleanup_worker, args=(general, dns), daemon=True)
    t.start()
    return {"success": True, "status": "running", "general_days": general, "dns_days": dns,
            "batch_size": Database.RETENTION_BATCH_SIZE}


@router.get("/api/config/retention/cleanup-status")
def get_retention_cleanup_status():
    """Return current or recent retention cleanup job state.

    Returns idle if no job is active or recent.
    """
    with _cleanup_lock:
        _cleanup_gc()
        if _cleanup_job:
            return dict(_cleanup_job)
    return {"status": "idle"}


_PURGEABLE_LOG_TYPES = {'wifi', 'system'}
_PURGE_BATCH_SIZE = 5000
_PURGE_RESULT_TTL = 30  # seconds to keep complete/failed status before clearing

# In-memory purge job tracker per log_type.
# States: running → complete | failed.  Cleared after _PURGE_RESULT_TTL.
_purge_jobs: dict = {}
_purge_lock = threading.Lock()


def _now_ts():
    return datetime.now(timezone.utc).isoformat()


def _purge_gc():
    """Remove finished jobs older than _PURGE_RESULT_TTL.  Caller must hold _purge_lock."""
    now = datetime.now(timezone.utc)
    expired = [
        lt for lt, job in _purge_jobs.items()
        if job['status'] in ('complete', 'failed')
        and (now - datetime.fromisoformat(job['finished_at'])).total_seconds() > _PURGE_RESULT_TTL
    ]
    for lt in expired:
        del _purge_jobs[lt]


def _run_purge(log_type: str, total_rows: int, max_id: int):
    """Background worker that deletes logs in batches and updates _purge_jobs.

    Only deletes rows with id <= max_id so new inserts during the purge are not affected.
    """
    batch_size = _PURGE_BATCH_SIZE
    total_batches = (total_rows + batch_size - 1) // batch_size
    log_type_upper = log_type.upper()
    total_deleted = 0
    conn = get_conn()
    try:
        batch_num = 0
        with conn.cursor() as cur:
            while True:
                try:
                    cur.execute(
                        "DELETE FROM logs WHERE id IN ("
                        "  SELECT id FROM logs WHERE log_type = %s AND id <= %s"
                        "  ORDER BY id FOR UPDATE SKIP LOCKED LIMIT %s"
                        ")",
                        [log_type, max_id, batch_size]
                    )
                    batch = cur.rowcount
                    conn.commit()
                except Exception as e:
                    conn.rollback()
                    logger.exception("PURGE %s: batch %d/%d — ERROR: %s",
                                     log_type_upper, batch_num, total_batches, e)
                    raise
                if batch == 0:
                    break
                batch_num += 1
                total_deleted += batch
                # Recalculate total_batches from actual progress so SKIP LOCKED
                # underfills don't push batch_num past the displayed total.
                remaining = total_rows - total_deleted
                if remaining > 0:
                    total_batches = batch_num + (remaining + batch_size - 1) // batch_size
                else:
                    total_batches = batch_num
                with _purge_lock:
                    _purge_jobs[log_type].update(batch=batch_num, total_batches=total_batches,
                                                 deleted_so_far=total_deleted, last_updated_at=_now_ts())
                logger.info("PURGE %s: batch %d/%d — deleted %s rows (total so far: %s)",
                            log_type_upper, batch_num, total_batches,
                            f"{batch:,}", f"{total_deleted:,}")
        now = _now_ts()
        with _purge_lock:
            _purge_jobs[log_type].update(status='complete', deleted_so_far=total_deleted,
                                         last_updated_at=now, finished_at=now)
        logger.info("PURGE %s: completed — %s records deleted", log_type_upper, f"{total_deleted:,}")
    except Exception as e:
        now = _now_ts()
        with _purge_lock:
            _purge_jobs[log_type].update(status='failed', error="Purge failed due to a database error. Check the container logs for details.",
                                         last_updated_at=now, finished_at=now)
        logger.exception("PURGE %s: failed after %s deleted rows", log_type_upper, f"{total_deleted:,}")
    finally:
        put_conn(conn)


@router.delete("/api/config/purge-logs/{log_type}")
def purge_logs_by_type(log_type: str):
    """Start background deletion of all logs of a given type.

    Returns immediately.  Poll GET /api/config/purge-status for progress.
    """
    if log_type not in _PURGEABLE_LOG_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid log type: {log_type}. Must be one of: {', '.join(sorted(_PURGEABLE_LOG_TYPES))}")
    with _purge_lock:
        _purge_gc()
        existing = _purge_jobs.get(log_type)
        if existing and existing['status'] == 'running':
            raise HTTPException(status_code=409, detail=f"Purge already in progress for {log_type}")
    # Snapshot count and max id — only rows up to this id will be deleted,
    # so new inserts arriving during the purge are not chased.
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*), MAX(id) FROM logs WHERE log_type = %s", [log_type])
            total_rows, max_id = cur.fetchone()
        conn.commit()
    finally:
        put_conn(conn)
    if total_rows == 0:
        logger.info("PURGE %s: 0 records, nothing to delete", log_type.upper())
        return {"success": True, "deleted": 0, "status": "complete"}
    total_batches = (total_rows + _PURGE_BATCH_SIZE - 1) // _PURGE_BATCH_SIZE
    now = _now_ts()
    with _purge_lock:
        _purge_jobs[log_type] = {
            'status': 'running',
            'batch': 0,
            'total_batches': total_batches,
            'deleted_so_far': 0,
            'total_rows': total_rows,
            'error': None,
            'started_at': now,
            'last_updated_at': now,
            'finished_at': None,
        }
    logger.info("PURGE %s: starting deletion of %s records (id <= %s) in ~%d batches",
                 log_type.upper(), f"{total_rows:,}", f"{max_id:,}", total_batches)
    t = threading.Thread(target=_run_purge, args=(log_type, total_rows, max_id), daemon=True)
    t.start()
    return {"success": True, "status": "running", "total_rows": total_rows, "total_batches": total_batches}


@router.get("/api/config/purge-status")
def get_purge_status():
    """Return current purge job status for all log types.

    Finished jobs are auto-cleared after _PURGE_RESULT_TTL seconds.
    Log types with no active or recent job are omitted (implicitly idle).
    """
    with _purge_lock:
        _purge_gc()
        return {lt: dict(job) for lt, job in _purge_jobs.items()}


# ── UI Settings (endpoints) ──────────────────────────────────────────────────

@router.get("/api/settings/ui")
def get_ui_settings():
    """Return current UI display settings."""
    return {k: get_config(enricher_db, k, v) for k, v in _UI_SETTINGS_DEFAULTS.items()}


@router.put("/api/settings/ui")
def update_ui_settings(body: dict):
    """Save UI display settings to system_config."""
    actually_changed_processing = False
    for key, constraint in _UI_SETTINGS_VALID.items():
        if key not in body:
            continue
        val = body[key]
        if isinstance(constraint, set):
            if val not in constraint:
                raise HTTPException(400, f"Invalid value for {key}: {val}")
        else:  # tuple = (lo, hi) range
            try:
                val = int(val)
            except (ValueError, TypeError):
                raise HTTPException(400, f"{key} must be an integer") from None
            lo, hi = constraint
            if not (lo <= val <= hi):
                raise HTTPException(400, f"{key} must be between {lo} and {hi}")
        # Track whether a processing key actually changed value
        if key in _PROCESSING_KEYS:
            current = get_config(enricher_db, key, _UI_SETTINGS_DEFAULTS[key])
            if val != current:
                actually_changed_processing = True
        set_config(enricher_db, key, val)
    # Signal receiver to reload only when processing settings actually changed
    if actually_changed_processing:
        signal_receiver()
    return {"success": True}
