"""UniFi settings, connection test, firewall proxy, and device endpoints."""

import json
import logging
import os
import queue
import threading

import requests as _requests
from requests.exceptions import ConnectionError as RequestsConnectionError, SSLError

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from psycopg2.extras import RealDictCursor

from db import get_config, set_config, encrypt_api_key, decrypt_api_key
from deps import get_conn, put_conn, enricher_db, unifi_api, signal_receiver
from firewall_policy_matcher import (
    match_log_to_policy, invalidate_cache as invalidate_fw_cache,
)
from unifi_api import UniFiPermissionError

logger = logging.getLogger('api.unifi')

router = APIRouter()


@router.get("/api/settings/unifi")
def get_unifi_settings():
    """Current UniFi settings (merged: env + DB + defaults)."""
    return unifi_api.get_settings_info()


@router.put("/api/settings/unifi")
def update_unifi_settings(body: dict):
    """Save UniFi settings to system_config."""
    if 'enabled' in body:
        set_config(enricher_db, 'unifi_enabled', body['enabled'])
    if 'host' in body:
        set_config(enricher_db, 'unifi_host', body['host'])
    if 'controller_type' in body:
        set_config(enricher_db, 'unifi_controller_type', body['controller_type'])
    if 'api_key' in body:
        key_val = body['api_key']
        if key_val == '':
            set_config(enricher_db, 'unifi_api_key', '')
        elif key_val is not None:
            set_config(enricher_db, 'unifi_api_key', encrypt_api_key(key_val))
    if 'username' in body:
        val = body['username']
        if val == '':
            set_config(enricher_db, 'unifi_username', '')
        elif val is not None:
            set_config(enricher_db, 'unifi_username', encrypt_api_key(val))
    if 'password' in body:
        val = body['password']
        if val == '':
            set_config(enricher_db, 'unifi_password', '')
        elif val is not None:
            set_config(enricher_db, 'unifi_password', encrypt_api_key(val))
    if 'site' in body:
        set_config(enricher_db, 'unifi_site', body['site'])
        # Clear cached site_id — self-hosted must re-resolve on next request
        set_config(enricher_db, 'unifi_site_id', None)
    if 'verify_ssl' in body:
        set_config(enricher_db, 'unifi_verify_ssl', body['verify_ssl'])
    if 'poll_interval' in body:
        set_config(enricher_db, 'unifi_poll_interval', body['poll_interval'])
    if 'features' in body:
        set_config(enricher_db, 'unifi_features', body['features'])

    unifi_api.reload_config()
    invalidate_fw_cache()
    signal_receiver()

    return {"success": True}


@router.post("/api/settings/unifi/test")
def test_unifi_connection(body: dict):
    """Test connection AND save settings on success."""
    host = body.get('host', '').strip()
    site = body.get('site', 'default').strip()
    verify_ssl = body.get('verify_ssl', True)
    controller_type = body.get('controller_type', 'unifi_os')
    use_env_key = body.get('use_env_key', False)
    use_saved_key = body.get('use_saved_key', False)
    use_saved_credentials = body.get('use_saved_credentials', False)

    if controller_type == 'self_hosted':
        # Self-hosted: cookie-based auth with username/password
        if use_saved_credentials:
            encrypted_user = get_config(enricher_db, 'unifi_username', '')
            encrypted_pass = get_config(enricher_db, 'unifi_password', '')
            if not encrypted_user or not encrypted_pass:
                raise HTTPException(status_code=400, detail="No saved credentials found. Please enter username and password.")
            try:
                username = decrypt_api_key(encrypted_user)
                password = decrypt_api_key(encrypted_pass)
            except Exception:
                raise HTTPException(
                    status_code=400,
                    detail="Saved credentials could not be decrypted. Please re-enter your credentials.",
                ) from None
        else:
            username = body.get('username', '').strip()
            password = body.get('password', '')

        if not host or not username or not password:
            raise HTTPException(status_code=400, detail="host, username, and password are required")

        result = unifi_api.test_connection(
            host, site, verify_ssl, controller_type='self_hosted',
            username=username, password=password)

        if result.get('success'):
            set_config(enricher_db, 'unifi_host', host)
            set_config(enricher_db, 'unifi_controller_type', 'self_hosted')
            if not use_saved_credentials:
                set_config(enricher_db, 'unifi_username', encrypt_api_key(username))
                set_config(enricher_db, 'unifi_password', encrypt_api_key(password))
            if result.get('site_id'):
                set_config(enricher_db, 'unifi_site_id', result['site_id'])
            set_config(enricher_db, 'unifi_site', site)
            set_config(enricher_db, 'unifi_verify_ssl', verify_ssl)
            set_config(enricher_db, 'unifi_controller_name', result.get('controller_name', ''))
            set_config(enricher_db, 'unifi_controller_version', result.get('version', ''))
            set_config(enricher_db, 'unifi_enabled', True)
            unifi_api.reload_config()
            signal_receiver()

    else:
        # UniFi OS: API key auth
        if use_env_key:
            api_key = os.environ.get('UNIFI_API_KEY', '')
        elif use_saved_key:
            encrypted = get_config(enricher_db, 'unifi_api_key', '')
            if not encrypted:
                api_key = ''
            else:
                try:
                    api_key = decrypt_api_key(encrypted)
                except Exception:
                    logger.warning("Failed to decrypt saved API key — SECRET_KEY/POSTGRES_PASSWORD may have changed")
                    raise HTTPException(
                        status_code=400,
                        detail="Saved API key could not be decrypted. Please re-enter your API key.",
                    ) from None
        else:
            api_key = body.get('api_key', '').strip()

        if not host or not api_key:
            raise HTTPException(status_code=400, detail="host and api_key are required")

        result = unifi_api.test_connection(
            host, site, verify_ssl, controller_type='unifi_os', api_key=api_key)

        if result.get('success'):
            set_config(enricher_db, 'unifi_host', host)
            set_config(enricher_db, 'unifi_controller_type', 'unifi_os')
            if not use_env_key and not use_saved_key:
                set_config(enricher_db, 'unifi_api_key', encrypt_api_key(api_key))
            set_config(enricher_db, 'unifi_site', site)
            set_config(enricher_db, 'unifi_verify_ssl', verify_ssl)
            set_config(enricher_db, 'unifi_controller_name', result.get('controller_name', ''))
            set_config(enricher_db, 'unifi_controller_version', result.get('version', ''))
            set_config(enricher_db, 'unifi_enabled', True)
            unifi_api.reload_config()
            signal_receiver()

    return result


@router.get("/api/setup/unifi-network-config")
def unifi_network_config():
    """UniFi API-based network topology for wizard."""
    if not unifi_api.enabled:
        raise HTTPException(status_code=400, detail="UniFi API not configured")
    try:
        return unifi_api.get_network_config()
    except SSLError:
        logger.exception("Failed to fetch UniFi network config")
        raise HTTPException(status_code=502,
            detail="SSL certificate verification failed. If using a self-signed certificate, enable 'Skip SSL verification' in UniFi settings.")
    except RequestsConnectionError:
        logger.exception("Failed to fetch UniFi network config")
        raise HTTPException(status_code=502,
            detail="Could not connect to the UniFi Controller. Check that the host is reachable and the URL is correct.")
    except Exception as e:
        logger.exception("Failed to fetch UniFi network config")
        raise HTTPException(status_code=502,
            detail="Failed to fetch network configuration from the UniFi Controller. Check the container logs for details.") from e


@router.post("/api/settings/unifi/dismiss-upgrade")
def dismiss_upgrade():
    """Permanently dismiss the v2.0 upgrade modal."""
    set_config(enricher_db, 'upgrade_v2_dismissed', True)
    return {"success": True}


def _normalize_dismissed_interfaces(value) -> list[str]:
    """Normalize a list of interface names: keep non-blank strings, trim, deduplicate."""
    if not isinstance(value, list):
        return []
    return list(dict.fromkeys(
        s.strip() for s in value if isinstance(s, str) and s.strip()
    ))


@router.post("/api/settings/unifi/dismiss-vpn-toast")
def dismiss_vpn_toast(body: dict):
    """Dismiss VPN toast for specific interfaces."""
    raw = body.get('interfaces')
    if not isinstance(raw, list):
        raise HTTPException(status_code=400, detail="interfaces must be a list")
    cleaned = _normalize_dismissed_interfaces(raw)
    existing = _normalize_dismissed_interfaces(
        get_config(enricher_db, 'vpn_toast_dismissed', [])
    )
    merged = list(dict.fromkeys(existing + cleaned))
    if merged != existing:
        set_config(enricher_db, 'vpn_toast_dismissed', merged)
    return {"success": True}


@router.get("/api/unifi/gateway-image")
def get_gateway_image():
    """Proxy the gateway device thumbnail from the controller."""
    if not unifi_api.host:
        raise HTTPException(status_code=404, detail="No gateway configured")
    url = f"{unifi_api.host.rstrip('/')}/assets/images/48.png"
    try:
        resp = _requests.get(url, verify=unifi_api.verify_ssl, timeout=5)
        ct = resp.headers.get('content-type', '')
        if resp.status_code != 200 or not ct.startswith('image/'):
            raise HTTPException(status_code=404, detail="Image not available")
        return Response(content=resp.content, media_type=ct,
                        headers={"Cache-Control": "public, max-age=86400"})
    except _requests.RequestException as e:
        raise HTTPException(status_code=404, detail="Image not available") from e


@router.get("/api/firewall/policies")
def get_firewall_policies():
    """Fetch all policies + zones (handles pagination internally)."""
    if not unifi_api.enabled:
        raise HTTPException(status_code=400, detail="UniFi API not configured")
    if not unifi_api.features.get('firewall_management', True):
        raise HTTPException(status_code=400,
            detail="Firewall management requires a UniFi OS gateway (not available on self-hosted controllers)")
    try:
        return unifi_api.get_firewall_data()
    except UniFiPermissionError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e)) from e
    except SSLError:
        logger.exception("Failed to fetch firewall policies")
        raise HTTPException(status_code=502,
            detail="SSL certificate verification failed. If using a self-signed certificate, enable 'Skip SSL verification' in UniFi settings.")
    except RequestsConnectionError:
        logger.exception("Failed to fetch firewall policies")
        raise HTTPException(status_code=502,
            detail="Could not connect to the UniFi Controller. Check that the host is reachable and the URL is correct.")
    except Exception as e:
        logger.exception("Failed to fetch firewall policies")
        raise HTTPException(status_code=502,
            detail="Could not retrieve firewall policies from the UniFi Controller. Check the container logs for details.") from e


@router.patch("/api/firewall/policies/{policy_id}")
def patch_firewall_policy(policy_id: str, body: dict):
    """Update a single policy's loggingEnabled."""
    if not unifi_api.enabled:
        raise HTTPException(status_code=400, detail="UniFi API not configured")
    if not unifi_api.features.get('firewall_management', True):
        raise HTTPException(status_code=400,
            detail="Firewall management requires a UniFi OS gateway (not available on self-hosted controllers)")

    # Reject DERIVED policies
    origin = body.get('origin', '')
    if origin == 'DERIVED':
        raise HTTPException(
            status_code=400,
            detail="This rule is auto-generated and cannot be modified. Manage it in your UniFi Controller under Traffic Rules."
        )

    logging_enabled = body.get('loggingEnabled')
    if logging_enabled is None:
        raise HTTPException(status_code=400, detail="loggingEnabled is required")

    try:
        result = unifi_api.patch_firewall_policy(policy_id, logging_enabled)
        invalidate_fw_cache()
        return {"success": True, "data": result}
    except UniFiPermissionError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e)) from e
    except Exception as e:
        status = 502
        msg = "Failed to update this firewall rule. The UniFi Controller may be unreachable, be busy or the rule may have changed."
        if hasattr(e, 'response') and e.response is not None:
            if e.response.status_code == 422:
                msg = "The controller rejected this change. The rule may have been modified or removed in the UniFi Controller."
                status = 422
            else:
                status = e.response.status_code
        logger.exception("Failed to patch firewall policy %s", policy_id)
        raise HTTPException(status_code=status, detail=msg) from e


@router.post("/api/firewall/policies/bulk-logging")
def bulk_update_logging(body: dict):
    """Batch-update loggingEnabled for multiple policies."""
    if not unifi_api.enabled:
        raise HTTPException(status_code=400, detail="UniFi API not configured")
    if not unifi_api.features.get('firewall_management', True):
        raise HTTPException(status_code=400,
            detail="Firewall management requires a UniFi OS gateway (not available on self-hosted controllers)")

    policies = body.get('policies', [])
    if not policies:
        raise HTTPException(status_code=400, detail="policies list is required")

    try:
        result = unifi_api.bulk_patch_logging(policies)
        invalidate_fw_cache()
        return result
    except UniFiPermissionError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e)) from e
    except Exception as e:
        logger.exception("Bulk firewall update failed")
        raise HTTPException(status_code=502,
            detail="Bulk update failed. One or more policies could not be processed. Check the container logs for details.") from e


@router.post("/api/firewall/policies/bulk-logging-stream")
def bulk_update_logging_stream(body: dict):
    """SSE stream: bulk-update loggingEnabled with live progress events."""
    if not unifi_api.enabled:
        raise HTTPException(status_code=400, detail="UniFi API not configured")
    if not unifi_api.features.get('firewall_management', True):
        raise HTTPException(status_code=400,
            detail="Firewall management requires a UniFi OS gateway (not available on self-hosted controllers)")

    policies = body.get('policies', [])
    if not policies:
        raise HTTPException(status_code=400, detail="policies list is required")

    def _event_stream():
        q = queue.Queue()

        def on_progress(completed, total, success, failed, phase='patching'):
            q.put({'event': 'progress', 'completed': completed, 'total': total,
                    'success': success, 'failed': failed, 'phase': phase})

        def run_bulk():
            try:
                result = unifi_api.bulk_patch_logging(policies, progress_callback=on_progress)
                invalidate_fw_cache()
                q.put({'event': 'complete', **result})
            except UniFiPermissionError as e:
                q.put({'event': 'error', 'detail': str(e)})
            except Exception as e:
                logger.exception("Bulk firewall stream failed")
                q.put({'event': 'error', 'detail': "Bulk update failed. One or more policies could not be processed. Check the container logs for details."})
            finally:
                q.put(None)  # sentinel

        t = threading.Thread(target=run_bulk, daemon=True)
        t.start()

        while True:
            msg = q.get()
            if msg is None:
                break
            yield f"data: {json.dumps(msg)}\n\n"

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Log-to-Policy Matching ────────────────────────────────────────────────

def _get_vpn_networks():
    """Read VPN networks from system_config. Returns dict or empty dict."""
    vpn_raw = get_config(enricher_db, 'vpn_networks')
    if not vpn_raw:
        return {}
    try:
        return json.loads(vpn_raw) if isinstance(vpn_raw, str) else vpn_raw
    except json.JSONDecodeError:
        logger.warning("Failed to parse vpn_networks from system_config")
        return {}


@router.post("/api/firewall/policies/match-log")
def match_log_to_policy_route(body: dict):
    """Match a firewall log entry to a policy for syslog toggle.

    Returns {"status": "disabled"} when UniFi/firewall_management is off,
    avoiding the need for unifiEnabled prop drilling in the frontend.
    """
    if not unifi_api.enabled:
        return {"status": "disabled"}
    if not unifi_api.features.get('firewall_management', True):
        return {"status": "disabled"}

    try:
        return match_log_to_policy(
            unifi_api,
            interface_in=body.get('interface_in', ''),
            interface_out=body.get('interface_out', ''),
            rule_name=body.get('rule_name', ''),
            vpn_networks=_get_vpn_networks(),
        )
    except Exception as e:
        logger.exception("Policy match failed")
        return {"status": "error", "message": "Could not match this log entry to a firewall policy. The rule may no longer exist."}



# ── Phase 2: Device Endpoints ────────────────────────────────────────────

@router.get("/api/unifi/clients")
def list_unifi_clients(
    search: str = Query(None, description="Filter by name, hostname, IP, or MAC"),
    limit: int = Query(200, ge=1, le=1000),
):
    """Return cached UniFi clients from the database."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if search:
                cur.execute("""
                    SELECT mac, host(ip) as ip, device_name, hostname, oui,
                           network, essid, vlan, is_fixed_ip, is_wired,
                           last_seen, updated_at
                    FROM unifi_clients
                    WHERE device_name ILIKE %s OR hostname ILIKE %s
                       OR host(ip) LIKE %s OR mac::text ILIKE %s
                    ORDER BY last_seen DESC NULLS LAST
                    LIMIT %s
                """, [f'%{search}%', f'%{search}%', f'%{search}%',
                      f'%{search}%', limit])
            else:
                cur.execute("""
                    SELECT mac, host(ip) as ip, device_name, hostname, oui,
                           network, essid, vlan, is_fixed_ip, is_wired,
                           last_seen, updated_at
                    FROM unifi_clients
                    ORDER BY last_seen DESC NULLS LAST
                    LIMIT %s
                """, [limit])
            rows = cur.fetchall()
        conn.commit()
        clients = []
        for r in rows:
            d = dict(r)
            if d.get('mac'):
                d['mac'] = str(d['mac'])
            for ts_key in ('last_seen', 'updated_at'):
                if d.get(ts_key):
                    d[ts_key] = d[ts_key].isoformat()
            clients.append(d)
        return {'clients': clients, 'total': len(clients)}
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching UniFi clients")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/unifi/devices")
def list_unifi_devices():
    """Return cached UniFi infrastructure devices from the database."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT mac, host(ip) as ip, device_name, model, shortname,
                       device_type, firmware, serial, state, uptime, updated_at
                FROM unifi_devices
                ORDER BY device_name NULLS LAST, model
            """)
            rows = cur.fetchall()
        conn.commit()
        devices = []
        for r in rows:
            d = dict(r)
            if d.get('mac'):
                d['mac'] = str(d['mac'])
            if d.get('updated_at'):
                d['updated_at'] = d['updated_at'].isoformat()
            devices.append(d)
        return {'devices': devices, 'total': len(devices)}
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching UniFi devices")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/unifi/status")
def unifi_poll_status():
    """Return current UniFi polling status."""
    settings = unifi_api.get_settings_info()
    return {
        'enabled': settings['enabled'],
        'status': settings['status'],
        'features': settings['features'],
        'poll_interval': settings['poll_interval'],
    }


@router.post("/api/unifi/backfill-device-names")
def backfill_device_names(body: dict):
    """On-demand backfill: patch historical logs with device names.

    Body: { "since": "2025-01-01T00:00:00Z" }
    Uses MAC-based join for src (DHCP-safe), time-bounded IP for dst.
    """
    since = body.get('since')
    if not since:
        raise HTTPException(status_code=400, detail="'since' date is required")

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # src_device_name: MAC-based join (stable across DHCP changes)
            cur.execute("""
                UPDATE logs
                SET src_device_name = COALESCE(c.device_name, c.hostname, c.oui)
                FROM unifi_clients c
                WHERE logs.mac_address = c.mac
                  AND logs.src_device_name IS NULL
                  AND logs.timestamp >= %s::timestamptz
                  AND COALESCE(c.device_name, c.hostname, c.oui) IS NOT NULL
            """, [since])
            src_patched = cur.rowcount

            # dst_device_name: IP-based join with time window to limit DHCP misattribution
            cur.execute("""
                UPDATE logs
                SET dst_device_name = sub.name
                FROM (
                    SELECT DISTINCT ON (host(ip)) ip,
                           COALESCE(device_name, hostname, oui) as name,
                           last_seen
                    FROM unifi_clients
                    WHERE COALESCE(device_name, hostname, oui) IS NOT NULL
                    ORDER BY host(ip), last_seen DESC NULLS LAST
                ) sub
                WHERE logs.dst_ip = sub.ip
                  AND logs.dst_device_name IS NULL
                  AND logs.timestamp >= %s::timestamptz
                  AND logs.timestamp >= sub.last_seen - INTERVAL '1 day'
            """, [since])
            dst_patched = cur.rowcount

        conn.commit()
        logger.info("Device name backfill: %d src, %d dst patched (since %s)",
                     src_patched, dst_patched, since)
        return {
            'success': True,
            'src_patched': src_patched,
            'dst_patched': dst_patched,
        }
    except Exception as e:
        conn.rollback()
        logger.exception("Device name backfill failed")
        raise HTTPException(status_code=500, detail="Backfill failed") from e
    finally:
        put_conn(conn)
