"""
UniFi Log Insight - UniFi Controller API Client

Handles all interactions with the UniFi Controller's Classic and Integration APIs.
Phase 1: Settings, wizard network config, firewall policy management.
Phase 2: Client/device polling, IP-to-device-name enrichment.
"""

import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests
from requests.exceptions import ConnectionError, Timeout, SSLError

from db import encrypt_api_key, decrypt_api_key

logger = logging.getLogger(__name__)

# WAN physical interface mapping from API wan_type + wan_networkgroup
_WAN_PHYSICAL_MAP = {
    ('pppoe', 'WAN'): 'ppp0',
    ('pppoe', 'WAN2'): 'ppp1',
    ('dhcp', 'WAN'): 'eth4',
    ('static', 'WAN'): 'eth4',
    ('dhcp', 'WAN2'): 'eth5',
    ('static', 'WAN2'): 'eth5',
}

_EPOCH_MIN = datetime.min.replace(tzinfo=timezone.utc)


class UniFiPermissionError(Exception):
    """Raised when the UniFi Integration API returns 401 (auth failure) or 403 (insufficient permissions)."""
    def __init__(self, message, status_code=403):
        super().__init__(message)
        self.status_code = status_code


class UniFiAPI:
    """UniFi Controller API client.

    Phase 1: Settings, wizard network config, firewall policy management.
    Phase 2: Client/device polling, IP-to-device-name enrichment.
    """

    TIMEOUT = 10  # seconds per request

    def __init__(self, db):
        self._db = db
        self._session = None
        self._site_uuid = None
        self.host = ''
        self.api_key = ''
        self.site = 'default'
        self.verify_ssl = True
        self.enabled = False
        self.features = {}
        # Self-hosted controller state
        self._controller_type = 'unifi_os'  # 'unifi_os' | 'self_hosted'
        self._username = ''
        self._password = ''
        self._csrf_token = None
        self._site_id = None  # resolved site _id for self-hosted
        # Phase 2: polling state
        self._poll_thread = None
        self._poll_stop = threading.Event()
        self._lock = threading.Lock()
        self._ip_to_name = {}
        self._mac_to_name = {}
        self._last_poll = None
        self._last_poll_error = None
        self._client_count = 0
        self._device_count = 0
        try:
            self._resolve_config()
        except Exception as e:
            logger.warning("UniFiAPI: config resolution failed (DB may not be ready): %s", e)

    # ── Config Resolution ─────────────────────────────────────────────────────

    def _resolve_config(self):
        """Load settings: env var > system_config DB > default."""
        self.host = (os.environ.get('UNIFI_HOST') or
                     self._db.get_config('unifi_host', '')).rstrip('/')
        self.api_key = (os.environ.get('UNIFI_API_KEY') or
                        self._decrypt_db_key())
        self.site = (os.environ.get('UNIFI_SITE') or
                     self._db.get_config('unifi_site', 'default'))

        ssl_env = os.environ.get('UNIFI_VERIFY_SSL', '').lower()
        if ssl_env in ('false', '0', 'no'):
            self.verify_ssl = False
        elif ssl_env:
            self.verify_ssl = True
        else:
            self.verify_ssl = self._db.get_config('unifi_verify_ssl', True)

        # Suppress noisy InsecureRequestWarning when SSL verification is
        # disabled AND log level is INFO. DEBUG/WARNING+ still see them.
        import warnings, urllib3
        if not self.verify_ssl and logger.getEffectiveLevel() == logging.INFO:
            warnings.filterwarnings('ignore', category=urllib3.exceptions.InsecureRequestWarning)
        else:
            warnings.filterwarnings('default', category=urllib3.exceptions.InsecureRequestWarning)

        self.features = self._db.get_config('unifi_features', {
            'client_names': True, 'device_discovery': True,
            'network_config': True, 'firewall_management': True,
        })

        # Self-hosted controller config (DB only — no env vars)
        self._controller_type = self._db.get_config('unifi_controller_type', 'unifi_os')
        self._username = self._decrypt_db_credential('unifi_username')
        self._password = self._decrypt_db_credential('unifi_password')
        self._site_id = self._db.get_config('unifi_site_id', None)

        # Force-disable firewall management for self-hosted (integration API not available)
        if self._controller_type == 'self_hosted':
            self.features = dict(self.features)
            self.features['firewall_management'] = False

        # Master toggle AND credentials must both be present
        unifi_enabled_env = os.environ.get('UNIFI_ENABLED', '').lower()
        if unifi_enabled_env in ('true', '1', 'yes'):
            unifi_enabled = True
        elif unifi_enabled_env in ('false', '0', 'no'):
            unifi_enabled = False
        else:
            unifi_enabled = self._db.get_config('unifi_enabled', False)

        has_credentials = (bool(self._username and self._password)
                          if self._controller_type == 'self_hosted'
                          else bool(self.api_key))
        self.enabled = bool(unifi_enabled) and bool(self.host) and has_credentials

        # Auto-enable when both env vars are set
        if (not unifi_enabled and self.host and self.api_key
                and os.environ.get('UNIFI_HOST') and os.environ.get('UNIFI_API_KEY')):
            try:
                self._db.set_config('unifi_enabled', True)
                self.enabled = True
                logger.info("UniFi API auto-enabled (UNIFI_HOST + UNIFI_API_KEY env vars detected)")
            except Exception as e:
                logger.debug("Failed to auto-enable UniFi (UNIFI_HOST+UNIFI_API_KEY): %s", e)

    def _decrypt_db_key(self) -> str:
        """Read and decrypt API key from system_config."""
        encrypted = self._db.get_config('unifi_api_key', '')
        if not encrypted:
            return ''
        try:
            return decrypt_api_key(encrypted)
        except Exception:
            logger.warning("Failed to decrypt saved API key — SECRET_KEY/POSTGRES_PASSWORD may have changed")
            return ''

    def _decrypt_db_credential(self, config_key):
        """Read and decrypt a credential from system_config."""
        encrypted = self._db.get_config(config_key, '')
        if not encrypted:
            return ''
        try:
            return decrypt_api_key(encrypted)
        except Exception:
            logger.warning("Failed to decrypt %s — SECRET_KEY/POSTGRES_PASSWORD may have changed", config_key)
            return ''

    def reload_config(self):
        """Re-read settings, invalidate session + site UUID, restart polling if needed."""
        was_polling = self._poll_thread is not None and self._poll_thread.is_alive()
        self._session = None
        self._site_uuid = None
        self._csrf_token = None
        self._resolve_config()
        logger.info("UniFi API config reloaded (enabled=%s, host=%s)", self.enabled, self.host or '(none)')
        # Restart polling if it was running (or start it if newly enabled)
        if was_polling or self.enabled:
            self.start_polling()

    def get_config_source(self, key: str) -> str:
        """Return 'env', 'db', or 'default' for a config key."""
        env_map = {
            'host': 'UNIFI_HOST',
            'api_key': 'UNIFI_API_KEY',
            'site': 'UNIFI_SITE',
            'verify_ssl': 'UNIFI_VERIFY_SSL',
        }
        env_var = env_map.get(key)
        if env_var and os.environ.get(env_var):
            return 'env'
        db_key = f'unifi_{key}'
        val = self._db.get_config(db_key)
        if val is not None and val != '':
            return 'db'
        return 'default'

    # ── HTTP Session ──────────────────────────────────────────────────────────

    def _get_session(self):
        """Lazily create and configure requests.Session."""
        if self._session is None:
            if self._controller_type == 'self_hosted':
                self._session = self._login_session(
                    self.host, self._username, self._password, self.verify_ssl)
            else:
                self._session = requests.Session()
                self._session.headers['X-API-KEY'] = self.api_key
                self._session.verify = self.verify_ssl
        return self._session

    def _make_session(self, api_key: str, verify_ssl: bool):
        """Create a temporary session for test_connection."""
        s = requests.Session()
        s.headers['X-API-KEY'] = api_key
        s.verify = verify_ssl
        return s

    # ── URL + Auth Helpers ─────────────────────────────────────────────────────

    def _build_url(self, path, host=None):
        """Centralized classic-API URL construction."""
        h = host or self.host
        if self._controller_type == 'self_hosted':
            site = self._site_id or self.site
            return f"{h}/api/s/{site}/{path.lstrip('/')}"
        site = self.site
        return f"{h}/proxy/network/api/s/{site}/{path.lstrip('/')}"

    def _login_session(self, host, username, password, verify_ssl):
        """Cookie-based login for self-hosted controllers."""
        session = requests.Session()
        session.verify = verify_ssl
        resp = session.post(f"{host}/api/login", json={
            "username": username,
            "password": password,
            "remember": True,
        }, timeout=self.TIMEOUT)
        resp.raise_for_status()
        csrf = resp.headers.get('X-Csrf-Token')
        if csrf:
            self._csrf_token = csrf
            session.headers['X-Csrf-Token'] = csrf
        return session

    def _resolve_site_id(self, session, host, site_name):
        """Resolve classic site name to unique _id for self-hosted controllers."""
        resp = session.get(f"{host}/api/self/sites", timeout=self.TIMEOUT)
        resp.raise_for_status()
        for site in resp.json().get('data', []):
            if site.get('name') == site_name or site.get('desc') == site_name:
                return site['_id']
        raise ValueError(f"Site '{site_name}' not found on this controller")

    @staticmethod
    def _is_login_required(resp):
        """Check if response indicates an expired session (self-hosted)."""
        try:
            body = resp.json()
            return body.get('meta', {}).get('msg') == 'api.err.LoginRequired'
        except Exception:
            return False

    # ── Classic API Helpers ───────────────────────────────────────────────────

    def _get(self, path, host=None, session=None):
        """GET from classic API."""
        h = host or self.host
        s = session or self._get_session()
        url = self._build_url(path, host=h)
        resp = s.get(url, timeout=self.TIMEOUT)
        # Re-auth on expired session (self-hosted only, persistent session only)
        if (self._controller_type == 'self_hosted' and session is None
                and (resp.status_code in (401, 403) or self._is_login_required(resp))):
            self._session = None
            s = self._get_session()
            resp = s.get(url, timeout=self.TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    # ── Integration API Helpers ───────────────────────────────────────────────

    def _get_integration(self, path, host=None, session=None):
        """GET from integration API (no site prefix)."""
        if self._controller_type == 'self_hosted':
            raise NotImplementedError("Integration API not available on self-hosted controllers")
        h = host or self.host
        s = session or self._get_session()
        url = f"{h}/proxy/network{path}"
        resp = s.get(url, timeout=self.TIMEOUT)
        self._check_integration_permissions(resp)
        resp.raise_for_status()
        return resp.json()

    def _get_integration_site(self, path):
        """GET from integration API with site UUID prefix."""
        if self._controller_type == 'self_hosted':
            raise NotImplementedError("Integration API not available on self-hosted controllers")
        if not self._site_uuid:
            self._discover_site_uuid()
        url = f"{self.host}/proxy/network/integration/v1/sites/{self._site_uuid}{path}"
        resp = self._get_session().get(url, timeout=self.TIMEOUT)
        self._check_integration_permissions(resp)
        resp.raise_for_status()
        return resp.json()

    def _patch_integration_site(self, path, body):
        """PATCH to integration API with site UUID prefix."""
        if self._controller_type == 'self_hosted':
            raise NotImplementedError("Integration API not available on self-hosted controllers")
        if not self._site_uuid:
            self._discover_site_uuid()
        url = f"{self.host}/proxy/network/integration/v1/sites/{self._site_uuid}{path}"
        resp = self._get_session().patch(url, json=body, timeout=self.TIMEOUT)
        self._check_integration_permissions(resp)
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _check_integration_permissions(resp):
        """Raise UniFiPermissionError on 401/403 from the Integration API."""
        if resp.status_code == 401:
            raise UniFiPermissionError(
                "Authentication failed. Check your API key.",
                status_code=401
            )
        if resp.status_code == 403:
            raise UniFiPermissionError(
                "Insufficient permissions. Your API key must belong to a "
                "Local Admin account with Network permissions. Read-only "
                "or viewer API keys cannot access the Integration API.",
                status_code=403
            )

    # ── Site UUID Discovery ───────────────────────────────────────────────────

    def _discover_site_uuid(self, host=None, session=None):
        """Map classic site name to integration API UUID."""
        if self._controller_type == 'self_hosted':
            raise NotImplementedError("Integration API not available on self-hosted controllers")
        sites = self._get_integration('/integration/v1/sites', host=host, session=session)
        for s in sites.get('data', []):
            if s.get('internalReference') == self.site:
                self._site_uuid = s['id']
                logger.info("Discovered site UUID: %s for site '%s'", self._site_uuid, self.site)
                return
        raise ValueError(f"Site '{self.site}' not found in integration API")

    # ── Phase 1: Connection & Config ──────────────────────────────────────────

    def test_connection(self, host: str, site: str = 'default',
                        verify_ssl: bool = True, controller_type: str = 'unifi_os',
                        api_key: str | None = None, username: str | None = None,
                        password: str | None = None) -> dict:
        """Test connectivity with provided credentials.

        Returns {success, controller_name, version, site_name} on success,
        or {success: false, error, error_code} on failure.
        Does NOT modify self — uses temporary session.
        """
        host = host.rstrip('/')

        try:
            if controller_type == 'self_hosted':
                return self._test_self_hosted(host, site, verify_ssl, username, password)
            return self._test_unifi_os(host, site, verify_ssl, api_key)

        except SSLError:
            return {'success': False,
                    'error': 'SSL certificate verification failed. Enable "Skip SSL verification" for self-signed certificates.',
                    'error_code': 'ssl_error'}
        except ConnectionError:
            return {'success': False,
                    'error': 'Could not connect to the controller. Check the URL and ensure it is reachable.',
                    'error_code': 'connection_error'}
        except Timeout:
            return {'success': False,
                    'error': 'Connection timed out. The controller may be unreachable.',
                    'error_code': 'timeout'}
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else 0
            if status in (401, 403):
                msg = ('Authentication failed. Check your credentials.'
                       if controller_type == 'self_hosted'
                       else 'Authentication failed. Check your API key.')
                return {'success': False, 'error': msg, 'error_code': 'auth_error'}
            return {'success': False,
                    'error': f'Controller returned error: {status}',
                    'error_code': 'invalid_response'}
        except Exception as e:
            return {'success': False,
                    'error': str(e),
                    'error_code': 'connection_error'}

    def _test_unifi_os(self, host, site, verify_ssl, api_key):
        """Test connection to a UniFi OS gateway (API key auth)."""
        session = self._make_session(api_key, verify_ssl)
        try:
            url = f"{host}/proxy/network/api/s/{site}/stat/sysinfo"
            resp = session.get(url, timeout=self.TIMEOUT)

            if resp.status_code == 401:
                return {'success': False, 'error': 'Authentication failed. Check your API key.',
                        'error_code': 'auth_error'}
            if resp.status_code == 403:
                return {'success': False,
                        'error': 'Insufficient permissions. Ensure your API key belongs to a Local Admin account.',
                        'error_code': 'auth_error'}
            resp.raise_for_status()

            data = resp.json()
            info = data.get('data', [{}])[0] if data.get('data') else {}
            controller_name = info.get('name') or info.get('hostname', 'Unknown')
            version = info.get('version', 'Unknown')

            # Verify integration API access (needed for firewall management)
            sites_url = f"{host}/proxy/network/integration/v1/sites"
            sites_resp = session.get(sites_url, timeout=self.TIMEOUT)

            if sites_resp.status_code == 401:
                return {
                    'success': False,
                    'error': 'Authentication failed. Check your API key.',
                    'error_code': 'auth_error',
                }

            if sites_resp.status_code == 403:
                # Classic API works but Integration API is denied — limited permissions
                return {
                    'success': True,
                    'controller_name': controller_name,
                    'version': version,
                    'site_name': site,
                    'warning': (
                        'Insufficient permissions \u2014 a Local Admin API key with '
                        'Network permissions is required for Firewall Syslog enablement. '
                        'You can continue to use the app but won\'t benefit from '
                        'Firewall Syslog Settings.'
                    ),
                }

            sites_resp.raise_for_status()
            sites_data = sites_resp.json()

            site_name = None
            for s in sites_data.get('data', []):
                if s.get('internalReference') == site:
                    site_name = s.get('name', site)
                    break

            if site_name is None:
                return {'success': False,
                        'error': f"Site '{site}' not found on this controller.",
                        'error_code': 'invalid_response'}

            return {
                'success': True,
                'controller_name': controller_name,
                'version': version,
                'site_name': site_name,
            }
        finally:
            session.close()

    def _test_self_hosted(self, host, site, verify_ssl, username, password):
        """Test connection to a self-hosted controller (cookie auth)."""
        session = None
        try:
            # Login with cookies
            session = self._login_session(host, username, password, verify_ssl)

            # Resolve the site _id (self-hosted requires unique _id, not name)
            site_id = self._resolve_site_id(session, host, site)

            # Probe sysinfo
            url = f"{host}/api/s/{site_id}/stat/sysinfo"
            resp = session.get(url, timeout=self.TIMEOUT)

            if self._is_login_required(resp):
                return {'success': False, 'error': 'Authentication failed. Check your credentials.',
                        'error_code': 'auth_error'}
            resp.raise_for_status()

            data = resp.json()
            info = data.get('data', [{}])[0] if data.get('data') else {}
            controller_name = info.get('name') or info.get('hostname', 'Unknown')
            version = info.get('version', 'Unknown')

            return {
                'success': True,
                'controller_name': controller_name,
                'version': version,
                'site_name': site,
                'site_id': site_id,
            }
        finally:
            if session:
                session.close()

    def get_network_config(self) -> dict:
        """Fetch network topology from Classic + Integration APIs for wizard."""
        if not self.enabled:
            return {'source': 'unifi_api', 'wan_interfaces': [], 'networks': []}

        # ── WAN interfaces from Classic API (/rest/networkconf + /stat/health) ──
        netconf = self._get('rest/networkconf')
        networks_raw = netconf.get('data', [])

        # Per-WAN health: 'wan' subsystem -> WAN, 'wan2' -> WAN2, 'wan3' -> WAN3, etc.
        health = self._get('stat/health')
        wan_health = {}
        for subsystem in health.get('data', []):
            sub_name = subsystem.get('subsystem', '')
            if sub_name == 'wan':
                wan_health['WAN'] = subsystem
            elif sub_name.startswith('wan') and sub_name[3:].isdigit():
                wan_health[f'WAN{sub_name[3:]}'] = subsystem
        logger.debug("stat/health WAN subsystems: %s",
                     {k: {'wan_ip': v.get('wan_ip'), 'status': v.get('status')}
                      for k, v in wan_health.items()})

        # ── Try to resolve physical interfaces from gateway wan* objects ──
        device_wan_map = {}   # networkgroup → uplink_ifname from stat/device
        device_wan_ips = {}   # networkgroup → ip (fallback when health missing)
        try:
            devices = self._get('stat/device')
            for dev in devices.get('data', []):
                # Find gateway by presence of wan* keys (no device-type filter)
                wan_keys = sorted(k for k in dev
                                  if k.startswith('wan') and k[3:].isdigit())
                if not wan_keys:
                    continue
                for key in wan_keys:
                    wan_obj = dev[key]
                    if not isinstance(wan_obj, dict):
                        continue
                    idx = key[3:]  # '1','2','3'
                    group = 'WAN' if idx == '1' else f'WAN{idx}'
                    uplink = wan_obj.get('uplink_ifname')
                    if uplink and group not in device_wan_map:
                        device_wan_map[group] = uplink
                    ip = wan_obj.get('ip')
                    if ip and group not in device_wan_ips:
                        device_wan_ips[group] = ip
                if device_wan_map:
                    logger.info("Resolved WAN interfaces from device: %s",
                                device_wan_map)
                break  # Only need the first gateway
        except Exception as e:
            logger.debug("Could not resolve WAN from stat/device: %s", e)

        wan_interfaces = []
        for net in networks_raw:
            if net.get('enabled') is False:
                continue
            if net.get('purpose') != 'wan':
                continue

            name = net.get('name', '')
            # API field is wan_networkgroup (not networkgroup)
            networkgroup = net.get('wan_networkgroup', '') or net.get('networkgroup', '')
            wan_type = net.get('wan_type', 'dhcp')
            wan_type_lower = wan_type.lower()
            logger.debug("WAN entry: name=%s, wan_type=%s, wan_networkgroup=%s",
                         name, wan_type, networkgroup)

            # Prefer gateway device detection over static map
            physical = device_wan_map.get(networkgroup)
            detected_from = 'device'
            if not physical:
                physical = _WAN_PHYSICAL_MAP.get(
                    (wan_type_lower, networkgroup),
                    'eth4' if networkgroup == 'WAN' else 'eth5'
                )
                detected_from = 'map'
                if (wan_type_lower, networkgroup) not in _WAN_PHYSICAL_MAP:
                    logger.warning("Unmapped WAN type: wan_type=%r, wan_networkgroup=%s "
                                   "-> defaulting to %s", wan_type, networkgroup, physical)

            health_sub = wan_health.get(networkgroup, {})

            # Detect tunnel WANs (GRE/5G backhaul) — device IP is inner tunnel
            # endpoint, not the public-facing IP. networkconf.wan_ip is authoritative.
            is_tunnel = (
                net.get('wan_5g_index') is not None
                or (net.get('ifname') or '').startswith('gre')
                or net.get('lan_tunnel_wan_device')
            )

            if is_tunnel:
                # networkconf.wan_ip is the public-facing IP for tunnel WANs;
                # health may be absent or unreliable; device.ip is inner endpoint.
                net_wan_ip = (
                    net.get('wan_ip')
                    or health_sub.get('wan_ip')
                    or device_wan_ips.get(networkgroup)
                )
                tunnel_ip = device_wan_ips.get(networkgroup)
                if tunnel_ip and tunnel_ip == net_wan_ip:
                    tunnel_ip = None
                logger.debug("Tunnel WAN detected: name=%s, group=%s, public=%s, tunnel=%s",
                             name, networkgroup, net_wan_ip, tunnel_ip)
            else:
                # Standard WANs: health is authoritative, device is fallback.
                net_wan_ip = health_sub.get('wan_ip') or device_wan_ips.get(networkgroup)
                tunnel_ip = None

            wan_interfaces.append({
                'name': name,
                'wan_ip': net_wan_ip,
                'tunnel_ip': tunnel_ip,
                'type': wan_type,
                'networkgroup': networkgroup,
                'physical_interface': physical,
                'active': bool(net_wan_ip),
                'detected_from': detected_from,
            })

        # ── Network segments from Integration API (/networks) ──
        # Subnet lookup from classic API /rest/networkconf (keyed by name)
        subnet_by_name = {}
        for net in networks_raw:
            n = net.get('name', '')
            if n and net.get('ip_subnet'):
                subnet_by_name[n] = net['ip_subnet']

        networks = []
        try:
            int_networks = self._get_integration_site('/networks')
            for net in int_networks.get('data', []):
                if not net.get('enabled', True):
                    continue
                vlan_id = net.get('vlanId')
                if vlan_id is None:
                    continue

                name = net.get('name', '')
                iface = 'br0' if vlan_id == 1 else f'br{vlan_id}'
                networks.append({
                    'name': name,
                    'interface': iface,
                    'vlan': vlan_id,
                    'ip_subnet': subnet_by_name.get(name, ''),
                })
        except Exception as e:
            logger.warning("Integration API /networks failed, falling back to classic: %s", e)
            for net in networks_raw:
                if not net.get('enabled', True):
                    continue
                purpose = net.get('purpose', '')
                if purpose not in ('corporate', 'guest', 'vlan-only'):
                    continue
                vlan = net.get('vlan')
                vlan_enabled = net.get('vlan_enabled', False)
                vlan_id = vlan if vlan and vlan_enabled else 1
                iface = 'br0' if vlan_id == 1 else f'br{vlan_id}'
                networks.append({
                    'name': net.get('name', ''),
                    'interface': iface,
                    'vlan': vlan_id,
                    'ip_subnet': net.get('ip_subnet', ''),
                })

        return {
            'source': 'unifi_api',
            'wan_interfaces': wan_interfaces,
            'networks': networks,
        }

    # ── VPN Network Discovery ─────────────────────────────────────────────

    # Maps UniFi vpn_type → (interface_prefix, badge)
    _VPN_TYPE_MAP = {
        'wireguard-server': ('wgsrv', 'WGD SRV'),
        'wireguard-client': ('wgclt', 'WGD CLT'),
        'site-magic-wan':   ('wgsts', 'S MAGIC'),
        'teleport':         ('tlprt', 'TELEPORT'),
        'ipsec-vpn':        ('vti',   'S2S IPSEC'),
        'openvpn-server':   ('tun',   'OVPN SRV'),
        'openvpn-client':   ('tunovpnc', 'OVPN CLT'),
        'l2tp-server':      ('l2tp',  'L2TP SRV'),
    }

    def get_vpn_networks(self) -> list:
        """Fetch VPN network configs from Classic API (/rest/networkconf).

        Returns list of dicts with normalised fields:
            interface, name, badge, cidr, vpn_type, enabled
        """
        if not self.enabled:
            return []

        try:
            data = self._get('rest/networkconf')
            networks = data.get('data', [])
        except Exception as e:
            logger.warning("Failed to fetch VPN networkconf: %s", e)
            return []

        results = []
        for net in networks:
            vpn_type = net.get('vpn_type', '')
            if not vpn_type:
                continue

            mapping = self._VPN_TYPE_MAP.get(vpn_type)
            if not mapping:
                logger.debug("Unknown vpn_type %r, skipping", vpn_type)
                continue

            prefix, badge = mapping

            # Derive interface name from prefix + numeric id
            iface = None
            if prefix:
                wg_id = net.get('wireguard_id')
                if wg_id is not None:
                    iface = f'{prefix}{wg_id}'
                elif vpn_type in ('openvpn-server', 'openvpn-client'):
                    # OpenVPN records lack wireguard_id; use tunnel_id,
                    # x_openvpn_tunnel_id, or fall back to index 0
                    ovpn_id = net.get('tunnel_id')
                    if ovpn_id is None:
                        ovpn_id = net.get('x_openvpn_tunnel_id')
                    iface = f'{prefix}{ovpn_id}' if ovpn_id is not None else f'{prefix}0'
                else:
                    iface = f'{prefix}0'

            # Extract network CIDR from ip_subnet (e.g. "10.10.70.1/29")
            cidr = net.get('ip_subnet', '')

            results.append({
                'interface': iface,
                'name': (net.get('name') or '').strip(),
                'badge': badge,
                'cidr': cidr,
                'vpn_type': vpn_type,
                'enabled': net.get('enabled', True),
            })

        return results

    def _get_poll_status(self) -> dict:
        """Return poll status, preferring in-memory state (receiver process)
        but falling back to DB-persisted state (API process)."""
        if self._last_poll is not None:
            # Receiver process — has live state. Acquire lock for consistent snapshot
            # since poll() writes these attributes under the same lock.
            with self._lock:
                return {
                    'connected': self._last_poll_error is None,
                    'last_poll': self._last_poll.isoformat(),
                    'last_error': self._last_poll_error,
                    'client_count': self._client_count,
                    'device_count': self._device_count,
                    'polling_paused': False,
                }
        # API process — read from DB (written by receiver)
        db_status = self._db.get_config('unifi_poll_status', None)
        if db_status and isinstance(db_status, dict):
            # Shallow copy to avoid mutating the value returned by get_config.
            result = dict(db_status)
            result['polling_paused'] = False
            return result
        # No poll data yet
        return {
            'connected': False,
            'last_poll': None,
            'last_error': None,
            'client_count': 0,
            'device_count': 0,
            'polling_paused': False,
        }

    def get_settings_info(self) -> dict:
        """Return current config with source indicators for Settings UI."""
        return {
            'enabled': self.enabled,
            'host': self.host,
            'host_source': self.get_config_source('host'),
            'api_key_set': bool(self.api_key),
            'api_key_source': self.get_config_source('api_key'),
            'site': self.site,
            'verify_ssl': self.verify_ssl,
            'poll_interval': int(os.environ.get('UNIFI_POLL_INTERVAL', 0) or
                                 self._db.get_config('unifi_poll_interval', 300)),
            'features': self.features,
            'controller_name': self._db.get_config('unifi_controller_name', ''),
            'controller_version': self._db.get_config('unifi_controller_version', ''),
            'controller_type': self._controller_type,
            'supports_firewall': self._controller_type != 'self_hosted',
            'auth_mode': 'cookie' if self._controller_type == 'self_hosted' else 'api_key',
            'username_set': bool(self._username),
            'status': self._get_poll_status(),
        }

    # ── Phase 1: Firewall Management ─────────────────────────────────────────

    def get_firewall_zones(self) -> list:
        """Fetch all firewall zones."""
        data = self._get_integration_site('/firewall/zones')
        return data.get('data', [])

    def get_firewall_policies(self) -> list:
        """Fetch ALL firewall policies (handles pagination internally)."""
        all_policies = []
        offset = 0
        limit = 50
        while True:
            data = self._get_integration_site(
                f'/firewall/policies?offset={offset}&limit={limit}'
            )
            page = data.get('data', [])
            all_policies.extend(page)
            total_count = data.get('totalCount', 0)
            if offset + len(page) >= total_count:
                break
            offset += len(page)
        return all_policies

    def get_firewall_data(self) -> dict:
        """Fetch policies + zones in one call for the frontend."""
        policies = self.get_firewall_policies()
        zones = self.get_firewall_zones()

        logging_enabled = sum(1 for p in policies if p.get('loggingEnabled'))
        logging_disabled = len(policies) - logging_enabled

        return {
            'policies': policies,
            'zones': zones,
            'totalCount': len(policies),
            'loggingEnabled': logging_enabled,
            'loggingDisabled': logging_disabled,
        }

    def patch_firewall_policy(self, policy_id: str, logging_enabled: bool) -> dict:
        """Update loggingEnabled on a single policy."""
        return self._patch_integration_site(
            f'/firewall/policies/{policy_id}',
            {'loggingEnabled': logging_enabled}
        )

    def _patch_one_policy(self, policy_id: str, logging_val: bool) -> dict:
        """Patch a single policy with retry. Returns result dict (thread-safe)."""
        max_retries = 3
        retried = 0
        for attempt in range(max_retries):
            try:
                self.patch_firewall_policy(policy_id, logging_val)
                return {'status': 'success', 'retried': retried}
            except requests.HTTPError as e:
                status = e.response.status_code if e.response is not None else 0
                if status in (429, 502, 503, 504) and attempt < max_retries - 1:
                    delay = 0.5 * (2 ** attempt)
                    logger.warning("Bulk patch: policy %s got HTTP %d, retrying in %.1fs (attempt %d/%d)",
                                   policy_id, status, delay, attempt + 1, max_retries)
                    time.sleep(delay)
                    retried += 1
                    continue
                err_text = e.response.text[:200] if e.response is not None else str(e)
                logger.warning("Bulk patch: policy %s failed (HTTP %d): %.200s", policy_id, status, err_text)
                return {'status': 'failed', 'id': policy_id, 'error': f'HTTP {status}: {err_text}', 'retried': retried}
            except Exception as e:
                logger.warning("Bulk patch: policy %s failed: %s", policy_id, e)
                return {'status': 'failed', 'id': policy_id, 'error': str(e), 'retried': retried}
        return {'status': 'failed', 'id': policy_id, 'error': 'max retries exceeded', 'retried': retried}  # defensive fallback

    def bulk_patch_logging(self, updates: list[dict], progress_callback=None) -> dict:
        """Batch-update loggingEnabled for multiple policies.

        updates: [{"id": "uuid", "loggingEnabled": bool}, ...]
        progress_callback: optional callable(completed, total, success, failed)
            called after each policy finishes patching.
        Returns summary: {total, success, failed, skipped, retried, errors}

        Uses 4 concurrent workers with retry + exponential backoff.
        After patching, verifies actual state matches requested state.
        """
        total = len(updates)
        success = 0
        failed = 0
        skipped = 0
        retried = 0
        errors = []

        # Filter out items with no loggingEnabled value
        work_items = []
        for item in updates:
            if item.get('loggingEnabled') is None:
                skipped += 1
            else:
                work_items.append(item)

        work_total = len(work_items)

        # Ensure session is initialized before spawning threads (avoids lazy-init race)
        self._get_session()

        # Patch concurrently (4 workers keeps controller happy)
        successful_ids = set()
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {
                pool.submit(self._patch_one_policy, item['id'], item['loggingEnabled']): item
                for item in work_items
            }
            for future in as_completed(futures):
                result = future.result()
                item = futures[future]
                retried += result.get('retried', 0)
                if result['status'] == 'success':
                    success += 1
                    successful_ids.add(item['id'])
                else:
                    failed += 1
                    errors.append({'id': result['id'], 'error': result['error']})
                if progress_callback:
                    try:
                        progress_callback(success + failed, work_total, success, failed, phase='patching')
                    except Exception:
                        logger.debug("progress_callback failed during patching", exc_info=True)

        # Verification pass: only verify policies that succeeded during patching
        mismatched = []
        if successful_ids:
            if progress_callback:
                try:
                    progress_callback(work_total, work_total, success, failed, phase='verifying')
                except Exception:
                    logger.debug("progress_callback failed during verification", exc_info=True)
            try:
                actual_policies = self.get_firewall_policies()
                actual_map = {p['id']: p.get('loggingEnabled', False) for p in actual_policies}
                for item in work_items:
                    pid = item['id']
                    if pid in successful_ids and actual_map.get(pid) != item['loggingEnabled']:
                        mismatched.append(pid)
                if mismatched:
                    logger.warning("Bulk patch: %d/%d policies did not reflect requested state after patching",
                                   len(mismatched), success)
                    failed += len(mismatched)
                    success = max(0, success - len(mismatched))
                    errors.append({
                        'verification': f'{len(mismatched)} policies did not reflect the requested state',
                        'ids': mismatched[:20],
                    })
            except Exception as e:
                logger.warning("Bulk patch: verification failed: %s", e)
                errors.append({'verification': f'Could not verify: {e}'})

        logger.info("Bulk patch complete: %d total, %d success, %d failed, %d skipped, %d retried, %d mismatched",
                     total, success, failed, skipped, retried, len(mismatched))

        return {
            'total': total,
            'success': success,
            'failed': failed,
            'skipped': skipped,
            'retried': retried,
            'errors': errors[:20],
        }

    # ── Phase 2: Client/Device Polling ───────────────────────────────────────

    def poll(self) -> bool:
        """Single poll cycle: fetch clients + devices, rebuild maps, persist.

        Returns True on success, False on error.
        """
        if not self.enabled:
            return False

        try:
            clients = []
            devices = []

            if self.features.get('client_names', True):
                clients = self._poll_clients()
            if self.features.get('device_discovery', True):
                devices = self._poll_devices()

            # Build in-memory maps atomically
            ip_map = {}
            mac_map = {}
            clients_sorted = sorted(clients, key=lambda c: c.get('last_seen') or _EPOCH_MIN)
            for c in clients_sorted:
                name = c.get('device_name') or c.get('hostname') or c.get('oui')
                if name:
                    if c.get('mac'):
                        mac_map[c['mac'].lower()] = name
                    if c.get('ip'):
                        ip_map[c['ip']] = name
            for d in devices:
                name = d.get('device_name') or d.get('model')
                if name:
                    if d.get('mac'):
                        mac_map[d['mac'].lower()] = name
                    if d.get('ip'):
                        ip_map[d['ip']] = name

            # Add WAN IPs → gateway device name before atomic swap
            if self.features.get('network_config', True):
                try:
                    net_config = self.get_network_config()
                    # Find gateway device name from polled devices
                    gateway_name = None
                    for d in devices:
                        if d.get('device_type') in ('ugw', 'udm', 'uxg'):
                            gateway_name = d.get('device_name') or d.get('model')
                            break
                    if gateway_name:
                        wan_ip_names = {}
                        for wan in net_config.get('wan_interfaces', []):
                            wan_ip = wan.get('wan_ip')
                            if wan_ip:
                                ip_map[wan_ip] = gateway_name
                                wan_ip_names[wan_ip] = gateway_name
                        if wan_ip_names:
                            self._db.set_config('wan_ip_names', wan_ip_names)
                    # Update wan_ip_by_iface from network config (keeps WAN IPs
                    # current through PPPoE reconnections, DHCP renewals, failover)
                    wan_interfaces = net_config.get('wan_interfaces', [])
                    wan_ip_by_iface = {
                        w['physical_interface']: w['wan_ip']
                        for w in wan_interfaces if w.get('wan_ip')
                    }
                    if wan_ip_by_iface:
                        self._db.set_config('wan_ip_by_iface', wan_ip_by_iface)
                        # Derive ordered wan_ips from wan_interfaces config
                        cfg_wan_ifaces = self._db.get_config('wan_interfaces') or []
                        wan_ips = [wan_ip_by_iface[iface] for iface in cfg_wan_ifaces
                                   if iface in wan_ip_by_iface]
                        if wan_ips:
                            self._db.set_config('wan_ips', wan_ips)
                            self._db.set_config('wan_ip', wan_ips[0])
                    # Extract gateway IP→VLAN mapping
                    gateway_vlans = {}
                    for net in net_config.get('networks', []):
                        subnet = net.get('ip_subnet', '')
                        if '/' in subnet:
                            gw_ip = subnet.split('/')[0]
                            gateway_vlans[gw_ip] = {
                                'vlan': net.get('vlan'),
                                'name': net.get('name', ''),
                            }
                    if gateway_vlans:
                        self._db.set_config('gateway_ip_vlans', gateway_vlans)
                        self._db.set_config('gateway_ips', list(gateway_vlans.keys()))
                except Exception as e:
                    logger.warning("Failed to extract network config: %s", e)

            # Atomic swap under lock — includes poll timestamp and error state
            # so _get_poll_status() reads a consistent snapshot.
            with self._lock:
                self._ip_to_name = ip_map
                self._mac_to_name = mac_map
                self._client_count = len(clients)
                self._device_count = len(devices)
                self._last_poll = datetime.now(timezone.utc)
                self._last_poll_error = None
                last_poll = self._last_poll

            # Persist to DB (outside lock to avoid holding it during I/O)
            if clients:
                self._db.upsert_unifi_clients(clients)
            if devices:
                self._db.upsert_unifi_devices(devices)

            # Persist poll status so the API process can read it
            try:
                self._db.set_config('unifi_poll_status', {
                    'connected': True,
                    'last_poll': last_poll.isoformat(),
                    'last_error': None,
                    'client_count': len(clients),
                    'device_count': len(devices),
                })
            except Exception as db_err:
                logger.error("Failed to persist poll success status: %s", db_err)
            logger.info("UniFi poll: %d clients, %d devices synced",
                        len(clients), len(devices))
            return True

        except Exception as e:
            # Acquire lock to update error state atomically with counts/timestamps
            # so _get_poll_status() reads a consistent snapshot.
            with self._lock:
                self._last_poll_error = str(e)
                poll_status = {
                    'connected': False,
                    'last_poll': self._last_poll.isoformat() if self._last_poll else None,
                    'last_error': self._last_poll_error,
                    'client_count': self._client_count,
                    'device_count': self._device_count,
                }
            try:
                self._db.set_config('unifi_poll_status', poll_status)
            except Exception as db_err:
                logger.error("Failed to persist poll error status: %s", db_err)
            logger.exception("UniFi poll failed")
            return False

    def _poll_clients(self) -> list[dict]:
        """Fetch active + historical clients, merge into unified list."""
        # Active clients (rich data: ip, network, essid, vlan)
        active_by_mac = {}
        try:
            data = self._get('stat/sta')
            for c in data.get('data', []):
                mac = c.get('mac', '').lower()
                if not mac:
                    continue
                active_by_mac[mac] = {
                    'mac': mac,
                    'ip': c.get('ip') or c.get('last_ip'),
                    'device_name': c.get('name'),
                    'hostname': c.get('hostname'),
                    'oui': c.get('oui'),
                    'network': c.get('network'),
                    'essid': c.get('essid'),
                    'vlan': c.get('vlan'),
                    'is_fixed_ip': c.get('use_fixedip', False),
                    'is_wired': c.get('is_wired'),
                    'last_seen': _parse_epoch(c.get('last_seen')),
                }
        except Exception as e:
            logger.warning("Failed to fetch stat/sta: %s", e)

        # All known clients (historical — reduced fields)
        all_by_mac = {}
        try:
            data = self._get('stat/alluser')
            for c in data.get('data', []):
                mac = c.get('mac', '').lower()
                if not mac:
                    continue
                all_by_mac[mac] = {
                    'mac': mac,
                    'ip': c.get('last_ip'),  # no 'ip' in alluser
                    'device_name': c.get('name'),
                    'hostname': c.get('hostname'),
                    'oui': c.get('oui'),
                    'network': c.get('last_connection_network_name'),
                    'essid': None,  # not available in alluser
                    'vlan': None,
                    'is_fixed_ip': c.get('use_fixedip', False),
                    'is_wired': c.get('is_wired'),
                    'last_seen': _parse_epoch(c.get('last_seen')),
                }
        except Exception as e:
            logger.warning("Failed to fetch stat/alluser: %s", e)

        # Merge: active clients take priority (richer data)
        merged = {**all_by_mac, **active_by_mac}
        return list(merged.values())

    def _poll_devices(self) -> list[dict]:
        """Fetch infrastructure devices (APs, switches, gateways)."""
        try:
            data = self._get('stat/device')
            devices = []
            for d in data.get('data', []):
                mac = d.get('mac', '').lower()
                if not mac:
                    continue
                devices.append({
                    'mac': mac,
                    'ip': d.get('ip'),
                    'device_name': d.get('name'),
                    'model': d.get('model'),
                    'shortname': d.get('shortname'),
                    'device_type': d.get('type'),
                    'firmware': d.get('version'),
                    'serial': d.get('serial'),
                    'state': d.get('state'),
                    'uptime': d.get('uptime'),
                })
            return devices
        except Exception as e:
            logger.warning("Failed to fetch stat/device: %s", e)
            return []

    def stop_polling(self):
        """Stop the background polling thread if running."""
        if self._poll_thread is not None and self._poll_thread.is_alive():
            self._poll_stop.set()
            self._poll_thread.join(timeout=5)
            logger.info("UniFi polling stopped")

    def start_polling(self):
        """Start (or restart) the background polling daemon thread."""
        # Stop existing thread if running
        self.stop_polling()

        if not self.enabled:
            return

        # Clear any stale paused flag (toggle was removed, polling always active)
        self._db.set_config('unifi_polling_paused', False)

        poll_interval = int(os.environ.get('UNIFI_POLL_INTERVAL', 0) or
                            self._db.get_config('unifi_poll_interval', 300))

        # Load cached maps from DB on cold start
        try:
            ip_map, mac_map = self._db.load_device_name_maps()
            # Also load persisted WAN IP → gateway name mappings
            wan_ip_names = self._db.get_config('wan_ip_names', {})
            if wan_ip_names:
                ip_map.update(wan_ip_names)
            with self._lock:
                self._ip_to_name = ip_map
                self._mac_to_name = mac_map
            if ip_map:
                logger.info("Loaded %d cached device names from DB", len(ip_map))
        except Exception as e:
            logger.warning("Failed to load cached device names from DB: %s", e)

        self._poll_stop = threading.Event()

        def _poll_loop():
            # Initial poll immediately
            self.poll()
            while not self._poll_stop.wait(poll_interval):
                self.poll()

        self._poll_thread = threading.Thread(target=_poll_loop, daemon=True,
                                              name='unifi-poller')
        self._poll_thread.start()
        logger.info("UniFi polling started (interval=%ds)", poll_interval)

    def resolve_name(self, ip: str | None = None, mac: str | None = None) -> str | None:
        """Resolve device name by IP or MAC from in-memory cache.

        Returns None if client_names feature is disabled or no match found.
        """
        if not self.features.get('client_names', True):
            return None
        with self._lock:
            if mac:
                name = self._mac_to_name.get(mac.lower())
                if name:
                    return name
            if ip:
                return self._ip_to_name.get(ip)
        return None


def _parse_epoch(epoch) -> datetime | None:
    """Convert UniFi epoch timestamp to datetime, or None."""
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return None
