"""Tests for syslog-toggle route contracts: match-log endpoint and cache invalidation hooks.

Covers:
- POST /api/firewall/policies/match-log disabled states
- Cache invalidation on PATCH, setup complete, and VPN save
"""

import sys
from unittest.mock import MagicMock, patch

import pytest


# ── Shared helpers ────────────────────────────────────────────────────────────

def _clear_route_modules(monkeypatch):
    """Remove cached route modules so each test gets a fresh import."""
    for mod_name in list(sys.modules):
        if mod_name.startswith('routes'):
            monkeypatch.delitem(sys.modules, mod_name, raising=False)


def _make_base_mock_deps():
    """Build a mock deps module with attributes common to all route tests."""
    mock_deps = MagicMock()
    mock_deps.APP_VERSION = '3.1.0-test'
    mock_deps.get_conn = MagicMock()
    mock_deps.put_conn = MagicMock()
    mock_deps.enricher_db = MagicMock()
    mock_deps.unifi_api = MagicMock()
    mock_deps.signal_receiver = MagicMock()
    return mock_deps


def _make_base_db_mock():
    """Build a mock db module with attributes common to all route tests."""
    mock_db = MagicMock()
    mock_db.get_config = MagicMock(return_value=None)
    mock_db.set_config = MagicMock()
    mock_db.encrypt_api_key = MagicMock()
    mock_db.decrypt_api_key = MagicMock()
    return mock_db


def _enable_unifi_with_features(mock_deps, firewall_management=True):
    """Set unifi_api.enabled and wire up features.get() on mock_deps."""
    mock_deps.unifi_api.enabled = True
    features_mock = MagicMock()
    features_mock.get = MagicMock(return_value=firewall_management)
    mock_deps.unifi_api.features = features_mock


class _UniFiPermissionError(Exception):
    """Mock replacement for unifi_api.UniFiPermissionError."""
    def __init__(self, msg='', status_code=403):
        super().__init__(msg)
        self.status_code = status_code


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def unifi_client(monkeypatch):
    """Create a FastAPI TestClient with mocked deps for routes/unifi.py."""
    _clear_route_modules(monkeypatch)

    mock_deps = _make_base_mock_deps()
    mock_deps.abuseipdb = MagicMock()
    monkeypatch.setitem(sys.modules, 'deps', mock_deps)

    mock_db_module = _make_base_db_mock()
    monkeypatch.setitem(sys.modules, 'db', mock_db_module)

    mock_uapi_module = MagicMock()
    mock_uapi_module.UniFiPermissionError = _UniFiPermissionError
    monkeypatch.setitem(sys.modules, 'unifi_api', mock_uapi_module)

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from routes.unifi import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app), mock_deps


@pytest.fixture
def setup_client(monkeypatch):
    """Create a FastAPI TestClient with mocked deps for routes/setup.py."""
    _clear_route_modules(monkeypatch)

    mock_deps = _make_base_mock_deps()
    # ttl_cache must work as a real passthrough decorator
    mock_deps.ttl_cache = lambda **kw: (lambda fn: fn)
    monkeypatch.setitem(sys.modules, 'deps', mock_deps)

    mock_db_module = _make_base_db_mock()
    mock_db_module.count_logs = MagicMock(return_value=100)
    mock_db_module.is_external_db = MagicMock(return_value=False)
    monkeypatch.setitem(sys.modules, 'db', mock_db_module)

    mock_parsers = MagicMock()
    mock_parsers.VPN_PREFIX_BADGES = {}
    mock_parsers.VPN_INTERFACE_PREFIXES = []
    mock_parsers.VPN_BADGE_CHOICES = {}
    mock_parsers.VPN_BADGE_LABELS = {}
    mock_parsers.VPN_PREFIX_DESCRIPTIONS = {}
    monkeypatch.setitem(sys.modules, 'parsers', mock_parsers)

    mock_qh = MagicMock()
    mock_qh.validate_view_filters = MagicMock()
    monkeypatch.setitem(sys.modules, 'query_helpers', mock_qh)

    # setup.py now imports UniFiAPI for the extractor
    mock_uapi_module = MagicMock()
    from unifi_api import UniFiAPI as _RealUniFiAPI
    mock_uapi_module.UniFiAPI = _RealUniFiAPI
    monkeypatch.setitem(sys.modules, 'unifi_api', mock_uapi_module)

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from routes.setup import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app), mock_deps, mock_db_module


# ── POST /api/firewall/policies/match-log ────────────────────────────────────

class TestMatchLogDisabled:
    def test_disabled_when_unifi_off(self, unifi_client):
        client, mock_deps = unifi_client
        mock_deps.unifi_api.enabled = False
        resp = client.post('/api/firewall/policies/match-log', json={
            'interface_in': 'br0', 'interface_out': 'eth3',
            'rule_name': 'LAN_WAN-D-100',
        })
        assert resp.status_code == 200
        assert resp.json() == {'status': 'disabled'}

    def test_disabled_when_firewall_management_off(self, unifi_client):
        client, mock_deps = unifi_client
        _enable_unifi_with_features(mock_deps, firewall_management=False)
        resp = client.post('/api/firewall/policies/match-log', json={
            'interface_in': 'br0', 'interface_out': 'eth3',
            'rule_name': 'LAN_WAN-D-100',
        })
        assert resp.status_code == 200
        assert resp.json() == {'status': 'disabled'}


# ── Permission error handling ─────────────────────────────────────────────────

class TestPermissionError:
    def test_patch_policy_returns_403_on_permission_error(self, unifi_client):
        client, mock_deps = unifi_client
        _enable_unifi_with_features(mock_deps)
        mock_deps.unifi_api.patch_firewall_policy.side_effect = \
            _UniFiPermissionError('Insufficient permissions', status_code=403)

        resp = client.patch('/api/firewall/policies/p1', json={
            'loggingEnabled': True, 'origin': 'USER_DEFINED',
        })
        assert resp.status_code == 403
        assert 'Insufficient permissions' in resp.json()['detail']


# ── Cache invalidation hooks ─────────────────────────────────────────────────

class TestCacheInvalidation:
    def test_patch_policy_invalidates_cache(self, unifi_client):
        client, mock_deps = unifi_client
        _enable_unifi_with_features(mock_deps)
        mock_deps.unifi_api.patch_firewall_policy.return_value = {'id': 'p1'}

        with patch('routes.unifi.invalidate_fw_cache') as mock_inv:
            resp = client.patch('/api/firewall/policies/p1', json={
                'loggingEnabled': True, 'origin': 'USER_DEFINED',
            })
            assert resp.status_code == 200
            mock_inv.assert_called_once()

    def test_setup_complete_invalidates_cache(self, setup_client):
        client, mock_deps, mock_db = setup_client
        mock_deps.unifi_api.reload_config = MagicMock()
        # get_config is called for wan_interfaces — must return a list
        mock_db.get_config.return_value = ['ppp0']

        with patch('routes.setup.invalidate_fw_cache') as mock_inv:
            resp = client.post('/api/setup/complete', json={
                'wan_interfaces': ['eth3'],
                'interface_labels': {},
            })
            assert resp.status_code == 200
            mock_inv.assert_called_once()

    def test_vpn_save_invalidates_cache(self, setup_client):
        client, mock_deps, mock_db = setup_client

        with patch('routes.setup.invalidate_fw_cache') as mock_inv:
            resp = client.post('/api/config/vpn-networks', json={
                'vpn_networks': {'wg0': {'badge': 'WireGuard', 'cidr': '10.0.0.0/24'}},
            })
            assert resp.status_code == 200
            mock_inv.assert_called_once()


class TestImportCacheInvalidation:
    """Cache invalidation triggered by /api/config/import for firewall-relevant keys."""

    def test_import_wan_interfaces_invalidates_cache(self, setup_client):
        client, mock_deps, mock_db = setup_client
        with patch('routes.setup.invalidate_fw_cache') as mock_inv:
            resp = client.post('/api/config/import', json={
                'config': {'wan_interfaces': ['eth3']},
            })
            assert resp.status_code == 200
            assert 'wan_interfaces' in resp.json()['imported_keys']
            mock_inv.assert_called_once()

    def test_import_interface_labels_invalidates_cache(self, setup_client):
        client, mock_deps, mock_db = setup_client
        with patch('routes.setup.invalidate_fw_cache') as mock_inv:
            resp = client.post('/api/config/import', json={
                'config': {'interface_labels': {'eth0': 'WAN'}},
            })
            assert resp.status_code == 200
            assert 'interface_labels' in resp.json()['imported_keys']
            mock_inv.assert_called_once()

    def test_import_vpn_networks_invalidates_cache(self, setup_client):
        client, mock_deps, mock_db = setup_client
        with patch('routes.setup.invalidate_fw_cache') as mock_inv:
            resp = client.post('/api/config/import', json={
                'config': {'vpn_networks': {'wg0': {'badge': 'WireGuard'}}},
            })
            assert resp.status_code == 200
            assert 'vpn_networks' in resp.json()['imported_keys']
            mock_inv.assert_called_once()

    def test_import_unifi_settings_invalidates_cache(self, setup_client):
        client, mock_deps, mock_db = setup_client
        with patch('routes.setup.invalidate_fw_cache') as mock_inv:
            resp = client.post('/api/config/import', json={
                'config': {'unifi_host': '192.168.1.1', 'unifi_enabled': True},
            })
            assert resp.status_code == 200
            mock_inv.assert_called_once()

    def test_import_unifi_api_key_invalidates_cache(self, setup_client):
        client, mock_deps, mock_db = setup_client
        mock_db.encrypt_api_key.return_value = 'encrypted_value'
        with patch('routes.setup.invalidate_fw_cache') as mock_inv:
            resp = client.post('/api/config/import', json={
                'config': {'unifi_api_key': 'my-secret-key'},
            })
            assert resp.status_code == 200
            assert 'unifi_api_key' in resp.json()['imported_keys']
            mock_inv.assert_called_once()

    def test_import_unrelated_config_does_not_invalidate_cache(self, setup_client):
        client, mock_deps, mock_db = setup_client
        with patch('routes.setup.invalidate_fw_cache') as mock_inv:
            resp = client.post('/api/config/import', json={
                'config': {'retention_days': 30, 'dns_retention_days': 7},
            })
            assert resp.status_code == 200
            assert 'retention_days' in resp.json()['imported_keys']
            mock_inv.assert_not_called()

    def test_import_invalid_keys_do_not_trigger_invalidation(self, setup_client):
        """Keys that fail validation should not trigger cache invalidation."""
        client, mock_deps, mock_db = setup_client
        with patch('routes.setup.invalidate_fw_cache') as mock_inv:
            resp = client.post('/api/config/import', json={
                'config': {'wan_interfaces': 'not-a-list'},  # invalid type
            })
            assert resp.status_code == 200
            assert 'wan_interfaces' in resp.json()['failed_keys']
            mock_inv.assert_not_called()


# ── Setup identity seeding ─────────────────────────────────────────────────

class TestSetupIdentitySeeding:
    def test_unifi_path_seeds_identity(self, setup_client):
        """UniFi-path setup seeds WAN/gateway identity via shared helper."""
        client, mock_deps, mock_db = setup_client
        mock_deps.unifi_api.reload_config = MagicMock()
        mock_deps.unifi_api.get_network_config.return_value = {
            'wan_interfaces': [
                {'physical_interface': 'eth0', 'wan_ip': '1.2.3.4'},
            ],
            'networks': [
                {'ip_subnet': '10.0.0.1/24', 'vlan': 1, 'name': 'LAN'},
            ],
        }
        mock_db.get_config.return_value = ['ppp0']

        with patch('routes.setup.invalidate_fw_cache'):
            resp = client.post('/api/setup/complete', json={
                'wan_interfaces': ['eth0'],
                'wizard_path': 'unifi_api',
            })

        assert resp.status_code == 200
        mock_deps.enricher_db.persist_network_identity.assert_called_once()

    def test_log_detection_branch_still_works(self, setup_client):
        """Log-detection branch persists via inline set_config, not shared helper."""
        client, mock_deps, mock_db = setup_client
        mock_db.get_config.return_value = ['ppp0']
        mock_deps.enricher_db.get_wan_ips_by_interface.return_value = {'ppp0': '9.9.9.9'}

        with patch('routes.setup.invalidate_fw_cache'):
            resp = client.post('/api/setup/complete', json={
                'wan_interfaces': ['ppp0'],
                'wizard_path': 'log_detection',
            })

        assert resp.status_code == 200
        mock_deps.enricher_db.get_wan_ips_by_interface.assert_called_once()
        # Shared helper NOT called — log path uses inline persistence
        mock_deps.enricher_db.persist_network_identity.assert_not_called()

    def test_partial_wan_does_not_hard_fail(self, setup_client):
        """UniFi setup succeeds even when get_network_config raises."""
        client, mock_deps, mock_db = setup_client
        mock_deps.unifi_api.reload_config = MagicMock()
        mock_deps.unifi_api.get_network_config.side_effect = Exception("API down")
        mock_db.get_config.return_value = ['ppp0']

        with patch('routes.setup.invalidate_fw_cache'):
            resp = client.post('/api/setup/complete', json={
                'wan_interfaces': ['eth0'],
                'wizard_path': 'unifi_api',
            })

        assert resp.status_code == 200
        assert resp.json()['success'] is True


# ── /api/interfaces mode split ─────────────────────────────────────────────

class TestInterfacesModeSplit:
    def test_unifi_enabled_does_not_run_log_scan(self, setup_client):
        """When unifi_enabled is true, /api/interfaces must not hit the DB."""
        client, mock_deps, mock_db = setup_client
        # Simulate unifi_enabled=True in persisted config
        mock_db.get_config.side_effect = lambda db, key, default=None: {
            'interface_labels': {},
            'wan_interfaces': ['eth0'],
            'vpn_networks': {},
            'unifi_enabled': True,
        }.get(key, default)
        mock_deps.unifi_api.get_network_config.return_value = {
            'wan_interfaces': [{'physical_interface': 'eth0'}],
            'networks': [{'interface': 'br0'}],
        }
        mock_deps.unifi_api.get_vpn_networks.return_value = []

        resp = client.get('/api/interfaces')

        assert resp.status_code == 200
        # The DB log scan (get_conn) must NOT have been called
        mock_deps.get_conn.assert_not_called()

    def test_unifi_disabled_runs_log_scan(self, setup_client):
        """When unifi_enabled is false, /api/interfaces runs the log scan."""
        client, mock_deps, mock_db = setup_client
        mock_db.get_config.side_effect = lambda db, key, default=None: {
            'interface_labels': {},
            'wan_interfaces': ['ppp0'],
            'vpn_networks': {},
            'unifi_enabled': False,
        }.get(key, default)

        # Mock the DB connection for log scan
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [('ppp0',), ('br0',)]
        mock_cursor.__enter__ = lambda s: s
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value = mock_cursor
        mock_deps.get_conn.return_value = mock_conn

        resp = client.get('/api/interfaces')

        assert resp.status_code == 200
        mock_deps.get_conn.assert_called_once()

    def test_degraded_credentials_still_uses_unifi_path(self, setup_client):
        """When unifi_enabled=true but unifi_api.enabled=false (broken creds),
        the route must NOT fall back to the log scan."""
        client, mock_deps, mock_db = setup_client
        mock_db.get_config.side_effect = lambda db, key, default=None: {
            'interface_labels': {'eth0': 'WAN'},
            'wan_interfaces': ['eth0'],
            'vpn_networks': {},
            'unifi_enabled': True,
        }.get(key, default)
        # Simulate broken credentials — unifi_api.enabled is false
        mock_deps.unifi_api.enabled = False
        mock_deps.unifi_api.get_network_config.return_value = {
            'wan_interfaces': [], 'networks': [],
        }
        mock_deps.unifi_api.get_vpn_networks.return_value = []

        resp = client.get('/api/interfaces')

        assert resp.status_code == 200
        # Must NOT fall back to log scan even with broken creds
        mock_deps.get_conn.assert_not_called()
        # Config-only interfaces should still appear
        ifaces = [i['name'] for i in resp.json()['interfaces']]
        assert 'eth0' in ifaces
