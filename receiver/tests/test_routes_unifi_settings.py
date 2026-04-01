"""Tests for UniFi settings/test endpoint identity seeding.

Covers:
- POST /api/settings/unifi/test seeds identity on success
- Partial/missing identity still returns success
- No log fallback is triggered
"""

import sys
from unittest.mock import MagicMock, patch, call

import pytest


# ── Shared helpers (same pattern as test_routes_unifi_match.py) ─────────────

def _clear_route_modules(monkeypatch):
    for mod_name in list(sys.modules):
        if mod_name.startswith('routes'):
            monkeypatch.delitem(sys.modules, mod_name, raising=False)


def _make_base_mock_deps():
    mock_deps = MagicMock()
    mock_deps.APP_VERSION = '3.1.0-test'
    mock_deps.get_conn = MagicMock()
    mock_deps.put_conn = MagicMock()
    mock_deps.enricher_db = MagicMock()
    mock_deps.unifi_api = MagicMock()
    mock_deps.signal_receiver = MagicMock()
    return mock_deps


def _make_base_db_mock():
    mock_db = MagicMock()
    mock_db.get_config = MagicMock(return_value=None)
    mock_db.set_config = MagicMock()
    mock_db.encrypt_api_key = MagicMock(return_value='encrypted')
    mock_db.decrypt_api_key = MagicMock(return_value='decrypted')
    return mock_db


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def unifi_test_client(monkeypatch):
    """TestClient for routes/unifi.py with identity seeding testable."""
    _clear_route_modules(monkeypatch)

    mock_deps = _make_base_mock_deps()
    mock_deps.abuseipdb = MagicMock()
    monkeypatch.setitem(sys.modules, 'deps', mock_deps)

    mock_db_module = _make_base_db_mock()
    monkeypatch.setitem(sys.modules, 'db', mock_db_module)

    # Mock unifi_api module — provide the real static extractor
    mock_uapi_module = MagicMock()

    class _MockUniFiPermissionError(Exception):
        def __init__(self, msg='', status_code=403):
            super().__init__(msg)
            self.status_code = status_code

    mock_uapi_module.UniFiPermissionError = _MockUniFiPermissionError

    # Provide the real extractor as a static method
    from unifi_api import UniFiAPI as _RealUniFiAPI
    mock_uapi_module.UniFiAPI = _RealUniFiAPI
    monkeypatch.setitem(sys.modules, 'unifi_api', mock_uapi_module)

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from routes.unifi import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app), mock_deps


# ── Tests ───────────────────────────────────────────────────────────────────

class TestUniFiTestSeedsIdentity:
    """POST /api/settings/unifi/test identity seeding."""

    def test_successful_test_seeds_identity(self, unifi_test_client):
        client, mock_deps = unifi_test_client

        mock_deps.unifi_api.test_connection.return_value = {
            'success': True, 'controller_name': 'UDM-Pro', 'version': '8.0',
        }
        mock_deps.unifi_api.get_network_config.return_value = {
            'wan_interfaces': [
                {'physical_interface': 'eth0', 'wan_ip': '1.2.3.4'},
            ],
            'networks': [
                {'ip_subnet': '192.168.1.1/24', 'vlan': 1, 'name': 'LAN'},
            ],
        }

        resp = client.post('/api/settings/unifi/test', json={
            'host': 'https://192.168.1.1',
            'site': 'default',
            'verify_ssl': False,
            'controller_type': 'unifi_os',
            'api_key': 'test-key',
        })

        assert resp.status_code == 200
        assert resp.json()['success'] is True
        # Identity was persisted
        mock_deps.enricher_db.persist_network_identity.assert_called_once()
        kw = mock_deps.enricher_db.persist_network_identity.call_args.kwargs
        assert kw['wan_ip_by_iface'] == {'eth0': '1.2.3.4'}
        assert '192.168.1.1' in kw['gateway_ip_vlans']

    def test_partial_identity_still_succeeds(self, unifi_test_client):
        """Test succeeds even when get_network_config raises."""
        client, mock_deps = unifi_test_client

        mock_deps.unifi_api.test_connection.return_value = {
            'success': True, 'controller_name': 'UDM-Pro', 'version': '8.0',
        }
        mock_deps.unifi_api.get_network_config.side_effect = Exception("API down")

        resp = client.post('/api/settings/unifi/test', json={
            'host': 'https://192.168.1.1',
            'site': 'default',
            'verify_ssl': False,
            'controller_type': 'unifi_os',
            'api_key': 'test-key',
        })

        assert resp.status_code == 200
        assert resp.json()['success'] is True
        # persist was not called because extraction failed
        mock_deps.enricher_db.persist_network_identity.assert_not_called()

    def test_signal_receiver_fires_on_success(self, unifi_test_client):
        client, mock_deps = unifi_test_client

        mock_deps.unifi_api.test_connection.return_value = {
            'success': True, 'controller_name': 'UDM-Pro', 'version': '8.0',
        }
        mock_deps.unifi_api.get_network_config.return_value = {
            'wan_interfaces': [], 'networks': [],
        }

        resp = client.post('/api/settings/unifi/test', json={
            'host': 'https://192.168.1.1',
            'site': 'default',
            'verify_ssl': False,
            'controller_type': 'unifi_os',
            'api_key': 'test-key',
        })

        assert resp.status_code == 200
        mock_deps.signal_receiver.assert_called_once()

    def test_self_hosted_test_also_seeds_identity(self, unifi_test_client):
        client, mock_deps = unifi_test_client

        mock_deps.unifi_api.test_connection.return_value = {
            'success': True, 'controller_name': 'Controller', 'version': '7.5',
        }
        mock_deps.unifi_api.get_network_config.return_value = {
            'wan_interfaces': [
                {'physical_interface': 'ppp0', 'wan_ip': '5.5.5.5'},
            ],
            'networks': [],
        }

        resp = client.post('/api/settings/unifi/test', json={
            'host': 'https://10.0.0.1:8443',
            'site': 'default',
            'verify_ssl': False,
            'controller_type': 'self_hosted',
            'username': 'admin',
            'password': 'secret',
        })

        assert resp.status_code == 200
        assert resp.json()['success'] is True
        mock_deps.enricher_db.persist_network_identity.assert_called_once()
        kw = mock_deps.enricher_db.persist_network_identity.call_args.kwargs
        assert kw['wan_ip_by_iface'] == {'ppp0': '5.5.5.5'}
