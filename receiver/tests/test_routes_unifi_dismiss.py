"""Tests for VPN toast per-interface dismissal.

Covers: dismiss endpoint normalization/merge, prune on VPN save,
prune on wizard complete, and legacy boolean isolation.
"""

import sys
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def client(monkeypatch):
    """TestClient with mocked deps — includes both unifi and setup routers."""
    for mod_name in list(sys.modules):
        if mod_name.startswith('routes'):
            monkeypatch.delitem(sys.modules, mod_name, raising=False)

    mock_deps = MagicMock()
    mock_deps.APP_VERSION = '3.3.0-test'
    mock_deps.enricher_db = MagicMock()
    mock_deps.unifi_api = MagicMock()
    mock_deps.unifi_api.enabled = False
    mock_deps.signal_receiver = MagicMock()
    mock_deps.ttl_cache = MagicMock()
    monkeypatch.setitem(sys.modules, 'deps', mock_deps)

    mock_db = MagicMock()
    # In-memory config store for realistic get/set behavior
    _config_store = {}

    def _get_config(_db, key, default=None):
        return _config_store.get(key, default)

    def _set_config(_db, key, value):
        _config_store[key] = value

    mock_db.get_config = MagicMock(side_effect=_get_config)
    mock_db.set_config = MagicMock(side_effect=_set_config)
    mock_db.count_logs = MagicMock(return_value=0)
    mock_db.encrypt_api_key = MagicMock(return_value='encrypted')
    mock_db.decrypt_api_key = MagicMock(return_value='decrypted')
    mock_db.is_external_db = MagicMock(return_value=False)
    monkeypatch.setitem(sys.modules, 'db', mock_db)

    # Mock modules that setup.py imports at module level
    mock_parsers = MagicMock()
    mock_parsers.VPN_PREFIX_BADGES = {}
    mock_parsers.VPN_INTERFACE_PREFIXES = ()
    mock_parsers.VPN_BADGE_CHOICES = []
    mock_parsers.VPN_BADGE_LABELS = {}
    mock_parsers.VPN_PREFIX_DESCRIPTIONS = {}
    monkeypatch.setitem(sys.modules, 'parsers', mock_parsers)

    monkeypatch.setitem(sys.modules, 'query_helpers', MagicMock())
    monkeypatch.setitem(sys.modules, 'firewall_policy_matcher', MagicMock())
    monkeypatch.setitem(sys.modules, 'unifi_api', MagicMock())

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from routes.unifi import router as unifi_router
    from routes.setup import router as setup_router

    app = FastAPI()
    app.include_router(unifi_router)
    app.include_router(setup_router)
    return TestClient(app), _config_store


class TestDismissVpnToast:
    def test_dismiss_vpn_merges_interfaces(self, client):
        tc, store = client
        resp = tc.post('/api/settings/unifi/dismiss-vpn-toast',
                       json={'interfaces': ['tun0']})
        assert resp.status_code == 200
        assert store['vpn_toast_dismissed'] == ['tun0']

        resp = tc.post('/api/settings/unifi/dismiss-vpn-toast',
                       json={'interfaces': ['wgsrv0']})
        assert resp.status_code == 200
        assert store['vpn_toast_dismissed'] == ['tun0', 'wgsrv0']

    def test_dismiss_vpn_normalizes_input(self, client):
        tc, store = client
        resp = tc.post('/api/settings/unifi/dismiss-vpn-toast',
                       json={'interfaces': ['tun0', '', '  ', 123, None, 'tun0']})
        assert resp.status_code == 200
        assert store['vpn_toast_dismissed'] == ['tun0']

    def test_dismiss_vpn_rejects_non_list(self, client):
        tc, _store = client
        resp = tc.post('/api/settings/unifi/dismiss-vpn-toast',
                       json={'interfaces': 'tun0'})
        assert resp.status_code == 400

    def test_dismiss_vpn_prune_on_save(self, client):
        tc, store = client
        # Pre-populate dismissed list
        store['vpn_toast_dismissed'] = ['tun0', 'tun1']
        # Save VPN config containing tun0 — should prune tun0
        resp = tc.post('/api/config/vpn-networks',
                       json={'vpn_networks': {'tun0': {'cidr': '10.0.0.0/24'}},
                             'vpn_labels': {'tun0': 'My VPN'}})
        assert resp.status_code == 200
        assert store['vpn_toast_dismissed'] == ['tun1']

    def test_dismiss_vpn_prune_on_wizard_complete(self, client):
        tc, store = client
        store['vpn_toast_dismissed'] = ['tun0', 'tun1']
        resp = tc.post('/api/setup/complete',
                       json={'wan_interfaces': ['ppp0'],
                             'vpn_networks': {'tun1': {'cidr': '10.8.0.0/24'}}})
        assert resp.status_code == 200
        # tun1 was configured, so pruned; tun0 remains
        assert store['vpn_toast_dismissed'] == ['tun0']

    def test_legacy_boolean_coerced_to_empty_list(self, client):
        tc, store = client
        # Simulate existing install where vpn_toast_dismissed = True (old boolean)
        store['vpn_toast_dismissed'] = True
        resp = tc.get('/api/config')
        assert resp.status_code == 200
        data = resp.json()
        # Same key, but True is coerced to [] so old global dismiss is dropped
        assert data['vpn_toast_dismissed'] == []
