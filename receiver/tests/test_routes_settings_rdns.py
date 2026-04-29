"""Tests for the dedicated /api/settings/rdns route + /api/config and
/api/settings/ui decoupling regression guards (issue #98).
"""
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


def _clear_route_modules(monkeypatch):
    for mod_name in list(sys.modules):
        if mod_name.startswith('routes'):
            monkeypatch.delitem(sys.modules, mod_name, raising=False)


@pytest.fixture
def client(monkeypatch):
    """TestClient for routes.setup, with an in-memory DB stub.

    Uses the REAL enrichment module (not mocked) so the dedicated route can
    import _resolve_rdns_enabled / _parse_bool_setting / token sets.
    """
    _clear_route_modules(monkeypatch)

    # In-memory system_config store
    store = {}

    def fake_get_config(_db, key, default=None):
        return store.get(key, default)

    def fake_set_config(_db, key, val):
        store[key] = val

    mock_deps = MagicMock()
    mock_deps.APP_VERSION = 'test'
    mock_deps.get_conn = MagicMock()
    mock_deps.put_conn = MagicMock()
    mock_deps.enricher_db = MagicMock()
    mock_deps.unifi_api = MagicMock()
    mock_deps.unifi_api.enabled = False
    mock_deps.signal_receiver = MagicMock()
    mock_deps.ttl_cache = MagicMock(return_value=lambda f: f)
    monkeypatch.setitem(sys.modules, 'deps', mock_deps)

    # Point the real db.get_config / set_config used by enrichment helpers at
    # the in-memory store so /api/settings/rdns and _resolve_rdns_enabled agree.
    import db as real_db
    monkeypatch.setattr(real_db, 'get_config', fake_get_config)
    monkeypatch.setattr(real_db, 'set_config', fake_set_config)

    # routes.setup imports get_config/set_config from db at module-import time.
    # Re-import after the patch so the bound names point at our stubs.
    monkeypatch.delitem(sys.modules, 'routes.setup', raising=False)

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from routes import setup as setup_module

    app = FastAPI()
    app.include_router(setup_module.router)
    return TestClient(app), mock_deps, store


# ── PUT /api/settings/rdns ───────────────────────────────────────────────────

class TestPutRdnsSettings:
    def test_accepts_true(self, client):
        c, deps, store = client
        r = c.put('/api/settings/rdns', json={'rdns_enabled': True})
        assert r.status_code == 200
        assert store['rdns_enabled'] is True

    def test_accepts_false(self, client):
        c, deps, store = client
        r = c.put('/api/settings/rdns', json={'rdns_enabled': False})
        assert r.status_code == 200
        assert store['rdns_enabled'] is False

    def test_accepts_string_yes(self, client):
        c, deps, store = client
        r = c.put('/api/settings/rdns', json={'rdns_enabled': 'yes'})
        assert r.status_code == 200
        assert store['rdns_enabled'] is True

    def test_accepts_string_off(self, client):
        c, deps, store = client
        r = c.put('/api/settings/rdns', json={'rdns_enabled': 'off'})
        assert r.status_code == 200
        assert store['rdns_enabled'] is False

    def test_rejects_invalid_value(self, client):
        c, deps, store = client
        r = c.put('/api/settings/rdns', json={'rdns_enabled': 'maybe'})
        assert r.status_code == 400
        assert 'rdns_enabled' not in store

    def test_rejects_missing_key(self, client):
        c, deps, store = client
        r = c.put('/api/settings/rdns', json={})
        assert r.status_code == 400

    def test_signals_only_on_change(self, client):
        c, deps, store = client
        r = c.put('/api/settings/rdns', json={'rdns_enabled': False})
        assert r.status_code == 200
        deps.signal_receiver.assert_called_once()
        deps.signal_receiver.reset_mock()

        # Same value again — no signal
        r = c.put('/api/settings/rdns', json={'rdns_enabled': False})
        assert r.status_code == 200
        deps.signal_receiver.assert_not_called()


# ── GET /api/settings/rdns ───────────────────────────────────────────────────

class TestGetRdnsSettings:
    def test_default_true(self, client, monkeypatch):
        monkeypatch.delenv('RDNS_ENABLED', raising=False)
        c, deps, store = client
        r = c.get('/api/settings/rdns')
        assert r.status_code == 200
        body = r.json()
        assert body == {'rdns_enabled': True, 'stored_value': None, 'source': 'default'}

    def test_returns_stored_when_no_env(self, client, monkeypatch):
        monkeypatch.delenv('RDNS_ENABLED', raising=False)
        c, deps, store = client
        store['rdns_enabled'] = False
        r = c.get('/api/settings/rdns')
        assert r.json() == {'rdns_enabled': False, 'stored_value': False, 'source': 'system_config'}

    def test_returns_effective_with_env_source(self, client, monkeypatch):
        monkeypatch.setenv('RDNS_ENABLED', 'false')
        c, deps, store = client
        store['rdns_enabled'] = True  # DB says true, env wins
        r = c.get('/api/settings/rdns')
        body = r.json()
        assert body['rdns_enabled'] is False
        assert body['stored_value'] is True
        assert body['source'] == 'env'

    def test_blank_env_reports_non_env_source_default(self, client, monkeypatch):
        monkeypatch.setenv('RDNS_ENABLED', '')
        c, deps, store = client
        r = c.get('/api/settings/rdns')
        body = r.json()
        assert body['source'] == 'default'
        assert body['rdns_enabled'] is True

    def test_blank_env_reports_non_env_source_system_config(self, client, monkeypatch):
        monkeypatch.setenv('RDNS_ENABLED', '')
        c, deps, store = client
        store['rdns_enabled'] = False
        r = c.get('/api/settings/rdns')
        body = r.json()
        assert body['source'] == 'system_config'
        assert body['rdns_enabled'] is False

    def test_unrecognised_env_reports_non_env_source(self, client, monkeypatch, caplog):
        import logging
        monkeypatch.setenv('RDNS_ENABLED', 'fasle')  # typo
        c, deps, store = client
        store['rdns_enabled'] = True
        with caplog.at_level(logging.WARNING, logger='enrichment'):
            r = c.get('/api/settings/rdns')
        body = r.json()
        assert body['source'] == 'system_config'
        assert body['rdns_enabled'] is True
        assert any('not recognised' in rec.message for rec in caplog.records)


# ── /api/settings/ui decoupling regression guard ─────────────────────────────

class TestUiSettingsDecoupling:
    def test_put_ui_does_not_accept_rdns_enabled(self, client):
        c, deps, store = client
        # Send a benign UI change plus an attempt to sneak in rdns_enabled
        r = c.put('/api/settings/ui', json={'ui_theme': 'light', 'rdns_enabled': False})
        assert r.status_code == 200
        # rdns_enabled MUST NOT have been written by the UI route
        assert 'rdns_enabled' not in store

    def test_get_ui_does_not_include_rdns_enabled(self, client):
        c, deps, store = client
        r = c.get('/api/settings/ui')
        assert r.status_code == 200
        assert 'rdns_enabled' not in r.json()


# ── /api/config includes effective rdns_enabled ─────────────────────────────

class TestApiConfigIncludesRdns:
    def test_includes_effective_with_env(self, client, monkeypatch):
        monkeypatch.setenv('RDNS_ENABLED', 'false')
        c, deps, store = client
        store['rdns_enabled'] = True
        r = c.get('/api/config')
        assert r.status_code == 200
        assert r.json()['rdns_enabled'] is False

    def test_default_true(self, client, monkeypatch):
        monkeypatch.delenv('RDNS_ENABLED', raising=False)
        c, deps, store = client
        r = c.get('/api/config')
        assert r.json()['rdns_enabled'] is True


# ── Config import strict bool validation ─────────────────────────────────────

class TestImportConfigRdnsValidation:
    def test_accepts_valid_bool(self, client):
        c, deps, store = client
        r = c.post('/api/config/import', json={'config': {'rdns_enabled': False}})
        assert r.status_code == 200
        body = r.json()
        assert 'rdns_enabled' in body['imported_keys']
        assert store['rdns_enabled'] is False

    def test_accepts_string_token(self, client):
        c, deps, store = client
        r = c.post('/api/config/import', json={'config': {'rdns_enabled': 'false'}})
        assert r.status_code == 200
        # Strict parser writes a real bool, not the raw string
        assert store['rdns_enabled'] is False
        assert isinstance(store['rdns_enabled'], bool)

    @pytest.mark.parametrize('bad_val', ['maybe', None, 2, [], {}])
    def test_rejects_invalid(self, client, bad_val):
        c, deps, store = client
        r = c.post('/api/config/import', json={'config': {'rdns_enabled': bad_val}})
        assert r.status_code == 200
        body = r.json()
        assert 'rdns_enabled' in body.get('failed_keys', [])
        assert 'rdns_enabled' not in store
