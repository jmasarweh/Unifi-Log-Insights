"""Tests for routes/abuseipdb.py POST /api/enrich/{ip} bootstrap allowance (Patch 3).

When AbuseIPDB stats show no /check has ever been made (limit=None,
remaining=None) and there is no active 429 pause, the endpoint must allow
the call through so subsequent callers see populated rate-limit state.
Real exhaustion and active pause must still return 429.
"""

import sys
import time
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def enrich_client(monkeypatch):
    """FastAPI TestClient over routes/abuseipdb.py with deps & enrichment mocked.

    Mirrors the test_routes_health.py fixture pattern: replace deps + db +
    enrichment in sys.modules before importing the route module. `from X
    import Y` captures Y at import time, so per-test stat overrides must be
    applied via setattr on the route module itself — not the source module.
    """
    for mod_name in list(sys.modules):
        if mod_name.startswith('routes'):
            monkeypatch.delitem(sys.modules, mod_name, raising=False)

    abuseipdb_mock = MagicMock()
    abuseipdb_mock.enabled = True
    abuseipdb_mock.cache = MagicMock()
    abuseipdb_mock.lookup = MagicMock(return_value={
        'threat_score': 80, 'threat_categories': ['test'],
        'abuse_usage_type': 'isp', 'abuse_hostnames': [],
        'abuse_total_reports': 2, 'abuse_last_reported': None,
        'abuse_is_whitelisted': False, 'abuse_is_tor': False,
    })
    abuseipdb_mock.remaining_budget = 998

    enricher_db_mock = MagicMock()
    conn = MagicMock()
    cursor = MagicMock()
    cursor.rowcount = 0
    conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
    conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    enricher_db_mock.get_conn.return_value.__enter__ = MagicMock(return_value=conn)
    enricher_db_mock.get_conn.return_value.__exit__ = MagicMock(return_value=False)

    mock_deps = MagicMock()
    mock_deps.abuseipdb = abuseipdb_mock
    mock_deps.enricher_db = enricher_db_mock
    monkeypatch.setitem(sys.modules, 'deps', mock_deps)

    mock_db = MagicMock()
    mock_db.get_config = MagicMock(return_value=[])
    mock_db.get_wan_ips_from_config = MagicMock(return_value=[])
    monkeypatch.setitem(sys.modules, 'db', mock_db)

    enrichment_mock = MagicMock()
    enrichment_mock.is_public_ip = MagicMock(return_value=True)
    enrichment_mock.get_abuseipdb_stats = MagicMock(return_value=None)
    monkeypatch.setitem(sys.modules, 'enrichment', enrichment_mock)

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import routes.abuseipdb as route_mod

    # Rebind the from-imported symbols on the route module so per-test
    # setattr(route_mod, 'get_abuseipdb_stats', ...) overrides take effect.
    monkeypatch.setattr(route_mod, 'is_public_ip', lambda ip: True)

    app = FastAPI()
    app.include_router(route_mod.router)
    return TestClient(app), abuseipdb_mock, route_mod, monkeypatch


class TestEnrichIpBootstrap:
    def test_bootstrap_allows_call(self, enrich_client):
        client, abuseipdb_mock, route_mod, monkeypatch = enrich_client
        # Bootstrap shape: limit + remaining both None, no pause.
        monkeypatch.setattr(route_mod, 'get_abuseipdb_stats', MagicMock(return_value={
            'limit': None, 'remaining': None, 'reset_at': None, 'paused_until': None,
        }))

        resp = client.post('/api/enrich/8.8.8.8')

        assert resp.status_code == 200, resp.text
        abuseipdb_mock.lookup.assert_called_once_with('8.8.8.8')

    def test_real_exhaustion_returns_429(self, enrich_client):
        client, abuseipdb_mock, route_mod, monkeypatch = enrich_client
        future = time.time() + 3600
        monkeypatch.setattr(route_mod, 'get_abuseipdb_stats', MagicMock(return_value={
            'limit': 1000, 'remaining': 0, 'reset_at': future, 'paused_until': None,
        }))

        resp = client.post('/api/enrich/8.8.8.8')

        assert resp.status_code == 429
        abuseipdb_mock.lookup.assert_not_called()

    def test_active_pause_returns_429(self, enrich_client):
        client, abuseipdb_mock, route_mod, monkeypatch = enrich_client
        future = time.time() + 600
        # Even with bootstrap-shaped limit/remaining, an active pause must block.
        monkeypatch.setattr(route_mod, 'get_abuseipdb_stats', MagicMock(return_value={
            'limit': None, 'remaining': None, 'reset_at': None, 'paused_until': future,
        }))

        resp = client.post('/api/enrich/8.8.8.8')

        assert resp.status_code == 429
        abuseipdb_mock.lookup.assert_not_called()
