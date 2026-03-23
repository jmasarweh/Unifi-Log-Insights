"""Tests for routes/stats.py — /api/stats/overview, /api/stats/charts, /api/stats/tables.

Critical: deps.py creates DB connections at import time.
We must mock the deps module BEFORE importing api.py.
"""

import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def client(monkeypatch):
    """Create a FastAPI TestClient with mocked deps module."""
    for mod_name in list(sys.modules):
        if mod_name.startswith('routes'):
            monkeypatch.delitem(sys.modules, mod_name, raising=False)

    mock_deps = MagicMock()
    mock_deps.get_conn = MagicMock()
    mock_deps.put_conn = MagicMock()
    mock_deps.enricher_db = MagicMock()

    monkeypatch.setitem(sys.modules, 'deps', mock_deps)

    mock_db_module = MagicMock()
    mock_db_module.get_config = MagicMock(return_value=None)
    mock_db_module.get_wan_ips_from_config = MagicMock(return_value=[])
    monkeypatch.setitem(sys.modules, 'db', mock_db_module)

    mock_ip_identity = MagicMock()
    mock_ip_identity.load_identity_config = MagicMock(return_value={})
    mock_ip_identity.annotate_ip = MagicMock(return_value=(None, None, None))
    mock_ip_identity.annotate_record = MagicMock()
    monkeypatch.setitem(sys.modules, 'ip_identity', mock_ip_identity)

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from routes.stats import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app), mock_deps, mock_db_module


def _mock_cursor_results(mock_deps, results_sequence):
    """Set up a mock connection/cursor that returns results_sequence in order.

    Each entry in results_sequence is either:
    - a dict (fetchone) → returned via fetchone()
    - a list of dicts (fetchall) → returned via fetchall()
    """
    mock_conn = MagicMock()
    mock_cursor = MagicMock()

    call_iter = iter(results_sequence)

    def fetchone_side_effect():
        try:
            val = next(call_iter)
        except StopIteration:
            raise AssertionError("_mock_cursor_results: iterator exhausted — not enough results provided")
        if not isinstance(val, dict):
            raise AssertionError(f"_mock_cursor_results: fetchone() expected dict, got {type(val).__name__}")
        return val

    def fetchall_side_effect():
        try:
            val = next(call_iter)
        except StopIteration:
            raise AssertionError("_mock_cursor_results: iterator exhausted — not enough results provided")
        if not isinstance(val, list):
            raise AssertionError(f"_mock_cursor_results: fetchall() expected list, got {type(val).__name__}")
        return val

    mock_cursor.fetchone = MagicMock(side_effect=fetchone_side_effect)
    mock_cursor.fetchall = MagicMock(side_effect=fetchall_side_effect)
    mock_cursor.execute = MagicMock()

    mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    mock_deps.get_conn.return_value = mock_conn
    return mock_conn, mock_cursor


class TestStatsOverview:
    def test_overview_returns_expected_keys(self, client):
        test_client, mock_deps, _ = client

        # overview runs: 1) scalar counts (fetchone), 2) by_direction (fetchall), 3) by_type (fetchall)
        _mock_cursor_results(mock_deps, [
            {'total': 1000, 'allowed': 500, 'blocked': 300, 'threats': 10},  # fetchone
            [{'direction': 'inbound', 'count': 600}, {'direction': 'outbound', 'count': 400}],  # fetchall
            [{'log_type': 'firewall', 'count': 800}, {'log_type': 'dns', 'count': 200}],  # fetchall
        ])

        resp = test_client.get('/api/stats/overview?time_range=24h')
        assert resp.status_code == 200
        data = resp.json()
        assert data['total'] == 1000
        assert data['allowed'] == 500
        assert data['blocked'] == 300
        assert data['threats'] == 10
        assert data['by_direction'] == {'inbound': 600, 'outbound': 400}
        assert data['by_type'] == {'firewall': 800, 'dns': 200}
        assert data['time_range'] == '24h'

    def test_overview_default_time_range(self, client):
        test_client, mock_deps, _ = client
        _mock_cursor_results(mock_deps, [
            {'total': 0, 'allowed': 0, 'blocked': 0, 'threats': 0},
            [],
            [],
        ])

        resp = test_client.get('/api/stats/overview')
        assert resp.status_code == 200
        assert resp.json()['time_range'] == '24h'

    def test_overview_db_failure(self, client):
        test_client, mock_deps, _ = client

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = Exception('DB error')
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_deps.get_conn.return_value = mock_conn

        resp = test_client.get('/api/stats/overview?time_range=24h')
        assert resp.status_code == 500
        assert 'detail' in resp.json()


class TestStatsCharts:
    def test_charts_returns_expected_keys(self, client):
        test_client, mock_deps, _ = client

        ts = datetime(2026, 3, 20, 12, 0, 0, tzinfo=timezone.utc)
        _mock_cursor_results(mock_deps, [
            # logs_over_time (fetchall)
            [{'period': ts, 'count': 100}],
            # traffic_by_action (fetchall)
            [{'period': ts, 'rule_action': 'allow', 'count': 80},
             {'period': ts, 'rule_action': 'block', 'count': 20}],
        ])

        resp = test_client.get('/api/stats/charts?time_range=24h')
        assert resp.status_code == 200
        data = resp.json()
        assert 'logs_over_time' in data
        assert 'logs_per_hour' in data  # backward-compat alias
        assert 'traffic_by_action' in data
        assert len(data['logs_over_time']) == 1
        assert data['logs_over_time'] == data['logs_per_hour']
        assert data['traffic_by_action'][0]['allow'] == 80
        assert data['traffic_by_action'][0]['block'] == 20

    def test_charts_db_failure(self, client):
        test_client, mock_deps, _ = client

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = Exception('DB error')
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_deps.get_conn.return_value = mock_conn

        resp = test_client.get('/api/stats/charts?time_range=24h')
        assert resp.status_code == 500
        assert 'detail' in resp.json()


class TestStatsTables:
    def test_tables_returns_expected_keys(self, client):
        test_client, mock_deps, _ = client

        # tables runs many queries — we need to provide results for each fetchall
        _mock_cursor_results(mock_deps, [
            # consolidated countries (fetchall)
            [{'country': 'US', 'rule_action': 'block', 'count': 50},
             {'country': 'CN', 'rule_action': 'allow', 'count': 30}],
            # consolidated services (fetchall)
            [{'service_name': 'SSH', 'rule_action': 'block', 'count': 40}],
            # top_blocked_ips (fetchall)
            [{'ip': '1.2.3.4', 'count': 100, 'country': 'US', 'asn': 'AS1234', 'threat_score': 90}],
            # top_blocked_internal_ips (fetchall)
            [{'ip': '192.168.1.10', 'count': 50, 'device_name': 'PC1'}],
            # top_threat_ips (fetchall)
            [{'ip': '5.6.7.8', 'count': 25, 'country': 'RU', 'asn': 'AS5678',
              'city': 'Moscow', 'rdns': None, 'threat_score': 95,
              'threat_categories': None, 'last_seen': datetime(2026, 3, 20, tzinfo=timezone.utc)}],
            # top_allowed_destinations (fetchall)
            [{'ip': '8.8.8.8', 'count': 200, 'country': 'US', 'asn': 'Google'}],
            # top_dns (fetchall)
            [{'dns_query': 'example.com', 'count': 150}],
            # top_active_internal_ips (fetchall)
            [{'ip': '192.168.1.20', 'count': 300, 'device_name': 'Server1'}],
        ])

        resp = test_client.get('/api/stats/tables?time_range=7d')
        assert resp.status_code == 200
        data = resp.json()

        expected_keys = [
            'top_blocked_countries', 'top_blocked_ips', 'top_blocked_internal_ips',
            'top_threat_ips', 'top_blocked_services', 'top_allowed_destinations',
            'top_allowed_countries', 'top_allowed_services', 'top_active_internal_ips',
            'top_dns',
        ]
        for key in expected_keys:
            assert key in data, f"Missing key: {key}"

        assert data['top_blocked_countries'] == [{'country': 'US', 'count': 50}]
        assert data['top_allowed_countries'] == [{'country': 'CN', 'count': 30}]
        assert data['top_blocked_ips'][0]['ip'] == '1.2.3.4'
        assert data['top_dns'][0]['dns_query'] == 'example.com'

    def test_tables_db_failure(self, client):
        test_client, mock_deps, _ = client

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = Exception('DB error')
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_deps.get_conn.return_value = mock_conn

        resp = test_client.get('/api/stats/tables?time_range=24h')
        assert resp.status_code == 500
        body = resp.json()
        assert 'detail' in body
