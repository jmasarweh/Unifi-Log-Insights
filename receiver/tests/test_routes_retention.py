"""Tests for retention cleanup async job routes.

Tests the POST /api/config/retention/cleanup and
GET /api/config/retention/cleanup-status endpoints.
"""

import sys
import time
import threading
from unittest.mock import MagicMock, patch

import pytest


def _poll_until(test_client, expected_status, path='/api/config/retention/cleanup-status',
                timeout=2.0, interval=0.05):
    """Poll the status endpoint until the expected status appears or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        resp = test_client.get(path)
        data = resp.json()
        if data.get('status') == expected_status:
            return resp, data
        time.sleep(interval)
    # Final attempt — let the assertion fail with the actual value
    resp = test_client.get(path)
    return resp, resp.json()


@pytest.fixture
def client(monkeypatch):
    """Create a FastAPI TestClient with mocked deps module.

    Route modules are removed from sys.modules so each test gets a fresh
    import (avoids stale module-level state like _cleanup_job).  The stubs
    below cover every import in routes/setup.py — if a new import is added
    there, add a corresponding stub here to avoid masking import errors.
    """
    for mod_name in list(sys.modules):
        if mod_name.startswith('routes'):
            monkeypatch.delitem(sys.modules, mod_name, raising=False)

    mock_deps = MagicMock()
    mock_deps.APP_VERSION = '3.4.1-test'
    mock_deps.get_conn = MagicMock()
    mock_deps.put_conn = MagicMock()
    mock_deps.enricher_db = MagicMock()
    mock_deps.enricher_db.resolve_retention_days = MagicMock(return_value=(60, 10))
    mock_deps.unifi_api = MagicMock()
    mock_deps.signal_receiver = MagicMock()
    mock_deps.ttl_cache = MagicMock(return_value=lambda f: f)

    monkeypatch.setitem(sys.modules, 'deps', mock_deps)

    mock_db_module = MagicMock()
    mock_db_module.Database = MagicMock()
    mock_db_module.Database.validate_retention_days = MagicMock()
    mock_db_module.Database.RETENTION_BATCH_SIZE = 5000
    mock_db_module.get_config = MagicMock(return_value=None)
    mock_db_module.set_config = MagicMock()
    mock_db_module.count_logs = MagicMock(return_value=0)
    mock_db_module.encrypt_api_key = MagicMock()
    mock_db_module.decrypt_api_key = MagicMock()
    monkeypatch.setitem(sys.modules, 'db', mock_db_module)

    # Stub other modules that setup.py imports
    for mod in ('unifi_api', 'firewall_policy_matcher', 'parsers'):
        if mod not in sys.modules:
            monkeypatch.setitem(sys.modules, mod, MagicMock())

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from routes import setup as setup_module

    # Reset module-level job state between tests
    setup_module._cleanup_job = None

    app = FastAPI()
    app.include_router(setup_module.router)
    return TestClient(app), mock_deps, mock_db_module, setup_module


class TestRetentionCleanupStart:
    def test_start_cleanup_returns_running(self, client):
        test_client, mock_deps, mock_db, setup_mod = client

        # Make run_retention_cleanup block until we release it
        started = threading.Event()
        release = threading.Event()

        def slow_cleanup(*args, **kwargs):
            started.set()
            release.wait(timeout=5)
            return {'status': 'complete', 'dns_deleted': 0, 'non_dns_deleted': 0,
                    'deleted_so_far': 0, 'batches_completed': 0, 'error': None}

        mock_deps.enricher_db.run_retention_cleanup = slow_cleanup

        resp = test_client.post('/api/config/retention/cleanup')
        assert resp.status_code == 200
        data = resp.json()
        assert data['success'] is True
        assert data['status'] == 'running'
        assert 'general_days' in data
        assert 'dns_days' in data

        # Clean up
        release.set()
        started.wait(timeout=2)

    def test_start_cleanup_409_when_already_running(self, client):
        test_client, mock_deps, mock_db, setup_mod = client

        release = threading.Event()

        def slow_cleanup(*args, **kwargs):
            release.wait(timeout=5)
            return {'status': 'complete', 'dns_deleted': 0, 'non_dns_deleted': 0,
                    'deleted_so_far': 0, 'batches_completed': 0, 'error': None}

        mock_deps.enricher_db.run_retention_cleanup = slow_cleanup

        resp1 = test_client.post('/api/config/retention/cleanup')
        assert resp1.status_code == 200

        resp2 = test_client.post('/api/config/retention/cleanup')
        assert resp2.status_code == 409
        assert 'already in progress' in resp2.json()['detail']

        release.set()

    def test_start_cleanup_400_on_invalid_days(self, client):
        test_client, mock_deps, mock_db, setup_mod = client

        mock_db.Database.validate_retention_days.side_effect = ValueError("must be positive")

        resp = test_client.post('/api/config/retention/cleanup')
        assert resp.status_code == 400
        assert 'positive' in resp.json()['detail']


class TestRetentionCleanupStatus:
    def test_status_idle_when_no_job(self, client):
        test_client, mock_deps, mock_db, setup_mod = client

        resp = test_client.get('/api/config/retention/cleanup-status')
        assert resp.status_code == 200
        assert resp.json()['status'] == 'idle'

    def test_status_shows_running_job(self, client):
        test_client, mock_deps, mock_db, setup_mod = client

        release = threading.Event()

        def slow_cleanup(*args, **kwargs):
            release.wait(timeout=5)
            return {'status': 'complete', 'dns_deleted': 0, 'non_dns_deleted': 0,
                    'deleted_so_far': 0, 'batches_completed': 0, 'error': None}

        mock_deps.enricher_db.run_retention_cleanup = slow_cleanup

        test_client.post('/api/config/retention/cleanup')

        resp = test_client.get('/api/config/retention/cleanup-status')
        assert resp.status_code == 200
        data = resp.json()
        assert data['status'] == 'running'
        assert 'deleted_so_far' in data

        release.set()

    def test_status_shows_complete(self, client):
        test_client, mock_deps, mock_db, setup_mod = client

        def fast_cleanup(*args, **kwargs):
            return {'status': 'complete', 'dns_deleted': 50, 'non_dns_deleted': 100,
                    'deleted_so_far': 150, 'batches_completed': 2, 'error': None}

        mock_deps.enricher_db.run_retention_cleanup = fast_cleanup

        test_client.post('/api/config/retention/cleanup')

        resp, data = _poll_until(test_client, 'complete')
        assert resp.status_code == 200
        assert data['status'] == 'complete'
        assert data['deleted_so_far'] == 150
        assert data['dns_deleted'] == 50
        assert data['non_dns_deleted'] == 100

    def test_status_shows_partial(self, client):
        test_client, mock_deps, mock_db, setup_mod = client

        def partial_cleanup(*args, **kwargs):
            return {'status': 'partial', 'dns_deleted': 25, 'non_dns_deleted': 0,
                    'deleted_so_far': 25, 'batches_completed': 1, 'error': 'db error'}

        mock_deps.enricher_db.run_retention_cleanup = partial_cleanup

        test_client.post('/api/config/retention/cleanup')

        resp, data = _poll_until(test_client, 'partial')
        assert data['status'] == 'partial'
        assert data['deleted_so_far'] == 25
        assert data['error'] == 'db error'

    def test_status_shows_failed(self, client):
        test_client, mock_deps, mock_db, setup_mod = client

        def failed_cleanup(*args, **kwargs):
            return {'status': 'failed', 'dns_deleted': 0, 'non_dns_deleted': 0,
                    'deleted_so_far': 0, 'batches_completed': 0, 'error': 'connection lost'}

        mock_deps.enricher_db.run_retention_cleanup = failed_cleanup

        test_client.post('/api/config/retention/cleanup')

        resp, data = _poll_until(test_client, 'failed')
        assert data['status'] == 'failed'
        assert data['error'] == 'connection lost'
