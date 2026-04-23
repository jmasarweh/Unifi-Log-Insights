"""Tests for retention cleanup async job routes.

Tests the POST /api/config/retention/cleanup and
GET /api/config/retention/cleanup-status endpoints.
"""

import sys
import time
import threading
from unittest.mock import MagicMock, patch

import pytest

# Import the real parser BEFORE any fixture runs. If we imported inside the
# fixture, sys.modules['db'] would already be replaced with a MagicMock and
# `parse_retention_time` would be an auto-attr. Importing at module-top means
# we hold a reference to the actual function object, immune to later mocking.
from db import parse_retention_time as _real_parse_retention_time


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
    from types import SimpleNamespace
    # SimpleNamespace, not RetentionDaysConfig / RetentionTimeConfig: the db
    # module is mocked in sys.modules before routes are imported, so importing
    # the real NamedTuples from it would return a MagicMock. SimpleNamespace
    # gives route code the same .general / .dns / .hour / .source attribute
    # access without pretending to be the real type.
    default_days = SimpleNamespace(general=60, general_source='default', dns=10, dns_source='default')
    default_time = SimpleNamespace(time='03:00', source='default')
    mock_deps.enricher_db = MagicMock()
    mock_deps.enricher_db.resolve_retention_days = MagicMock(return_value=default_days)
    mock_deps.unifi_api = MagicMock()
    mock_deps.signal_receiver = MagicMock()
    mock_deps.ttl_cache = MagicMock(return_value=lambda f: f)

    monkeypatch.setitem(sys.modules, 'deps', mock_deps)

    mock_db_module = MagicMock()
    mock_db_module.Database = MagicMock()
    mock_db_module.Database.validate_retention_days = MagicMock()
    mock_db_module.Database.resolve_retention_days = MagicMock(return_value=default_days)
    mock_db_module.Database.resolve_retention_time = MagicMock(return_value=default_time)
    mock_db_module.Database.RETENTION_BATCH_SIZE = 5000
    # Use the REAL parse_retention_time (imported at module top) so test and
    # production share one function — semantics can't drift.
    mock_db_module.parse_retention_time = _real_parse_retention_time
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


class TestRetentionConfigGet:
    def test_get_includes_retention_time_default(self, client):
        test_client, mock_deps, mock_db, setup_mod = client
        # Fixture default: ('03:00', 'default'). No env dependence — the resolver is mocked.
        resp = test_client.get('/api/config/retention')
        assert resp.status_code == 200
        data = resp.json()
        assert data['retention_time'] == '03:00'
        assert data['time_source'] == 'default'

    def test_get_returns_saved_retention_time(self, client):
        from types import SimpleNamespace
        test_client, mock_deps, mock_db, setup_mod = client
        mock_db.Database.resolve_retention_time.return_value = SimpleNamespace(time='07:30', source='ui')
        resp = test_client.get('/api/config/retention')
        assert resp.status_code == 200
        data = resp.json()
        assert data['retention_time'] == '07:30'
        assert data['time_source'] == 'ui'


class TestRetentionConfigPost:
    def test_post_saves_valid_retention_time(self, client):
        test_client, mock_deps, mock_db, setup_mod = client
        resp = test_client.post('/api/config/retention', json={'retention_time': '05:17'})
        assert resp.status_code == 200
        # signal_receiver called so the running process re-registers the job
        mock_deps.signal_receiver.assert_called_once()
        # set_config called with the new value
        saved = [c for c in mock_db.set_config.call_args_list
                 if c.args[1] == 'retention_time']
        assert len(saved) == 1
        assert saved[0].args[2] == '05:17'

    def test_post_canonicalises_retention_time(self, client):
        """Parser zero-pads — '3:5' stored as '03:05'."""
        test_client, mock_deps, mock_db, _ = client
        resp = test_client.post('/api/config/retention', json={'retention_time': '3:5'})
        assert resp.status_code == 200
        saved = [c for c in mock_db.set_config.call_args_list
                 if c.args[1] == 'retention_time']
        assert saved[0].args[2] == '03:05'

    def test_post_rejects_non_string_retention_time(self, client):
        test_client, _, _, _ = client
        resp = test_client.post('/api/config/retention', json={'retention_time': 1230})
        assert resp.status_code == 400
        assert 'retention_time' in resp.json()['detail']

    def test_post_rejects_out_of_range_retention_time(self, client):
        test_client, _, _, _ = client
        for bad in ('24:00', '12:60', '-1:00', 'noon', '12', '12:30:45'):
            resp = test_client.post('/api/config/retention', json={'retention_time': bad})
            assert resp.status_code == 400, f'{bad!r} should be rejected'

    def test_post_without_time_does_not_signal(self, client):
        """Days-only updates should not trigger SIGUSR2 — scheduler doesn't need it."""
        test_client, mock_deps, _, _ = client
        resp = test_client.post('/api/config/retention', json={'retention_days': 30})
        assert resp.status_code == 200
        mock_deps.signal_receiver.assert_not_called()

    def test_post_with_unchanged_time_does_not_signal(self, client):
        """Saving the same retention_time as currently effective must not
        trigger SIGUSR2. The UI sends retention_time on every save (part of
        the combined dirty check), so a days-only edit always arrives with a
        retention_time field."""
        from types import SimpleNamespace
        test_client, mock_deps, mock_db, _ = client

        # Effective value is '05:17' (regardless of source — UI, env, or default)
        mock_db.Database.resolve_retention_time.return_value = SimpleNamespace(
            time='05:17', source='ui')

        resp = test_client.post('/api/config/retention', json={'retention_time': '05:17'})
        assert resp.status_code == 200
        mock_deps.signal_receiver.assert_not_called()
        saved = [c for c in mock_db.set_config.call_args_list
                 if c.args[1] == 'retention_time']
        assert saved == [], 'unchanged time must not be re-written'

    def test_post_with_env_sourced_time_does_not_flip_source_to_ui(self, client):
        """REGRESSION: When the effective time comes from RETENTION_TIME env
        (or the default), a days-only edit that echoes back the same effective
        time in the payload must NOT write it to system_config.

        Writing would silently flip time_source from 'env'/'default' to 'ui',
        permanently pinning the current time against future env overrides.
        Found by review after the hour→time refactor — the initial no-op check
        compared against get_config('retention_time') which is None when the
        time is env/default-sourced, so every days-only save would trip it.
        """
        from types import SimpleNamespace
        test_client, mock_deps, mock_db, _ = client

        # Effective time is '23:17' from env (system_config row absent).
        mock_db.Database.resolve_retention_time.return_value = SimpleNamespace(
            time='23:17', source='env')
        # get_config('retention_time') returns None — nothing in DB.
        # (Fixture default already has get_config returning None for all keys.)

        resp = test_client.post('/api/config/retention', json={
            'retention_days': 30,           # days-only edit
            'retention_time': '23:17',      # UI echoes the effective env value
        })
        assert resp.status_code == 200
        mock_deps.signal_receiver.assert_not_called()

        saved = [c for c in mock_db.set_config.call_args_list
                 if c.args[1] == 'retention_time']
        assert saved == [], 'env-sourced time must not be promoted to system_config on a days-only save'


class TestRetentionTimeImport:
    def test_import_accepts_valid_retention_time(self, client):
        test_client, mock_deps, mock_db, setup_mod = client
        resp = test_client.post('/api/config/import', json={
            'config': {'retention_time': '15:30'}
        })
        assert resp.status_code == 200
        data = resp.json()
        assert 'retention_time' in data.get('imported_keys', [])
        assert 'retention_time' not in data.get('failed_keys', [])

    def test_import_rejects_out_of_range_retention_time(self, client):
        test_client, _, _, _ = client
        resp = test_client.post('/api/config/import', json={
            'config': {'retention_time': '25:00'}
        })
        assert resp.status_code == 200
        data = resp.json()
        assert 'retention_time' in data.get('failed_keys', [])
        assert 'retention_time' not in data.get('imported_keys', [])

    def test_import_rejects_non_string_retention_time(self, client):
        test_client, _, _, _ = client
        resp = test_client.post('/api/config/import', json={
            'config': {'retention_time': 1230}
        })
        assert resp.status_code == 200
        data = resp.json()
        assert 'retention_time' in data.get('failed_keys', [])
