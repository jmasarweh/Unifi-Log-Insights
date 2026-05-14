"""Tests for BlacklistFetcher.fetch_and_store — free-tier resilience.

Covers Patch 1's blacklist-side acceptance criteria:
- Timestamp persisted only on successful pull.
- HTTP 429 does NOT persist timestamp.
- Empty/zero-count response does NOT persist timestamp.
"""

from unittest.mock import MagicMock, patch

import pytest

import blacklist


@pytest.fixture
def db_with_no_wan():
    """A MagicMock db whose get_wan_ips/gateway_ips return empty lists."""
    db = MagicMock()
    db.bulk_upsert_threats = MagicMock(side_effect=lambda entries: len(entries))
    return db


def _mk_response(status=200, json_data=None):
    resp = MagicMock()
    resp.status_code = status
    resp.json = MagicMock(return_value=json_data or {})
    resp.raise_for_status = MagicMock()
    return resp


class TestBlacklistFetcherTimestamp:
    def test_success_writes_timestamp(self, db_with_no_wan, monkeypatch):
        monkeypatch.setattr(blacklist, 'get_wan_ips_from_config', lambda db: [])
        monkeypatch.setattr(blacklist, 'get_config', lambda db, key, default=None: None if key == 'gateway_ips' else default)
        set_config_mock = MagicMock()
        monkeypatch.setattr(blacklist, 'set_config', set_config_mock)
        monkeypatch.setattr(blacklist, 'time', MagicMock(time=MagicMock(return_value=1_700_000_000.0)))

        fetcher = blacklist.BlacklistFetcher(db_with_no_wan, api_key='fake-key')
        fake_data = {'data': [{'ipAddress': '1.2.3.4', 'abuseConfidenceScore': 92}]}

        with patch.object(blacklist.requests, 'get', return_value=_mk_response(200, fake_data)):
            count = fetcher.fetch_and_store()

        assert count == 1
        set_config_mock.assert_called_once()
        args, _ = set_config_mock.call_args
        assert args[1] == 'last_blacklist_pull_at'
        assert args[2] == 1_700_000_000  # int(time.time())

    def test_rate_limited_does_not_write_timestamp(self, db_with_no_wan, monkeypatch):
        monkeypatch.setattr(blacklist, 'get_wan_ips_from_config', lambda db: [])
        monkeypatch.setattr(blacklist, 'get_config', lambda db, key, default=None: None if key == 'gateway_ips' else default)
        set_config_mock = MagicMock()
        monkeypatch.setattr(blacklist, 'set_config', set_config_mock)

        fetcher = blacklist.BlacklistFetcher(db_with_no_wan, api_key='fake-key')

        with patch.object(blacklist.requests, 'get', return_value=_mk_response(429)):
            count = fetcher.fetch_and_store()

        assert count == 0
        set_config_mock.assert_not_called()

    def test_empty_response_does_not_write_timestamp(self, db_with_no_wan, monkeypatch):
        monkeypatch.setattr(blacklist, 'get_wan_ips_from_config', lambda db: [])
        monkeypatch.setattr(blacklist, 'get_config', lambda db, key, default=None: None if key == 'gateway_ips' else default)
        set_config_mock = MagicMock()
        monkeypatch.setattr(blacklist, 'set_config', set_config_mock)

        fetcher = blacklist.BlacklistFetcher(db_with_no_wan, api_key='fake-key')

        with patch.object(blacklist.requests, 'get', return_value=_mk_response(200, {'data': []})):
            count = fetcher.fetch_and_store()

        assert count == 0
        set_config_mock.assert_not_called()

    def test_no_api_key_does_not_write_timestamp(self, db_with_no_wan, monkeypatch):
        monkeypatch.setenv('ABUSEIPDB_API_KEY', '')
        set_config_mock = MagicMock()
        monkeypatch.setattr(blacklist, 'set_config', set_config_mock)

        fetcher = blacklist.BlacklistFetcher(db_with_no_wan, api_key='')

        with patch.object(blacklist.requests, 'get') as get_mock:
            count = fetcher.fetch_and_store()

        assert count == 0
        get_mock.assert_not_called()
        set_config_mock.assert_not_called()
