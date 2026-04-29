"""Tests for enrichment.py — IP validation, TTLCache, GeoIP, AbuseIPDB."""

import socket
import threading
import time as _time
from unittest.mock import MagicMock, patch

import pytest

from enrichment import (
    AbuseIPDBEnricher,
    Enricher,
    GeoIPEnricher,
    RDNSEnricher,
    TTLCache,
    _parse_bool_setting,
    _resolve_rdns_enabled,
    is_public_ip,
)


# ── is_public_ip ─────────────────────────────────────────────────────────────

class TestIsPublicIp:
    def test_public_v4(self):
        assert is_public_ip('8.8.8.8') is True

    def test_private_10(self):
        assert is_public_ip('10.0.0.1') is False

    def test_private_172(self):
        assert is_public_ip('172.16.0.1') is False

    def test_private_192(self):
        assert is_public_ip('192.168.1.1') is False

    def test_loopback(self):
        assert is_public_ip('127.0.0.1') is False

    def test_ipv6_loopback(self):
        assert is_public_ip('::1') is False

    def test_ipv6_ula(self):
        assert is_public_ip('fc00::1') is False

    def test_multicast(self):
        assert is_public_ip('224.0.0.1') is False

    def test_empty(self):
        assert is_public_ip('') is False

    def test_none(self):
        assert is_public_ip(None) is False

    def test_invalid(self):
        assert is_public_ip('not-an-ip') is False

    def test_public_ipv6(self):
        assert is_public_ip('2001:4860:4860::8888') is True


# ── TTLCache ─────────────────────────────────────────────────────────────────

class TestTTLCache:
    def test_set_and_get(self):
        cache = TTLCache(ttl_seconds=60)
        cache.set('key1', {'value': 42})
        assert cache.get('key1') == {'value': 42}

    def test_get_expired(self, monkeypatch):
        cache = TTLCache(ttl_seconds=10)
        # Set an entry at time 1000
        real_time = [1000.0]
        monkeypatch.setattr(_time, 'time', lambda: real_time[0])
        cache.set('key1', {'value': 1})
        # Advance past TTL
        real_time[0] = 1011.0
        assert cache.get('key1') is None

    def test_get_within_ttl(self, monkeypatch):
        cache = TTLCache(ttl_seconds=10)
        real_time = [1000.0]
        monkeypatch.setattr(_time, 'time', lambda: real_time[0])
        cache.set('key1', {'value': 1})
        real_time[0] = 1005.0
        assert cache.get('key1') == {'value': 1}

    def test_delete(self):
        cache = TTLCache()
        cache.set('key1', {'value': 1})
        cache.delete('key1')
        assert cache.get('key1') is None

    def test_delete_nonexistent(self):
        cache = TTLCache()
        cache.delete('missing')  # Should not raise

    def test_size(self):
        cache = TTLCache()
        assert cache.size() == 0
        cache.set('a', {})
        cache.set('b', {})
        assert cache.size() == 2

    def test_get_miss(self):
        cache = TTLCache()
        assert cache.get('nonexistent') is None

    def test_set_existing_key_replaces_value_without_growing(self):
        cache = TTLCache(ttl_seconds=60, max_entries=3)

        cache.set('a', {'value': 1})
        cache.set('a', {'value': 2})

        assert cache.size() == 1
        assert cache.get('a') == {'value': 2}

    @pytest.mark.parametrize(
        ('kwargs', 'message'),
        [
            ({'max_entries': 0}, 'positive'),
            ({'max_entries': -1}, 'positive'),
            ({'max_entries': 1, 'prune_trigger_ratio': 0.99}, '>= 1.0'),
            ({'max_entries': 1, 'prune_target_ratio': 0}, 'within'),
            ({'max_entries': 1, 'prune_target_ratio': 1.01}, 'within'),
        ],
    )
    def test_constructor_validation(self, kwargs, message):
        with pytest.raises(ValueError, match=message):
            TTLCache(**kwargs)

    def test_set_prunes_expired_entries_at_watermark(self, monkeypatch):
        cache = TTLCache(ttl_seconds=10, max_entries=3)
        real_time = [1000.0]
        monkeypatch.setattr(_time, 'time', lambda: real_time[0])

        cache.set('a', {'value': 'a'})
        cache.set('b', {'value': 'b'})
        cache.set('c', {'value': 'c'})

        real_time[0] = 1011.0
        cache.set('d', {'value': 'd'})

        assert cache.size() == 1
        assert cache.get('a') is None
        assert cache.get('b') is None
        assert cache.get('c') is None
        assert cache.get('d') == {'value': 'd'}

    def test_set_evicts_lru_down_to_watermark_target(self):
        cache = TTLCache(ttl_seconds=60, max_entries=3)

        cache.set('a', {'value': 'a'})
        cache.set('b', {'value': 'b'})
        cache.set('c', {'value': 'c'})
        assert cache.get('a') == {'value': 'a'}  # refresh recency
        cache.set('d', {'value': 'd'})

        assert cache.size() == 2
        assert cache.get('a') == {'value': 'a'}
        assert cache.get('d') == {'value': 'd'}
        assert cache.get('b') is None
        assert cache.get('c') is None

    def test_set_prunes_expired_then_evicts_lru_when_still_over_cap(self, monkeypatch):
        cache = TTLCache(
            ttl_seconds=10,
            max_entries=5,
            prune_trigger_ratio=2.0,
            prune_target_ratio=0.8,
        )
        real_time = [1000.0]
        monkeypatch.setattr(_time, 'time', lambda: real_time[0])

        for key in ('a', 'b', 'c'):
            cache.set(key, {'value': key})

        real_time[0] = 1005.0
        for key in ('d', 'e', 'f', 'g', 'h', 'i'):
            cache.set(key, {'value': key})

        real_time[0] = 1011.0
        cache.set('j', {'value': 'j'})

        assert cache.size() == 4
        for key in ('a', 'b', 'c', 'd', 'e', 'f'):
            assert cache.get(key) is None
        for key in ('g', 'h', 'i', 'j'):
            assert cache.get(key) == {'value': key}


# ── GeoIPEnricher ────────────────────────────────────────────────────────────

class TestGeoIPEnricher:
    def test_no_reader_returns_empty(self, tmp_path):
        enricher = GeoIPEnricher(db_dir=str(tmp_path))
        assert enricher.city_reader is None
        assert enricher.asn_reader is None
        result = enricher.lookup('8.8.8.8')
        assert result == {}

    def test_lookup_with_mocked_readers(self):
        enricher = GeoIPEnricher(db_dir='/nonexistent')

        # Mock city reader
        city_resp = MagicMock()
        city_resp.country.iso_code = 'US'
        city_resp.city.name = 'Mountain View'
        city_resp.location.latitude = 37.386
        city_resp.location.longitude = -122.084
        enricher.city_reader = MagicMock()
        enricher.city_reader.city.return_value = city_resp

        # Mock ASN reader
        asn_resp = MagicMock()
        asn_resp.autonomous_system_number = 15169
        asn_resp.autonomous_system_organization = 'Google LLC'
        enricher.asn_reader = MagicMock()
        enricher.asn_reader.asn.return_value = asn_resp

        result = enricher.lookup('8.8.8.8')
        assert result['geo_country'] == 'US'
        assert result['geo_city'] == 'Mountain View'
        assert result['asn_number'] == 15169
        assert result['asn_name'] == 'Google LLC'

    def test_lookup_exception_handled(self):
        enricher = GeoIPEnricher(db_dir='/nonexistent')
        enricher.city_reader = MagicMock()
        enricher.city_reader.city.side_effect = Exception('db error')
        # Should not raise, just return empty
        result = enricher.lookup('8.8.8.8')
        assert 'geo_country' not in result


# ── AbuseIPDBEnricher ────────────────────────────────────────────────────────

class TestAbuseIPDBEnricher:
    def test_disabled_returns_empty(self):
        enricher = AbuseIPDBEnricher(api_key='')
        assert enricher.lookup('1.2.3.4') == {}

    def test_excluded_ip_returns_empty(self):
        enricher = AbuseIPDBEnricher(api_key='test-key')
        enricher.exclude_ip('1.2.3.4')
        assert enricher.lookup('1.2.3.4') == {}

    def test_cached_result_no_api_call(self):
        enricher = AbuseIPDBEnricher(api_key='test-key')
        enricher.cache.set('1.2.3.4', {'threat_score': 75})
        result = enricher.lookup('1.2.3.4')
        assert result == {'threat_score': 75}

    @patch('enrichment.requests.get')
    def test_api_call_on_cache_miss(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'data': {
                'abuseConfidenceScore': 90,
                'reports': [{'categories': [14, 18]}],
            }
        }
        mock_resp.headers = {
            'X-RateLimit-Limit': '1000',
            'X-RateLimit-Remaining': '999',
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        enricher = AbuseIPDBEnricher(api_key='test-key')
        result = enricher.lookup('1.2.3.4')
        assert result['threat_score'] == 90
        assert '14' in result['threat_categories']
        assert '18' in result['threat_categories']
        mock_get.assert_called_once()

    @patch('enrichment.requests.get')
    def test_429_returns_empty(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.headers = {'Retry-After': '3600'}
        mock_get.return_value = mock_resp

        enricher = AbuseIPDBEnricher(api_key='test-key')
        result = enricher.lookup('1.2.3.4')
        assert result == {}
        assert enricher._paused_until > _time.time()


# ── _parse_bool_setting ──────────────────────────────────────────────────────

class TestParseBoolSetting:
    @pytest.mark.parametrize('value,expected', [
        (True, True),
        (False, False),
        ('1', True),
        ('0', False),
        ('true', True),
        ('TRUE', True),
        ('  True  ', True),
        ('yes', True),
        ('on', True),
        ('false', False),
        ('FALSE', False),
        ('  False  ', False),
        ('no', False),
        ('off', False),
        (1, True),
        (0, False),
    ])
    def test_recognised_values(self, value, expected):
        assert _parse_bool_setting(value) is expected

    @pytest.mark.parametrize('value', [
        'maybe', 'enabled', 'disabled', '', '   ',
        2, -1, 100,
        None, [], {}, 1.5,
    ])
    def test_unrecognised_returns_default_none(self, value):
        assert _parse_bool_setting(value) is None

    def test_unrecognised_returns_explicit_default(self):
        assert _parse_bool_setting('maybe', default=True) is True
        assert _parse_bool_setting('maybe', default=False) is False

    def test_default_passes_through_for_invalid_int(self):
        # 2 is not in (0, 1) — must NOT bool() it as True
        assert _parse_bool_setting(2, default='SENTINEL') == 'SENTINEL'


# ── _resolve_rdns_enabled ────────────────────────────────────────────────────

class TestResolveRdnsEnabled:
    def test_returns_true_when_db_is_none_and_no_env(self):
        # env cleared by autouse conftest — confirm tolerant of db=None
        assert _resolve_rdns_enabled(None) is True

    def test_env_true_wins_over_db_none(self, monkeypatch):
        monkeypatch.setenv('RDNS_ENABLED', 'true')
        assert _resolve_rdns_enabled(None) is True

    def test_env_false_wins_over_db_none(self, monkeypatch):
        monkeypatch.setenv('RDNS_ENABLED', 'false')
        assert _resolve_rdns_enabled(None) is False

    def test_env_off_token_recognised(self, monkeypatch):
        monkeypatch.setenv('RDNS_ENABLED', 'off')
        assert _resolve_rdns_enabled(None) is False

    def test_env_uppercase_recognised(self, monkeypatch):
        monkeypatch.setenv('RDNS_ENABLED', 'YES')
        assert _resolve_rdns_enabled(None) is True

    def test_env_wins_over_db_setting(self, monkeypatch):
        monkeypatch.setenv('RDNS_ENABLED', 'false')
        db = MagicMock()
        db.get_config = MagicMock(return_value=True)  # DB says true
        assert _resolve_rdns_enabled(db) is False  # env wins

    def test_db_used_when_env_unset(self, monkeypatch):
        # env cleared by conftest
        db = MagicMock()
        db.get_config = MagicMock(return_value=False)
        assert _resolve_rdns_enabled(db) is False

    def test_db_string_false_parsed_strictly(self, monkeypatch):
        # config import may have stored stringly-typed "false"
        db = MagicMock()
        db.get_config = MagicMock(return_value='false')
        assert _resolve_rdns_enabled(db) is False  # not bool('false')==True

    def test_swallows_db_errors(self, monkeypatch):
        db = MagicMock()
        db.get_config = MagicMock(side_effect=RuntimeError('db blew up'))
        # Default True on unreadable DB
        assert _resolve_rdns_enabled(db) is True

    def test_unrecognised_env_falls_through_to_db_with_warning(self, monkeypatch, caplog):
        import logging
        monkeypatch.setenv('RDNS_ENABLED', 'fasle')  # typo
        db = MagicMock()
        db.get_config = MagicMock(return_value=True)
        with caplog.at_level(logging.WARNING, logger='enrichment'):
            assert _resolve_rdns_enabled(db) is True
        assert any('not recognised' in rec.message for rec in caplog.records)

    def test_blank_env_falls_through_silently(self, monkeypatch, caplog):
        import logging
        monkeypatch.setenv('RDNS_ENABLED', '')
        db = MagicMock()
        db.get_config = MagicMock(return_value=True)
        with caplog.at_level(logging.WARNING, logger='enrichment'):
            result = _resolve_rdns_enabled(db)
        assert result is True
        assert not any('not recognised' in rec.message for rec in caplog.records)


# ── RDNSEnricher (two-tier cache) ────────────────────────────────────────────

def _make_db_row(hostname, status, age_seconds):
    return {'hostname': hostname, 'status': status, 'age_seconds': age_seconds}


class TestRDNSEnricherCold:
    def test_returns_db_cached_success_within_ttl(self):
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=_make_db_row('host.example.com', 'success', 3600))
        db.set_rdns_cache = MagicMock()
        e = RDNSEnricher(timeout=2.0, db=db)
        with patch('enrichment.socket.gethostbyaddr') as mock_gha:
            assert e.lookup('1.2.3.4') == {'rdns': 'host.example.com'}
            mock_gha.assert_not_called()

    def test_returns_db_cached_failure_within_negative_ttl(self):
        db = MagicMock()
        # 3 days old — well under 7d failure TTL
        db.get_rdns_cache = MagicMock(return_value=_make_db_row(None, 'failure', 3 * 86400))
        e = RDNSEnricher(db=db)
        with patch('enrichment.socket.gethostbyaddr') as mock_gha:
            assert e.lookup('1.2.3.4') == {'rdns': None}
            mock_gha.assert_not_called()

    def test_returns_db_cached_transient_within_short_ttl(self):
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=_make_db_row(None, 'transient', 1800))  # 30m
        e = RDNSEnricher(db=db)
        with patch('enrichment.socket.gethostbyaddr') as mock_gha:
            assert e.lookup('1.2.3.4') == {'rdns': None}
            mock_gha.assert_not_called()

    def test_db_hit_uses_remaining_ttl_for_hot_tier(self, monkeypatch):
        """A near-expired DB row must NOT be extended in memory by a fresh full TTL.

        First call: DB returns a failure row with 60s remaining; hot-cache it
        with that remaining TTL.
        Second call after 120s elapsed: hot entry must be treated as expired.
        Simulate the DB row also having expired (returning None on second
        get_rdns_cache call), so a fresh live PTR is issued. If the hot tier
        had been extended to a full 7d, the second call would have served from
        memory and never re-queried the DB.
        """
        db = MagicMock()
        # First DB hit: 7d - 60s old (60s remaining lifetime).
        # Second DB read: row expired/evicted by retention sweep — return None.
        db.get_rdns_cache = MagicMock(side_effect=[
            _make_db_row(None, 'failure', 7 * 86400 - 60),
            None,
        ])
        db.set_rdns_cache = MagicMock()
        e = RDNSEnricher(db=db)

        clock = [1_000_000.0]
        monkeypatch.setattr('enrichment.time.time', lambda: clock[0])

        e.lookup('1.2.3.4')
        # Advance past the original DB row's expiry (was 60s away)
        clock[0] += 120
        with patch('enrichment.socket.gethostbyaddr', return_value=('hot.example.com', [], [])) as mock_gha:
            e.lookup('1.2.3.4')
            # Hot entry expired → fell through to DB → DB miss → live PTR
            mock_gha.assert_called_once()
        assert db.get_rdns_cache.call_count == 2  # second call proves hot miss

    def test_refreshes_expired_db_failure(self):
        db = MagicMock()
        # 8d old — past 7d failure TTL
        db.get_rdns_cache = MagicMock(return_value=_make_db_row(None, 'failure', 8 * 86400))
        db.set_rdns_cache = MagicMock()
        e = RDNSEnricher(db=db)
        with patch('enrichment.socket.gethostbyaddr', return_value=('host.example.com', [], [])) as mock_gha:
            assert e.lookup('1.2.3.4') == {'rdns': 'host.example.com'}
            mock_gha.assert_called_once()
        db.set_rdns_cache.assert_called_once_with('1.2.3.4', 'host.example.com', 'success')

    def test_refreshes_expired_db_transient(self):
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=_make_db_row(None, 'transient', 90 * 60))
        db.set_rdns_cache = MagicMock()
        e = RDNSEnricher(db=db)
        with patch('enrichment.socket.gethostbyaddr', return_value=('h.example.com', [], [])):
            e.lookup('1.2.3.4')
        db.set_rdns_cache.assert_called_once()

    def test_db_hit_does_not_rewrite_looked_up_at(self):
        """Read-through must not rewrite looked_up_at."""
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=_make_db_row('h', 'success', 3600))
        db.set_rdns_cache = MagicMock()
        e = RDNSEnricher(db=db)
        e.lookup('1.2.3.4')
        db.set_rdns_cache.assert_not_called()

    def test_db_hit_populates_hot_tier(self):
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=_make_db_row('h', 'success', 3600))
        db.set_rdns_cache = MagicMock()
        e = RDNSEnricher(db=db)
        e.lookup('1.2.3.4')
        # Second call: hot hit, no DB read, no live PTR
        db.get_rdns_cache.reset_mock()
        with patch('enrichment.socket.gethostbyaddr') as mock_gha:
            assert e.lookup('1.2.3.4') == {'rdns': 'h'}
        db.get_rdns_cache.assert_not_called()
        mock_gha.assert_not_called()


class TestRDNSEnricherClassification:
    def test_writes_success_to_db(self):
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=None)
        db.set_rdns_cache = MagicMock()
        e = RDNSEnricher(db=db)
        with patch('enrichment.socket.gethostbyaddr', return_value=('h.example.com', [], [])):
            e.lookup('1.2.3.4')
        db.set_rdns_cache.assert_called_once_with('1.2.3.4', 'h.example.com', 'success')

    def test_classifies_durable_gaierror_as_failure(self):
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=None)
        db.set_rdns_cache = MagicMock()
        e = RDNSEnricher(db=db)
        with patch('enrichment.socket.gethostbyaddr',
                   side_effect=socket.gaierror(socket.EAI_NONAME, 'name not known')):
            assert e.lookup('1.2.3.4') == {'rdns': None}
        db.set_rdns_cache.assert_called_once_with('1.2.3.4', None, 'failure')

    def test_classifies_eai_again_gaierror_as_transient(self):
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=None)
        db.set_rdns_cache = MagicMock()
        e = RDNSEnricher(db=db)
        with patch('enrichment.socket.gethostbyaddr',
                   side_effect=socket.gaierror(socket.EAI_AGAIN, 'temporary failure')):
            assert e.lookup('1.2.3.4') == {'rdns': None}
        db.set_rdns_cache.assert_called_once_with('1.2.3.4', None, 'transient')

    def test_classifies_durable_herror_as_failure(self):
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=None)
        db.set_rdns_cache = MagicMock()
        e = RDNSEnricher(db=db)
        with patch('enrichment.socket.gethostbyaddr',
                   side_effect=socket.herror(1, 'host not found')):
            assert e.lookup('1.2.3.4') == {'rdns': None}
        db.set_rdns_cache.assert_called_once_with('1.2.3.4', None, 'failure')

    def test_classifies_try_again_herror_as_transient(self):
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=None)
        db.set_rdns_cache = MagicMock()
        e = RDNSEnricher(db=db)
        with patch('enrichment.socket.gethostbyaddr',
                   side_effect=socket.herror(2, 'try again')):
            assert e.lookup('1.2.3.4') == {'rdns': None}
        db.set_rdns_cache.assert_called_once_with('1.2.3.4', None, 'transient')

    def test_classifies_socket_timeout_as_transient(self):
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=None)
        db.set_rdns_cache = MagicMock()
        e = RDNSEnricher(db=db)
        with patch('enrichment.socket.gethostbyaddr', side_effect=socket.timeout()):
            assert e.lookup('1.2.3.4') == {'rdns': None}
        db.set_rdns_cache.assert_called_once_with('1.2.3.4', None, 'transient')

    def test_classifies_bare_oserror_as_transient(self):
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=None)
        db.set_rdns_cache = MagicMock()
        e = RDNSEnricher(db=db)
        with patch('enrichment.socket.gethostbyaddr',
                   side_effect=OSError('network unreachable')):
            assert e.lookup('1.2.3.4') == {'rdns': None}
        db.set_rdns_cache.assert_called_once_with('1.2.3.4', None, 'transient')

    def test_applies_socket_timeout(self):
        """The 2s contract: setdefaulttimeout(self.timeout) before gethostbyaddr."""
        e = RDNSEnricher(timeout=1.25, db=None)
        with patch('enrichment.socket.setdefaulttimeout') as mock_set, \
             patch('enrichment.socket.gethostbyaddr', return_value=('h', [], [])):
            e.lookup('1.2.3.4')
        mock_set.assert_called_with(1.25)


class TestRDNSEnricherHotTierPerStatusTTL:
    def test_hot_tier_honours_transient_ttl_not_global_ttl(self, monkeypatch):
        clock = [1_000_000.0]
        monkeypatch.setattr('enrichment.time.time', lambda: clock[0])

        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=None)
        db.set_rdns_cache = MagicMock()

        e = RDNSEnricher(db=db)
        # Seed transient
        with patch('enrichment.socket.gethostbyaddr', side_effect=socket.timeout()):
            e.lookup('1.2.3.4')
        # Advance past 1h transient TTL but well under 7d (cache ceiling)
        clock[0] += 2 * 3600
        with patch('enrichment.socket.gethostbyaddr', return_value=('h', [], [])) as mock_gha:
            e.lookup('1.2.3.4')
            mock_gha.assert_called_once()  # Stale by status, not by global TTL

    def test_hot_tier_honours_success_ttl(self, monkeypatch):
        clock = [1_000_000.0]
        monkeypatch.setattr('enrichment.time.time', lambda: clock[0])

        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=None)
        db.set_rdns_cache = MagicMock()
        e = RDNSEnricher(db=db)
        with patch('enrichment.socket.gethostbyaddr', return_value=('h', [], [])):
            e.lookup('1.2.3.4')
        clock[0] += 25 * 3600  # 25h — past 24h success TTL
        with patch('enrichment.socket.gethostbyaddr', return_value=('h2', [], [])) as mock_gha:
            e.lookup('1.2.3.4')
            mock_gha.assert_called_once()

    def test_hot_tier_serves_unexpired_transient(self, monkeypatch):
        clock = [1_000_000.0]
        monkeypatch.setattr('enrichment.time.time', lambda: clock[0])

        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=None)
        db.set_rdns_cache = MagicMock()
        e = RDNSEnricher(db=db)
        with patch('enrichment.socket.gethostbyaddr', side_effect=socket.timeout()):
            e.lookup('1.2.3.4')
        clock[0] += 600  # 10 minutes — well under 1h transient TTL
        with patch('enrichment.socket.gethostbyaddr') as mock_gha:
            assert e.lookup('1.2.3.4') == {'rdns': None}
            mock_gha.assert_not_called()


class TestRDNSEnricherShape:
    def test_preserves_public_return_shape_hot(self):
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=None)
        db.set_rdns_cache = MagicMock()
        e = RDNSEnricher(db=db)
        with patch('enrichment.socket.gethostbyaddr', return_value=('h', [], [])):
            e.lookup('1.2.3.4')
        # Now hot hit
        with patch('enrichment.socket.gethostbyaddr'):
            result = e.lookup('1.2.3.4')
        assert result == {'rdns': 'h'}
        assert 'status' not in result
        assert 'expires_at' not in result

    def test_preserves_public_return_shape_db_hit(self):
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=_make_db_row('h', 'success', 60))
        e = RDNSEnricher(db=db)
        result = e.lookup('1.2.3.4')
        assert result == {'rdns': 'h'}
        assert 'status' not in result and 'expires_at' not in result

    def test_failure_shape_is_rdns_none(self):
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=_make_db_row(None, 'failure', 60))
        result = RDNSEnricher(db=db).lookup('1.2.3.4')
        assert result == {'rdns': None}

    def test_db_failure_row_with_stale_hostname_returns_none(self):
        """Defense in depth: even if a non-success row has a stale hostname
        (e.g. from a buggy older write or manual DB edit), the lookup must
        suppress it. Only success rows expose a hostname.
        """
        db = MagicMock()
        # Pathological row: status=failure but hostname is non-null
        db.get_rdns_cache = MagicMock(return_value=_make_db_row('stale.example.com', 'failure', 60))
        e = RDNSEnricher(db=db)
        assert e.lookup('1.2.3.4') == {'rdns': None}
        # Hot tier read-back must also yield None — the stale hostname must
        # not have been cached as the user-facing rdns value.
        with patch('enrichment.socket.gethostbyaddr') as mock_gha:
            assert e.lookup('1.2.3.4') == {'rdns': None}
            mock_gha.assert_not_called()

    def test_db_transient_row_with_stale_hostname_returns_none(self):
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=_make_db_row('stale.example.com', 'transient', 60))
        assert RDNSEnricher(db=db).lookup('1.2.3.4') == {'rdns': None}


class TestRDNSEnricherResilience:
    def test_falls_back_to_memory_when_db_get_raises(self):
        db = MagicMock()
        db.get_rdns_cache = MagicMock(side_effect=RuntimeError('db down'))
        db.set_rdns_cache = MagicMock(side_effect=RuntimeError('db down'))
        e = RDNSEnricher(db=db)
        with patch('enrichment.socket.gethostbyaddr', return_value=('h', [], [])):
            assert e.lookup('1.2.3.4') == {'rdns': 'h'}
        # Hot tier populated; second call serves from memory
        with patch('enrichment.socket.gethostbyaddr') as mock_gha:
            assert e.lookup('1.2.3.4') == {'rdns': 'h'}
            mock_gha.assert_not_called()

    def test_falls_back_to_memory_when_db_set_raises(self):
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=None)
        db.set_rdns_cache = MagicMock(side_effect=RuntimeError('db down'))
        e = RDNSEnricher(db=db)
        with patch('enrichment.socket.gethostbyaddr', return_value=('h', [], [])):
            assert e.lookup('1.2.3.4') == {'rdns': 'h'}
        with patch('enrichment.socket.gethostbyaddr') as mock_gha:
            assert e.lookup('1.2.3.4') == {'rdns': 'h'}
            mock_gha.assert_not_called()

    def test_works_without_db(self):
        e = RDNSEnricher(db=None)
        with patch('enrichment.socket.gethostbyaddr', return_value=('h', [], [])):
            assert e.lookup('1.2.3.4') == {'rdns': 'h'}
        # Hot tier populated
        with patch('enrichment.socket.gethostbyaddr') as mock_gha:
            assert e.lookup('1.2.3.4') == {'rdns': 'h'}
            mock_gha.assert_not_called()


class TestRDNSEnricherConcurrency:
    def test_shared_instance_thread_safe(self):
        """Concurrent lookups must not corrupt the cache; same-IP calls return
        identical results. Duplicate concurrent PTRs are allowed by design
        (no per-key single-flight lock) — see plan Phase 3 concurrency note.
        """
        db = MagicMock()
        db.get_rdns_cache = MagicMock(return_value=None)
        db.set_rdns_cache = MagicMock()

        # Stable mapping per IP — ensures all callers for the same IP see the
        # same hostname even if multiple concurrent live lookups happen.
        def fake_gha(ip):
            return (f'host-{ip}.example.com', [], [])

        e = RDNSEnricher(db=db)
        results = {}
        errors = []
        lock = threading.Lock()

        def worker(ip, key):
            try:
                with patch('enrichment.socket.gethostbyaddr', side_effect=fake_gha):
                    r = e.lookup(ip)
                with lock:
                    results.setdefault(ip, []).append(r)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = []
        # 4 threads on the same IP, 4 on distinct IPs
        for _ in range(4):
            threads.append(threading.Thread(target=worker, args=('1.2.3.4', 'shared')))
        for i in range(4):
            threads.append(threading.Thread(target=worker, args=(f'5.6.7.{i}', f'unique-{i}')))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f'unexpected exceptions: {errors}'
        # All same-IP results identical
        shared = results['1.2.3.4']
        assert len(shared) == 4
        for r in shared:
            assert r == {'rdns': 'host-1.2.3.4.example.com'}


# ── Enricher toggle gates (live + reload) ────────────────────────────────────

class TestEnricherRdnsToggle:
    def _make_enricher(self, monkeypatch, db=None):
        # Disable heavy IO
        monkeypatch.setattr('enrichment.GeoIPEnricher', MagicMock)
        monkeypatch.setattr('enrichment.AbuseIPDBEnricher', MagicMock)
        return Enricher(db=db)

    def test_disabled_via_env_skips_lookup(self, monkeypatch):
        monkeypatch.setenv('RDNS_ENABLED', 'false')
        e = self._make_enricher(monkeypatch, db=None)
        e.rdns = MagicMock()
        e.rdns.lookup = MagicMock()

        parsed = {
            'log_type': 'firewall',
            'src_ip': '8.8.8.8',
            'dst_ip': '192.168.1.5',
            'rule_action': 'allow',
        }
        # Make geoip a no-op
        e.geoip.lookup = MagicMock(return_value={})
        e.enrich(parsed)
        e.rdns.lookup.assert_not_called()
        assert 'rdns' not in parsed

    def test_disabled_via_system_config_skips_lookup(self, monkeypatch):
        # env unset by conftest
        db = MagicMock()
        db.get_config = MagicMock(side_effect=lambda key, default=None: (
            False if key == 'rdns_enabled' else default
        ))
        # Avoid wiring real DB plumbing — patch out helpers used in __init__
        monkeypatch.setattr('enrichment.GeoIPEnricher', MagicMock)
        monkeypatch.setattr('enrichment.AbuseIPDBEnricher', MagicMock)
        # Patch the wan/gateway pre-loaders by stubbing get_wan_ips_from_config
        # on the mock db module path used by enrichment via `from db import ...`
        import db as real_db
        monkeypatch.setattr(real_db, 'get_wan_ips_from_config', lambda _db: [], raising=False)
        # `get_config` is imported lazily inside Enricher.__init__ from db
        monkeypatch.setattr(real_db, 'get_config', lambda _db, key, default=None: (
            False if key == 'rdns_enabled' else default
        ))
        e = Enricher(db=db)
        e.rdns = MagicMock()
        e.rdns.lookup = MagicMock()
        e.geoip.lookup = MagicMock(return_value={})

        parsed = {'log_type': 'firewall', 'src_ip': '8.8.8.8', 'dst_ip': '192.168.1.5',
                  'rule_action': 'allow'}
        e.enrich(parsed)
        e.rdns.lookup.assert_not_called()

    def test_enabled_default_true(self, monkeypatch):
        e = self._make_enricher(monkeypatch, db=None)
        assert e._rdns_enabled is True

    def test_env_overrides_system_config(self, monkeypatch):
        monkeypatch.setenv('RDNS_ENABLED', 'true')
        db = MagicMock()
        db.get_config = MagicMock(return_value=False)
        import db as real_db
        monkeypatch.setattr(real_db, 'get_wan_ips_from_config', lambda _db: [], raising=False)
        monkeypatch.setattr(real_db, 'get_config', lambda _db, key, default=None: (
            False if key == 'rdns_enabled' else default
        ))
        monkeypatch.setattr('enrichment.GeoIPEnricher', MagicMock)
        monkeypatch.setattr('enrichment.AbuseIPDBEnricher', MagicMock)
        e = Enricher(db=db)
        assert e._rdns_enabled is True

    def test_sigusr2_reload_picks_up_db_change(self, monkeypatch):
        # env unset; start enabled then DB flips to false
        import db as real_db
        flag = {'value': True}
        monkeypatch.setattr(real_db, 'get_config', lambda _db, key, default=None: (
            flag['value'] if key == 'rdns_enabled' else default
        ))
        monkeypatch.setattr(real_db, 'get_wan_ips_from_config', lambda _db: [], raising=False)
        monkeypatch.setattr('enrichment.GeoIPEnricher', MagicMock)
        monkeypatch.setattr('enrichment.AbuseIPDBEnricher', MagicMock)
        db = MagicMock()
        e = Enricher(db=db)
        assert e._rdns_enabled is True

        flag['value'] = False
        e.reload_config()
        assert e._rdns_enabled is False


# ── Backfill toggle gate ─────────────────────────────────────────────────────

class TestBackfillRdnsToggle:
    """Drive the actual BackfillTask._fix_wan_ip_enrichment loop and assert
    `RDNSEnricher.lookup` is gated by `enricher._rdns_enabled`. The earlier
    flag-only test would have passed even if the backfill code path still
    called the lookup unconditionally.
    """

    def _make_backfill(self, enricher, rows):
        """Construct a BackfillTask whose DB returns one batch of rows then EOF.

        The fake cursor advances on every execute() rather than sniffing SQL
        text — keeps the test resilient if the SELECT is ever reordered. The
        test patches `extras.execute_batch` to a no-op so UPDATE statements
        never reach this cursor; only SELECTs do.
        """
        from contextlib import contextmanager
        from backfill import BackfillTask

        # First SELECT returns rows, second returns [] (loop exit).
        select_responses = [list(rows), []]
        select_idx = [0]

        class FakeCursor:
            def __init__(self):
                self._last_rows = []

            def execute(self, sql, params=None):
                if select_idx[0] < len(select_responses):
                    self._last_rows = select_responses[select_idx[0]]
                else:
                    self._last_rows = []
                select_idx[0] += 1

            def fetchall(self):
                return self._last_rows

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class FakeConn:
            def cursor(self):
                return FakeCursor()

        @contextmanager
        def get_conn():
            yield FakeConn()

        db = MagicMock()
        db.get_conn = get_conn
        task = BackfillTask(db=db, enricher=enricher)
        return task

    def test_backfill_skips_lookup_when_flag_off(self, monkeypatch):
        # Stub heavy enricher subobjects
        monkeypatch.setattr('enrichment.GeoIPEnricher', MagicMock)
        monkeypatch.setattr('enrichment.AbuseIPDBEnricher', MagicMock)
        monkeypatch.setenv('RDNS_ENABLED', 'false')
        e = Enricher(db=None)
        e.rdns = MagicMock()
        e.rdns.lookup = MagicMock(return_value={'rdns': 'should-not-leak'})
        e.geoip.lookup = MagicMock(return_value={})
        # _is_remote_ip must report True so we reach the gated branch
        monkeypatch.setattr(e, '_is_remote_ip', lambda ip: True)

        # Drive the backfill path
        import db as real_db
        # Gate get_config('enrichment_wan_fix_pending') True, then return WAN IPs
        monkeypatch.setattr(real_db, 'get_config',
                            lambda _db, key, default=None: True if key == 'enrichment_wan_fix_pending' else default,
                            raising=False)
        monkeypatch.setattr(real_db, 'set_config', lambda *a, **kw: None, raising=False)
        monkeypatch.setattr(real_db, 'get_wan_ips_from_config',
                            lambda _db: ['10.0.0.1'], raising=False)
        # Avoid running the post-loop cache-refill/threats refresh paths
        from backfill import extras as backfill_extras
        monkeypatch.setattr(backfill_extras, 'execute_batch', lambda *a, **kw: None)

        task = self._make_backfill(e, rows=[(1, '8.8.8.8'), (2, '1.1.1.1')])
        # Stub out post-update bits we don't care about
        task.db.bulk_upsert_threats = MagicMock(return_value=0)
        # Run the gated backfill
        task._fix_wan_ip_enrichment()
        e.rdns.lookup.assert_not_called()

    def test_backfill_calls_lookup_when_flag_on(self, monkeypatch):
        monkeypatch.setattr('enrichment.GeoIPEnricher', MagicMock)
        monkeypatch.setattr('enrichment.AbuseIPDBEnricher', MagicMock)
        monkeypatch.delenv('RDNS_ENABLED', raising=False)
        e = Enricher(db=None)
        assert e._rdns_enabled is True
        e.rdns = MagicMock()
        e.rdns.lookup = MagicMock(return_value={'rdns': 'h.example.com'})
        e.geoip.lookup = MagicMock(return_value={})
        monkeypatch.setattr(e, '_is_remote_ip', lambda ip: True)

        import db as real_db
        monkeypatch.setattr(real_db, 'get_config',
                            lambda _db, key, default=None: True if key == 'enrichment_wan_fix_pending' else default,
                            raising=False)
        monkeypatch.setattr(real_db, 'set_config', lambda *a, **kw: None, raising=False)
        monkeypatch.setattr(real_db, 'get_wan_ips_from_config',
                            lambda _db: ['10.0.0.1'], raising=False)
        from backfill import extras as backfill_extras
        monkeypatch.setattr(backfill_extras, 'execute_batch', lambda *a, **kw: None)

        task = self._make_backfill(e, rows=[(1, '8.8.8.8')])
        task.db.bulk_upsert_threats = MagicMock(return_value=0)
        task._fix_wan_ip_enrichment()
        e.rdns.lookup.assert_called()
