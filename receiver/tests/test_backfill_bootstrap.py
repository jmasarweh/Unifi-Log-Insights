"""Tests for backfill._reenrich_stale_threats bootstrap allowance (Patch 2).

When the AbuseIPDB rate-limit state has never been populated
(_rate_limit_remaining is None), remaining_budget returns 0 — but the
enricher's _check_rate_limit will still permit exactly one call. The
re-enrichment loop must take that path to bootstrap state on a fresh
install, mirroring _process_queue.
"""

from unittest.mock import MagicMock

import pytest

import backfill


def _make_task(rate_limit_remaining, stale_ips):
    db = MagicMock()
    db.get_stale_threat_candidates = MagicMock(return_value=list(stale_ips))
    # get_conn / cursor for the UPDATE ip_threats path
    conn = MagicMock()
    cursor = MagicMock()
    conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
    conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    db.get_conn.return_value.__enter__ = MagicMock(return_value=conn)
    db.get_conn.return_value.__exit__ = MagicMock(return_value=False)

    enricher = MagicMock()
    abuseipdb = MagicMock()
    abuseipdb.enabled = True
    abuseipdb._rate_limit_remaining = rate_limit_remaining
    abuseipdb.remaining_budget = 0  # bootstrap state: budget always reports 0 if remaining is None
    abuseipdb.cache = MagicMock()
    # lookup returns a result with threat_score so the loop counts it as a hit.
    abuseipdb.lookup = MagicMock(return_value={'threat_score': 50})
    enricher.abuseipdb = abuseipdb
    enricher.geoip = MagicMock()
    enricher.rdns = MagicMock()

    task = backfill.BackfillTask(db, enricher)
    return task, abuseipdb


class TestReenrichStaleBootstrap:
    def test_bootstrap_when_rate_limit_unknown_makes_one_call(self, monkeypatch):
        monkeypatch.setattr(backfill, 'get_service_mappings', MagicMock(return_value={}))
        # No sleep in tests
        monkeypatch.setattr(backfill.time, 'sleep', lambda *_: None)
        # Avoid touching db helper
        import sys as _sys
        fake_db_mod = MagicMock()
        fake_db_mod.get_wan_ips_from_config = MagicMock(return_value=[])
        monkeypatch.setitem(_sys.modules, 'db', fake_db_mod)

        task, abuseipdb = _make_task(rate_limit_remaining=None, stale_ips=['1.1.1.1'])

        task._reenrich_stale_threats()

        assert abuseipdb.lookup.call_count == 1, "bootstrap must call lookup exactly once"

    def test_real_exhaustion_makes_zero_calls(self, monkeypatch):
        monkeypatch.setattr(backfill, 'get_service_mappings', MagicMock(return_value={}))
        monkeypatch.setattr(backfill.time, 'sleep', lambda *_: None)
        import sys as _sys
        fake_db_mod = MagicMock()
        fake_db_mod.get_wan_ips_from_config = MagicMock(return_value=[])
        monkeypatch.setitem(_sys.modules, 'db', fake_db_mod)

        task, abuseipdb = _make_task(rate_limit_remaining=0, stale_ips=['1.1.1.1', '2.2.2.2'])

        result = task._reenrich_stale_threats()

        assert result == 0
        assert abuseipdb.lookup.call_count == 0, "real exhaustion must NOT call lookup"
