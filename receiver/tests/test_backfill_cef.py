"""Tests for the one-shot CEF parser backfill in ``backfill.py``.

Mirrors the in-process style used by the other backfill tests (see
``TestBackfillRdnsToggle`` in ``test_enrichment.py``): we mock ``db``
at the Database-method boundary rather than the cursor level, so the
tests assert *behaviour* (which batch was requested, which updates
were applied) rather than coupling to SQL text.
"""

from unittest.mock import MagicMock

import pytest

from backfill import BackfillTask


# Real-world CEF threat as it would be stored in ``raw_log``:
# a full RFC3164 syslog line containing a Network 10.x SIEM-Server
# CEF threat event (DShield Block List, ECID 201, ``incoming``).
SAMPLE_CEF_RAW = (
    'May 14 13:51:35 UDMPRO '
    'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected and Blocked|7|'
    'src=176.65.148.67 dst=192.168.200.56 proto=UDP spt=123 dpt=64280 '
    'act=blocked UNIFIrisk=medium UNIFIpolicyName=DShield Block List '
    'UNIFIpolicyType=IDS/IPS UNIFIdirection=incoming UNIFIsrcRegion=NL '
    'UNIFIipsSignature=ET DROP Dshield Block Listed Source group 1'
)


@pytest.fixture
def task():
    """Build a ``BackfillTask`` with all DB methods mocked.

    Tests configure ``cef_parser_backfill_batch.return_value`` per case
    and inspect what was passed to ``patch_cef_parsed_logs``.
    """
    db = MagicMock()
    enricher = MagicMock()
    enricher.abuseipdb.enabled = False
    enricher.enrich.side_effect = lambda parsed, **_kwargs: parsed
    return BackfillTask(db=db, enricher=enricher)


@pytest.fixture
def config_store(monkeypatch):
    """Replace ``db.get_config`` / ``db.set_config`` with an in-memory dict.

    Returns the dict so tests can pre-seed gate flags and assert that
    the backfill writes the cursor and done-flag correctly.
    """
    import db as db_module
    store: dict = {}

    def fake_get(_db, key, default=None):
        return store.get(key, default)

    def fake_set(_db, key, value):
        store[key] = value

    monkeypatch.setattr(db_module, 'get_config', fake_get, raising=False)
    monkeypatch.setattr(db_module, 'set_config', fake_set, raising=False)
    return store


class TestBackfillCefParser:
    """Functional tests for ``BackfillTask._backfill_cef_parser``."""

    def test_gate_when_done_returns_early(self, task, config_store):
        """Once ``cef_parser_backfill_done=True``, the backfill no-ops.

        This is the idempotency contract: a deploy of UIP after the
        backfill completed must not re-scan the entire ``logs`` table.
        """
        config_store['cef_parser_backfill_done'] = True

        task._backfill_cef_parser()

        task.db.cef_parser_backfill_batch.assert_not_called()
        task.db.patch_cef_parsed_logs.assert_not_called()

    def test_empty_batch_marks_done(self, task, config_store):
        """When the DB returns no candidate rows, the done flag is set so
        subsequent cycles short-circuit on the gate above."""
        task.db.cef_parser_backfill_batch.return_value = []

        task._backfill_cef_parser()

        assert config_store.get('cef_parser_backfill_done') is True
        # No updates attempted on an empty batch.
        task.db.patch_cef_parsed_logs.assert_not_called()

    def test_parses_and_patches_real_threat(self, task, config_store):
        """Happy path: a real CEF threat row is parsed, enriched, and
        submitted to ``patch_cef_parsed_logs`` with all expected
        structural fields. ``enricher.enrich`` is called in local-only mode
        so geo / ASN / rDNS / remote_ip populate without synchronous
        AbuseIPDB API calls — without this, Threat Map (which filters on
        ``geo_lat IS NOT NULL``) would miss the backfilled rows."""
        task.db.cef_parser_backfill_batch.return_value = [(42, SAMPLE_CEF_RAW)]
        task.db.patch_cef_parsed_logs.return_value = 1

        task._backfill_cef_parser()

        # The DB was asked for the next batch starting after id=0.
        task.db.cef_parser_backfill_batch.assert_called_once()
        called_last_id = task.db.cef_parser_backfill_batch.call_args[0][0]
        assert called_last_id == 0

        # Each parsed row was run through local enrichment (geo_*, asn_*,
        # rdns, remote_ip) without synchronous AbuseIPDB lookups. Without
        # this call, historical CEF rows never appear on the Threat Map.
        task.enricher.enrich.assert_called_once()
        assert task.enricher.enrich.call_args.kwargs == {'include_threat': False}

        # Exactly one update submitted, for row 42, with the expected fields.
        task.db.patch_cef_parsed_logs.assert_called_once()
        (updates,), _ = task.db.patch_cef_parsed_logs.call_args
        assert len(updates) == 1
        row_id, parsed = updates[0]
        assert row_id == 42
        assert parsed['log_type'] == 'firewall'
        assert parsed['src_ip'] == '176.65.148.67'
        assert parsed['dst_ip'] == '192.168.200.56'
        assert parsed['rule_action'] == 'block'
        assert parsed['geo_country'] == 'NL'
        assert parsed['threat_score'] == 60  # medium → 60

        # Cursor advanced to the highest id processed.
        assert config_store.get('cef_parser_backfill_last_id') == 42
        # Not yet marked done — there might be more on the next cycle.
        assert config_store.get('cef_parser_backfill_done') is None

    def test_enriched_remote_ip_is_enqueued_for_deferred_abuseipdb(self, task, config_store):
        """CEF backfill must not perform synchronous AbuseIPDB lookups, but it
        should still feed the normal deferred queue once local enrichment has
        identified the remote IP."""
        task.enricher.abuseipdb.enabled = True
        task.db.cef_parser_backfill_batch.return_value = [(42, SAMPLE_CEF_RAW)]
        task.db.patch_cef_parsed_logs.return_value = 1

        def fake_enrich(parsed, *, include_threat=True):
            assert include_threat is False
            parsed['remote_ip'] = parsed['src_ip']
            parsed['geo_lat'] = 52.3676
            parsed['geo_lon'] = 4.9041
            return parsed

        task.enricher.enrich.side_effect = fake_enrich

        task._backfill_cef_parser()

        task.db.enqueue_threat_backfill.assert_called_once_with(
            '176.65.148.67',
            source='cef_backfill',
        )
        (updates,), _ = task.db.patch_cef_parsed_logs.call_args
        assert updates[0][1]['remote_ip'] == '176.65.148.67'
        assert updates[0][1]['geo_lat'] == 52.3676

    def test_cursor_resumes_from_persisted_last_id(self, task, config_store):
        """An interrupted backfill resumes from the persisted cursor
        rather than re-scanning from id=0."""
        config_store['cef_parser_backfill_last_id'] = 1000
        task.db.cef_parser_backfill_batch.return_value = []

        task._backfill_cef_parser()

        # The query was issued with last_id=1000, not 0.
        called_last_id = task.db.cef_parser_backfill_batch.call_args[0][0]
        assert called_last_id == 1000

    def test_non_threat_row_is_skipped(self, task, config_store):
        """Defensive: if a row passes the SQL regex pre-filter but
        ``parse_cef_threat`` returns ``None`` (e.g. malformed extensions or
        foreign-vendor CEF that slipped through), it is silently
        skipped and not included in the update batch."""
        # An audit CEF event masquerading at an unexpected position —
        # ``parse_cef_threat`` will reject it (ECID 5xx, not threat-class).
        non_threat = (
            'May 14 00:59:56 UDMPRO '
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|546|Config Modified|5|'
            'UNIFIcategory=Audit src=192.168.200.144'
        )
        task.db.cef_parser_backfill_batch.return_value = [
            (10, SAMPLE_CEF_RAW),
            (11, non_threat),
        ]

        task._backfill_cef_parser()

        # Only the real threat made it into the update batch.
        (updates,), _ = task.db.patch_cef_parsed_logs.call_args
        assert len(updates) == 1
        assert updates[0][0] == 10

        # Cursor still advances past *both* rows so they don't come back
        # on the next cycle — they've been examined and rejected.
        assert config_store.get('cef_parser_backfill_last_id') == 11

    def test_missing_cef_marker_in_raw_log_is_skipped(self, task, config_store):
        """Truly pathological: ``raw_log`` matched the regex (perhaps via
        a future Postgres bug or a copy-paste in the column) but doesn't
        actually contain ``CEF:0|Ubiquiti|``. The parser must not crash."""
        task.db.cef_parser_backfill_batch.return_value = [
            (1, 'May 14 13:00:00 UDMPRO syslog: not actually a CEF line'),
        ]

        task._backfill_cef_parser()

        # No updates submitted, cursor still advances.
        task.db.patch_cef_parsed_logs.assert_not_called()
        assert config_store.get('cef_parser_backfill_last_id') == 1

    def test_full_batch_does_not_mark_done(self, task, config_store):
        """If the batch is full (size N), there may be more rows pending
        — done flag must NOT be set yet, the cursor advances for the
        next cycle to pick up where this one left off."""
        from backfill import CEF_PARSER_BATCH_SIZE

        # Build N+ rows so the batch comes back at max size.
        rows = [(i, SAMPLE_CEF_RAW) for i in range(1, CEF_PARSER_BATCH_SIZE + 1)]
        task.db.cef_parser_backfill_batch.return_value = rows
        task.db.patch_cef_parsed_logs.return_value = CEF_PARSER_BATCH_SIZE

        task._backfill_cef_parser()

        # Cursor at the last row, but NOT done.
        assert config_store.get('cef_parser_backfill_last_id') == CEF_PARSER_BATCH_SIZE
        assert config_store.get('cef_parser_backfill_done') is None
