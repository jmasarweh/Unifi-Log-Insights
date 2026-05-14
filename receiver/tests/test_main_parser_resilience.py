"""Tests for SyslogReceiver._handle_message resilience to malformed packets.

Security context: UDP/514 is bound to all interfaces (`::`) and accepts
packets from any source. Before this fix, an unhandled exception in
parse_log or enricher.enrich would crash the receiver thread, allowing a
one-packet remote DoS. The handler now wraps the critical section in
try/except and rate-limits the warning log so a sustained attack cannot
fill the disk with warnings.

Findings addressed:
- C4 (Gemini VULN-001) — malformed packet → receiver thread crash
"""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def receiver(monkeypatch):
    """Build a SyslogReceiver with heavy deps stubbed.

    Mirrors test_main_retention_scheduler.py's main_module fixture: deps.py
    runs wait_for_postgres() at import time, which blocks for 30 retries when
    no DB is reachable. We stub the offending modules in sys.modules before
    `import main`. We keep the REAL `parsers` module so test_malformed_timestamp
    exercises the actual datetime() crash path.
    """
    import sys
    for name in ('enrichment', 'backfill', 'blacklist',
                 'unifi_api', 'pihole_api', 'routes.auth', 'deps', 'db'):
        monkeypatch.setitem(sys.modules, name, MagicMock())

    monkeypatch.delitem(sys.modules, 'main', raising=False)
    from main import SyslogReceiver

    db = MagicMock()
    db.get_config = MagicMock(return_value=True)
    enricher = MagicMock()
    enricher.enrich = MagicMock(side_effect=lambda p: p)

    r = SyslogReceiver(db, enricher)
    r._disabled_log_types = set()
    return r


class TestHandleMessageResilience:
    def test_malformed_timestamp_does_not_raise(self, receiver):
        # "Feb 99 99:99:99 host body" — passes the SYSLOG_HEADER regex but
        # the components are out of range. Before the fix, datetime() raised
        # ValueError and that propagated up out of _handle_message.
        data = b"Feb 99 99:99:99 host kernel: anything"
        # Must not raise.
        receiver._handle_message(data, ('1.2.3.4', 1234))
        # The malformed packet should be counted as 'failed' (parse_log
        # returns None when the timestamp is unparseable).
        assert receiver.stats['failed'] >= 1

    def test_parse_log_raising_is_swallowed(self, receiver, monkeypatch):
        # Defense-in-depth: even if parse_log itself raises an unexpected
        # exception (e.g. future regression in a downstream parser), the
        # handler must not propagate.
        import main as main_module
        monkeypatch.setattr(main_module, 'parse_log',
                            MagicMock(side_effect=RuntimeError("simulated parser bug")))

        data = b"Feb  8 16:43:49 host kernel: anything"
        receiver._handle_message(data, ('1.2.3.4', 1234))

        assert receiver.stats['parse_exceptions'] == 1
        # Receiver state is otherwise normal — batch is unaffected.
        assert receiver.batch == []

    def test_enricher_raising_is_swallowed(self, receiver, monkeypatch):
        # If enricher.enrich raises, we must catch it. Same threat model.
        receiver.enricher.enrich = MagicMock(side_effect=RuntimeError("simulated enricher bug"))

        # Use a syslog header the real parser accepts so we reach enrich().
        data = b"Feb  8 16:43:49 host kernel: [WAN_IN-B] IN=ppp0 OUT=br20 SRC=1.2.3.4 DST=10.0.0.5 PROTO=TCP SPT=1234 DPT=80"
        receiver._handle_message(data, ('1.2.3.4', 1234))

        assert receiver.stats['parse_exceptions'] == 1

    def test_burst_of_bad_packets_logs_bounded_warnings(self, receiver, monkeypatch, caplog):
        # An attacker sending 1000 malformed packets must not produce 1000
        # WARNING log entries (which would fill the disk).
        import main as main_module
        monkeypatch.setattr(main_module, 'parse_log',
                            MagicMock(side_effect=RuntimeError("boom")))

        import logging
        with caplog.at_level(logging.WARNING, logger='__main__'):
            for _ in range(1000):
                receiver._handle_message(b"any payload", ('1.2.3.4', 1234))

        assert receiver.stats['parse_exceptions'] == 1000
        # Rate-limited at 1-per-100 starting from the first: expect ~10 warnings.
        warning_records = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert 1 <= len(warning_records) <= 12, \
            f"expected ~10 rate-limited warnings, got {len(warning_records)}"

    def test_normal_packet_after_bad_packet_still_works(self, receiver):
        # Send a malformed packet, then a normal one. State must not be
        # corrupted; the normal packet should be parsed and batched.
        bad = b"Feb 99 99:99:99 host kernel: junk"
        good = b"Feb  8 16:43:49 host kernel: [WAN_IN-B] IN=ppp0 OUT=br20 SRC=1.2.3.4 DST=10.0.0.5 PROTO=TCP SPT=1234 DPT=80"

        receiver._handle_message(bad, ('attacker', 1234))
        receiver._handle_message(good, ('gateway', 514))

        # The good packet should have been parsed and added to the batch.
        assert receiver.stats['parsed'] >= 1
        assert len(receiver.batch) >= 1
