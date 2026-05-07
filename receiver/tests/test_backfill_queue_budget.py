"""Regression tests for queue-budget gating (issue #103)."""

from types import SimpleNamespace
import sys
from unittest.mock import MagicMock

from backfill import BackfillTask, QUEUE_BATCH_SIZE


def _make_task(*, budget: int, enabled: bool, rate_limit_remaining):
    db = MagicMock()
    enricher = MagicMock()

    abuseipdb = MagicMock()
    abuseipdb.remaining_budget = budget
    abuseipdb.enabled = enabled
    abuseipdb._rate_limit_remaining = rate_limit_remaining

    enricher.abuseipdb = abuseipdb
    enricher.geoip = MagicMock()
    enricher.rdns = MagicMock()

    return BackfillTask(db=db, enricher=enricher), db


def test_process_queue_skips_db_pull_when_budget_exhausted(monkeypatch):
    task, db = _make_task(budget=0, enabled=True, rate_limit_remaining=0)

    # _process_queue imports this helper lazily from `db`.
    monkeypatch.setitem(
        sys.modules,
        'db',
        SimpleNamespace(get_wan_ips_from_config=lambda _db: []),
    )

    task._process_queue()

    db.pull_due_queue_batch.assert_not_called()


def test_process_queue_pulls_when_bootstrap_allowed(monkeypatch):
    task, db = _make_task(budget=0, enabled=True, rate_limit_remaining=None)
    db.pull_due_queue_batch.return_value = []

    monkeypatch.setitem(
        sys.modules,
        'db',
        SimpleNamespace(get_wan_ips_from_config=lambda _db: []),
    )

    task._process_queue()

    db.pull_due_queue_batch.assert_called_once_with(limit=QUEUE_BATCH_SIZE)


def test_process_queue_pulls_when_budget_available(monkeypatch):
    """Verify that queue is pulled when budget is positive (normal path)."""
    task, db = _make_task(budget=5, enabled=True, rate_limit_remaining=50)
    db.pull_due_queue_batch.return_value = []

    monkeypatch.setitem(
        sys.modules,
        'db',
        SimpleNamespace(get_wan_ips_from_config=lambda _db: []),
    )

    task._process_queue()

    db.pull_due_queue_batch.assert_called_once_with(limit=QUEUE_BATCH_SIZE)
