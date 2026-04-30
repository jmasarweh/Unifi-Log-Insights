"""Tests for the retention-job (re)registration in main.py.

Covers: tagged job creation, replacement on re-register, tag isolation,
Event initial state, and the Event-driven mailbox that keeps `schedule`
mutation on one thread.
"""
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock
import pytest
import schedule


def _time_cfg(time, source='ui'):
    """Shape-compatible stand-in for RetentionTimeConfig — same .time/.source access."""
    return SimpleNamespace(time=time, source=source)


@pytest.fixture(autouse=True)
def reset_schedule():
    schedule.clear()
    yield
    schedule.clear()


@pytest.fixture
def main_module(monkeypatch):
    """Import main.py with heavy deps stubbed."""
    for name in ('parsers', 'enrichment', 'backfill', 'blacklist',
                 'unifi_api', 'pihole_api', 'routes.auth'):
        monkeypatch.setitem(sys.modules, name, MagicMock())

    monkeypatch.delitem(sys.modules, 'main', raising=False)
    import main
    # Replace the Database reference on the module with a fake for isolation.
    main.Database = MagicMock()
    # Also reset the Event in case another test left it set.
    main._retention_reload_requested.clear()
    return main


def test_register_retention_job_creates_tagged_job(main_module):
    db = MagicMock()
    main_module.Database.resolve_retention_time = MagicMock(return_value=_time_cfg('05:17', 'ui'))

    main_module._register_retention_job(db)

    tagged = list(schedule.get_jobs('retention'))
    assert len(tagged) == 1
    assert tagged[0].at_time.hour == 5
    assert tagged[0].at_time.minute == 17  # minute precision preserved


def test_register_retention_job_replaces_existing(main_module):
    db = MagicMock()
    main_module.Database.resolve_retention_time = MagicMock(
        side_effect=[_time_cfg('03:00', 'default'), _time_cfg('18:45', 'ui')])

    main_module._register_retention_job(db)
    assert list(schedule.get_jobs('retention'))[0].at_time.hour == 3

    main_module._register_retention_job(db)
    tagged = list(schedule.get_jobs('retention'))
    assert len(tagged) == 1, 'expected exactly one retention job after re-registration'
    assert tagged[0].at_time.hour == 18
    assert tagged[0].at_time.minute == 45


def test_register_retention_job_does_not_clear_other_tags(main_module):
    db = MagicMock()
    main_module.Database.resolve_retention_time = MagicMock(return_value=_time_cfg('03:00', 'default'))

    # Pre-existing unrelated tagged job
    schedule.every().day.at('04:00').do(lambda: None).tag('blacklist')

    main_module._register_retention_job(db)

    assert len(list(schedule.get_jobs('blacklist'))) == 1
    assert len(list(schedule.get_jobs('retention'))) == 1


def test_reload_request_event_is_initially_unset(main_module):
    # After a fresh import of main, the Event must not be pre-fired.
    assert not main_module._retention_reload_requested.is_set()


def test_scheduler_tick_rebuilds_job_when_event_set(main_module):
    """The critical mailbox contract: setting the Event causes the next
    _scheduler_tick on the scheduler thread to rebuild the retention job.
    """
    db = MagicMock()
    # First call: initial registration at 03:00. Second call: rebuild at 18:45.
    main_module.Database.resolve_retention_time = MagicMock(
        side_effect=[_time_cfg('03:00', 'default'), _time_cfg('18:45', 'ui')])

    main_module._register_retention_job(db)
    assert list(schedule.get_jobs('retention'))[0].at_time.hour == 3

    # Signal handler equivalent (runs on "main thread" in prod)
    main_module._retention_reload_requested.set()

    # Scheduler thread equivalent — one tick
    main_module._scheduler_tick(db)

    tagged = list(schedule.get_jobs('retention'))
    assert len(tagged) == 1
    assert tagged[0].at_time.hour == 18
    assert tagged[0].at_time.minute == 45
    assert not main_module._retention_reload_requested.is_set(), \
        'tick must clear the Event so the job is not rebuilt every tick'


def test_scheduler_tick_is_noop_when_event_unset(main_module):
    """Without the Event set, _scheduler_tick must not re-query retention_time
    or touch the retention job — only run pending scheduled tasks.
    """
    db = MagicMock()
    resolver = MagicMock(return_value=_time_cfg('03:00', 'default'))
    main_module.Database.resolve_retention_time = resolver

    main_module._register_retention_job(db)
    assert resolver.call_count == 1  # from the _register_retention_job call above

    # Event unset — tick must not consult the resolver again
    main_module._scheduler_tick(db)
    assert resolver.call_count == 1, 'resolver must not be called when Event is clear'


# ── rdns_cache retention sweep (issue #98) ──────────────────────────────────

def test_retention_cleanup_invokes_cleanup_rdns_cache(main_module):
    """Each scheduled retention pass must also sweep rdns_cache."""
    db = MagicMock()
    main_module.Database.resolve_retention_days = MagicMock(
        return_value=SimpleNamespace(general=60, dns=10))
    db.run_retention_cleanup = MagicMock(return_value={
        'status': 'complete', 'deleted_so_far': 0, 'error': None,
    })
    db.cleanup_rdns_cache = MagicMock(return_value=0)

    main_module._retention_cleanup(db)

    db.cleanup_rdns_cache.assert_called_once_with()


def test_retention_cleanup_logs_nonzero_rdns_sweep(main_module, caplog):
    import logging
    db = MagicMock()
    main_module.Database.resolve_retention_days = MagicMock(
        return_value=SimpleNamespace(general=60, dns=10))
    db.run_retention_cleanup = MagicMock(return_value={
        'status': 'complete', 'deleted_so_far': 0, 'error': None,
    })
    db.cleanup_rdns_cache = MagicMock(return_value=42)

    with caplog.at_level(logging.INFO):
        main_module._retention_cleanup(db)

    assert any('rdns_cache retention sweep deleted 42' in rec.message
               for rec in caplog.records)


def test_retention_cleanup_rdns_failure_isolated_from_log_retention(main_module, caplog):
    """An rdns_cache sweep error must not be misreported as log-retention failure."""
    import logging
    db = MagicMock()
    main_module.Database.resolve_retention_days = MagicMock(
        return_value=SimpleNamespace(general=60, dns=10))
    db.run_retention_cleanup = MagicMock(return_value={
        'status': 'complete', 'deleted_so_far': 100, 'error': None,
    })
    db.cleanup_rdns_cache = MagicMock(side_effect=RuntimeError('db gone'))

    with caplog.at_level(logging.WARNING):
        main_module._retention_cleanup(db)

    # Log retention reported success (no error/warning about it)
    log_retention_errors = [r for r in caplog.records
                            if r.levelno >= logging.ERROR
                            and 'Retention cleanup failed' in r.message]
    assert log_retention_errors == []
    # rdns sweep failure logged as WARNING
    assert any(r.levelno == logging.WARNING and 'rdns_cache retention sweep failed' in r.message
               for r in caplog.records)
