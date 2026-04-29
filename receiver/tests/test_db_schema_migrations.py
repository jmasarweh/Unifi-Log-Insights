"""Regression tests for db.py schema migration coordination."""

import inspect
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import db as db_module
from db import Database


class FakeCursor:
    """Minimal cursor stub that records SQL and can inject failures."""

    def __init__(self, fetches=None, on_execute=None):
        self.fetches = list(fetches or [])
        self.on_execute = on_execute
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        if self.on_execute:
            self.on_execute(sql, params, len(self.executed) - 1)

    def fetchone(self):
        if self.fetches:
            return self.fetches.pop(0)
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeConn:
    """Connection stub that returns scripted cursors in order."""

    def __init__(self, cursors):
        self._cursors = list(cursors)

    def cursor(self):
        if not self._cursors:
            raise AssertionError("No scripted cursor available for this call")
        return self._cursors.pop(0)


class FakeUniqueViolation(Exception):
    """Patchable UniqueViolation replacement with a psycopg-like diag object."""

    def __init__(self, message, primary=None, constraint_name=None):
        super().__init__(message)
        self.diag = SimpleNamespace(
            message_primary=primary or message,
            constraint_name=constraint_name,
        )


def _make_database(monkeypatch, cursors, logger=None):
    """Create a Database instance with schema side effects stubbed out."""

    database = Database(conn_params={'user': 'unifi'})

    @contextmanager
    def fake_get_conn():
        yield FakeConn(cursors)

    monkeypatch.setattr(database, 'get_conn', fake_get_conn)
    monkeypatch.setattr(database, '_backfill_tz_timestamps', MagicMock())
    if logger is None:
        logger = MagicMock()
    monkeypatch.setattr(db_module, 'logger', logger)
    return database, logger


def _validation_cursor():
    """Validation cursor with truthy responses for table/index checks.

    Order: logs table, idx_logs_timestamp, threat_backfill_queue table,
    ip_threats.last_seen_at column, ip_threats.last_seen_at column_default,
    idx_logs_fw_block_null_threat_src index, rdns_cache table.
    """
    return FakeCursor(fetches=[
        (1,),
        (1,),
        (1,),
        (1,),
        ("now()",),
        (1,),
        (1,),
    ])


def test_ensure_schema_uses_transaction_scoped_advisory_lock(monkeypatch):
    migration_cursor = FakeCursor()
    database, _logger = _make_database(
        monkeypatch,
        [migration_cursor, _validation_cursor()],
    )

    database._ensure_schema()

    executed_sql = [sql for sql, _params in migration_cursor.executed]
    assert executed_sql[0] == "SELECT pg_advisory_xact_lock(20250314)"
    assert "SELECT pg_try_advisory_lock(20250314)" not in executed_sql
    assert "SELECT pg_advisory_unlock(20250314)" not in executed_sql
    assert any(sql.startswith("SAVEPOINT sp_0") for sql in executed_sql)
    database._backfill_tz_timestamps.assert_called_once_with()


def test_ensure_schema_has_known_pg_type_race_guard():
    source = inspect.getsource(Database._ensure_schema)

    assert "pg_advisory_xact_lock(20250314)" in source
    assert 'e.diag.constraint_name and "pg_type" in e.diag.constraint_name' in source
    assert "SELECT pg_try_advisory_lock(20250314)" not in source


def test_ensure_schema_skips_known_pg_type_race(monkeypatch):
    raised = False

    def on_execute(sql, _params, _idx):
        nonlocal raised
        if not raised and "CREATE TABLE IF NOT EXISTS logs" in sql:
            raised = True
            raise FakeUniqueViolation(
                'duplicate key value violates unique constraint "pg_type_typname_nsp_index"',
                'duplicate key value violates unique constraint "pg_type_typname_nsp_index"',
                constraint_name='pg_type_typname_nsp_index',
            )

    migration_cursor = FakeCursor(on_execute=on_execute)
    database, logger = _make_database(
        monkeypatch,
        [migration_cursor, _validation_cursor()],
    )
    monkeypatch.setattr(db_module.psycopg2.errors, 'UniqueViolation', FakeUniqueViolation)

    database._ensure_schema()

    executed_sql = [sql for sql, _params in migration_cursor.executed]
    assert "ROLLBACK TO SAVEPOINT sp_0" in executed_sql
    assert "SAVEPOINT sp_1" in executed_sql
    logger.critical.assert_not_called()
    logger.info.assert_any_call(
        "Schema type already exists, skipping: %s",
        'duplicate key value violates unique constraint "pg_type_typname_nsp_index"',
    )


def test_ensure_schema_exits_when_last_seen_at_has_no_default(monkeypatch):
    """Boot must abort if ip_threats.last_seen_at exists but has no DEFAULT.

    This catches the InsufficientPrivilege edge case where ALTER COLUMN
    SET DEFAULT is silently skipped, leaving bulk_upsert_threats() inserting
    NULLs into last_seen_at.
    """
    validation_cursor = FakeCursor(fetches=[
        (1,),                                                  # logs table
        (1,),                                                  # idx_logs_timestamp
        (1,),                                                  # threat_backfill_queue
        (1,),                                                  # last_seen_at column exists
        (None,),                                               # column_default is NULL
    ])
    migration_cursor = FakeCursor()
    database, logger = _make_database(
        monkeypatch,
        [migration_cursor, validation_cursor],
    )

    with pytest.raises(SystemExit) as exc:
        database._ensure_schema()

    assert exc.value.code == 1
    logger.critical.assert_called_once()
    assert "no DEFAULT" in logger.critical.call_args[0][0]


def test_ensure_post_boot_indexes_skips_if_exists(monkeypatch):
    """ensure_post_boot_indexes() does nothing when the index already exists."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = (1,)  # index exists
    mock_cursor.__enter__ = lambda s: s
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cursor

    database = Database(conn_params={'user': 'unifi'})
    monkeypatch.setattr('db.psycopg2.connect', lambda **kw: mock_conn)

    database.ensure_post_boot_indexes()

    # Should query pg_indexes but NOT run CREATE INDEX
    assert any('pg_indexes' in str(c) for c in mock_cursor.execute.call_args_list)
    executed_sql = ' '.join(str(c) for c in mock_cursor.execute.call_args_list)
    assert 'CREATE INDEX' not in executed_sql


def test_ensure_post_boot_indexes_creates_when_missing(monkeypatch):
    """ensure_post_boot_indexes() creates all indexes when they don't exist."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None  # all indexes missing
    mock_cursor.__enter__ = lambda s: s
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cursor

    database = Database(conn_params={'user': 'unifi'})
    monkeypatch.setattr('db.psycopg2.connect', lambda **kw: mock_conn)

    database.ensure_post_boot_indexes()

    executed_sql = ' '.join(str(c) for c in mock_cursor.execute.call_args_list)
    assert 'CREATE INDEX CONCURRENTLY' in executed_sql
    assert 'spgist' in executed_sql.lower()
    assert 'idx_logs_type_id' in executed_sql
    assert 'idx_logs_nondns_timestamp' in executed_sql
    assert mock_conn.autocommit is True


def test_ensure_post_boot_indexes_warns_on_failure(monkeypatch):
    """ensure_post_boot_indexes() logs a warning and continues on failure."""
    database = Database(conn_params={'user': 'unifi'})
    monkeypatch.setattr('db.psycopg2.connect',
                        MagicMock(side_effect=Exception("connect failed")))
    mock_logger = MagicMock()
    monkeypatch.setattr(db_module, 'logger', mock_logger)

    # Should not raise
    database.ensure_post_boot_indexes()

    mock_logger.warning.assert_called_once()
    assert 'connect' in mock_logger.warning.call_args[0][0]


def test_ensure_post_boot_indexes_continues_after_single_failure(monkeypatch):
    """If one index fails, remaining indexes are still attempted."""
    mock_conn = MagicMock()
    call_count = [0]

    def execute_side_effect(sql, params=None):
        nonlocal call_count
        call_count[0] += 1
        if isinstance(sql, str) and 'pg_indexes' in sql:
            return  # fetchone returns None (index missing)
        if isinstance(sql, str) and 'idx_logs_type_id' in sql:
            raise Exception("simulated CREATE INDEX failure")

    mock_cursor = MagicMock()
    mock_cursor.execute = MagicMock(side_effect=execute_side_effect)
    mock_cursor.fetchone.return_value = None  # all indexes missing
    mock_cursor.__enter__ = lambda s: s
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cursor

    database = Database(conn_params={'user': 'unifi'})
    monkeypatch.setattr('db.psycopg2.connect', lambda **kw: mock_conn)
    mock_logger = MagicMock()
    monkeypatch.setattr(db_module, 'logger', mock_logger)

    database.ensure_post_boot_indexes()

    # Should have warned about the failed index
    warning_calls = [c for c in mock_logger.warning.call_args_list
                     if 'idx_logs_type_id' in str(c)]
    assert len(warning_calls) == 1
    # Should have attempted all 3 indexes (check + create for each = 6 execute calls,
    # minus the one that failed mid-create). Just verify more than 2 execute calls
    # happened, proving it didn't stop at the first failure.
    assert call_count[0] >= 4  # at least 2 indexes attempted beyond the failed one


def test_ensure_schema_does_not_contain_concurrent_ddl():
    """_ensure_schema() must not contain CONCURRENTLY — that belongs in
    ensure_post_boot_indexes() only."""
    source = inspect.getsource(Database._ensure_schema)
    assert 'CONCURRENTLY' not in source


def test_ensure_schema_exits_on_unrelated_unique_violation(monkeypatch):
    def on_execute(sql, _params, _idx):
        if "CREATE TABLE IF NOT EXISTS logs" in sql:
            raise FakeUniqueViolation(
                'duplicate key value violates unique constraint "saved_views_name_key"',
                'duplicate key value violates unique constraint "saved_views_name_key"',
                constraint_name='saved_views_name_key',
            )

    migration_cursor = FakeCursor(on_execute=on_execute)
    database, logger = _make_database(monkeypatch, [migration_cursor])
    monkeypatch.setattr(db_module.psycopg2.errors, 'UniqueViolation', FakeUniqueViolation)

    with pytest.raises(SystemExit) as exc:
        database._ensure_schema()

    executed_sql = [sql for sql, _params in migration_cursor.executed]
    assert exc.value.code == 1
    assert "ROLLBACK TO SAVEPOINT sp_0" in executed_sql
    logger.critical.assert_called_once_with("Schema migration failed", exc_info=True)
    database._backfill_tz_timestamps.assert_not_called()


# ── Post-boot index list ─────────────────────────────────────────────────────

def test_post_boot_index_list_has_expected_entries():
    """_POST_BOOT_INDEXES contains all expected upgrade indexes."""
    names = {idx['name'] for idx in Database._POST_BOOT_INDEXES}
    assert 'idx_logs_spgist_dst_ip_firewall' in names
    assert 'idx_logs_type_id' in names
    assert 'idx_logs_nondns_timestamp' in names


def test_post_boot_indexes_all_use_concurrently():
    """Every post-boot index SQL must use CONCURRENTLY."""
    for idx in Database._POST_BOOT_INDEXES:
        assert 'CONCURRENTLY' in idx['sql'], f"{idx['name']} missing CONCURRENTLY"


# ── Post-boot drops (issue #85) ──────────────────────────────────────────────

def test_post_boot_drops_list_has_expected_entries():
    """_POST_BOOT_DROPS contains the two redundant leftmost-prefix indexes."""
    names = {name for name, _sql in Database._POST_BOOT_DROPS}
    assert names == {'idx_logs_type', 'idx_logs_rule_action'}


def test_post_boot_drops_all_use_concurrently_and_if_exists():
    """Every drop SQL must be CONCURRENTLY + IF EXISTS (idempotent, safe)."""
    for _name, sql in Database._POST_BOOT_DROPS:
        assert 'DROP INDEX CONCURRENTLY IF EXISTS' in sql


def test_post_boot_drops_executed(monkeypatch):
    """ensure_post_boot_indexes() issues DROP IF EXISTS for each redundant index."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = (1,)  # creates skipped (already exist)
    mock_cursor.__enter__ = lambda s: s
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cursor

    database = Database(conn_params={'user': 'unifi'})
    monkeypatch.setattr('db.psycopg2.connect', lambda **kw: mock_conn)

    database.ensure_post_boot_indexes()

    executed_sql = ' '.join(str(c) for c in mock_cursor.execute.call_args_list)
    assert 'DROP INDEX CONCURRENTLY IF EXISTS idx_logs_type' in executed_sql
    assert 'DROP INDEX CONCURRENTLY IF EXISTS idx_logs_rule_action' in executed_sql


def test_post_boot_drops_set_lock_timeout_before_drops(monkeypatch):
    """SET lock_timeout must be issued before any DROP INDEX to bound startup stall."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = (1,)  # creates skipped
    mock_cursor.__enter__ = lambda s: s
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cursor

    database = Database(conn_params={'user': 'unifi'})
    monkeypatch.setattr('db.psycopg2.connect', lambda **kw: mock_conn)

    database.ensure_post_boot_indexes()

    executed = [str(c) for c in mock_cursor.execute.call_args_list]
    lock_timeout_idx = next(i for i, s in enumerate(executed) if 'lock_timeout' in s)
    first_drop_idx = next(i for i, s in enumerate(executed) if 'DROP INDEX' in s)
    assert lock_timeout_idx < first_drop_idx


def test_post_boot_drops_skipped_if_set_lock_timeout_fails(monkeypatch):
    """If SET lock_timeout fails, drops are skipped entirely and a warning is logged."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = (1,)  # creates skipped

    def execute_side_effect(sql, params=None):
        if 'lock_timeout' in str(sql):
            raise Exception("simulated SET failure")

    mock_cursor.execute.side_effect = execute_side_effect
    mock_cursor.__enter__ = lambda s: s
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cursor

    database = Database(conn_params={'user': 'unifi'})
    monkeypatch.setattr('db.psycopg2.connect', lambda **kw: mock_conn)
    mock_logger = MagicMock()
    monkeypatch.setattr(db_module, 'logger', mock_logger)

    database.ensure_post_boot_indexes()

    executed_sql = ' '.join(str(c) for c in mock_cursor.execute.call_args_list)
    assert 'DROP INDEX' not in executed_sql

    warning_calls = [c for c in mock_logger.warning.call_args_list
                     if 'lock_timeout' in str(c)]
    assert len(warning_calls) == 1, \
        "Expected a warning mentioning lock_timeout when SET fails"


def test_post_boot_drops_continue_after_single_failure(monkeypatch):
    """If one drop fails, the remaining drops are still attempted."""
    def execute_side_effect(sql, params=None):
        if isinstance(sql, str) and sql == "DROP INDEX CONCURRENTLY IF EXISTS idx_logs_type":
            raise Exception("simulated DROP failure")

    mock_cursor = MagicMock()
    mock_cursor.execute = MagicMock(side_effect=execute_side_effect)
    mock_cursor.fetchone.return_value = (1,)  # creates skipped
    mock_cursor.__enter__ = lambda s: s
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    database = Database(conn_params={'user': 'unifi'})
    monkeypatch.setattr('db.psycopg2.connect', lambda **kw: mock_conn)
    mock_logger = MagicMock()
    monkeypatch.setattr(db_module, 'logger', mock_logger)

    database.ensure_post_boot_indexes()

    executed = ' '.join(str(c) for c in mock_cursor.execute.call_args_list)
    assert 'idx_logs_rule_action' in executed  # second drop attempted
    warning_calls = [c for c in mock_logger.warning.call_args_list
                     if 'idx_logs_type' in str(c)]
    assert len(warning_calls) >= 1


# ── Retention validation ──────────────────────────────────────────────────────

def test_validate_retention_days_rejects_zero():
    with pytest.raises(ValueError, match="positive"):
        Database.validate_retention_days(0, 10)


def test_validate_retention_days_rejects_negative():
    with pytest.raises(ValueError, match="positive"):
        Database.validate_retention_days(60, -1)


def test_validate_retention_days_rejects_non_int():
    with pytest.raises(ValueError, match="integers"):
        Database.validate_retention_days("60", 10)


def test_validate_retention_days_accepts_valid():
    # Should not raise
    Database.validate_retention_days(60, 10)
    Database.validate_retention_days(1, 1)


# ── Retention time resolution ────────────────────────────────────────────────

def test_resolve_retention_time_returns_ui_value(monkeypatch):
    """system_config value wins over env and default."""
    db = MagicMock()
    db.get_config = MagicMock(return_value='05:17')
    monkeypatch.setenv('RETENTION_CLEANUP_TIME', '99:99')  # would be invalid — proves UI wins
    assert Database.resolve_retention_time(db) == ('05:17', 'ui')


def test_resolve_retention_time_falls_back_to_env(monkeypatch):
    db = MagicMock()
    db.get_config = MagicMock(return_value=None)
    monkeypatch.setenv('RETENTION_CLEANUP_TIME', '07:45')
    assert Database.resolve_retention_time(db) == ('07:45', 'env')


def test_resolve_retention_time_default_when_unset(monkeypatch):
    # conftest._clean_env already delenv'd both env vars. Test is env-insensitive.
    db = MagicMock()
    db.get_config = MagicMock(return_value=None)
    assert Database.resolve_retention_time(db) == ('03:00', 'default')


def test_resolve_retention_time_invalid_env_string_falls_to_default(monkeypatch):
    db = MagicMock()
    db.get_config = MagicMock(return_value=None)
    monkeypatch.setenv('RETENTION_CLEANUP_TIME', 'not-a-time')
    assert Database.resolve_retention_time(db) == ('03:00', 'default')


def test_resolve_retention_time_out_of_range_env_falls_to_default(monkeypatch):
    db = MagicMock()
    db.get_config = MagicMock(return_value=None)
    monkeypatch.setenv('RETENTION_CLEANUP_TIME', '25:00')
    assert Database.resolve_retention_time(db) == ('03:00', 'default')


def test_resolve_retention_time_invalid_ui_falls_through_to_env(monkeypatch):
    """Invalid system_config value must NOT short-circuit — env should still win."""
    db = MagicMock()
    db.get_config = MagicMock(return_value='99:99')  # out of range
    monkeypatch.setenv('RETENTION_CLEANUP_TIME', '07:30')
    assert Database.resolve_retention_time(db) == ('07:30', 'env')


# ── Legacy RETENTION_TIME deprecation fallback (v3.6.2 → v3.6.3 rename) ──────

def test_resolve_retention_time_legacy_env_var_still_honored(monkeypatch, caplog):
    """v3.6.2 shipped with RETENTION_TIME. v3.6.3 renamed to RETENTION_CLEANUP_TIME
    but honours the old name for one release so existing deployments don't
    silently revert to 03:00 on upgrade. Emits a WARNING when used."""
    import logging
    db = MagicMock()
    db.get_config = MagicMock(return_value=None)
    monkeypatch.setenv('RETENTION_TIME', '23:42')

    with caplog.at_level(logging.WARNING, logger='db'):
        result = Database.resolve_retention_time(db)

    assert result == ('23:42', 'env')
    assert any('RETENTION_TIME' in rec.message and 'deprecated' in rec.message.lower()
               for rec in caplog.records), \
        'deprecation warning must fire when legacy env var is used'


def test_resolve_retention_time_new_env_wins_over_legacy(monkeypatch):
    """If both RETENTION_CLEANUP_TIME and RETENTION_TIME are set, the canonical
    name wins and no deprecation fallback runs."""
    db = MagicMock()
    db.get_config = MagicMock(return_value=None)
    monkeypatch.setenv('RETENTION_CLEANUP_TIME', '10:00')
    monkeypatch.setenv('RETENTION_TIME', '23:42')
    assert Database.resolve_retention_time(db) == ('10:00', 'env')


def test_resolve_retention_time_legacy_warning_fires_once(monkeypatch, caplog):
    """The deprecation warning must NOT fire on every resolver call —
    the resolver runs on every GET /api/config/retention and every SIGUSR2
    scheduler rebuild. Warning once per process is enough."""
    import logging
    db = MagicMock()
    db.get_config = MagicMock(return_value=None)
    monkeypatch.setenv('RETENTION_TIME', '23:42')

    with caplog.at_level(logging.WARNING, logger='db'):
        Database.resolve_retention_time(db)
        Database.resolve_retention_time(db)
        Database.resolve_retention_time(db)

    deprecation_warnings = [
        rec for rec in caplog.records
        if 'RETENTION_TIME' in rec.message and 'deprecated' in rec.message.lower()
    ]
    assert len(deprecation_warnings) == 1, \
        f'expected exactly 1 deprecation warning, got {len(deprecation_warnings)}'


def test_resolve_retention_time_invalid_legacy_env_falls_to_default(monkeypatch):
    """Bad legacy env value shouldn't keep the app stuck on it — fall
    through to default just like the canonical env path does."""
    db = MagicMock()
    db.get_config = MagicMock(return_value=None)
    monkeypatch.setenv('RETENTION_TIME', 'nonsense')
    assert Database.resolve_retention_time(db) == ('03:00', 'default')


# ── parse_retention_time direct coverage ─────────────────────────────────────

def test_parse_retention_time_accepts_minute_precision():
    from db import parse_retention_time
    assert parse_retention_time('23:17') == '23:17'
    assert parse_retention_time('00:00') == '00:00'
    assert parse_retention_time('23:59') == '23:59'


def test_parse_retention_time_zero_pads():
    from db import parse_retention_time
    assert parse_retention_time('3:5') == '03:05'
    assert parse_retention_time('9:0') == '09:00'


def test_parse_retention_time_rejects_invalid():
    from db import parse_retention_time
    assert parse_retention_time('24:00') is None     # hour out of range
    assert parse_retention_time('12:60') is None     # minute out of range
    assert parse_retention_time('not-a-time') is None
    assert parse_retention_time('12') is None        # missing colon
    assert parse_retention_time('12:30:45') is None  # too many parts
    assert parse_retention_time(1230) is None        # not a string
    assert parse_retention_time(None) is None


# ── Retention days resolution ────────────────────────────────────────────────

def test_resolve_retention_days_ui_wins_over_env(monkeypatch):
    db = MagicMock()
    def get_config(key, *a, **kw):
        return {'retention_days': 7, 'dns_retention_days': 5}.get(key)
    db.get_config = MagicMock(side_effect=get_config)
    monkeypatch.setenv('RETENTION_DAYS', '999')
    monkeypatch.setenv('DNS_RETENTION_DAYS', '999')
    assert Database.resolve_retention_days(db) == (7, 'ui', 5, 'ui')


def test_resolve_retention_days_env_when_ui_unset(monkeypatch):
    db = MagicMock()
    db.get_config = MagicMock(return_value=None)
    monkeypatch.setenv('RETENTION_DAYS', '14')
    monkeypatch.setenv('DNS_RETENTION_DAYS', '3')
    assert Database.resolve_retention_days(db) == (14, 'env', 3, 'env')


def test_resolve_retention_days_defaults_when_all_unset():
    # conftest._clean_env scrubs the env; no need to delenv here.
    db = MagicMock()
    db.get_config = MagicMock(return_value=None)
    assert Database.resolve_retention_days(db) == (60, 'default', 10, 'default')


def test_resolve_retention_days_invalid_env_falls_through_to_default(monkeypatch):
    db = MagicMock()
    db.get_config = MagicMock(return_value=None)
    monkeypatch.setenv('RETENTION_DAYS', 'not-a-number')
    monkeypatch.setenv('DNS_RETENTION_DAYS', 'also-bad')
    assert Database.resolve_retention_days(db) == (60, 'default', 10, 'default')


def test_resolve_retention_days_independent_sources(monkeypatch):
    """General and DNS can resolve from different sources in the same call."""
    db = MagicMock()
    def get_config(key, *a, **kw):
        return 30 if key == 'retention_days' else None
    db.get_config = MagicMock(side_effect=get_config)
    monkeypatch.setenv('DNS_RETENTION_DAYS', '5')
    assert Database.resolve_retention_days(db) == (30, 'ui', 5, 'env')


# ── Batched retention cleanup ─────────────────────────────────────────────────

class FakeRetentionConn:
    """Simulates a connection that processes batched deletes."""

    def __init__(self, dns_rows=0, nondns_rows=0, batch_size=5000):
        self._remaining = {'dns': dns_rows, 'non_dns': nondns_rows}
        self._batch_size = batch_size
        self._current_label = None

    def cursor(self):
        return FakeRetentionCursor(self)

    def commit(self):
        pass


class FakeRetentionCursor:
    def __init__(self, conn):
        self._conn = conn
        self.rowcount = 0

    def execute(self, sql, params=None):
        if sql and 'DELETE' in sql:
            if "log_type = 'dns'" in sql and "!=" not in sql:
                label = 'dns'
            else:
                label = 'non_dns'
            remaining = self._conn._remaining[label]
            batch = min(remaining, self._conn._batch_size)
            self._conn._remaining[label] -= batch
            self.rowcount = batch

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_run_retention_cleanup_structured_result(monkeypatch):
    """run_retention_cleanup returns structured result with correct counts."""
    database = Database(conn_params={'user': 'unifi'})

    remaining = {'dns': 100, 'non_dns': 200}

    @contextmanager
    def fake_get_conn():
        conn = FakeRetentionConn(
            dns_rows=remaining['dns'],
            nondns_rows=remaining['non_dns'],
            batch_size=5000,
        )
        yield conn
        remaining['dns'] = conn._remaining['dns']
        remaining['non_dns'] = conn._remaining['non_dns']

    monkeypatch.setattr(database, 'get_conn', fake_get_conn)

    result = database.run_retention_cleanup(60, 10)
    assert result['status'] == 'complete'
    assert result['error'] is None
    assert result['dns_deleted'] == 100
    assert result['non_dns_deleted'] == 200
    assert result['deleted_so_far'] == 300


def test_run_retention_cleanup_no_data(monkeypatch):
    """run_retention_cleanup with no expired data returns zero counts."""
    database = Database(conn_params={'user': 'unifi'})

    remaining = {'dns': 0, 'non_dns': 0}

    @contextmanager
    def fake_get_conn():
        conn = FakeRetentionConn(dns_rows=remaining['dns'], nondns_rows=remaining['non_dns'])
        yield conn
        remaining['dns'] = conn._remaining['dns']
        remaining['non_dns'] = conn._remaining['non_dns']

    monkeypatch.setattr(database, 'get_conn', fake_get_conn)

    result = database.run_retention_cleanup(60, 10)
    assert result['status'] == 'complete'
    assert result['deleted_so_far'] == 0
    assert result['dns_deleted'] == 0
    assert result['non_dns_deleted'] == 0


def test_run_retention_cleanup_invalid_days():
    """run_retention_cleanup rejects invalid day values."""
    database = Database(conn_params={'user': 'unifi'})
    with pytest.raises(ValueError):
        database.run_retention_cleanup(0, 10)
    with pytest.raises(ValueError):
        database.run_retention_cleanup(60, -1)


def test_run_retention_cleanup_progress_callback(monkeypatch):
    """progress_cb is called during cleanup."""
    database = Database(conn_params={'user': 'unifi'})

    from contextlib import contextmanager as cm

    # Shared mutable state across all get_conn() calls
    remaining = {'dns': 100, 'non_dns': 0}

    @contextmanager
    def fake_get_conn():
        conn = FakeRetentionConn(
            dns_rows=remaining['dns'],
            nondns_rows=remaining['non_dns'],
            batch_size=5000,
        )
        yield conn
        # Sync remaining back so next call sees updated state
        remaining['dns'] = conn._remaining['dns']
        remaining['non_dns'] = conn._remaining['non_dns']

    monkeypatch.setattr(database, 'get_conn', fake_get_conn)

    progress_calls = []
    result = database.run_retention_cleanup(60, 10, progress_cb=progress_calls.append)
    assert result['status'] == 'complete'
    assert len(progress_calls) >= 1
    assert progress_calls[0]['phase'] == 'dns'
