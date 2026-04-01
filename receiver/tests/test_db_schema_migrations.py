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
    monkeypatch.setattr(database, '_fix_function_ownership', MagicMock())
    monkeypatch.setattr(database, '_backfill_tz_timestamps', MagicMock())
    if logger is None:
        logger = MagicMock()
    monkeypatch.setattr(db_module, 'logger', logger)
    return database, logger


def _validation_cursor():
    """Validation cursor with truthy responses for table/function/index checks.

    Order: logs table, cleanup_old_logs function, idx_logs_timestamp,
    threat_backfill_queue table, ip_threats.last_seen_at column,
    ip_threats.last_seen_at column_default,
    idx_logs_fw_block_null_threat_src index.
    """
    return FakeCursor(fetches=[
        (1,),
        ('public.cleanup_old_logs(integer,integer)',),
        (1,),
        (1,),
        (1,),
        ("now()",),
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
    database._fix_function_ownership.assert_called_once_with()
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
        ('public.cleanup_old_logs(integer,integer)',),          # function
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
    """ensure_post_boot_indexes() creates the index when it doesn't exist."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None  # index missing
    mock_cursor.__enter__ = lambda s: s
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cursor

    database = Database(conn_params={'user': 'unifi'})
    monkeypatch.setattr('db.psycopg2.connect', lambda **kw: mock_conn)

    database.ensure_post_boot_indexes()

    executed_sql = ' '.join(str(c) for c in mock_cursor.execute.call_args_list)
    assert 'CREATE INDEX CONCURRENTLY' in executed_sql
    assert 'spgist' in executed_sql.lower()
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
    assert 'idx_logs_spgist_dst_ip_firewall' in mock_logger.warning.call_args[0][1]


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
