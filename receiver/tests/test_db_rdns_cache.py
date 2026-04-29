"""Tests for rdns_cache DB helpers (issue #98).

Mirrors the FakeConn / FakeCursor pattern from test_db_schema_migrations.py.
No real PostgreSQL is required.
"""
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest

from db import Database


class FakeCursor:
    def __init__(self, fetches=None, rowcount=0):
        self.fetches = list(fetches or [])
        self.rowcount = rowcount
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchone(self):
        if self.fetches:
            return self.fetches.pop(0)
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeConn:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor


def _make_db(monkeypatch, cursor):
    db = Database(conn_params={'user': 'unifi'})

    @contextmanager
    def fake_get_conn():
        yield FakeConn(cursor)

    monkeypatch.setattr(db, 'get_conn', fake_get_conn)
    return db


# ── get_rdns_cache ───────────────────────────────────────────────────────────

class TestGetRdnsCache:
    def test_returns_none_when_missing(self, monkeypatch):
        cur = FakeCursor(fetches=[])  # fetchone → None
        db = _make_db(monkeypatch, cur)
        assert db.get_rdns_cache('1.2.3.4') is None

    def test_returns_dict_with_age_seconds(self, monkeypatch):
        cur = FakeCursor(fetches=[('host.example.com', 'success', 3600)])
        db = _make_db(monkeypatch, cur)
        row = db.get_rdns_cache('1.2.3.4')
        assert row == {
            'hostname': 'host.example.com',
            'status': 'success',
            'age_seconds': 3600,
        }

    def test_uses_extract_epoch_for_age(self, monkeypatch):
        cur = FakeCursor(fetches=[('h', 'failure', 1234)])
        db = _make_db(monkeypatch, cur)
        db.get_rdns_cache('1.2.3.4')
        sql_text = ' '.join(sql for sql, _ in cur.executed)
        assert 'EXTRACT(EPOCH FROM NOW() - looked_up_at)' in sql_text


# ── set_rdns_cache ───────────────────────────────────────────────────────────

class TestSetRdnsCache:
    def test_upserts_with_now_for_looked_up_at(self, monkeypatch):
        cur = FakeCursor()
        db = _make_db(monkeypatch, cur)
        db.set_rdns_cache('1.2.3.4', 'h.example.com', 'success')

        assert len(cur.executed) == 1
        sql, params = cur.executed[0]
        assert 'INSERT INTO rdns_cache' in sql
        assert 'ON CONFLICT (ip) DO UPDATE' in sql
        assert 'looked_up_at = NOW()' in sql
        assert params == ['1.2.3.4', 'h.example.com', 'success']

    def test_accepts_none_hostname(self, monkeypatch):
        cur = FakeCursor()
        db = _make_db(monkeypatch, cur)
        db.set_rdns_cache('1.2.3.4', None, 'failure')
        assert cur.executed[0][1] == ['1.2.3.4', None, 'failure']


# ── cleanup_rdns_cache ───────────────────────────────────────────────────────

class TestCleanupRdnsCache:
    def test_deletes_rows_older_than_8_days(self, monkeypatch):
        cur = FakeCursor(rowcount=3)
        db = _make_db(monkeypatch, cur)
        deleted = db.cleanup_rdns_cache()
        assert deleted == 3
        sql_text = ' '.join(sql for sql, _ in cur.executed)
        assert 'DELETE FROM rdns_cache' in sql_text
        assert "INTERVAL '8 days'" in sql_text

    def test_returns_deleted_count(self, monkeypatch):
        cur = FakeCursor(rowcount=42)
        db = _make_db(monkeypatch, cur)
        assert db.cleanup_rdns_cache() == 42

    def test_no_op_when_empty_returns_zero(self, monkeypatch):
        cur = FakeCursor(rowcount=0)
        db = _make_db(monkeypatch, cur)
        assert db.cleanup_rdns_cache() == 0


# ── Schema (source-level assertions, mirrors existing pattern) ──────────────

class TestRdnsCacheSchema:
    def test_rdns_cache_table_in_migrations_source(self):
        """The rdns_cache CREATE TABLE must be present in _ensure_schema."""
        import inspect
        source = inspect.getsource(Database._ensure_schema)
        assert 'CREATE TABLE IF NOT EXISTS rdns_cache' in source
        # Three valid statuses, mandatory CHECK constraint
        assert "CHECK (status IN ('success', 'failure', 'transient'))" in source
        assert 'idx_rdns_cache_looked_up_at' in source

    def test_fail_fast_validation_present(self):
        import inspect
        source = inspect.getsource(Database._ensure_schema)
        assert "table_name = 'rdns_cache'" in source
        # Validation block exits the process on missing table
        assert "FATAL: 'rdns_cache' table missing" in source
