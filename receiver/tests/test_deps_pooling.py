"""Tests for put_conn() connection-pool hygiene.

Verifies that non-IDLE connections (e.g. after statement_timeout) are
rolled back or discarded before being returned to the pool, preventing
InFailedSqlTransaction poisoning of subsequent requests.

Imports the real put_conn function source at module load time (via a
one-shot module stub) and validates it against a mock pool.  The test
also asserts structural parity with deps.py to catch future drift.
"""

import inspect
import sys
from unittest.mock import MagicMock, PropertyMock

from psycopg2 import extensions

import pytest


# ── Import the real put_conn without triggering deps module-level init ──────
# Stash heavy deps, import deps, grab put_conn, then restore.

_stashed = {}
for _mod in ('db', 'enrichment', 'unifi_api'):
    _stashed[_mod] = sys.modules.get(_mod)
    sys.modules[_mod] = MagicMock()

# Patch pool constructor so it doesn't connect
import psycopg2.pool as _pool_mod
_orig_pool = _pool_mod.ThreadedConnectionPool
_pool_mod.ThreadedConnectionPool = lambda *a, **kw: MagicMock()

import deps as _deps_module
_real_put_conn = _deps_module.put_conn

# Restore — remove the contaminated deps module (its singletons like
# enricher_db and db_pool are MagicMocks from the stub phase) and
# restore transitive modules.  This is safe because every test file
# that imports deps already replaces it via monkeypatch before route
# import — no test does a bare `from deps import ...` at module level.
_pool_mod.ThreadedConnectionPool = _orig_pool
sys.modules.pop('deps', None)
for _mod, _orig in _stashed.items():
    if _orig is None:
        sys.modules.pop(_mod, None)
    else:
        sys.modules[_mod] = _orig


# ── Helpers ─────────────────────────────────────────────────────────────────

def _make_conn(*, closed=False, status=extensions.TRANSACTION_STATUS_IDLE,
               status_after_rollback=None, rollback_raises=False):
    """Build a mock connection with configurable transaction state."""
    conn = MagicMock()
    conn.closed = closed

    statuses = [status]
    if status_after_rollback is not None:
        statuses.append(status_after_rollback)

    type(conn.info).transaction_status = PropertyMock(side_effect=statuses)

    if rollback_raises:
        conn.rollback.side_effect = Exception("rollback failed")

    return conn


@pytest.fixture(autouse=True)
def _patch_pool(monkeypatch):
    """Redirect put_conn's db_pool to a fresh mock for each test."""
    mock_pool = MagicMock()
    monkeypatch.setattr(_deps_module, 'db_pool', mock_pool)
    return mock_pool


# ── Structural parity check ────────────────────────────────────────────────

def test_production_put_conn_contains_transaction_status_check():
    """Verify the production put_conn checks transaction_status.

    Guards against future drift where deps.py is changed without
    updating these tests.
    """
    source = inspect.getsource(_real_put_conn)
    assert 'transaction_status' in source
    assert 'TRANSACTION_STATUS_IDLE' in source
    assert 'rollback' in source


# ── Behavior tests ──────────────────────────────────────────────────────────

def test_idle_connection_returned_to_pool(_patch_pool):
    """IDLE connection is returned to the pool without rollback."""
    conn = _make_conn(status=extensions.TRANSACTION_STATUS_IDLE)

    _real_put_conn(conn)

    conn.rollback.assert_not_called()
    _patch_pool.putconn.assert_called_once_with(conn, close=False)


def test_inerror_connection_rolled_back_before_reuse(_patch_pool):
    """INERROR connection is rolled back, then returned to pool."""
    conn = _make_conn(
        status=extensions.TRANSACTION_STATUS_INERROR,
        status_after_rollback=extensions.TRANSACTION_STATUS_IDLE,
    )

    _real_put_conn(conn)

    conn.rollback.assert_called_once()
    _patch_pool.putconn.assert_called_once_with(conn, close=False)


def test_intrans_connection_rolled_back_before_reuse(_patch_pool):
    """INTRANS connection is rolled back, then returned to pool."""
    conn = _make_conn(
        status=extensions.TRANSACTION_STATUS_INTRANS,
        status_after_rollback=extensions.TRANSACTION_STATUS_IDLE,
    )

    _real_put_conn(conn)

    conn.rollback.assert_called_once()
    _patch_pool.putconn.assert_called_once_with(conn, close=False)


def test_rollback_failure_discards_connection(_patch_pool):
    """If rollback raises, the connection is discarded."""
    conn = _make_conn(
        status=extensions.TRANSACTION_STATUS_INERROR,
        rollback_raises=True,
    )

    _real_put_conn(conn)

    _patch_pool.putconn.assert_called_once_with(conn, close=True)


def test_still_not_idle_after_rollback_discards_connection(_patch_pool):
    """If connection is still non-IDLE after rollback, it is discarded."""
    conn = _make_conn(
        status=extensions.TRANSACTION_STATUS_INERROR,
        status_after_rollback=extensions.TRANSACTION_STATUS_INERROR,
    )

    _real_put_conn(conn)

    conn.rollback.assert_called_once()
    _patch_pool.putconn.assert_called_once_with(conn, close=True)


def test_closed_connection_discarded(_patch_pool):
    """Already-closed connection is passed with close=True."""
    conn = _make_conn(closed=True)

    _real_put_conn(conn)

    _patch_pool.putconn.assert_called_once_with(conn, close=True)
