"""Shared fixtures for backend tests."""

import pytest


@pytest.fixture(autouse=True)
def _reset_parser_globals(monkeypatch):
    """Reset mutable parser module-level state between tests."""
    import parsers
    monkeypatch.setattr(parsers, '_wan_ip', None)
    monkeypatch.setattr(parsers, 'WAN_IPS', set())
    monkeypatch.setattr(parsers, '_wan_ip_by_iface_present', False)
    monkeypatch.setattr(parsers, 'WAN_INTERFACES', {'ppp0'})
    monkeypatch.setattr(parsers, 'INTERFACE_LABELS', {})


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Ensure DB/encryption env vars don't leak between tests."""
    for var in ('SECRET_KEY', 'POSTGRES_PASSWORD', 'DB_HOST', 'DB_PORT',
                'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_SSLMODE',
                'DB_SSLROOTCERT', 'DB_SSLCERT', 'DB_SSLKEY', 'TZ',
                'RETENTION_HOUR', 'RETENTION_DAYS', 'DNS_RETENTION_DAYS'):
        monkeypatch.delenv(var, raising=False)
