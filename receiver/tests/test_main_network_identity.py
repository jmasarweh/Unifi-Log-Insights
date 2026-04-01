"""Tests for runtime network identity gating in main.py.

Covers:
- _use_log_identity_detection()
- _refresh_network_identity_from_logs()

main.py imports routes.auth which triggers deps.py's PostgreSQL init.
We stub all heavy transitive dependencies before importing the functions
under test.
"""

import sys
from unittest.mock import MagicMock

# Stub heavy transitive dependencies of main.py before import.
# Order matters: deps must be stubbed before routes.auth.
_stubs = (
    'schedule', 'enrichment', 'backfill', 'blacklist',
    'deps', 'routes', 'routes.auth',
)
_originals = {}
for _mod in _stubs:
    if _mod in sys.modules:
        _originals[_mod] = sys.modules[_mod]
    else:
        sys.modules[_mod] = MagicMock()

# Now safe to import the functions under test
from main import _use_log_identity_detection, _refresh_network_identity_from_logs

# Restore original module state so stubs don't leak to other test files
for _mod, _orig in _originals.items():
    sys.modules[_mod] = _orig
for _mod in _stubs:
    if _mod not in _originals:
        sys.modules.pop(_mod, None)


class TestUseLogIdentityDetection:

    def test_returns_true_when_unifi_disabled(self):
        db = MagicMock()
        db.get_config.return_value = False
        assert _use_log_identity_detection(db) is True

    def test_returns_false_when_unifi_enabled(self):
        db = MagicMock()
        db.get_config.return_value = True
        assert _use_log_identity_detection(db) is False

    def test_returns_true_when_config_missing(self):
        db = MagicMock()
        db.get_config.return_value = None
        assert _use_log_identity_detection(db) is True


class TestRefreshNetworkIdentityFromLogs:

    def test_noop_when_unifi_enabled(self):
        db = MagicMock()
        db.get_config.return_value = True
        _refresh_network_identity_from_logs(db)
        db.detect_wan_ip.assert_not_called()
        db.detect_gateway_ips.assert_not_called()

    def test_calls_detection_when_unifi_disabled(self):
        db = MagicMock()
        db.get_config.return_value = False
        _refresh_network_identity_from_logs(db)
        db.detect_wan_ip.assert_called_once()
        db.detect_gateway_ips.assert_called_once()

    def test_gateway_still_runs_when_wan_detection_fails(self):
        db = MagicMock()
        db.get_config.return_value = False
        db.detect_wan_ip.side_effect = Exception("WAN failed")
        _refresh_network_identity_from_logs(db)
        db.detect_gateway_ips.assert_called_once()
