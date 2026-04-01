"""Tests for shared network identity extraction and persistence helpers.

Covers:
- extract_network_identity_from_net_config()
- Database.persist_network_identity()
"""

from unittest.mock import MagicMock

import pytest

from db import Database
from unifi_api import UniFiAPI


# ── Extractor tests ─────────────────────────────────────────────────────────

class TestExtractNetworkIdentity:
    """Tests for UniFiAPI.extract_network_identity_from_net_config()."""

    def test_extracts_wan_ip_by_iface(self):
        net_config = {
            'wan_interfaces': [
                {'physical_interface': 'eth0', 'wan_ip': '1.2.3.4'},
                {'physical_interface': 'eth1', 'wan_ip': '5.6.7.8'},
            ],
            'networks': [],
        }
        wan_ip_by_iface, _ = UniFiAPI.extract_network_identity_from_net_config(net_config)
        assert wan_ip_by_iface == {'eth0': '1.2.3.4', 'eth1': '5.6.7.8'}

    def test_skips_wan_without_physical_interface(self):
        net_config = {
            'wan_interfaces': [
                {'physical_interface': '', 'wan_ip': '1.2.3.4'},
                {'wan_ip': '5.6.7.8'},
            ],
            'networks': [],
        }
        wan_ip_by_iface, _ = UniFiAPI.extract_network_identity_from_net_config(net_config)
        assert wan_ip_by_iface == {}

    def test_skips_wan_without_ip(self):
        net_config = {
            'wan_interfaces': [
                {'physical_interface': 'eth0', 'wan_ip': None},
                {'physical_interface': 'eth1'},
            ],
            'networks': [],
        }
        wan_ip_by_iface, _ = UniFiAPI.extract_network_identity_from_net_config(net_config)
        assert wan_ip_by_iface == {}

    def test_extracts_gateway_ip_vlans(self):
        net_config = {
            'wan_interfaces': [],
            'networks': [
                {'ip_subnet': '192.168.1.1/24', 'vlan': 1, 'name': 'LAN'},
                {'ip_subnet': '10.0.50.1/24', 'vlan': 50, 'name': 'IoT'},
            ],
        }
        _, gateway_ip_vlans = UniFiAPI.extract_network_identity_from_net_config(net_config)
        assert gateway_ip_vlans == {
            '192.168.1.1': {'vlan': 1, 'name': 'LAN'},
            '10.0.50.1': {'vlan': 50, 'name': 'IoT'},
        }

    def test_skips_network_without_ip_subnet(self):
        net_config = {
            'wan_interfaces': [],
            'networks': [
                {'ip_subnet': '', 'vlan': 1, 'name': 'LAN'},
                {'vlan': 2, 'name': 'VLAN2'},
            ],
        }
        _, gateway_ip_vlans = UniFiAPI.extract_network_identity_from_net_config(net_config)
        assert gateway_ip_vlans == {}

    def test_empty_net_config(self):
        wan_ip_by_iface, gateway_ip_vlans = UniFiAPI.extract_network_identity_from_net_config({})
        assert wan_ip_by_iface == {}
        assert gateway_ip_vlans == {}

    def test_mixed_valid_and_invalid(self):
        net_config = {
            'wan_interfaces': [
                {'physical_interface': 'eth0', 'wan_ip': '1.2.3.4'},
                {'physical_interface': '', 'wan_ip': '9.9.9.9'},
                {'physical_interface': 'eth2'},
            ],
            'networks': [
                {'ip_subnet': '10.0.0.1/24', 'vlan': None, 'name': 'Default'},
                {'ip_subnet': '', 'vlan': 5, 'name': 'Empty'},
            ],
        }
        wan_ip_by_iface, gateway_ip_vlans = UniFiAPI.extract_network_identity_from_net_config(net_config)
        assert wan_ip_by_iface == {'eth0': '1.2.3.4'}
        assert gateway_ip_vlans == {'10.0.0.1': {'vlan': None, 'name': 'Default'}}


# ── Persistence tests ───────────────────────────────────────────────────────

class TestPersistNetworkIdentity:
    """Tests for Database.persist_network_identity()."""

    @pytest.fixture()
    def mock_db(self):
        db = MagicMock()
        db.get_config.return_value = ['eth0', 'eth1']
        return db

    def test_persists_wan_identity(self, mock_db):
        Database.persist_network_identity(
            mock_db,
            wan_ip_by_iface={'eth0': '1.2.3.4', 'eth1': '5.6.7.8'},
        )
        mock_db.set_config.assert_any_call('wan_ip_by_iface', {'eth0': '1.2.3.4', 'eth1': '5.6.7.8'})
        mock_db.set_config.assert_any_call('wan_ips', ['1.2.3.4', '5.6.7.8'])
        mock_db.set_config.assert_any_call('wan_ip', '1.2.3.4')

    def test_wan_ips_ordered_by_wan_interfaces_config(self, mock_db):
        """wan_ips must follow the configured wan_interfaces order."""
        from db import Database
        mock_db.get_config.return_value = ['eth1', 'eth0']
        Database.persist_network_identity(
            mock_db,
            wan_ip_by_iface={'eth0': '1.1.1.1', 'eth1': '2.2.2.2'},
        )
        mock_db.set_config.assert_any_call('wan_ips', ['2.2.2.2', '1.1.1.1'])
        mock_db.set_config.assert_any_call('wan_ip', '2.2.2.2')

    def test_persists_gateway_identity(self, mock_db):
        Database.persist_network_identity(
            mock_db,
            gateway_ip_vlans={'10.0.0.1': {'vlan': 1, 'name': 'LAN'}},
        )
        mock_db.set_config.assert_any_call('gateway_ip_vlans', {'10.0.0.1': {'vlan': 1, 'name': 'LAN'}})
        mock_db.set_config.assert_any_call('gateway_ips', ['10.0.0.1'])

    def test_empty_wan_ip_by_iface_does_not_clear(self, mock_db):
        """Empty wan_ip_by_iface must not overwrite last-known-good values."""
        Database.persist_network_identity(mock_db, wan_ip_by_iface={})
        # set_config should NOT be called for WAN keys
        for c in mock_db.set_config.call_args_list:
            assert c[0][0] not in ('wan_ip_by_iface', 'wan_ips', 'wan_ip')

    def test_none_wan_ip_by_iface_does_not_clear(self, mock_db):
        """None wan_ip_by_iface must not overwrite last-known-good values."""
        Database.persist_network_identity(mock_db, wan_ip_by_iface=None)
        for c in mock_db.set_config.call_args_list:
            assert c[0][0] not in ('wan_ip_by_iface', 'wan_ips', 'wan_ip')

    def test_empty_gateway_ip_vlans_does_not_clear(self, mock_db):
        """Empty gateway_ip_vlans must not overwrite last-known-good values."""
        Database.persist_network_identity(mock_db, gateway_ip_vlans={})
        for c in mock_db.set_config.call_args_list:
            assert c[0][0] not in ('gateway_ip_vlans', 'gateway_ips')

    def test_both_wan_and_gateway(self, mock_db):
        Database.persist_network_identity(
            mock_db,
            wan_ip_by_iface={'eth0': '1.2.3.4'},
            gateway_ip_vlans={'10.0.0.1': {'vlan': 1, 'name': 'LAN'}},
        )
        keys_written = [c[0][0] for c in mock_db.set_config.call_args_list]
        assert 'wan_ip_by_iface' in keys_written
        assert 'gateway_ip_vlans' in keys_written
