"""Tests for firewall_policy_matcher.py — rule parsing, zone map, matching, and caching."""

import time
from unittest.mock import MagicMock, patch

import pytest

import firewall_policy_matcher as fpm


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clear_cache():
    """Ensure each test starts with a clean cache."""
    fpm.invalidate_cache()
    yield
    fpm.invalidate_cache()


def _make_api(zones=None, networks=None, net_config=None, policies=None):
    """Build a mock unifi_api with controllable return data."""
    api = MagicMock()
    api.get_firewall_zones.return_value = zones or []
    # Networks are delivered via get_network_config()['networks']
    base_net_config = net_config or {'wan_interfaces': []}
    if networks:
        base_net_config.setdefault('networks', []).extend(networks)
    elif 'networks' not in base_net_config:
        base_net_config['networks'] = []
    api.get_network_config.return_value = base_net_config
    api.get_firewall_data.return_value = {
        'policies': policies or [],
        'zones': zones or [],
        'totalCount': len(policies) if policies else 0,
    }
    return api


def _zone(zone_id, name, network_ids=None, origin='SYSTEM_DEFINED'):
    return {
        'id': zone_id,
        'name': name,
        'networkIds': network_ids or [],
        'metadata': {'origin': origin},
    }


def _network(net_id, name, vlan_id):
    iface = 'br0' if vlan_id == 1 else f'br{vlan_id}'
    return {'id': net_id, 'name': name, 'interface': iface, 'vlan': vlan_id}


def _policy(policy_id, name, src_zone, dst_zone, action, index,
            logging=False, origin='USER_DEFINED', enabled=True):
    return {
        'id': policy_id,
        'name': name,
        'source': {'zoneId': src_zone},
        'destination': {'zoneId': dst_zone},
        'action': {'type': action},
        'index': index,
        'loggingEnabled': logging,
        'enabled': enabled,
        'metadata': {'origin': origin},
    }


# ── parse_firewall_rule ──────────────────────────────────────────────────────

class TestParseFirewallRule:
    def test_legacy_allow(self):
        result = fpm.parse_firewall_rule('WAN_LOCAL-A-100')
        assert result['format'] == 'legacy'
        assert result['chain'] == 'WAN_LOCAL'
        assert result['action_code'] == 'A'
        assert result['resolved_action'] == 'allow'
        assert result['action_source'] == 'rule_name'
        assert result['index'] == 100

    def test_legacy_block_D(self):
        result = fpm.parse_firewall_rule('LAN_WAN-D-2147483647')
        assert result['format'] == 'legacy'
        assert result['action_code'] == 'D'
        assert result['resolved_action'] == 'block'
        assert result['index'] == 2147483647

    def test_legacy_block_B(self):
        result = fpm.parse_firewall_rule('WAN_IN-B-1')
        assert result['format'] == 'legacy'
        assert result['action_code'] == 'B'
        assert result['resolved_action'] == 'block'

    def test_legacy_reject(self):
        result = fpm.parse_firewall_rule('WAN_LOCAL-R-50')
        assert result['format'] == 'legacy'
        assert result['action_code'] == 'R'
        assert result['resolved_action'] == 'block'

    def test_legacy_custom_chain(self):
        result = fpm.parse_firewall_rule('CUSTOM2_WAN-A-2147483647')
        assert result['format'] == 'legacy'
        assert result['chain'] == 'CUSTOM2_WAN'
        assert result['action_code'] == 'A'
        assert result['index'] == 2147483647

    def test_zone_index_no_desc(self):
        result = fpm.parse_firewall_rule('GUEST_WAN-30004')
        assert result['format'] == 'zone_index'
        assert result['chain'] == 'GUEST_WAN'
        assert result['index'] == 30004
        assert result['action_code'] is None
        assert result['resolved_action'] is None
        assert result['action_source'] == 'default'

    def test_zone_index_with_block_desc(self):
        result = fpm.parse_firewall_rule('GUEST_WAN-30004',
                                          rule_desc='[GUEST_WAN]Block Unauthorized Traffic')
        assert result['format'] == 'zone_index'
        assert result['resolved_action'] is None  # NOT pre-populated
        assert result['action_source'] == 'default'
        assert result['desc_hint'] == 'block'  # stored as hint for fallback

    def test_zone_index_with_allow_desc(self):
        result = fpm.parse_firewall_rule('LAN_WAN-100',
                                          rule_desc='Allow All Traffic')
        assert result['format'] == 'zone_index'
        assert result['resolved_action'] is None
        assert result['desc_hint'] == 'allow'

    def test_zone_index_with_drop_desc(self):
        result = fpm.parse_firewall_rule('LAN_WAN-200',
                                          rule_desc='Drop Invalid State')
        assert result['resolved_action'] is None
        assert result['desc_hint'] == 'block'

    def test_zone_index_with_reject_desc(self):
        result = fpm.parse_firewall_rule('LAN_WAN-300',
                                          rule_desc='Reject and Log')
        assert result['resolved_action'] is None
        assert result['desc_hint'] == 'block'

    def test_zone_index_no_action_keyword_in_desc(self):
        result = fpm.parse_firewall_rule('LAN_WAN-400',
                                          rule_desc='Some Custom Rule')
        assert result['resolved_action'] is None
        assert result['action_source'] == 'default'
        assert result['desc_hint'] is None

    def test_zone_index_desc_case_insensitive(self):
        result = fpm.parse_firewall_rule('GUEST_WAN-30004',
                                          rule_desc='BLOCK all unauthorized')
        assert result['desc_hint'] == 'block'

    def test_zone_index_custom(self):
        result = fpm.parse_firewall_rule('CUSTOM1_WAN-100')
        assert result['format'] == 'zone_index'
        assert result['chain'] == 'CUSTOM1_WAN'
        assert result['index'] == 100

    def test_redirect_dnat(self):
        result = fpm.parse_firewall_rule('DNAT-1')
        assert result['format'] == 'redirect'
        assert result['resolved_action'] == 'redirect'
        assert result['action_source'] == 'rule_name'

    def test_redirect_prerouting(self):
        result = fpm.parse_firewall_rule('PREROUTING-1')
        assert result['format'] == 'redirect'
        assert result['resolved_action'] == 'redirect'

    def test_none_input(self):
        assert fpm.parse_firewall_rule(None) is None

    def test_empty_string(self):
        assert fpm.parse_firewall_rule('') is None

    def test_unrecognized(self):
        assert fpm.parse_firewall_rule('CUSTOM_RULE') is None

    def test_unrecognized_action_code(self):
        """X is not a valid action code for legacy format."""
        assert fpm.parse_firewall_rule('WAN_LOCAL-X-100') is None

    def test_missing_index(self):
        assert fpm.parse_firewall_rule('WAN_LOCAL-A-') is None


# ── resolve_rule_action ──────────────────────────────────────────────────────

class TestResolveRuleAction:
    def _setup(self, action='BLOCK', index=30004):
        """Build a mock API with hotspot→external policy."""
        zones = [
            _zone('z-hot', 'Hotspot', ['net-guest']),
            _zone('z-ext', 'External'),
            _zone('z-gw', 'Gateway'),
        ]
        networks = [_network('net-guest', 'Guest', 50)]
        net_config = {'wan_interfaces': [
            {'name': 'WAN', 'physical_interface': 'eth3', 'active': True},
        ]}
        policies = [_policy('p1', 'Block Unauthorized', 'z-hot', 'z-ext', action, index)]
        return _make_api(zones=zones, networks=networks, net_config=net_config, policies=policies)

    def test_resolves_block(self):
        api = self._setup(action='BLOCK', index=30004)
        parsed = fpm.parse_firewall_rule('GUEST_WAN-30004')
        result = fpm.resolve_rule_action(parsed, api, 'br50', 'eth3')
        assert result == 'block'
        assert parsed['resolved_action'] == 'block'
        assert parsed['action_source'] == 'policy_lookup'

    def test_resolves_allow(self):
        api = self._setup(action='ALLOW', index=30004)
        parsed = fpm.parse_firewall_rule('GUEST_WAN-30004')
        result = fpm.resolve_rule_action(parsed, api, 'br50', 'eth3')
        assert result == 'allow'

    def test_unmatched_index_no_desc(self):
        api = self._setup(action='BLOCK', index=999)
        parsed = fpm.parse_firewall_rule('GUEST_WAN-30004')
        result = fpm.resolve_rule_action(parsed, api, 'br50', 'eth3')
        assert result is None
        assert parsed['resolved_action'] is None

    def test_unmatched_index_falls_back_to_desc_hint(self):
        """When policy lookup finds no match, desc_hint is used as fallback."""
        api = self._setup(action='BLOCK', index=999)  # won't match 30004
        parsed = fpm.parse_firewall_rule('GUEST_WAN-30004',
                                          rule_desc='Block Unauthorized Traffic')
        assert parsed['desc_hint'] == 'block'
        assert parsed['resolved_action'] is None  # not pre-populated
        result = fpm.resolve_rule_action(parsed, api, 'br50', 'eth3')
        assert result == 'block'
        assert parsed['resolved_action'] == 'block'
        assert parsed['action_source'] == 'rule_desc'

    def test_policy_overrides_desc_hint(self):
        """Policy metadata takes precedence over desc_hint."""
        api = self._setup(action='ALLOW', index=30004)
        parsed = fpm.parse_firewall_rule('GUEST_WAN-30004',
                                          rule_desc='Block Unauthorized Traffic')
        assert parsed['desc_hint'] == 'block'  # desc says block
        result = fpm.resolve_rule_action(parsed, api, 'br50', 'eth3')
        assert result == 'allow'  # but policy says allow — policy wins
        assert parsed['action_source'] == 'policy_lookup'

    def test_no_api_falls_back_to_desc_hint(self):
        """When no UniFi API is available, desc_hint is used."""
        parsed = fpm.parse_firewall_rule('GUEST_WAN-30004',
                                          rule_desc='Block Unauthorized Traffic')
        result = fpm.resolve_rule_action(parsed, None, 'br50', 'eth3')
        assert result == 'block'
        assert parsed['action_source'] == 'rule_desc'

    def test_skips_already_resolved(self):
        """If resolved_action is already set, return it without API calls."""
        parsed = fpm.parse_firewall_rule('WAN_IN-A-1')
        api = MagicMock()
        result = fpm.resolve_rule_action(parsed, api, 'br0', 'eth3')
        assert result == 'allow'
        api.get_firewall_data.assert_not_called()

    def test_none_parsed(self):
        assert fpm.resolve_rule_action(None, MagicMock(), 'br0', 'eth3') is None

    def test_unknown_interface(self):
        api = self._setup()
        parsed = fpm.parse_firewall_rule('GUEST_WAN-30004')
        result = fpm.resolve_rule_action(parsed, api, 'br999', 'eth3')
        assert result is None


# ── build_zone_map ───────────────────────────────────────────────────────────

class TestBuildZoneMap:
    def test_basic_lan_zone(self):
        api = _make_api(
            zones=[_zone('z1', 'Internal', ['net1'])],
            networks=[_network('net1', 'Default', 1)],
        )
        result = fpm.build_zone_map(api)
        zm = result['zone_map']
        assert len(zm) == 1
        assert zm[0]['zone_id'] == 'z1'
        assert zm[0]['chain_name'] == 'LAN'
        assert zm[0]['interfaces'][0]['interface'] == 'br0'

    def test_vlan_interface(self):
        api = _make_api(
            zones=[_zone('z1', 'Internal', ['net1'])],
            networks=[_network('net1', 'IoT', 50)],
        )
        result = fpm.build_zone_map(api)
        assert result['zone_map'][0]['interfaces'][0]['interface'] == 'br50'

    def test_external_zone_wan(self):
        api = _make_api(
            zones=[_zone('z2', 'External')],
            net_config={'wan_interfaces': [
                {'name': 'WAN', 'physical_interface': 'eth3', 'active': True, 'wan_ip': '1.2.3.4'},
            ]},
        )
        result = fpm.build_zone_map(api)
        ifaces = result['zone_map'][0]['interfaces']
        assert len(ifaces) == 1
        assert ifaces[0]['interface'] == 'eth3'

    def test_gateway_zone_no_interfaces(self):
        api = _make_api(zones=[_zone('z3', 'Gateway')])
        result = fpm.build_zone_map(api)
        assert result['zone_map'][0]['interfaces'] == []
        assert result['zone_map'][0]['chain_name'] == 'LOCAL'

    def test_vpn_zone(self):
        api = _make_api(zones=[_zone('z4', 'VPN')])
        vpn = {'wg0': {'badge': 'WireGuard', 'cidr': '10.0.0.0/24'}}
        result = fpm.build_zone_map(api, vpn_networks=vpn)
        ifaces = result['zone_map'][0]['interfaces']
        assert len(ifaces) == 1
        assert ifaces[0]['interface'] == 'wg0'
        assert ifaces[0]['vpn'] is True

    def test_custom_zone_chain_name(self):
        api = _make_api(zones=[_zone('z5', 'SmartHome')])
        result = fpm.build_zone_map(api)
        assert result['zone_map'][0]['chain_name'] == 'CUSTOM1'

    def test_missing_network_id_graceful(self):
        # Zone references a network ID not present in net_config
        api = _make_api(zones=[_zone('z1', 'Internal', ['net-missing'])])
        result = fpm.build_zone_map(api)
        # Should succeed with no interfaces (graceful degradation)
        assert result['zone_map'][0]['interfaces'] == []

    def test_classic_fallback_ids_do_not_match_integration_zone_ids(self):
        """Documented limitation: if get_network_config() falls back to the classic API,
        network IDs use MongoDB-style _id values while zone networkIds use Integration
        API UUIDs. The ID mismatch means no zone-to-interface joins succeed, silently
        degrading matching for all non-WAN/Gateway zones."""
        api = _make_api(
            zones=[_zone('z1', 'Internal', ['integration-uuid-abc123'])],
            networks=[_network('classic_5f8a1b2c3d', 'Default', 1)],
        )
        result = fpm.build_zone_map(api)
        # IDs don't match → zone gets no interfaces (silent degradation)
        assert result['zone_map'][0]['interfaces'] == []

    def test_v2_zone_id_maps_interface_from_network_firewall_zone_id(self):
        """v2 zones omit networkIds, so direct network→zone ids must be honored.

        UniFi's v2 firewall policies reference v2 zone ids. When zones also come
        from v2, the zone records may not carry Integration-style networkIds.
        The classic networkconf record carries firewall_zone_id in the same v2
        namespace, which lets log-policy matching still map br* interfaces to
        the same zone ids returned by the policy endpoint.
        """
        api = _make_api(
            zones=[_zone('zone-v2-internal', 'Internal')],
            net_config={
                'wan_interfaces': [],
                'networks': [
                    {
                        'id': 'integration-network-id',
                        'name': 'Default',
                        'interface': 'br0',
                        'vlan': 1,
                        'firewall_zone_id': 'zone-v2-internal',
                    },
                ],
            },
        )

        result = fpm.build_zone_map(api)

        assert result['zone_map'][0]['zone_id'] == 'zone-v2-internal'
        assert result['zone_map'][0]['interfaces'][0]['interface'] == 'br0'


# ── match_log_to_policy ──────────────────────────────────────────────────────

class TestMatchLogToPolicy:
    def _setup_match(self, policies=None, extra_zones=None):
        """Standard 3-zone setup: Internal(br0), External(eth3), Gateway(no ifaces)."""
        zones = [
            _zone('z-int', 'Internal', ['net-default']),
            _zone('z-ext', 'External'),
            _zone('z-gw', 'Gateway'),
        ]
        if extra_zones:
            zones.extend(extra_zones)
        networks = [_network('net-default', 'Default', 1)]
        net_config = {'wan_interfaces': [
            {'name': 'WAN', 'physical_interface': 'eth3', 'active': True},
        ]}
        api = _make_api(
            zones=zones,
            networks=networks,
            net_config=net_config,
            policies=policies or [],
        )
        return api

    def test_matched_single_policy(self):
        policies = [_policy('p1', 'Block IoT', 'z-int', 'z-ext', 'BLOCK', 100, logging=True)]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'matched'
        assert result['policy']['id'] == 'p1'
        assert result['policy']['loggingEnabled'] is True

    def test_unmatched_no_policy(self):
        api = self._setup_match(policies=[])
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'unmatched'

    def test_unmatched_wrong_index(self):
        policies = [_policy('p1', 'Block IoT', 'z-int', 'z-ext', 'BLOCK', 200)]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'unmatched'

    def test_unmatched_wrong_action(self):
        policies = [_policy('p1', 'Allow All', 'z-int', 'z-ext', 'ALLOW', 100)]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'unmatched'

    def test_gateway_zone_empty_interface_out(self):
        """Falsy interface_out maps to Gateway zone."""
        policies = [_policy('p1', 'Block to GW', 'z-int', 'z-gw', 'BLOCK', 50)]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='',
            rule_name='LAN_LOCAL-D-50',
        )
        assert result['status'] == 'matched'
        assert result['policy']['id'] == 'p1'

    def test_uncontrollable_derived(self):
        policies = [_policy('p1', 'Auto Rule', 'z-int', 'z-ext', 'BLOCK', 100,
                            origin='DERIVED')]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'uncontrollable'
        assert 'auto-generated' in result['message']

    def test_uncontrollable_disabled(self):
        policies = [_policy('p1', 'Disabled Rule', 'z-int', 'z-ext', 'BLOCK', 100,
                            enabled=False)]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'uncontrollable'
        assert 'disabled' in result['message']

    def test_controllable_with_derived_twin(self):
        """DERIVED twin should be filtered out, leaving one controllable match."""
        policies = [
            _policy('p1', 'User Rule', 'z-int', 'z-ext', 'BLOCK', 100, origin='USER_DEFINED'),
            _policy('p2', 'Auto Rule', 'z-int', 'z-ext', 'BLOCK', 100, origin='DERIVED'),
        ]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'matched'
        assert result['policy']['id'] == 'p1'

    def test_ambiguous_two_controllable(self):
        policies = [
            _policy('p1', 'Rule A', 'z-int', 'z-ext', 'BLOCK', 100),
            _policy('p2', 'Rule B', 'z-int', 'z-ext', 'BLOCK', 100),
        ]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'ambiguous'

    def test_unsupported_reject(self):
        api = self._setup_match()
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-R-100',
        )
        assert result['status'] == 'unsupported'
        assert 'Reject' in result['message']

    def test_unsupported_unparseable_rule(self):
        api = self._setup_match()
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='garbage',
        )
        assert result['status'] == 'unsupported'

    def test_unknown_interface_in(self):
        api = self._setup_match()
        result = fpm.match_log_to_policy(
            api, interface_in='br999', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'unmatched'
        assert 'Unknown source interface' in result['message']

    def test_unknown_interface_out(self):
        api = self._setup_match()
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth99',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'unmatched'
        assert 'Unknown destination interface' in result['message']

    def test_error_on_api_failure(self):
        api = self._setup_match()
        api.get_firewall_data.side_effect = Exception('connection refused')
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert result['status'] == 'error'

    def test_origin_flat_in_response(self):
        """origin should be a flat field in the policy response, not nested in metadata."""
        policies = [_policy('p1', 'Test', 'z-int', 'z-ext', 'ALLOW', 50,
                            origin='USER_DEFINED')]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-A-50',
        )
        assert result['policy']['origin'] == 'USER_DEFINED'
        assert 'metadata' not in result['policy']

    def test_zone_index_matched_block(self):
        """Zone-index format rule matches policy and returns action."""
        # Add hotspot zone for GUEST_WAN matching
        hotspot_zone = _zone('z-hot', 'Hotspot', ['net-guest'])
        guest_net = _network('net-guest', 'Guest Network', 50)
        policies = [_policy('p1', 'Block Unauthorized', 'z-hot', 'z-ext', 'BLOCK', 30004)]
        api = self._setup_match(policies, extra_zones=[hotspot_zone])
        net_config = api.get_network_config.return_value
        api.get_network_config.return_value = {**net_config, 'networks': net_config['networks'] + [guest_net]}
        result = fpm.match_log_to_policy(
            api, interface_in='br50', interface_out='eth3',
            rule_name='GUEST_WAN-30004',
        )
        assert result['status'] == 'matched'
        assert result['policy']['id'] == 'p1'
        assert result['policy']['action'] == 'block'

    def test_zone_index_unmatched(self):
        """Zone-index format with no matching policy."""
        api = self._setup_match(policies=[])
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-30004',
        )
        assert result['status'] == 'unmatched'

    def test_legacy_block_B(self):
        """Legacy -B- action code should match BLOCK policies."""
        policies = [_policy('p1', 'Block Rule', 'z-int', 'z-ext', 'BLOCK', 1)]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-B-1',
        )
        assert result['status'] == 'matched'
        assert result['policy']['id'] == 'p1'

    def test_redirect_unsupported(self):
        """Redirect rules should return unsupported status."""
        api = self._setup_match()
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='DNAT-1',
        )
        assert result['status'] == 'unsupported'
        assert 'Redirect' in result['message']

    def test_action_in_matched_response(self):
        """Matched response should include action field."""
        policies = [_policy('p1', 'Allow All', 'z-int', 'z-ext', 'ALLOW', 50)]
        api = self._setup_match(policies)
        result = fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-A-50',
        )
        assert result['status'] == 'matched'
        assert result['policy']['action'] == 'allow'


# ── Snapshot cache ───────────────────────────────────────────────────────────

class TestSnapshotCache:
    def _setup(self):
        policies = [_policy('p1', 'Test', 'z-int', 'z-ext', 'BLOCK', 100)]
        zones = [
            _zone('z-int', 'Internal', ['net1']),
            _zone('z-ext', 'External'),
            _zone('z-gw', 'Gateway'),
        ]
        networks = [_network('net1', 'Default', 1)]
        net_config = {'wan_interfaces': [
            {'name': 'WAN', 'physical_interface': 'eth3', 'active': True},
        ]}
        api = _make_api(zones=zones, networks=networks, net_config=net_config, policies=policies)
        return api

    def test_cache_hit(self):
        api = self._setup()
        # First call populates cache
        fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        call_count = api.get_firewall_data.call_count

        # Second call should hit cache
        fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert api.get_firewall_data.call_count == call_count

    def test_cache_invalidation(self):
        api = self._setup()
        fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        call_count = api.get_firewall_data.call_count

        fpm.invalidate_cache()

        fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert api.get_firewall_data.call_count == call_count + 1

    def test_cache_expiry(self):
        api = self._setup()
        fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        call_count = api.get_firewall_data.call_count

        # Manually expire the cache
        with fpm._cache_lock:
            fpm._cached_snapshot['expires_at'] = time.monotonic() - 1

        fpm.match_log_to_policy(
            api, interface_in='br0', interface_out='eth3',
            rule_name='LAN_WAN-D-100',
        )
        assert api.get_firewall_data.call_count == call_count + 1

    def test_cache_ttl_is_5_minutes(self):
        assert fpm._CACHE_TTL == 300
