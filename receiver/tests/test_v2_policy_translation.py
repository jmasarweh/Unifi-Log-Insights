"""Tests for UniFi firewall policy v2 endpoint compatibility.

The firewall syslog UI expects the Integration API policy schema, but UniFi
Network 10.x omits Integration API ``id`` values for some policies created in
the controller UI. These tests lock down the compatibility layer that reads and
writes those policies through the internal v2 endpoint while preserving the
existing shape consumed by the rest of the app.
"""

import os
from copy import deepcopy
from unittest.mock import MagicMock, patch

import pytest
import requests

from unifi_api import UniFiAPI


POLICY_ID = "65f31c0a1234567890abcdef"


def _response(json_body, status_code=200):
    """Build a requests.Response-like mock with a stable JSON body."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.json.return_value = json_body
    resp.raise_for_status = MagicMock()
    resp.text = ""
    return resp


def _base_v2_policy(**overrides):
    """Return a representative v2 firewall policy record for translator tests."""
    policy = {
        "_id": POLICY_ID,
        "enabled": True,
        "name": "Allow IoT telemetry",
        "description": "",
        "index": 1200,
        "logging": False,
        "action": "ALLOW",
        "create_allow_respond": True,
        "ip_version": "BOTH",
        "predefined": False,
        "source": {
            "zone_id": "zone-internal",
            "matching_target": "ANY",
        },
        "destination": {
            "zone_id": "zone-external",
            "matching_target": "ANY",
        },
    }
    for key, value in overrides.items():
        if key in ("source", "destination"):
            policy[key].update(value)
        else:
            policy[key] = value
    return policy


@pytest.fixture
def api():
    """Create a UniFiAPI instance whose HTTP session is fully mocked."""
    mock_db = MagicMock()
    mock_db.get_config = MagicMock(return_value=None)
    with patch.object(UniFiAPI, "_resolve_config"):
        uapi = UniFiAPI(mock_db)
    uapi.host = "https://fake-controller"
    uapi.site = "default"
    uapi.api_key = "test-key"
    uapi.enabled = True
    uapi._controller_type = "unifi_os"
    uapi._session = MagicMock()
    return uapi


class TestV2PolicyTranslation:
    def test_any_target_preserves_existing_integration_shape(self, api):
        """ANY matching omits trafficFilter and exposes every policy with id."""
        mapped = api._v2_policy_to_integration_shape(_base_v2_policy())

        assert mapped == {
            "id": POLICY_ID,
            "enabled": True,
            "name": "Allow IoT telemetry",
            "description": "",
            "index": 1200,
            "loggingEnabled": False,
            "action": {
                "type": "ALLOW",
                "allowReturnTraffic": True,
            },
            "ipProtocolScope": {
                "ipVersion": "IPV4_AND_IPV6",
            },
            "source": {
                "zoneId": "zone-internal",
            },
            "destination": {
                "zoneId": "zone-external",
            },
            "metadata": {
                "origin": "USER_DEFINED",
            },
        }

    def test_app_target_maps_to_application_filter(self, api):
        """APP matching carries v2 app_ids into applicationFilter."""
        mapped = api._v2_policy_to_integration_shape(_base_v2_policy(
            source={
                "matching_target": "APP",
                "app_ids": ["app-a", "app-b"],
            },
        ))

        assert mapped["source"]["trafficFilter"] == {
            "type": "APPLICATION",
            "applicationFilter": {
                "applicationIds": ["app-a", "app-b"],
            },
        }

    def test_ip_target_maps_to_ip_address_filter(self, api):
        """IP matching expands each address into Integration API item objects."""
        mapped = api._v2_policy_to_integration_shape(_base_v2_policy(
            destination={
                "matching_target": "IP",
                "ips": ["192.0.2.10", "2001:db8::10"],
                "match_opposite_ips": True,
            },
        ))

        assert mapped["destination"]["trafficFilter"] == {
            "type": "IP_ADDRESS",
            "ipAddressFilter": {
                "type": "IP_ADDRESSES",
                "matchOpposite": True,
                "items": [
                    {"type": "IP_ADDRESS", "value": "192.0.2.10"},
                    {"type": "IP_ADDRESS", "value": "2001:db8::10"},
                ],
            },
        }

    def test_network_target_maps_to_network_filter(self, api):
        """NETWORK matching preserves v2 network IDs for logging toggles."""
        mapped = api._v2_policy_to_integration_shape(_base_v2_policy(
            source={
                "matching_target": "NETWORK",
                "network_ids": ["net-mongo-a", "net-mongo-b"],
                "match_opposite_networks": False,
            },
        ))

        assert mapped["source"]["trafficFilter"] == {
            "type": "NETWORK",
            "networkFilter": {
                "networkIds": ["net-mongo-a", "net-mongo-b"],
                "matchOpposite": False,
            },
        }

    def test_system_defined_policy_origin_and_ipv6_are_preserved(self, api):
        """predefined and ip_version fields map to existing frontend names."""
        mapped = api._v2_policy_to_integration_shape(_base_v2_policy(
            predefined=True,
            ip_version="IPV6",
            action="BLOCK",
            create_allow_respond=True,
        ))

        assert mapped["metadata"]["origin"] == "SYSTEM_DEFINED"
        assert mapped["ipProtocolScope"]["ipVersion"] == "IPV6"
        assert mapped["action"] == {"type": "BLOCK"}

    def test_unknown_matching_target_fails_loudly(self, api):
        """Unexpected v2 matching targets should not be silently dropped."""
        with pytest.raises(ValueError, match="Unsupported v2 firewall policy matching_target"):
            api._v2_policy_to_integration_shape(_base_v2_policy(
                source={"matching_target": "REGION"},
            ))


class TestV2FirewallPolicyEndpoints:
    def test_get_firewall_policies_reads_v2_endpoint_and_translates(self, api):
        """Firewall policy reads use v2 so UI-created policies always have ids."""
        api._session.get.return_value = _response([_base_v2_policy()])

        policies = api.get_firewall_policies()

        api._session.get.assert_called_once_with(
            "https://fake-controller/proxy/network/v2/api/site/default/firewall-policies",
            timeout=api.TIMEOUT,
        )
        assert policies[0]["id"] == POLICY_ID
        assert policies[0]["loggingEnabled"] is False

    def test_patch_firewall_policy_puts_full_v2_body(self, api):
        """v2 rejects partial updates, so patch fetches and PUTs the full record."""
        original = _base_v2_policy(logging=False)
        updated = _base_v2_policy(logging=True)
        api._session.get.return_value = _response([deepcopy(original)])
        api._session.put.return_value = _response(updated)

        result = api.patch_firewall_policy(POLICY_ID, True)

        api._session.get.assert_called_once_with(
            "https://fake-controller/proxy/network/v2/api/site/default/firewall-policies",
            timeout=api.TIMEOUT,
        )
        api._session.put.assert_called_once()
        put_url = api._session.put.call_args.args[0]
        put_body = api._session.put.call_args.kwargs["json"]
        assert put_url == (
            "https://fake-controller/proxy/network/v2/api/site/default/"
            f"firewall-policies/{POLICY_ID}"
        )
        assert put_body["_id"] == POLICY_ID
        assert put_body["logging"] is True
        assert set(original).issubset(set(put_body))
        assert result["id"] == POLICY_ID
        assert result["loggingEnabled"] is True

    def test_patch_firewall_policy_skips_put_when_state_already_matches(self, api):
        """A no-op logging change should return the translated record without PUT."""
        api._session.get.return_value = _response([_base_v2_policy(logging=True)])

        result = api.patch_firewall_policy(POLICY_ID, True)

        api._session.put.assert_not_called()
        assert result["id"] == POLICY_ID
        assert result["loggingEnabled"] is True

    def test_patch_firewall_policy_raises_when_policy_missing(self, api):
        """Missing ids surface clearly instead of writing to an undefined URL."""
        api._session.get.return_value = _response([_base_v2_policy()])

        with pytest.raises(ValueError, match="policy not found"):
            api.patch_firewall_policy("65f31c0a0000000000000000", True)

        api._session.put.assert_not_called()


def test_live_controller_v2_firewall_policy_toggle_round_trip():
    """Optional live controller smoke test, skipped unless explicitly enabled.

    Set UNIFI_LIVE_FIREWALL_TOGGLE=1 together with UNIFI_HOST and
    UNIFI_API_KEY to run this against a real UniFi OS controller. The test picks
    a user-defined policy when one exists, toggles logging, verifies the read
    path observes the change, and restores the original logging value.
    """
    if os.environ.get("UNIFI_LIVE_FIREWALL_TOGGLE") != "1":
        pytest.skip("set UNIFI_LIVE_FIREWALL_TOGGLE=1 to modify a live policy")
    if not os.environ.get("UNIFI_HOST") or not os.environ.get("UNIFI_API_KEY"):
        pytest.skip("UNIFI_HOST and UNIFI_API_KEY are required for live testing")

    mock_db = MagicMock()
    mock_db.get_config = MagicMock(return_value=None)
    with patch.object(UniFiAPI, "_resolve_config"):
        uapi = UniFiAPI(mock_db)
    uapi.host = os.environ["UNIFI_HOST"].rstrip("/")
    uapi.api_key = os.environ["UNIFI_API_KEY"]
    uapi.site = os.environ.get("UNIFI_SITE", "default")
    uapi.verify_ssl = os.environ.get("UNIFI_VERIFY_SSL", "").lower() not in (
        "false",
        "0",
        "no",
    )

    policies = uapi.get_firewall_policies()
    assert policies
    assert all(policy.get("id") for policy in policies)

    candidate = next(
        (policy for policy in policies
         if policy.get("metadata", {}).get("origin") == "USER_DEFINED"),
        policies[0],
    )
    original_logging = candidate.get("loggingEnabled", False)
    try:
        updated = uapi.patch_firewall_policy(candidate["id"], not original_logging)
        assert updated["loggingEnabled"] is (not original_logging)
        reread = {policy["id"]: policy for policy in uapi.get_firewall_policies()}
        assert reread[candidate["id"]]["loggingEnabled"] is (not original_logging)
    finally:
        uapi.patch_firewall_policy(candidate["id"], original_logging)
