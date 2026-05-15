"""Tests for parsers.py — syslog parsing, direction/action derivation, VPN matching."""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

import parsers
from parsers import (
    _is_broadcast_or_multicast,
    build_vpn_cidr_map,
    derive_action,
    derive_direction,
    detect_log_type,
    extract_mac,
    match_vpn_ip,
    parse_cef_threat,
    parse_dhcp,
    parse_dns,
    parse_firewall,
    parse_log,
    parse_syslog_timestamp,
    parse_wifi,
)


# ── _is_broadcast_or_multicast ───────────────────────────────────────────────

class TestIsBroadcastOrMulticast:
    def test_broadcast(self):
        assert _is_broadcast_or_multicast('255.255.255.255') is True

    def test_multicast_v4(self):
        assert _is_broadcast_or_multicast('224.0.0.1') is True

    def test_regular_ip(self):
        assert _is_broadcast_or_multicast('192.168.1.1') is False

    def test_empty(self):
        assert _is_broadcast_or_multicast('') is False

    def test_none(self):
        assert _is_broadcast_or_multicast(None) is False

    def test_invalid(self):
        assert _is_broadcast_or_multicast('not-an-ip') is False


# ── parse_syslog_timestamp ───────────────────────────────────────────────────

class TestParseSyslogTimestamp:
    def test_normal(self, monkeypatch):
        monkeypatch.setenv('TZ', 'UTC')
        ts = parse_syslog_timestamp('Feb', '8', '16:43:49')
        assert ts.tzinfo == timezone.utc
        assert ts.month == 2
        assert ts.day == 8
        assert ts.hour == 16
        assert ts.minute == 43
        assert ts.second == 49

    def test_year_rollover(self, monkeypatch):
        """Dec log arriving in January should get previous year."""
        monkeypatch.setenv('TZ', 'UTC')
        # Mock "now" to be January
        fake_now = datetime(2026, 1, 5, 10, 0, 0, tzinfo=timezone.utc)
        with patch('parsers.datetime') as mock_dt:
            mock_dt.now.return_value = fake_now
            mock_dt.side_effect = lambda *a, **k: datetime(*a, **k)
            ts = parse_syslog_timestamp('Dec', '31', '23:59:59')
        assert ts.year == 2025

    def test_no_rollover_near_month(self, monkeypatch):
        """Log month 1 month ahead should NOT roll back year (only >6 months triggers rollback)."""
        monkeypatch.setenv('TZ', 'UTC')
        fake_now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        with patch('parsers.datetime') as mock_dt:
            mock_dt.now.return_value = fake_now
            mock_dt.side_effect = lambda *a, **k: datetime(*a, **k)
            ts = parse_syslog_timestamp('Feb', '1', '12:00:00')
        assert ts.year == 2026

    def test_no_rollover_same_month(self, monkeypatch):
        """Same month should NOT roll back year."""
        monkeypatch.setenv('TZ', 'UTC')
        fake_now = datetime(2026, 3, 5, 10, 0, 0, tzinfo=timezone.utc)
        with patch('parsers.datetime') as mock_dt:
            mock_dt.now.return_value = fake_now
            mock_dt.side_effect = lambda *a, **k: datetime(*a, **k)
            ts = parse_syslog_timestamp('Mar', '5', '10:00:01')
        assert ts.year == 2026

    @pytest.mark.skipif(
        __import__('sys').platform == 'win32',
        reason='ZoneInfo America/New_York not available on Windows without tzdata'
    )
    def test_timezone_conversion(self, monkeypatch):
        """Non-UTC timezone should convert to UTC for storage."""
        monkeypatch.setenv('TZ', 'America/New_York')
        ts = parse_syslog_timestamp('Feb', '8', '12:00:00')
        assert ts.tzinfo == timezone.utc
        # EST is UTC-5, so 12:00 EST = 17:00 UTC
        assert ts.hour == 17

    def test_invalid_tz_falls_back(self, monkeypatch):
        monkeypatch.setenv('TZ', 'Invalid/Zone')
        ts = parse_syslog_timestamp('Feb', '8', '12:00:00')
        assert ts.tzinfo == timezone.utc


# ── detect_log_type ──────────────────────────────────────────────────────────

class TestDetectLogType:
    def test_firewall(self):
        body = 'kernel: [WAN_IN-B-4000000003-D]IN=ppp0 OUT=br20 SRC=1.2.3.4 DST=10.0.0.5 PROTO=TCP'
        assert detect_log_type(body) == 'firewall'

    def test_firewall_descr(self):
        body = '[WAN_LOCAL-A-1] DESCR="Allow All" IN=ppp0'
        assert detect_log_type(body) == 'firewall'

    def test_dns_query(self):
        body = 'dnsmasq[1234]: query[A] example.com from 192.168.1.5'
        assert detect_log_type(body) == 'dns'

    def test_dns_reply(self):
        body = 'dnsmasq[1234]: reply example.com is 1.2.3.4'
        assert detect_log_type(body) == 'dns'

    def test_dhcp_ack(self):
        body = 'dnsmasq-dhcp[1234]: DHCPACK(br0) 192.168.1.100 aa:bb:cc:dd:ee:ff host1'
        assert detect_log_type(body) == 'dhcp'

    def test_dhcp_discover(self):
        body = 'DHCPDISCOVER(br0) aa:bb:cc:dd:ee:ff'
        assert detect_log_type(body) == 'dhcp'

    def test_wifi_stamgr(self):
        body = 'stamgr: STA aa:bb:cc:dd:ee:ff associated'
        assert detect_log_type(body) == 'wifi'

    def test_wifi_hostapd(self):
        body = 'hostapd: ath0: STA aa:bb:cc:dd:ee:ff authenticated'
        assert detect_log_type(body) == 'wifi'

    def test_wifi_stahtd(self):
        body = 'stahtd[1234]: {"mac":"aa:bb:cc:dd:ee:ff","event_type":"connect"}'
        assert detect_log_type(body) == 'wifi'

    def test_system(self):
        body = 'systemd[1]: Starting Daily Cleanup...'
        assert detect_log_type(body) == 'system'

    def test_system_earlyoom(self):
        body = 'earlyoom[456]: mem avail 1234 MiB'
        assert detect_log_type(body) == 'system'

    def test_cef_threat_routes_to_firewall(self):
        """Network 10.x SIEM Server CEF threat events share the
        ``firewall`` log_type with netfilter blocks.

        These are firewall block decisions from a user perspective and
        share UIP's existing FIREWALL/BLOCK filter UI; the
        ``rule_desc='IDS/IPS'`` column distinguishes them downstream.
        """
        body = (
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected and Blocked|7|'
            'UNIFIcategory=Security src=1.2.3.4'
        )
        assert detect_log_type(body) == 'firewall'

    def test_cef_audit_falls_through_to_system(self):
        """Non-threat CEF (audit / config / admin) is intentionally left to
        ``parse_system`` until dedicated routing is added in a future change.

        This preserves current behaviour for audit events that previously
        landed in ``system`` — no silent regression for existing users.
        """
        body = (
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|546|Config Modified|5|'
            'UNIFIcategory=Audit'
        )
        assert detect_log_type(body) == 'system'

    def test_cef_non_ubiquiti_falls_through(self):
        """Foreign-vendor CEF (theoretically possible with rsyslog relays)
        must not be hijacked by this parser. We only claim Ubiquiti CEF."""
        body = (
            'CEF:0|Fortinet|FortiGate|7.4.0|201|Some Event|7|'
            'src=1.2.3.4'
        )
        assert detect_log_type(body) == 'system'


# ── parse_firewall ───────────────────────────────────────────────────────────

class TestParseFirewall:
    FULL_LINE = (
        'kernel: [WAN_IN-B-4000000003-D]IN=ppp0 OUT=br20 '
        'MAC=aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:08:00 '
        'SRC=203.0.113.5 DST=10.0.20.100 '
        'PROTO=TCP SPT=54321 DPT=443'
    )

    def test_full_parse(self):
        r = parse_firewall(self.FULL_LINE)
        assert r['log_type'] == 'firewall'
        assert r['rule_name'] == 'WAN_IN-B-4000000003-D'
        assert r['interface_in'] == 'ppp0'
        assert r['interface_out'] == 'br20'
        assert r['src_ip'] == '203.0.113.5'
        assert r['dst_ip'] == '10.0.20.100'
        assert r['protocol'] == 'tcp'
        assert r['src_port'] == 54321
        assert r['dst_port'] == 443
        assert r['mac_address'] == '11:22:33:44:55:66'
        assert r['rule_action'] == 'block'
        assert r['direction'] == 'inbound'

    def test_zone_index_rule_with_block_desc(self):
        """Issue #80: GUEST_WAN-30004 with 'Block Unauthorized Traffic' description."""
        body = (
            'kernel: [GUEST_WAN-30004] DESCR="[GUEST_WAN]Block Unauthorized Traffic" '
            'IN=br70 OUT=eth4 MAC=00:00:00:00:00:00:11:22:33:44:55:66:08:00 '
            'SRC=10.120.70.96 DST=142.250.129.95 LEN=1278 TOS=00 PREC=0x00 TTL=63 '
            'ID=16702 DF PROTO=UDP SPT=40682 DPT=443 LEN=1258 MARK=1a0000'
        )
        r = parse_firewall(body)
        assert r['rule_name'] == 'GUEST_WAN-30004'
        assert r['rule_desc'] == '[GUEST_WAN]Block Unauthorized Traffic'
        assert r['rule_action'] == 'block'

    def test_missing_optional_fields(self):
        body = 'kernel: SRC=1.2.3.4 DST=10.0.0.1 PROTO=ICMP'
        r = parse_firewall(body)
        assert r['src_ip'] == '1.2.3.4'
        assert r['protocol'] == 'icmp'
        assert r['src_port'] is None
        assert r['dst_port'] is None
        assert r['mac_address'] is None
        assert r['rule_name'] is None

    def test_ipv6_addresses(self):
        body = 'kernel: [RULE1]IN=ppp0 OUT= SRC=2001:db8::1 DST=fd00::2 PROTO=TCP SPT=80 DPT=8080'
        r = parse_firewall(body)
        assert r['src_ip'] == '2001:db8::1'
        assert r['dst_ip'] == 'fd00::2'


# ── parse_dns ────────────────────────────────────────────────────────────────

class TestParseDns:
    def test_query(self):
        body = 'dnsmasq[1234]: query[A] example.com from 192.168.1.5'
        r = parse_dns(body)
        assert r['log_type'] == 'dns'
        assert r['dns_type'] == 'A'
        assert r['dns_query'] == 'example.com'
        assert r['src_ip'] == '192.168.1.5'

    def test_reply(self):
        body = 'dnsmasq[1234]: reply example.com is 1.2.3.4'
        r = parse_dns(body)
        assert r['dns_query'] == 'example.com'
        assert r['dns_answer'] == '1.2.3.4'

    def test_forward(self):
        body = 'dnsmasq[1234]: forwarded example.com to 8.8.8.8'
        r = parse_dns(body)
        assert r['dns_query'] == 'example.com'
        assert r['dst_ip'] == '8.8.8.8'

    def test_cached(self):
        body = 'dnsmasq[1234]: cached example.com is 1.2.3.4'
        r = parse_dns(body)
        assert r['dns_query'] == 'example.com'
        assert r['dns_answer'] == '1.2.3.4'

    def test_no_match(self):
        body = 'dnsmasq[1234]: some unknown line'
        r = parse_dns(body)
        assert r['log_type'] == 'dns'
        assert 'dns_query' not in r


# ── parse_dhcp ───────────────────────────────────────────────────────────────

class TestParseDhcp:
    def test_ack_with_hostname(self):
        body = 'dnsmasq-dhcp[1234]: DHCPACK(br0) 192.168.1.100 aa:bb:cc:dd:ee:ff myhost'
        r = parse_dhcp(body)
        assert r['dhcp_event'] == 'DHCPACK'
        assert r['src_ip'] == '192.168.1.100'
        assert r['mac_address'] == 'aa:bb:cc:dd:ee:ff'
        assert r['hostname'] == 'myhost'

    def test_ack_without_hostname(self):
        body = 'dnsmasq-dhcp[1234]: DHCPACK(br0) 192.168.1.100 aa:bb:cc:dd:ee:ff'
        r = parse_dhcp(body)
        assert r['dhcp_event'] == 'DHCPACK'
        assert r['hostname'] is None

    def test_discover(self):
        body = 'dnsmasq-dhcp[1234]: DHCPDISCOVER(br0) aa:bb:cc:dd:ee:ff'
        r = parse_dhcp(body)
        assert r['dhcp_event'] == 'DHCPDISCOVER'
        assert r['mac_address'] == 'aa:bb:cc:dd:ee:ff'
        assert 'src_ip' not in r

    def test_discover_with_ip(self):
        """Some gateways emit IP before MAC in DHCPDISCOVER."""
        body = 'dnsmasq-dhcp[1234]: DHCPDISCOVER(br40) 10.10.10.5 aa:bb:cc:dd:ee:ff'
        r = parse_dhcp(body)
        assert r['dhcp_event'] == 'DHCPDISCOVER'
        assert r['mac_address'] == 'aa:bb:cc:dd:ee:ff'
        assert r['src_ip'] == '10.10.10.5'
        assert r['interface_in'] == 'br40'

    def test_request(self):
        body = 'dnsmasq-dhcp[1234]: DHCPREQUEST(br0) 192.168.1.100 aa:bb:cc:dd:ee:ff'
        r = parse_dhcp(body)
        assert r['dhcp_event'] == 'DHCPREQUEST'

    def test_offer(self):
        body = 'dnsmasq-dhcp[1234]: DHCPOFFER(br0) 192.168.1.100 aa:bb:cc:dd:ee:ff'
        r = parse_dhcp(body)
        assert r['dhcp_event'] == 'DHCPOFFER'


# ── parse_wifi ───────────────────────────────────────────────────────────────

class TestParseWifi:
    def test_association(self):
        body = 'hostapd: ath0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated'
        r = parse_wifi(body)
        assert r['log_type'] == 'wifi'
        assert r['mac_address'] == 'aa:bb:cc:dd:ee:ff'
        assert r['wifi_event'] == 'associated'

    def test_disassociation(self):
        body = 'hostapd: ath0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: disassociated'
        r = parse_wifi(body)
        assert r['wifi_event'] == 'disassociated'

    def test_stamgr_event(self):
        body = 'stamgr: STA aa:bb:cc:dd:ee:ff'
        r = parse_wifi(body)
        assert r['wifi_event'] == 'stamgr'
        assert r['mac_address'] == 'aa:bb:cc:dd:ee:ff'

    def test_stahtd_json(self):
        body = 'stahtd[1234]: {"mac":"aa:bb:cc:dd:ee:ff","event_type":"connect"}'
        r = parse_wifi(body)
        assert r['mac_address'] == 'aa:bb:cc:dd:ee:ff'
        assert r['wifi_event'] == 'connect'

    def test_stahtd_invalid_json(self):
        body = 'stahtd[1234]: {not valid json}'
        r = parse_wifi(body)
        assert r['wifi_event'] == 'stahtd'


# ── parse_cef_threat ─────────────────────────────────────────────────────────

class TestParseCefThreat:
    """Tests for the CEF threat-class event parser.

    Sample events here are abridged but field-faithful renderings of real
    syslog messages received from a UDM Pro running UniFi OS 5.0.16 /
    Network 10.3.58 with *Settings → CyberSecure → Traffic Logging →
    Activity Logging → SIEM Server* enabled. Threat events route to
    ``log_type='firewall'`` so they share UIP's existing FIREWALL /
    BLOCK filter UI with netfilter blocks; ``rule_desc='IDS/IPS'``
    distinguishes them downstream.
    """

    # Real-world incoming-threat event: DShield Block List rule on the
    # IDS/IPS policy, captured 2026-05-14. Blocked NTP query from a
    # known-bad NL host to an internal client.
    INBOUND_THREAT = (
        'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected and Blocked|7|'
        'UNIFIcategory=Security UNIFIhost=UDMPRO proto=UDP spt=123 dpt=64280 '
        'act=blocked app=Other UNIFIrisk=medium UNIFIpolicyName=DShield Block List '
        'UNIFIpolicyType=IDS/IPS UNIFIdirection=incoming '
        'deviceOutboundInterface=Default UNIFIdeviceMac=e0:63:da:5b:17:11 '
        'UNIFIdeviceName=UDMPRO UNIFIdeviceModel=UDM-Pro UNIFIdeviceIp=192.168.200.1 '
        'UNIFIdeviceVersion=5.0.16 src=176.65.148.67 dst=192.168.200.56 '
        'UNIFIsrcRegion=NL UNIFIdstZone=Internal UNIFIdstDomain=pool.ntp.org '
        'UNIFIipsSignature=ET DROP Dshield Block Listed Source group 1 '
        'UNIFIipsSignatureId=2402000 UNIFIutcTime=2026-05-14T11:51:35.761Z '
        'msg=A network intrusion attempt from 176.65.148.67 to 192.168.200.56 '
        'has been detected and blocked.'
    )

    # Real-world outgoing-block: an internal client trying BitTorrent DHT
    # ping, blocked by the P2P IDS policy. Same event class (201) but
    # opposite direction — exercises the inverted geo-country mapping.
    OUTBOUND_P2P = (
        'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected and Blocked|9|'
        'UNIFIcategory=Security proto=UDP spt=27032 dpt=6881 act=blocked '
        'app=Other UNIFIrisk=high UNIFIpolicyName=P2P UNIFIpolicyType=IDS/IPS '
        'UNIFIdirection=outgoing src=192.168.200.175 dst=46.107.202.150 '
        'UNIFIsrcZone=Internal UNIFIdstRegion=HU '
        'UNIFIipsSignature=ET P2P BitTorrent DHT ping request '
        'UNIFIipsSignatureId=2008581 UNIFIutcTime=2026-05-14T10:44:34.387Z '
        'msg=A network intrusion attempt from 192.168.200.175 to 46.107.202.150 '
        'has been detected and blocked.'
    )

    # Audit event — same CEF envelope, different event class (5xx range)
    # and category. Should NOT be claimed by parse_cef; parse_log routes
    # it to parse_system instead.
    CONFIG_AUDIT = (
        'CEF:0|Ubiquiti|UniFi Network|10.3.58|546|Config Modified|5|'
        'UNIFIcategory=Audit UNIFIhost=UDMPRO src=192.168.200.159 '
        'UNIFIutcTime=2026-05-13T22:59:56.816Z msg=Config change.'
    )

    def test_inbound_threat_full_fields(self):
        """All structured fields populated from a real DShield-block event."""
        r = parse_cef_threat(self.INBOUND_THREAT)
        assert r is not None
        assert r['log_type'] == 'firewall'
        assert r['src_ip'] == '176.65.148.67'
        assert r['dst_ip'] == '192.168.200.56'
        assert r['src_port'] == 123
        assert r['dst_port'] == 64280
        assert r['protocol'] == 'udp'
        assert r['rule_action'] == 'block'
        assert r['rule_name'] == 'DShield Block List'
        assert r['rule_desc'] == 'IDS/IPS'
        assert r['direction'] == 'inbound'
        assert r['geo_country'] == 'NL'
        assert r['threat_score'] == 60  # medium → 60 (clears Threats counter)
        assert r['threat_categories'] == ['ET DROP Dshield Block Listed Source group 1']

    def test_outbound_p2p_inverts_geo_to_dst_region(self):
        """For outbound flows the external party is the destination, so
        ``UNIFIdstRegion`` (not ``UNIFIsrcRegion``) is the interesting geo."""
        r = parse_cef_threat(self.OUTBOUND_P2P)
        assert r is not None
        assert r['src_ip'] == '192.168.200.175'
        assert r['dst_ip'] == '46.107.202.150'
        assert r['direction'] == 'outbound'
        assert r['geo_country'] == 'HU'
        assert r['threat_score'] == 80  # high → 80
        assert r['rule_name'] == 'P2P'

    def test_audit_event_returns_none(self):
        """Audit / non-threat CEF events are out of scope for this parser."""
        assert parse_cef_threat(self.CONFIG_AUDIT) is None

    def test_foreign_vendor_returns_none(self):
        """CEF from non-Ubiquiti devices (e.g. a relayed Fortinet feed) is
        not claimed — we have no field map for foreign vendors."""
        body = (
            'CEF:0|Fortinet|FortiGate|7.4.0|201|IPS Detection|7|'
            'src=1.2.3.4 dst=10.0.0.1 act=blocked'
        )
        assert parse_cef_threat(body) is None

    def test_malformed_header_returns_none(self):
        """A truncated or otherwise unparseable CEF header is rejected
        cleanly — must not raise."""
        assert parse_cef_threat('CEF:0|Ubiquiti|truncated') is None

    def test_non_cef_body_returns_none(self):
        """Lines that don't begin with the CEF marker are out of scope."""
        assert parse_cef_threat('Feb 8 16:43:49 UDR kernel: ordinary syslog line') is None

    def test_protocol_normalised_to_lowercase(self):
        """Match the firewall parser's convention: protocol is lowercase."""
        r = parse_cef_threat(self.INBOUND_THREAT)
        assert r['protocol'] == 'udp'

    def test_act_allowed_maps_to_allow(self):
        """``act=allowed`` (rare for the threat event class but possible)
        maps to the existing ``rule_action='allow'`` schema value."""
        body = (
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected|7|'
            'act=allowed src=1.2.3.4 dst=2.3.4.5'
        )
        r = parse_cef_threat(body)
        assert r['rule_action'] == 'allow'

    def test_unknown_risk_yields_no_score(self):
        """Risk levels not in the known mapping leave ``threat_score``
        unset rather than guess a value."""
        body = (
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected|7|'
            'src=1.2.3.4 dst=2.3.4.5 UNIFIrisk=unknown'
        )
        r = parse_cef_threat(body)
        assert r.get('threat_score') is None

    def test_low_risk_maps_to_score(self):
        body = (
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected|7|'
            'src=1.2.3.4 dst=2.3.4.5 UNIFIrisk=low'
        )
        assert parse_cef_threat(body)['threat_score'] == 20

    def test_medium_risk_clears_threats_counter_threshold(self):
        """The UIP ``Threats`` stats counter is ``threat_score > 50``.
        Mapping ``medium`` to 60 ensures verified threat-intel hits
        (e.g. DShield Block List) show up there rather than only as
        plain "blocked" entries."""
        body = (
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected|7|'
            'src=1.2.3.4 dst=2.3.4.5 UNIFIrisk=medium'
        )
        score = parse_cef_threat(body)['threat_score']
        assert score == 60
        assert score > 50  # The Threats-counter SQL filter

    def test_high_risk_maps_to_score(self):
        body = (
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected|7|'
            'src=1.2.3.4 dst=2.3.4.5 UNIFIrisk=high'
        )
        assert parse_cef_threat(body)['threat_score'] == 80

    def test_critical_risk_maps_to_score(self):
        body = (
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected|7|'
            'src=1.2.3.4 dst=2.3.4.5 UNIFIrisk=critical'
        )
        assert parse_cef_threat(body)['threat_score'] == 95

    def test_service_name_derived_from_dst_port(self):
        """``service_name`` is set from dst_port + protocol so the
        Dataflow view labels CEF rows the same way as iptables rows
        (e.g. UDP/123 → NTP, UDP/53 → DNS)."""
        body = (
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected|7|'
            'src=1.2.3.4 dst=2.3.4.5 proto=UDP dpt=123'
        )
        r = parse_cef_threat(body)
        assert r['service_name'] is not None
        # Don't assert exact value — depends on services.py mapping;
        # just confirm derivation fires when port+proto are present.

    def test_missing_optional_fields_yields_none_values(self):
        """A minimal threat event with only required header + a couple of
        fields parses without raising; missing fields read as ``None``."""
        body = (
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected|7|'
            'src=1.2.3.4 dst=2.3.4.5'
        )
        r = parse_cef_threat(body)
        assert r is not None
        assert r['log_type'] == 'firewall'
        assert r['src_ip'] == '1.2.3.4'
        assert r['dst_ip'] == '2.3.4.5'
        assert r.get('src_port') is None
        assert r.get('dst_port') is None
        assert r.get('threat_score') is None
        assert r.get('rule_name') is None

    def test_msg_field_preserves_spaces_and_punctuation(self):
        """The ``msg=`` extension is special — its value runs to end-of-line
        and contains arbitrary text. It must not be tokenised into key=value
        fragments (a naive whitespace split would corrupt the message)."""
        r = parse_cef_threat(self.INBOUND_THREAT)
        # parse_cef does not currently surface msg as a top-level field, but
        # parsing must not crash and surrounding fields must remain correct.
        assert r['src_ip'] == '176.65.148.67'
        assert r['threat_categories'] == ['ET DROP Dshield Block Listed Source group 1']

    def test_extension_with_equals_in_value_is_handled(self):
        """``msg=`` content can include ``=`` (e.g. shell-style ``a=b``)
        without breaking the parser. Robustness against pathological inputs."""
        body = (
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected|7|'
            'src=1.2.3.4 dst=2.3.4.5 msg=foo=bar baz=qux'
        )
        r = parse_cef_threat(body)
        assert r is not None
        assert r['src_ip'] == '1.2.3.4'

    def test_embedded_msg_marker_does_not_truncate_trailing_fields(self):
        """Regression: an earlier extension value (e.g. a Suricata
        signature description) may contain the literal substring
        " msg=". Using ``rfind(' msg=')`` instead of ``find(' msg=')``
        ensures the actual msg boundary (last in line, per UniFi's
        emitter) wins and every field between the embedded " msg="
        and end-of-line still parses.

        Counterexample contributed during code review — preserved here
        so future refactors of the extension parser cannot regress it.

        Known limitation acknowledged: the inner key=value tokeniser
        will still truncate ``UNIFIipsSignature`` at the embedded
        ``msg=`` (it has no way to know it's inside a value, and CEF
        doesn't escape ``=`` characters). In real UniFi output,
        Suricata signature descriptions are descriptive English text
        and don't contain ``key=`` patterns; this counterexample is
        defensive. The rfind fix recovers the high-value fields
        (``dst``, ``UNIFIrisk``, the real ``msg``) — full immunity
        would require a known-key tokeniser, which is over-engineered
        for the data UniFi actually emits.
        """
        body = (
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected|7|'
            'src=1.2.3.4 UNIFIipsSignature=contains msg= text '
            'dst=2.3.4.5 UNIFIrisk=high msg=real message at end'
        )
        r = parse_cef_threat(body)
        assert r is not None
        # Fields after the embedded " msg=" all parse correctly thanks
        # to rfind picking the trailing msg= boundary.
        assert r['src_ip'] == '1.2.3.4'
        assert r['dst_ip'] == '2.3.4.5'         # would be missing without rfind
        assert r['threat_score'] == 80          # high — would be unset without rfind
        # Known limitation (see docstring): UNIFIipsSignature is
        # truncated at the embedded ``msg=`` by the inner tokeniser.
        assert r['threat_categories'] == ['contains']

    def test_invalid_port_does_not_crash(self):
        """A non-numeric port value (defensive: shouldn't happen with real
        UniFi output, but the parser must not raise on malformed input)."""
        body = (
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected|7|'
            'src=1.2.3.4 dst=2.3.4.5 spt=abc dpt=def'
        )
        r = parse_cef_threat(body)
        assert r is not None
        assert r.get('src_port') is None
        assert r.get('dst_port') is None

    def test_direction_unknown_value_left_unset(self):
        """An ``UNIFIdirection`` value outside the known mapping leaves
        ``direction`` unset rather than passing through a garbage value."""
        body = (
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected|7|'
            'src=1.2.3.4 dst=2.3.4.5 UNIFIdirection=lateral'
        )
        r = parse_cef_threat(body)
        assert r.get('direction') is None

    def test_geo_fallback_src_region_when_direction_missing(self):
        """When ``UNIFIdirection`` is absent and only ``UNIFIsrcRegion`` is
        present, fall back to using the source region — better than no
        geo data at all."""
        body = (
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected|7|'
            'src=1.2.3.4 dst=2.3.4.5 UNIFIsrcRegion=DE'
        )
        r = parse_cef_threat(body)
        assert r['geo_country'] == 'DE'

    def test_geo_fallback_dst_region_when_direction_missing(self):
        """Symmetric fallback: only ``UNIFIdstRegion`` present, no
        direction hint — use the destination region."""
        body = (
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected|7|'
            'src=1.2.3.4 dst=2.3.4.5 UNIFIdstRegion=FR'
        )
        r = parse_cef_threat(body)
        assert r['geo_country'] == 'FR'

    def test_msg_only_extension(self):
        """When the extension portion contains *only* ``msg=...`` (no
        other key=value pairs), the parser must not blow up — the rest
        of the result is still well-formed albeit sparse."""
        body = (
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected|7|'
            'msg=A bare message with no other fields.'
        )
        r = parse_cef_threat(body)
        assert r is not None
        assert r['log_type'] == 'firewall'
        # Nothing else should be set
        assert r.get('src_ip') is None
        assert r.get('rule_action') is None


# ── derive_direction ─────────────────────────────────────────────────────────

class TestDeriveDirection:
    def test_inbound(self):
        assert derive_direction('ppp0', 'br20', 'WAN_IN-B-1') == 'inbound'

    def test_outbound(self):
        assert derive_direction('br0', 'ppp0', 'LAN_OUT-A-1') == 'outbound'

    def test_inter_vlan(self):
        assert derive_direction('br0', 'br20', 'VLAN-A-1') == 'inter_vlan'

    def test_vpn(self):
        assert derive_direction('wgsrv0', 'br0', 'RULE1') == 'vpn'

    def test_vpn_outbound(self):
        assert derive_direction('br0', 'wgsrv0', 'RULE1') == 'vpn'

    def test_nat(self):
        assert derive_direction('ppp0', 'br0', 'DNAT-1') == 'nat'

    def test_prerouting(self):
        assert derive_direction('ppp0', 'br0', 'PREROUTING-1') == 'nat'

    def test_local_no_out(self):
        assert derive_direction('br0', '', 'RULE1') == 'local'

    def test_wan_to_router(self):
        assert derive_direction('ppp0', '', 'WAN_LOCAL-A-1') == 'inbound'

    def test_broadcast_is_local(self):
        assert derive_direction('ppp0', 'br0', 'R1', '1.2.3.4', '255.255.255.255') == 'local'

    def test_multicast_is_local(self):
        assert derive_direction('br0', 'br20', 'R1', '10.0.0.1', '224.0.0.1') == 'local'

    def test_no_interfaces(self):
        assert derive_direction('', '', 'RULE1') is None

    def test_wan_ip_source_local(self, monkeypatch):
        """Traffic from router's WAN IP to LAN should be 'local'."""
        monkeypatch.setattr(parsers, 'WAN_IPS', {'1.2.3.4'})
        assert derive_direction('br0', 'br0', 'R1', src_ip='1.2.3.4') == 'local'


# ── derive_action ────────────────────────────────────────────────────────────

class TestDeriveAction:
    def test_allow(self):
        assert derive_action('WAN_IN-A-1') == 'allow'

    def test_block(self):
        assert derive_action('WAN_IN-B-1') == 'block'

    def test_block_d(self):
        assert derive_action('WAN_IN-D-1') == 'block'

    def test_reject(self):
        assert derive_action('WAN_IN-R-1') == 'block'

    def test_redirect(self):
        assert derive_action('DNAT-1') == 'redirect'

    def test_prerouting_redirect(self):
        assert derive_action('PREROUTING-1') == 'redirect'

    def test_default_allow(self):
        assert derive_action('CUSTOM_RULE') == 'allow'

    def test_none_input(self):
        assert derive_action(None) is None

    def test_new_format_returns_none(self):
        """Zone-index format without description — returns None."""
        assert derive_action('GUEST_WAN-30004') is None

    def test_new_format_custom_zone(self):
        assert derive_action('CUSTOM1_WAN-100') is None

    def test_new_format_with_block_desc(self):
        """Zone-index format with 'Block' in description — returns 'block'."""
        assert derive_action('GUEST_WAN-30004', '[GUEST_WAN]Block Unauthorized Traffic') == 'block'

    def test_new_format_with_allow_desc(self):
        assert derive_action('LAN_WAN-100', 'Allow All Traffic') == 'allow'

    def test_new_format_with_no_action_desc(self):
        """Description without action keyword — returns None."""
        assert derive_action('GUEST_WAN-30004', 'Some Custom Rule') is None


# ── extract_mac ──────────────────────────────────────────────────────────────

class TestExtractMac:
    def test_full_14_octets(self):
        mac_field = 'aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:08:00'
        assert extract_mac(mac_field) == '11:22:33:44:55:66'

    def test_short_field(self):
        assert extract_mac('aa:bb:cc') == 'aa:bb:cc'

    def test_none(self):
        assert extract_mac(None) is None

    def test_empty(self):
        assert extract_mac('') is None


# ── build_vpn_cidr_map / match_vpn_ip ────────────────────────────────────────

class TestVpnCidrMatching:
    VPN_CONFIG = {
        'wgsrv0': {'cidr': '10.10.0.0/24', 'badge': 'WGD SRV'},
        'wgclt0': {'cidr': '10.20.0.0/24', 'badge': 'WGD CLT'},
    }

    def test_build_map(self):
        cidrs = build_vpn_cidr_map(self.VPN_CONFIG)
        assert len(cidrs) == 2

    def test_match_client(self):
        cidrs = build_vpn_cidr_map(self.VPN_CONFIG)
        result = match_vpn_ip('10.10.0.50', cidrs)
        assert result is not None
        badge, _ = result
        assert badge == 'WGD SRV'

    def test_match_gateway(self):
        cidrs = build_vpn_cidr_map(self.VPN_CONFIG)
        result = match_vpn_ip('10.10.0.1', cidrs)
        assert result == ('WGD SRV', 'Gateway')

    def test_no_match(self):
        cidrs = build_vpn_cidr_map(self.VPN_CONFIG)
        assert match_vpn_ip('192.168.1.1', cidrs) is None

    def test_excluded_ip(self):
        cidrs = build_vpn_cidr_map(self.VPN_CONFIG)
        assert match_vpn_ip('10.10.0.50', cidrs, exclude_ips={'10.10.0.50'}) is None

    def test_empty_cidrs(self):
        assert match_vpn_ip('10.10.0.1', []) is None

    def test_none_ip(self):
        cidrs = build_vpn_cidr_map(self.VPN_CONFIG)
        assert match_vpn_ip(None, cidrs) is None

    def test_invalid_cidr_skipped(self):
        config = {'wgsrv0': {'cidr': 'not-a-cidr', 'badge': 'WGD SRV'}}
        cidrs = build_vpn_cidr_map(config)
        assert len(cidrs) == 0


# ── parse_log (end-to-end) ───────────────────────────────────────────────────

class TestParseLog:
    FULL_SYSLOG = (
        'Feb  8 16:43:49 UDR-UK kernel: [WAN_IN-B-4000000003-D]'
        'IN=ppp0 OUT=br20 SRC=203.0.113.5 DST=10.0.20.100 PROTO=TCP SPT=54321 DPT=443'
    )

    def test_full_firewall_line(self, monkeypatch):
        monkeypatch.setenv('TZ', 'UTC')
        r = parse_log(self.FULL_SYSLOG)
        assert r is not None
        assert r['log_type'] == 'firewall'
        assert r['src_ip'] == '203.0.113.5'
        assert r['timestamp'].tzinfo == timezone.utc
        assert r['raw_log'] == self.FULL_SYSLOG

    def test_rfc3164_priority_prefix(self, monkeypatch):
        monkeypatch.setenv('TZ', 'UTC')
        line = '<13>' + self.FULL_SYSLOG
        r = parse_log(line)
        assert r is not None
        assert r['log_type'] == 'firewall'
        assert r['raw_log'] == line  # Original raw preserved

    def test_unparseable_returns_none(self):
        assert parse_log('garbage data here') is None

    def test_invalid_ip_set_to_none(self, monkeypatch):
        monkeypatch.setenv('TZ', 'UTC')
        line = 'Feb  8 16:43:49 UDR kernel: SRC=not_ip DST=10.0.0.1 PROTO=TCP'
        r = parse_log(line)
        assert r is not None
        assert r['src_ip'] is None

    def test_dns_end_to_end(self, monkeypatch):
        monkeypatch.setenv('TZ', 'UTC')
        line = 'Feb  8 16:43:49 UDR dnsmasq[1234]: query[A] example.com from 192.168.1.5'
        r = parse_log(line)
        assert r['log_type'] == 'dns'
        assert r['dns_query'] == 'example.com'

    def test_valid_dhcp_mac_preserved(self, monkeypatch):
        """Valid MAC from DHCPDISCOVER with IP is preserved through validation."""
        monkeypatch.setenv('TZ', 'UTC')
        line = 'Feb  8 16:43:49 UDR dnsmasq-dhcp[1234]: DHCPDISCOVER(br40) 10.10.10.5 aa:bb:cc:dd:ee:ff'
        r = parse_log(line)
        assert r['log_type'] == 'dhcp'
        assert r['mac_address'] == 'aa:bb:cc:dd:ee:ff'

    def test_invalid_mac_set_to_none(self, monkeypatch):
        """MAC validation rejects non-MAC strings before DB insert."""
        monkeypatch.setenv('TZ', 'UTC')
        line = 'Feb  8 16:43:49 UDR hostapd: ath0: STA aa:bb:cc IEEE 802.11: associated'
        r = parse_log(line)
        assert r['log_type'] == 'wifi'
        assert r['mac_address'] is None

    def test_wifi_mac_survives_validation(self, monkeypatch):
        """Global MAC validation must not break valid WiFi MACs."""
        monkeypatch.setenv('TZ', 'UTC')
        line = 'Feb  8 16:43:49 UDR hostapd: ath0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated'
        r = parse_log(line)
        assert r['log_type'] == 'wifi'
        assert r['mac_address'] == 'aa:bb:cc:dd:ee:ff'

    def test_system_end_to_end(self, monkeypatch):
        monkeypatch.setenv('TZ', 'UTC')
        line = 'Feb  8 16:43:49 UDR systemd[1]: Starting Daily Cleanup...'
        r = parse_log(line)
        assert r['log_type'] == 'system'

    def test_cef_threat_end_to_end(self, monkeypatch):
        """A real CEF threat line wrapped in the usual RFC3164 syslog
        header is parsed into structured ``log_type='firewall'`` fields
        so it shares the FIREWALL filter UI with netfilter blocks."""
        monkeypatch.setenv('TZ', 'UTC')
        line = (
            'May 14 13:51:35 UDMPRO '
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|201|Threat Detected and Blocked|7|'
            'src=176.65.148.67 dst=192.168.200.56 proto=UDP spt=123 dpt=64280 '
            'act=blocked UNIFIrisk=medium UNIFIpolicyName=DShield Block List '
            'UNIFIpolicyType=IDS/IPS UNIFIdirection=incoming UNIFIsrcRegion=NL'
        )
        r = parse_log(line)
        assert r is not None
        assert r['log_type'] == 'firewall'
        assert r['src_ip'] == '176.65.148.67'
        assert r['dst_ip'] == '192.168.200.56'
        assert r['rule_action'] == 'block'
        assert r['geo_country'] == 'NL'
        assert r['protocol'] == 'udp'
        assert r['raw_log'] == line  # Original raw preserved

    def test_cef_audit_end_to_end_no_regression(self, monkeypatch):
        """Audit / config-change CEF events still resolve to ``log_type='system'``
        with ``raw_log`` preserved — no silent regression for existing data."""
        monkeypatch.setenv('TZ', 'UTC')
        line = (
            'May 14 00:59:56 UDMPRO '
            'CEF:0|Ubiquiti|UniFi Network|10.3.58|546|Config Modified|5|'
            'UNIFIcategory=Audit UNIFIadmin=Operator src=192.168.200.159'
        )
        r = parse_log(line)
        assert r is not None
        assert r['log_type'] == 'system'
        assert r['raw_log'] == line

    def test_cef_unifi_os_doubled_timestamp_end_to_end(self, monkeypatch):
        """UniFi OS-level CEF events sometimes carry a doubled timestamp
        (RFC3164 *and* ISO8601), which pushes the hostname into the syslog
        body and prefixes the ``CEF:`` marker. These are out-of-scope
        audit-style events (ECID 11xx) — must not be claimed by the CEF
        threat parser and must not crash; falling through to ``system``
        with ``raw_log`` preserved is the correct behaviour."""
        monkeypatch.setenv('TZ', 'UTC')
        line = (
            'May 15 00:41:02 2026-05-15T00:41:02.199Z UDMPRO '
            'CEF:0|Ubiquiti|UniFi OS|5.0.16|1102|Application Updated|1|'
            'UNIFIhost=Host UNIFIdeviceName=UDMPRO msg=Talk has been updated.'
        )
        r = parse_log(line)
        assert r is not None
        assert r['log_type'] == 'system'
        assert r['raw_log'] == line
