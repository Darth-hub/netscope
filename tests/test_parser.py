"""
Tests for netscope.parser

Tests cover ParsedPacket properties, TCP flag decoding,
ICMP type naming, and service resolution.
Scapy is never imported here — all tests operate on pure Python objects.
"""

import unittest
from datetime import datetime

from netscope.parser import (
    ParsedPacket,
    _parse_tcp_flags,
    _icmp_type_name,
    resolve_service,
    WELL_KNOWN_PORTS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_packet(**overrides) -> ParsedPacket:
    defaults = dict(
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        protocol="TCP",
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=80,
        length=128,
    )
    defaults.update(overrides)
    return ParsedPacket(**defaults)


# ---------------------------------------------------------------------------
# ParsedPacket properties
# ---------------------------------------------------------------------------

class TestParsedPacketDirection(unittest.TestCase):

    def test_direction_includes_src_and_dst(self):
        pkt = make_packet(src_ip="1.2.3.4", dst_ip="5.6.7.8", src_port=1234, dst_port=443)
        self.assertEqual(pkt.direction, "1.2.3.4:1234 → 5.6.7.8:443")

    def test_direction_uses_asterisk_for_no_port(self):
        pkt = make_packet(protocol="ICMP", src_port=None, dst_port=None)
        self.assertIn(":*", pkt.direction)

    def test_direction_separator_is_arrow(self):
        pkt = make_packet()
        self.assertIn("→", pkt.direction)


class TestParsedPacketServiceInfo(unittest.TestCase):

    def test_service_info_with_known_ports(self):
        pkt = make_packet(src_port=80, dst_port=443, src_service="HTTP", dst_service="HTTPS")
        self.assertEqual(pkt.service_info, "HTTP → HTTPS")

    def test_service_info_falls_back_to_port_numbers(self):
        pkt = make_packet(src_port=9999, dst_port=8888, src_service=None, dst_service=None)
        self.assertIn("9999", pkt.service_info)
        self.assertIn("8888", pkt.service_info)

    def test_service_info_empty_when_no_ports(self):
        pkt = make_packet(protocol="ICMP", src_port=None, dst_port=None)
        self.assertEqual(pkt.service_info, "")


class TestParsedPacketSuspicion(unittest.TestCase):

    def test_telnet_dst_is_suspicious(self):
        self.assertTrue(make_packet(dst_port=23).is_suspicious)

    def test_telnet_src_is_suspicious(self):
        self.assertTrue(make_packet(src_port=23).is_suspicious)

    def test_ftp_is_suspicious(self):
        self.assertTrue(make_packet(dst_port=21).is_suspicious)

    def test_pop3_is_suspicious(self):
        self.assertTrue(make_packet(dst_port=110).is_suspicious)

    def test_imap_is_suspicious(self):
        self.assertTrue(make_packet(dst_port=143).is_suspicious)

    def test_https_not_suspicious(self):
        self.assertFalse(make_packet(src_port=54321, dst_port=443, flags="SYN").is_suspicious)

    def test_ssh_not_suspicious(self):
        self.assertFalse(make_packet(dst_port=22).is_suspicious)


class TestParsedPacketEncryption(unittest.TestCase):

    def test_https_is_encrypted(self):
        self.assertTrue(make_packet(dst_port=443, is_encrypted=True).is_encrypted)

    def test_http_not_encrypted(self):
        self.assertFalse(make_packet(dst_port=80, is_encrypted=False).is_encrypted)

    def test_default_is_not_encrypted(self):
        pkt = ParsedPacket(
            timestamp=datetime(2026, 1, 1), protocol="TCP", length=64
        )
        self.assertFalse(pkt.is_encrypted)


# ---------------------------------------------------------------------------
# TCP flag parsing
# ---------------------------------------------------------------------------

class TestParseTcpFlags(unittest.TestCase):

    def test_syn_only(self):
        self.assertEqual(_parse_tcp_flags("S"), "SYN")

    def test_syn_ack(self):
        result = _parse_tcp_flags("SA")
        self.assertIn("SYN", result)
        self.assertIn("ACK", result)

    def test_fin_ack(self):
        result = _parse_tcp_flags("FA")
        self.assertIn("FIN", result)
        self.assertIn("ACK", result)

    def test_rst(self):
        self.assertIn("RST", _parse_tcp_flags("R"))

    def test_push_ack(self):
        result = _parse_tcp_flags("PA")
        self.assertIn("PSH", result)
        self.assertIn("ACK", result)

    def test_empty_returns_none_string(self):
        self.assertEqual(_parse_tcp_flags(""), "NONE")

    def test_flags_joined_with_plus(self):
        result = _parse_tcp_flags("SA")
        self.assertIn("+", result)


# ---------------------------------------------------------------------------
# ICMP type naming
# ---------------------------------------------------------------------------

class TestIcmpTypeName(unittest.TestCase):

    def test_echo_request(self):
        self.assertEqual(_icmp_type_name(8, 0), "Echo Request")

    def test_echo_reply(self):
        self.assertEqual(_icmp_type_name(0, 0), "Echo Reply")

    def test_port_unreachable(self):
        name = _icmp_type_name(3, 3)
        self.assertIn("Unreachable", name)

    def test_host_unreachable(self):
        name = _icmp_type_name(3, 1)
        self.assertIn("Unreachable", name)

    def test_time_exceeded(self):
        self.assertEqual(_icmp_type_name(11, 0), "Time Exceeded")

    def test_unknown_type_includes_number(self):
        result = _icmp_type_name(99, 0)
        self.assertIn("99", result)


# ---------------------------------------------------------------------------
# Service resolution
# ---------------------------------------------------------------------------

class TestResolveService(unittest.TestCase):

    def test_http(self):
        self.assertEqual(resolve_service(80), "HTTP")

    def test_https(self):
        self.assertEqual(resolve_service(443), "HTTPS")

    def test_ssh(self):
        self.assertEqual(resolve_service(22), "SSH")

    def test_dns(self):
        self.assertEqual(resolve_service(53), "DNS")

    def test_unknown_returns_port_string(self):
        self.assertEqual(resolve_service(9999), "9999")

    def test_mysql(self):
        self.assertEqual(resolve_service(3306), "MySQL")


class TestWellKnownPortsCompleteness(unittest.TestCase):

    def test_critical_ports_present(self):
        required = [22, 23, 25, 53, 80, 110, 143, 443]
        for port in required:
            with self.subTest(port=port):
                self.assertIn(port, WELL_KNOWN_PORTS)


if __name__ == "__main__":
    unittest.main()
