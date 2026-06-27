"""
Tests for netscope.filter

Covers post-parse packet matching and BPF expression generation.
No network access, no Scapy — tests operate on pure ParsedPacket objects.
"""

import unittest
from datetime import datetime

from netscope.parser import ParsedPacket
from netscope.filter import PacketFilter


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
# Packet matching
# ---------------------------------------------------------------------------

class TestPacketFilterMatching(unittest.TestCase):

    def test_empty_filter_matches_everything(self):
        f = PacketFilter()
        self.assertTrue(f.matches(make_packet()))
        self.assertTrue(f.matches(make_packet(protocol="UDP", dst_port=53)))

    # -- Port filtering --

    def test_port_filter_matches_dst_port(self):
        self.assertTrue(PacketFilter(port=80).matches(make_packet(dst_port=80)))

    def test_port_filter_matches_src_port(self):
        self.assertTrue(PacketFilter(port=54321).matches(make_packet(src_port=54321)))

    def test_port_filter_rejects_non_matching_port(self):
        f = PacketFilter(port=443)
        pkt = make_packet(src_port=12345, dst_port=80)
        self.assertFalse(f.matches(pkt))

    def test_port_zero_not_set(self):
        # port=0 treated as not set (falsy), so no filtering
        f = PacketFilter(port=None)
        self.assertTrue(f.matches(make_packet(dst_port=9999)))

    # -- Protocol filtering --

    def test_proto_tcp_matches(self):
        self.assertTrue(PacketFilter(proto="tcp").matches(make_packet(protocol="TCP")))

    def test_proto_udp_matches(self):
        self.assertTrue(PacketFilter(proto="udp").matches(make_packet(protocol="UDP")))

    def test_proto_case_insensitive(self):
        self.assertTrue(PacketFilter(proto="TCP").matches(make_packet(protocol="TCP")))

    def test_proto_rejects_wrong_protocol(self):
        self.assertFalse(PacketFilter(proto="udp").matches(make_packet(protocol="TCP")))

    def test_proto_icmp(self):
        self.assertTrue(PacketFilter(proto="icmp").matches(make_packet(protocol="ICMP")))

    # -- IP filtering --

    def test_src_ip_matches(self):
        self.assertTrue(
            PacketFilter(src_ip="192.168.1.10").matches(make_packet(src_ip="192.168.1.10"))
        )

    def test_src_ip_rejects_wrong(self):
        self.assertFalse(
            PacketFilter(src_ip="1.2.3.4").matches(make_packet(src_ip="192.168.1.10"))
        )

    def test_dst_ip_matches(self):
        self.assertTrue(
            PacketFilter(dst_ip="10.0.0.1").matches(make_packet(dst_ip="10.0.0.1"))
        )

    def test_dst_ip_rejects_wrong(self):
        self.assertFalse(
            PacketFilter(dst_ip="8.8.8.8").matches(make_packet(dst_ip="10.0.0.1"))
        )

    # -- Combined filtering (AND semantics) --

    def test_combined_all_match(self):
        f = PacketFilter(port=443, proto="tcp", src_ip="192.168.1.10")
        pkt = make_packet(protocol="TCP", src_ip="192.168.1.10", dst_port=443)
        self.assertTrue(f.matches(pkt))

    def test_combined_one_miss_fails(self):
        f = PacketFilter(port=443, proto="tcp", src_ip="1.2.3.4")
        pkt = make_packet(protocol="TCP", src_ip="192.168.1.10", dst_port=443)
        self.assertFalse(f.matches(pkt))

    def test_port_and_proto_both_must_match(self):
        f = PacketFilter(port=80, proto="udp")
        pkt_tcp_80 = make_packet(protocol="TCP", dst_port=80)
        pkt_udp_80 = make_packet(protocol="UDP", dst_port=80)
        self.assertFalse(f.matches(pkt_tcp_80))
        self.assertTrue(f.matches(pkt_udp_80))


# ---------------------------------------------------------------------------
# is_active property
# ---------------------------------------------------------------------------

class TestIsActive(unittest.TestCase):

    def test_no_filters_not_active(self):
        self.assertFalse(PacketFilter().is_active)

    def test_port_filter_is_active(self):
        self.assertTrue(PacketFilter(port=80).is_active)

    def test_proto_filter_is_active(self):
        self.assertTrue(PacketFilter(proto="tcp").is_active)

    def test_src_ip_filter_is_active(self):
        self.assertTrue(PacketFilter(src_ip="1.2.3.4").is_active)

    def test_dst_ip_filter_is_active(self):
        self.assertTrue(PacketFilter(dst_ip="1.2.3.4").is_active)


# ---------------------------------------------------------------------------
# BPF expression generation
# ---------------------------------------------------------------------------

class TestBPFGeneration(unittest.TestCase):

    def test_empty_filter_produces_empty_bpf(self):
        self.assertEqual(PacketFilter().to_bpf(), "")

    def test_proto_only(self):
        self.assertEqual(PacketFilter(proto="tcp").to_bpf(), "tcp")

    def test_proto_uppercase_lowercased_in_bpf(self):
        self.assertEqual(PacketFilter(proto="TCP").to_bpf(), "tcp")

    def test_port_only(self):
        self.assertEqual(PacketFilter(port=80).to_bpf(), "port 80")

    def test_src_ip_only(self):
        self.assertEqual(PacketFilter(src_ip="1.2.3.4").to_bpf(), "src host 1.2.3.4")

    def test_dst_ip_only(self):
        self.assertEqual(PacketFilter(dst_ip="1.2.3.4").to_bpf(), "dst host 1.2.3.4")

    def test_proto_and_port_joined_with_and(self):
        bpf = PacketFilter(proto="tcp", port=443).to_bpf()
        self.assertIn("tcp", bpf)
        self.assertIn("port 443", bpf)
        self.assertIn(" and ", bpf)

    def test_all_criteria_joined_with_and(self):
        bpf = PacketFilter(proto="tcp", port=80, src_ip="1.2.3.4", dst_ip="5.6.7.8").to_bpf()
        self.assertEqual(bpf.count(" and "), 3)

    def test_multiple_ands_not_duplicated(self):
        bpf = PacketFilter(proto="tcp", port=80).to_bpf()
        self.assertEqual(bpf.count(" and "), 1)


# ---------------------------------------------------------------------------
# describe()
# ---------------------------------------------------------------------------

class TestDescribe(unittest.TestCase):

    def test_empty_returns_none_string(self):
        self.assertEqual(PacketFilter().describe(), "none")

    def test_proto_in_description(self):
        self.assertIn("protocol=TCP", PacketFilter(proto="tcp").describe())

    def test_port_in_description(self):
        self.assertIn("port=80", PacketFilter(port=80).describe())

    def test_src_ip_in_description(self):
        self.assertIn("src=1.2.3.4", PacketFilter(src_ip="1.2.3.4").describe())

    def test_dst_ip_in_description(self):
        self.assertIn("dst=5.6.7.8", PacketFilter(dst_ip="5.6.7.8").describe())

    def test_combined_description_comma_separated(self):
        desc = PacketFilter(proto="tcp", port=80).describe()
        self.assertIn(",", desc)


if __name__ == "__main__":
    unittest.main()
