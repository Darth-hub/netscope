"""
filter.py — Packet filtering with BPF expression generation.

Filters are applied in two stages:
1. BPF string passed to Scapy's sniff() — kernel-level, zero-copy, efficient.
2. Post-parse matching on ParsedPacket fields for criteria not expressible in BPF.

All active criteria are AND-combined: a packet must satisfy every criterion to pass.
"""

from typing import Optional, List
from netscope.parser import ParsedPacket


class PacketFilter:
    """
    Builds BPF filter expressions and performs post-parse packet matching.

    Args:
        port:   Match packets where src OR dst port equals this value.
        proto:  Match packets of this protocol ('tcp', 'udp', 'icmp').
        src_ip: Match packets from this source IP address.
        dst_ip: Match packets destined for this IP address.
    """

    def __init__(
        self,
        port: Optional[int] = None,
        proto: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
    ):
        self.port = port
        self.proto = proto.upper() if proto else None
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    # ------------------------------------------------------------------
    # Post-parse matching
    # ------------------------------------------------------------------

    def matches(self, pkt: ParsedPacket) -> bool:
        """
        Return True if the packet satisfies all active filter criteria.

        Called after parse_packet() so it works on ParsedPacket fields.
        """
        if self.proto and pkt.protocol != self.proto:
            return False
        if self.port is not None:
            if pkt.src_port != self.port and pkt.dst_port != self.port:
                return False
        if self.src_ip and pkt.src_ip != self.src_ip:
            return False
        if self.dst_ip and pkt.dst_ip != self.dst_ip:
            return False
        return True

    # ------------------------------------------------------------------
    # BPF generation
    # ------------------------------------------------------------------

    def to_bpf(self) -> str:
        """
        Generate a Berkeley Packet Filter expression for Scapy's sniff().

        Pre-filtering at the capture layer is significantly more efficient
        than post-filtering parsed packets on high-traffic interfaces, as it
        avoids copying unmatched frames into user space entirely.

        Returns an empty string if no filters are set (capture everything).
        """
        expressions: List[str] = []

        if self.proto:
            expressions.append(self.proto.lower())
        if self.port is not None:
            expressions.append(f"port {self.port}")
        if self.src_ip:
            expressions.append(f"src host {self.src_ip}")
        if self.dst_ip:
            expressions.append(f"dst host {self.dst_ip}")

        return " and ".join(expressions)

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    @property
    def is_active(self) -> bool:
        """True if at least one filter criterion is set."""
        return any([self.port is not None, self.proto, self.src_ip, self.dst_ip])

    def describe(self) -> str:
        """Return a compact human-readable description of active filters."""
        parts = []
        if self.proto:
            parts.append(f"protocol={self.proto}")
        if self.port is not None:
            parts.append(f"port={self.port}")
        if self.src_ip:
            parts.append(f"src={self.src_ip}")
        if self.dst_ip:
            parts.append(f"dst={self.dst_ip}")
        return ", ".join(parts) if parts else "none"
