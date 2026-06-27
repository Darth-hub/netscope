"""
parser.py — Protocol header parsing for IP, TCP, UDP, and ICMP layers.

Converts raw Scapy packets into structured ParsedPacket dataclasses
so the rest of the codebase never touches Scapy objects directly.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from datetime import datetime


# Well-known port → service name mappings
WELL_KNOWN_PORTS: Dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    27017: "MongoDB",
}

# Ports that carry encrypted traffic
ENCRYPTED_PORTS = {443, 8443, 993, 995, 465, 22}

# Ports that are unencrypted and credentials may be exposed
UNENCRYPTED_CRED_PORTS = {21, 23, 110, 143}

TCP_FLAGS: Dict[str, str] = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}


@dataclass
class ParsedPacket:
    """
    Structured representation of a captured network packet.

    All fields are optional except timestamp, protocol, and length —
    ICMP packets have no ports, and non-IP packets have no IPs.
    """

    timestamp: datetime
    protocol: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    src_service: Optional[str] = None
    dst_service: Optional[str] = None
    flags: Optional[str] = None
    ttl: Optional[int] = None
    length: int = 0
    payload_size: int = 0
    is_encrypted: bool = False
    raw_summary: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def direction(self) -> str:
        """Human-readable src → dst string."""
        src = f"{self.src_ip}:{self.src_port or '*'}"
        dst = f"{self.dst_ip}:{self.dst_port or '*'}"
        return f"{src} → {dst}"

    @property
    def service_info(self) -> str:
        """Resolved service names for display (e.g. 'HTTP → HTTPS')."""
        src = self.src_service or (str(self.src_port) if self.src_port else "")
        dst = self.dst_service or (str(self.dst_port) if self.dst_port else "")
        if src or dst:
            return f"{src} → {dst}"
        return ""

    @property
    def is_suspicious(self) -> bool:
        """
        Flag packets that warrant closer inspection.

        Currently flags:
        - Connections on unencrypted credential-bearing protocols (Telnet, FTP, POP3, IMAP)
        - SYN+RST combinations that may indicate a port scan response
        """
        if self.dst_port in UNENCRYPTED_CRED_PORTS or self.src_port in UNENCRYPTED_CRED_PORTS:
            return True
        if self.flags and "RST" in self.flags and "SYN" in self.flags:
            return True
        return False


def parse_packet(pkt) -> Optional[ParsedPacket]:
    """
    Parse a raw Scapy packet into a ParsedPacket.

    Returns None for non-IP packets or packets that cannot be parsed.
    Scapy import is deferred to this function so the rest of the module
    can be imported and tested without Scapy installed.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP  # noqa: PLC0415

        if not pkt.haslayer(IP):
            return None

        ip_layer = pkt[IP]
        parsed = ParsedPacket(
            timestamp=datetime.fromtimestamp(float(pkt.time)),
            protocol="IP",
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            ttl=ip_layer.ttl,
            length=len(pkt),
        )

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            parsed.protocol = "TCP"
            parsed.src_port = tcp.sport
            parsed.dst_port = tcp.dport
            parsed.src_service = WELL_KNOWN_PORTS.get(tcp.sport)
            parsed.dst_service = WELL_KNOWN_PORTS.get(tcp.dport)
            parsed.flags = _parse_tcp_flags(tcp.flags)
            parsed.payload_size = len(tcp.payload)
            parsed.is_encrypted = (
                tcp.dport in ENCRYPTED_PORTS or tcp.sport in ENCRYPTED_PORTS
            )

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            parsed.protocol = "UDP"
            parsed.src_port = udp.sport
            parsed.dst_port = udp.dport
            parsed.src_service = WELL_KNOWN_PORTS.get(udp.sport)
            parsed.dst_service = WELL_KNOWN_PORTS.get(udp.dport)
            parsed.payload_size = len(udp.payload)

        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            parsed.protocol = "ICMP"
            parsed.extra["type"] = icmp.type
            parsed.extra["code"] = icmp.code
            parsed.extra["type_name"] = _icmp_type_name(icmp.type, icmp.code)

        else:
            proto_num = ip_layer.proto
            parsed.protocol = f"IP/{proto_num}"

        parsed.raw_summary = pkt.summary()
        return parsed

    except Exception:
        # Silently discard malformed or unsupported packets.
        return None


def _parse_tcp_flags(flags) -> str:
    """
    Decode Scapy's TCP flags integer/string into a human-readable form.

    Example: 'SA' → 'SYN+ACK'
    """
    flag_str = str(flags)
    if not flag_str:
        return "NONE"
    parts = [TCP_FLAGS.get(ch, ch) for ch in flag_str]
    return "+".join(parts)


def _icmp_type_name(icmp_type: int, code: int) -> str:
    """Map an ICMP type + code pair to a human-readable name."""
    type_map: Dict = {
        0: "Echo Reply",
        3: {
            0: "Net Unreachable",
            1: "Host Unreachable",
            3: "Port Unreachable",
            "default": "Dest Unreachable",
        },
        5: "Redirect",
        8: "Echo Request",
        11: "Time Exceeded",
        12: "Parameter Problem",
    }
    entry = type_map.get(icmp_type, f"Type {icmp_type}")
    if isinstance(entry, dict):
        return entry.get(code, entry.get("default", f"Type {icmp_type} Code {code}"))
    return entry


def resolve_service(port: int) -> str:
    """Return the well-known service name for a port, or the port number as a string."""
    return WELL_KNOWN_PORTS.get(port, str(port))
