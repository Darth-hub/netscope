"""
capture.py — Live network packet capture using Scapy.

Applies BPF filters at the kernel level for efficiency, then performs
post-parse filtering on fields not expressible in BPF (e.g. combined
src IP + port conditions against a single host).

Requires CAP_NET_RAW capability (Linux) or administrator privileges (macOS/Windows).
"""

import threading
from typing import Optional, List

from netscope.parser import parse_packet, ParsedPacket
from netscope.filter import PacketFilter


class PacketCapture:
    """
    Captures live packets from a network interface using Scapy's sniff().

    BPF pre-filtering is used to drop unmatched frames before they reach
    user space. Post-parse filtering catches any criteria the BPF expression
    cannot represent (e.g. port appears on either src or dst on the same host).
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        port_filter: Optional[int] = None,
        proto_filter: Optional[str] = None,
        src_filter: Optional[str] = None,
        dst_filter: Optional[str] = None,
        verbose: bool = False,
        output: Optional[str] = None,
        display=None,
    ):
        """
        Args:
            interface:    Network interface to capture on (None = auto-detect).
            port_filter:  Restrict capture to packets on this port.
            proto_filter: Restrict capture to 'tcp', 'udp', or 'icmp'.
            src_filter:   Restrict capture to packets from this source IP.
            dst_filter:   Restrict capture to packets to this destination IP.
            verbose:      Print full packet detail including extra fields.
            output:       Path to save captured packets as a .pcap file.
            display:      Display instance for output rendering.
        """
        self.interface = interface
        self.verbose = verbose
        self.output = output
        self.display = display

        self._stop_event = threading.Event()
        self._packet_count = 0
        self._raw_packets: List = []  # kept only when saving to pcap

        self.pkt_filter = PacketFilter(
            port=port_filter,
            proto=proto_filter,
            src_ip=src_filter,
            dst_ip=dst_filter,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self, count: int = 0) -> None:
        """
        Begin capturing packets.

        Args:
            count: Number of packets to capture. 0 = capture until Ctrl-C.

        Raises:
            PermissionError: If the process lacks raw socket privileges.
        """
        from scapy.all import sniff, wrpcap  # deferred: Scapy takes ~300ms to import

        bpf = self.pkt_filter.to_bpf()
        self.display.capture_start(
            interface=self.interface or "auto",
            bpf=bpf or "none",
            filter_desc=self.pkt_filter.describe(),
        )

        try:
            sniff(
                iface=self.interface,
                filter=bpf or None,
                prn=self._handle_packet,
                count=count or 0,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=bool(self.output),
            )
        except PermissionError:
            raise
        except KeyboardInterrupt:
            pass
        finally:
            self._finish(wrpcap if self.output else None)

    def stop(self) -> None:
        """Signal the capture loop to exit on the next packet."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _handle_packet(self, raw_pkt) -> None:
        """
        Scapy callback — invoked once per captured packet.

        Parsing and post-BPF filtering happen here before display.
        Raw packets are retained only when a pcap output path is set.
        """
        parsed = parse_packet(raw_pkt)
        if parsed is None:
            return

        # Post-parse filter for criteria not covered by the BPF expression
        if self.pkt_filter.is_active and not self.pkt_filter.matches(parsed):
            return

        self._packet_count += 1

        if self.output:
            self._raw_packets.append(raw_pkt)

        self.display.print_packet(parsed, verbose=self.verbose)

    def _finish(self, wrpcap_fn) -> None:
        """Print capture summary and optionally write pcap output."""
        self.display.capture_end(self._packet_count)
        if self.output and self._raw_packets and wrpcap_fn is not None:
            wrpcap_fn(self.output, self._raw_packets)
            self.display.info(
                f"Saved {self._packet_count} packet(s) to '{self.output}'"
            )
