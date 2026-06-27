"""
cli.py — Command-line interface for NetScope.

Two sub-commands:
  netscope capture   Live packet capture and protocol decoding.
  netscope scan      Host security scan (ports, services, TLS certificates).
"""

import argparse
import sys

from netscope.display import Display


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscope",
        description="NetScope — Network Packet Analyzer & Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo netscope capture -i eth0 --proto tcp --port 443\n"
            "  sudo netscope capture --src 192.168.1.5 -c 50 -o out.pcap\n"
            "  netscope scan example.com --ports 1-1024 --tls\n"
            "  netscope scan 192.168.1.1 --ports 22,80,443 --threads 50\n"
        ),
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ------------------------------------------------------------------
    # capture sub-command
    # ------------------------------------------------------------------
    cap = sub.add_parser(
        "capture",
        help="Capture and decode live network packets",
        description=(
            "Capture live packets from a network interface.\n"
            "Requires root / CAP_NET_RAW privileges."
        ),
    )
    cap.add_argument(
        "-i", "--interface",
        default=None,
        metavar="IFACE",
        help="Network interface to capture on (default: auto-detect)",
    )
    cap.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        metavar="N",
        help="Number of packets to capture, 0 = unlimited (default: 0)",
    )
    cap.add_argument(
        "-p", "--port",
        type=int,
        default=None,
        metavar="PORT",
        help="Filter packets by port number (src or dst)",
    )
    cap.add_argument(
        "--proto",
        choices=["tcp", "udp", "icmp"],
        default=None,
        metavar="PROTO",
        help="Filter by protocol: tcp | udp | icmp",
    )
    cap.add_argument(
        "--src",
        default=None,
        metavar="IP",
        help="Filter packets by source IP address",
    )
    cap.add_argument(
        "--dst",
        default=None,
        metavar="IP",
        help="Filter packets by destination IP address",
    )
    cap.add_argument(
        "-o", "--output",
        default=None,
        metavar="FILE",
        help="Save captured packets to a .pcap file",
    )
    cap.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print full packet detail (ICMP codes, extra fields)",
    )

    # ------------------------------------------------------------------
    # scan sub-command
    # ------------------------------------------------------------------
    sc = sub.add_parser(
        "scan",
        help="Run a security scan on a target host",
        description="Scan a host for open ports, unencrypted services, and TLS issues.",
    )
    sc.add_argument(
        "target",
        help="Target hostname or IP address",
    )
    sc.add_argument(
        "--ports",
        default="1-1024",
        metavar="SPEC",
        help=(
            "Ports to scan. Formats: single (80), range (1-1024), "
            "list (22,80,443), or mixed (22,80-82,443). Default: 1-1024"
        ),
    )
    sc.add_argument(
        "--threads",
        type=int,
        default=100,
        metavar="N",
        help="Max concurrent scan threads (default: 100)",
    )
    sc.add_argument(
        "--tls",
        action="store_true",
        default=True,
        help="Inspect TLS certificates on HTTPS ports (default: on)",
    )
    sc.add_argument(
        "--no-tls",
        dest="tls",
        action="store_false",
        help="Skip TLS certificate inspection",
    )
    sc.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        metavar="SEC",
        help="Per-connection socket timeout in seconds (default: 1.0)",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    display = Display()
    display.banner()

    if args.command == "capture":
        from netscope.capture import PacketCapture

        capture = PacketCapture(
            interface=args.interface,
            port_filter=args.port,
            proto_filter=args.proto,
            src_filter=args.src,
            dst_filter=args.dst,
            verbose=args.verbose,
            output=args.output,
            display=display,
        )
        try:
            capture.start(count=args.count)
        except PermissionError:
            display.error(
                "Packet capture requires root privileges. Re-run with: sudo netscope capture ..."
            )
            sys.exit(1)
        except KeyboardInterrupt:
            capture.stop()

    elif args.command == "scan":
        from netscope.security import SecurityScanner

        scanner = SecurityScanner(
            target=args.target,
            port_spec=args.ports,
            threads=args.threads,
            check_tls=args.tls,
            timeout=args.timeout,
            display=display,
        )
        scanner.run()


if __name__ == "__main__":
    main()
