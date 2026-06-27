"""
security.py — Host security scanner.

Three-stage analysis:
1. Concurrent TCP port scan (socket connect, not raw SYN — no root needed).
2. Service classification: banner grabbing, encryption status, risk level.
3. TLS certificate analysis: version, cipher, expiry, SAN list, weak-version detection.

Port scanning uses ThreadPoolExecutor because port-scan workload is purely
IO-bound (blocking on socket connect timeouts). Threading gives near-linear
speedup until the target's TCP stack becomes the bottleneck.
"""

import socket
import ssl
import concurrent.futures
import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict


# --------------------------------------------------------------------------
# Static maps
# --------------------------------------------------------------------------

WELL_KNOWN_PORTS: Dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
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
}

# Ports that should carry encrypted traffic
ENCRYPTED_PORTS = {22, 443, 465, 993, 995, 8443}

# Unencrypted protocols where credentials may be exposed; mapped to (name, risk)
RISKY_UNENCRYPTED_PORTS: Dict[int, tuple] = {
    21: ("FTP", "high"),
    23: ("Telnet", "high"),
    25: ("SMTP", "medium"),
    80: ("HTTP", "low"),
    110: ("POP3", "high"),
    143: ("IMAP", "high"),
    8080: ("HTTP-ALT", "low"),
}

# TLS versions considered insecure
WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


# --------------------------------------------------------------------------
# Data classes
# --------------------------------------------------------------------------

@dataclass
class PortResult:
    """Result for a single scanned port."""
    port: int
    is_open: bool
    service: str = "unknown"
    banner: str = ""
    is_encrypted: bool = False
    tls_info: Optional[Dict] = None
    risk: str = "info"  # one of: info | low | medium | high


@dataclass
class ScanResult:
    """Aggregate result for a complete host scan."""
    target: str
    resolved_ip: str
    open_ports: List[PortResult] = field(default_factory=list)
    unencrypted_services: List[PortResult] = field(default_factory=list)
    tls_issues: List[str] = field(default_factory=list)
    scan_time: float = 0.0


# --------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------

class SecurityScanner:
    """
    Host security scanner: concurrent port scan, service fingerprinting,
    risk classification, and TLS certificate inspection.

    Args:
        target:     Hostname or IP address to scan.
        port_spec:  Port specification string. Supports:
                      - Single port:        '80'
                      - Comma-separated:    '22,80,443'
                      - Range:              '1-1024'
                      - Mixed:              '22,80-82,443'
        threads:    Maximum concurrent scan threads (default 100).
        check_tls:  Whether to perform TLS certificate analysis on HTTPS ports.
        timeout:    Per-connection socket timeout in seconds.
        display:    Display instance for output rendering.
    """

    def __init__(
        self,
        target: str,
        port_spec: str = "1-1024",
        threads: int = 100,
        check_tls: bool = True,
        timeout: float = 1.0,
        display=None,
    ):
        self.target = target
        self.ports = self._parse_port_spec(port_spec)
        self.threads = min(threads, len(self.ports))
        self.check_tls = check_tls
        self.timeout = timeout
        self.display = display

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> ScanResult:
        """
        Execute the full scan pipeline and return a ScanResult.

        Steps:
          1. Resolve hostname to IP.
          2. Concurrent TCP connect scan across all specified ports.
          3. Classify each open port (service, encryption, risk, banner).
          4. TLS certificate analysis on HTTPS-like ports (if enabled).
        """
        import time

        start = time.time()

        try:
            resolved_ip = socket.gethostbyname(self.target)
        except socket.gaierror as exc:
            self.display.error(f"Cannot resolve '{self.target}': {exc}")
            return ScanResult(target=self.target, resolved_ip="")

        self.display.scan_start(self.target, resolved_ip, len(self.ports))
        result = ScanResult(target=self.target, resolved_ip=resolved_ip)

        # Stage 1: concurrent port scan
        open_port_numbers = self._scan_ports_concurrent(resolved_ip)

        # Stage 2: classify each open port
        for port in open_port_numbers:
            pr = self._classify_port(resolved_ip, port)
            result.open_ports.append(pr)
            if pr.risk in ("medium", "high"):
                result.unencrypted_services.append(pr)

        # Stage 3: TLS certificate analysis
        if self.check_tls:
            tls_ports = [p for p in open_port_numbers if p in {443, 8443}]
            for port in tls_ports:
                result.tls_issues.extend(self._audit_tls(resolved_ip, port))

        result.scan_time = time.time() - start
        self.display.scan_result(result)
        return result

    # ------------------------------------------------------------------
    # Port scanning
    # ------------------------------------------------------------------

    def _scan_ports_concurrent(self, ip: str) -> List[int]:
        """
        Scan all ports concurrently using a thread pool.

        IO-bound workload: threads spend almost all their time blocked on
        socket connect() calls, so threading achieves near-linear speedup
        up to the target's connection-rate limit.
        """
        open_ports: List[int] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._is_port_open, ip, p): p for p in self.ports}
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                        self.display.port_found(
                            port, WELL_KNOWN_PORTS.get(port, "unknown")
                        )
                except Exception:
                    pass  # individual scan failures are non-fatal

        return sorted(open_ports)

    def _is_port_open(self, ip: str, port: int) -> bool:
        """
        TCP connect check — returns True if the port accepts connections.

        Uses a full TCP handshake (connect), not a raw SYN, so root
        privileges are not required.
        """
        try:
            with socket.create_connection((ip, port), timeout=self.timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    # ------------------------------------------------------------------
    # Service classification
    # ------------------------------------------------------------------

    def _classify_port(self, ip: str, port: int) -> PortResult:
        """
        Determine service name, encryption status, risk level, and banner
        for an open port.

        Banner grabbing is skipped on encrypted ports to avoid partial TLS
        handshake errors — TLS info is captured separately via _get_tls_info().
        """
        service = WELL_KNOWN_PORTS.get(port, "unknown")
        is_encrypted = port in ENCRYPTED_PORTS
        risk_entry = RISKY_UNENCRYPTED_PORTS.get(port)
        risk = risk_entry[1] if risk_entry else "info"

        banner = ""
        if not is_encrypted:
            banner = self._grab_banner(ip, port)

        tls_info = None
        if self.check_tls and port in {443, 8443}:
            tls_info = self._get_tls_info(ip, port)

        return PortResult(
            port=port,
            is_open=True,
            service=service,
            banner=banner,
            is_encrypted=is_encrypted,
            tls_info=tls_info,
            risk=risk,
        )

    def _grab_banner(self, ip: str, port: int) -> str:
        """
        Attempt to read the first response bytes from a service.

        Many services (SSH, FTP, SMTP) send an identification banner
        immediately on connect without requiring a client message first.
        Truncated to 200 characters to prevent runaway reads.
        """
        try:
            with socket.create_connection((ip, port), timeout=2.0) as s:
                s.settimeout(2.0)
                data = s.recv(1024)
                return data.decode("utf-8", errors="replace").strip()[:200]
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # TLS analysis
    # ------------------------------------------------------------------

    def _get_tls_info(self, ip: str, port: int) -> Optional[Dict]:
        """
        Retrieve TLS session metadata and certificate details.

        Inspects:
        - Protocol version (TLS 1.2 / 1.3, or flagged legacy versions)
        - Cipher suite in use
        - Certificate subject CN and issuer
        - Certificate expiry date and days remaining
        - Subject Alternative Names (SANs)
        """
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.target) as tls:
                    cert = tls.getpeercert()
                    version = tls.version()
                    cipher = tls.cipher()

                    not_after = cert.get("notAfter", "")
                    expiry = None
                    days_left = None
                    if not_after:
                        expiry = datetime.datetime.strptime(
                            not_after, "%b %d %H:%M:%S %Y %Z"
                        )
                        days_left = (expiry - datetime.datetime.utcnow()).days

                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

                    return {
                        "version": version,
                        "cipher": cipher[0] if cipher else "unknown",
                        "cn": subject.get("commonName", "unknown"),
                        "issuer": issuer.get("organizationName", "unknown"),
                        "expiry": expiry.strftime("%Y-%m-%d") if expiry else "unknown",
                        "days_left": days_left,
                        "sans": sans[:5],
                    }

        except ssl.SSLCertVerificationError as exc:
            return {"error": f"Cert verification failed: {exc}"}
        except Exception as exc:
            return {"error": str(exc)}

    def _audit_tls(self, ip: str, port: int) -> List[str]:
        """
        Return a list of TLS issues found on a given port.

        Currently checks:
        - Expired certificates
        - Certificates expiring within 30 days
        - Weak TLS versions (SSLv2/3, TLS 1.0/1.1)
        """
        issues: List[str] = []
        info = self._get_tls_info(ip, port)
        if not info:
            return issues

        if "error" in info:
            issues.append(f"Port {port}: TLS error — {info['error']}")
            return issues

        days = info.get("days_left")
        if days is not None:
            if days < 0:
                issues.append(
                    f"Port {port}: Certificate EXPIRED {abs(days)} day(s) ago"
                )
            elif days < 30:
                issues.append(
                    f"Port {port}: Certificate expires in {days} day(s) — renew soon"
                )

        version = info.get("version", "")
        if version in WEAK_TLS_VERSIONS:
            issues.append(
                f"Port {port}: Weak TLS version '{version}' in use — upgrade to TLS 1.2+"
            )

        return issues

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_port_spec(spec: str) -> List[int]:
        """
        Parse a port specification string into a sorted list of port numbers.

        Supports:
            '80'            → [80]
            '80,443'        → [80, 443]
            '1-1024'        → [1, 2, ..., 1024]
            '22,80-82,443'  → [22, 80, 81, 82, 443]
        """
        ports: set = set()
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                ports.update(range(int(lo), int(hi) + 1))
            else:
                ports.add(int(part))
        return sorted(ports)
