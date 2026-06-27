"""
Tests for netscope.security

Covers port spec parsing, risk classification, and socket-level
scanning logic. All network calls are mocked — no live connections.
"""

import socket
import unittest
from unittest.mock import patch, MagicMock, call

from netscope.security import (
    SecurityScanner,
    PortResult,
    RISKY_UNENCRYPTED_PORTS,
    ENCRYPTED_PORTS,
    WELL_KNOWN_PORTS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_scanner(target="localhost", port_spec="80", **kwargs) -> SecurityScanner:
    display = MagicMock()
    return SecurityScanner(
        target=target,
        port_spec=port_spec,
        display=display,
        timeout=0.5,
        check_tls=False,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Port spec parsing
# ---------------------------------------------------------------------------

class TestParsePortSpec(unittest.TestCase):

    def test_single_port(self):
        self.assertEqual(SecurityScanner._parse_port_spec("80"), [80])

    def test_range(self):
        self.assertEqual(SecurityScanner._parse_port_spec("80-82"), [80, 81, 82])

    def test_comma_separated(self):
        self.assertEqual(SecurityScanner._parse_port_spec("80,443,22"), [22, 80, 443])

    def test_mixed_range_and_list(self):
        result = SecurityScanner._parse_port_spec("22,80-82,443")
        self.assertIn(22, result)
        for p in (80, 81, 82):
            self.assertIn(p, result)
        self.assertIn(443, result)

    def test_result_is_sorted(self):
        result = SecurityScanner._parse_port_spec("443,80,22")
        self.assertEqual(result, sorted(result))

    def test_duplicates_deduplicated(self):
        result = SecurityScanner._parse_port_spec("80,80-81")
        self.assertEqual(result.count(80), 1)

    def test_high_port(self):
        self.assertEqual(SecurityScanner._parse_port_spec("65535"), [65535])


# ---------------------------------------------------------------------------
# Risk classification static data
# ---------------------------------------------------------------------------

class TestRiskyPortData(unittest.TestCase):

    def test_telnet_high_risk(self):
        self.assertEqual(RISKY_UNENCRYPTED_PORTS[23][1], "high")

    def test_ftp_high_risk(self):
        self.assertEqual(RISKY_UNENCRYPTED_PORTS[21][1], "high")

    def test_pop3_high_risk(self):
        self.assertEqual(RISKY_UNENCRYPTED_PORTS[110][1], "high")

    def test_imap_high_risk(self):
        self.assertEqual(RISKY_UNENCRYPTED_PORTS[143][1], "high")

    def test_http_low_risk(self):
        self.assertEqual(RISKY_UNENCRYPTED_PORTS[80][1], "low")

    def test_smtp_medium_risk(self):
        self.assertEqual(RISKY_UNENCRYPTED_PORTS[25][1], "medium")

    def test_encrypted_ports_not_in_risky(self):
        for port in ENCRYPTED_PORTS:
            self.assertNotIn(port, RISKY_UNENCRYPTED_PORTS)


# ---------------------------------------------------------------------------
# is_port_open (mocked socket)
# ---------------------------------------------------------------------------

class TestIsPortOpen(unittest.TestCase):

    @patch("netscope.security.socket.create_connection")
    def test_returns_true_when_connection_succeeds(self, mock_conn):
        ctx = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=ctx)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        s = make_scanner()
        self.assertTrue(s._is_port_open("127.0.0.1", 80))

    @patch("netscope.security.socket.create_connection")
    def test_returns_false_on_connection_refused(self, mock_conn):
        mock_conn.side_effect = ConnectionRefusedError
        s = make_scanner()
        self.assertFalse(s._is_port_open("127.0.0.1", 9998))

    @patch("netscope.security.socket.create_connection")
    def test_returns_false_on_timeout(self, mock_conn):
        mock_conn.side_effect = socket.timeout
        s = make_scanner()
        self.assertFalse(s._is_port_open("1.2.3.4", 80))

    @patch("netscope.security.socket.create_connection")
    def test_returns_false_on_os_error(self, mock_conn):
        mock_conn.side_effect = OSError
        s = make_scanner()
        self.assertFalse(s._is_port_open("1.2.3.4", 80))


# ---------------------------------------------------------------------------
# _classify_port (mocked banner grab)
# ---------------------------------------------------------------------------

class TestClassifyPort(unittest.TestCase):

    @patch.object(SecurityScanner, "_grab_banner", return_value="Apache/2.4.54")
    def test_http_port_low_risk_unencrypted(self, _):
        s = make_scanner()
        result = s._classify_port("127.0.0.1", 80)
        self.assertEqual(result.service, "HTTP")
        self.assertFalse(result.is_encrypted)
        self.assertEqual(result.risk, "low")
        self.assertEqual(result.banner, "Apache/2.4.54")

    @patch.object(SecurityScanner, "_grab_banner", return_value="")
    def test_https_port_encrypted_info_risk(self, _):
        s = make_scanner()
        result = s._classify_port("127.0.0.1", 443)
        self.assertEqual(result.service, "HTTPS")
        self.assertTrue(result.is_encrypted)
        self.assertEqual(result.risk, "info")

    @patch.object(SecurityScanner, "_grab_banner", return_value="SSH-2.0-OpenSSH_8.9")
    def test_ssh_port_encrypted(self, _):
        # ssh banner grab is skipped for encrypted, but classified correctly
        s = make_scanner()
        result = s._classify_port("127.0.0.1", 22)
        self.assertTrue(result.is_encrypted)
        self.assertEqual(result.service, "SSH")

    @patch.object(SecurityScanner, "_grab_banner", return_value="")
    def test_telnet_port_high_risk(self, _):
        s = make_scanner()
        result = s._classify_port("127.0.0.1", 23)
        self.assertEqual(result.risk, "high")
        self.assertFalse(result.is_encrypted)

    @patch.object(SecurityScanner, "_grab_banner", return_value="")
    def test_unknown_port_info_risk(self, _):
        s = make_scanner()
        result = s._classify_port("127.0.0.1", 9999)
        self.assertEqual(result.risk, "info")
        self.assertEqual(result.service, "unknown")

    def test_banner_not_grabbed_for_encrypted_port(self):
        s = make_scanner()
        with patch.object(s, "_grab_banner") as mock_grab:
            s._classify_port("127.0.0.1", 443)
            mock_grab.assert_not_called()


# ---------------------------------------------------------------------------
# _audit_tls
# ---------------------------------------------------------------------------

class TestAuditTls(unittest.TestCase):

    def test_expired_cert_reported(self):
        s = make_scanner()
        tls_info = {
            "version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cn": "example.com",
            "issuer": "Let's Encrypt",
            "expiry": "2025-01-01",
            "days_left": -30,
            "sans": [],
        }
        with patch.object(s, "_get_tls_info", return_value=tls_info):
            issues = s._audit_tls("93.184.216.34", 443)
        self.assertTrue(any("EXPIRED" in i for i in issues))

    def test_expiry_within_30_days_reported(self):
        s = make_scanner()
        tls_info = {
            "version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cn": "example.com",
            "issuer": "DigiCert",
            "expiry": "2026-07-10",
            "days_left": 13,
            "sans": [],
        }
        with patch.object(s, "_get_tls_info", return_value=tls_info):
            issues = s._audit_tls("93.184.216.34", 443)
        self.assertTrue(any("expires" in i.lower() for i in issues))

    def test_weak_tls_version_reported(self):
        s = make_scanner()
        tls_info = {
            "version": "TLSv1",
            "cipher": "AES128-SHA",
            "cn": "old.example.com",
            "issuer": "Comodo",
            "expiry": "2027-01-01",
            "days_left": 200,
            "sans": [],
        }
        with patch.object(s, "_get_tls_info", return_value=tls_info):
            issues = s._audit_tls("1.2.3.4", 443)
        self.assertTrue(any("Weak" in i or "weak" in i.lower() for i in issues))

    def test_healthy_cert_no_issues(self):
        s = make_scanner()
        tls_info = {
            "version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cn": "example.com",
            "issuer": "DigiCert",
            "expiry": "2027-06-01",
            "days_left": 340,
            "sans": ["example.com", "www.example.com"],
        }
        with patch.object(s, "_get_tls_info", return_value=tls_info):
            issues = s._audit_tls("93.184.216.34", 443)
        self.assertEqual(issues, [])

    def test_tls_error_reported(self):
        s = make_scanner()
        with patch.object(s, "_get_tls_info", return_value={"error": "cert verify failed"}):
            issues = s._audit_tls("1.2.3.4", 443)
        self.assertTrue(len(issues) > 0)
        self.assertTrue(any("TLS error" in i for i in issues))


# ---------------------------------------------------------------------------
# PortResult dataclass
# ---------------------------------------------------------------------------

class TestPortResult(unittest.TestCase):

    def test_default_risk_is_info(self):
        pr = PortResult(port=9999, is_open=True)
        self.assertEqual(pr.risk, "info")

    def test_default_not_encrypted(self):
        pr = PortResult(port=80, is_open=True)
        self.assertFalse(pr.is_encrypted)

    def test_service_defaults_to_unknown(self):
        pr = PortResult(port=9999, is_open=True)
        self.assertEqual(pr.service, "unknown")


if __name__ == "__main__":
    unittest.main()
