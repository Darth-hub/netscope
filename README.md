# NetScope

A command-line network packet analyzer and host security scanner built in Python.

Captures and decodes live TCP/UDP/ICMP traffic with BPF-level filtering, and performs host security audits — concurrent port scanning, service fingerprinting, and TLS certificate analysis.

---

## Features

- **Live packet capture** — real-time parsing of IP / TCP / UDP / ICMP headers
- **BPF pre-filtering** — kernel-level filtering by protocol, port, or IP before packets reach user space
- **Protocol intelligence** — well-known port resolution, TCP flag decoding, ICMP type mapping
- **Encrypted vs. plaintext detection** — flags unencrypted HTTP, FTP, Telnet, POP3, IMAP connections in red
- **Concurrent port scanner** — `ThreadPoolExecutor`-based TCP connect scan, 100 threads by default
- **Service fingerprinting** — banner grabbing and risk classification per open port
- **TLS certificate analysis** — version, cipher suite, expiry date, days remaining, weak-version detection
- **PCAP export** — save captures to `.pcap` for further analysis in Wireshark

---

## Installation

```bash
git clone https://github.com/Darth-hub/netscope.git
cd netscope
pip install -e .
```

> Packet capture requires root / `CAP_NET_RAW`. Port scanning does not.

---

## Usage

### Capture live traffic

```bash
# Capture all traffic (auto-detect interface)
sudo netscope capture

# TCP traffic on port 443 only
sudo netscope capture --proto tcp --port 443

# Filter by source IP, verbose output
sudo netscope capture --src 192.168.1.5 -v

# Capture 100 packets and save to pcap
sudo netscope capture -c 100 -o session.pcap

# Specify interface
sudo netscope capture -i eth0 --proto udp --port 53
```

### Security scan

```bash
# Scan common ports on a host
netscope scan example.com

# Specific ports with TLS certificate inspection
netscope scan example.com --ports 80,443,8080 --tls

# Full port range, more threads
netscope scan 192.168.1.1 --ports 1-65535 --threads 200

# Fast scan, short timeout, skip TLS
netscope scan 10.0.0.5 --ports 1-1024 --timeout 0.3 --no-tls
```

---

## Sample Output

### Capture

```
Interface: eth0   BPF: tcp and port 443   Filters: protocol=TCP, port=443
Ctrl-C to stop.

TIME         PROTO  SRC                       DST                       FLAGS             BYTES  SERVICE
─────────────────────────────────────────────────────────────────────────────────────────────────────────
14:32:01.122 TCP    192.168.1.10:54321        93.184.216.34:443         SYN                 60B  → HTTPS 🔒
14:32:01.145 TCP    93.184.216.34:443         192.168.1.10:54321        SYN+ACK             60B  HTTPS →  🔒
14:32:01.200 UDP    192.168.1.10:51234        8.8.8.8:53                                    72B  → DNS
14:32:01.300 TCP    192.168.1.10:55000        203.0.113.5:23            SYN                 60B  → Telnet [!]
```

`[!]` marks suspicious connections (unencrypted credential protocols, scan patterns).  
`🔒` marks encrypted traffic.

### Security Scan

```
Target: example.com (93.184.216.34)   Ports: 1024

  OPEN  22     SSH
  OPEN  80     HTTP
  OPEN  443    HTTPS

Open Ports — example.com (93.184.216.34)
 Port  Service   Enc.  Risk    Banner                    TLS
──────────────────────────────────────────────────────────────────────────────
   22  SSH        ✓   INFO    SSH-2.0-OpenSSH_8.9p1
   80  HTTP       ✗   LOW     HTTP/1.1 301 Moved Perm…
  443  HTTPS      ✓   INFO                              TLSv1.3 · exp 2027-03-15 (261d)

⚠  Unencrypted / High-Risk Services:
  • Port 80 (HTTP) LOW — data transmitted in plaintext

✓  No TLS / certificate issues detected.

Completed in 3.42s — 3 open port(s) found.
```

---

## Running Tests

```bash
pip install -e .
python -m unittest discover tests/
```

Tests cover packet parsing, filter matching, BPF generation, port classification, and TLS audit logic. All network calls are mocked — no live connections required.

---

## Project Structure

```
netscope/
├── netscope/
│   ├── __init__.py
│   ├── capture.py     Scapy sniff() wrapper, BPF + post-parse filtering
│   ├── parser.py      IP / TCP / UDP / ICMP header parsing → ParsedPacket
│   ├── filter.py      BPF expression generation + packet matching
│   ├── security.py    Port scanner, banner grabbing, TLS certificate analysis
│   ├── display.py     Rich terminal output (all formatting centralised here)
│   └── cli.py         argparse entry points for `capture` and `scan`
└── tests/
    ├── test_parser.py
    ├── test_filter.py
    └── test_security.py
```

---

## Architecture Notes

**BPF pre-filtering** — Filter expressions are constructed from CLI flags and passed directly to Scapy's `sniff()`. The kernel's packet filter drops unmatched frames before they are copied to user space, which significantly reduces CPU load on high-traffic interfaces compared to sniffing everything and filtering in Python.

**Post-parse filtering** — A second filter pass on `ParsedPacket` fields handles criteria that BPF cannot represent alone (e.g., matching a port on either src or dst for a single specific host).

**Concurrent port scanning** — Port scanning is IO-bound: each thread spends almost all its time blocked on a `socket.connect()` timeout. `ThreadPoolExecutor` with 100 workers achieves near-linear speedup vs. sequential scanning up to the target's connection-rate limit.

**TLS inspection** — Uses Python's built-in `ssl` module — no `nmap`, `openssl` binary, or external dependency. Inspects certificate expiry, issuer, SANs, and detects legacy TLS versions (TLS 1.0/1.1, SSLv2/3).

---

## Ethical Use

This tool is intended for use on networks and systems you own or have explicit written authorisation to test. Unauthorised packet capture or port scanning may be illegal in your jurisdiction.
