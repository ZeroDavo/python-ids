from scapy.all import sniff, IP, TCP, UDP, DNS, ARP, ICMP
from datetime import datetime
from collections import defaultdict

# ─── Port service labels ─────────────────────────────────────────
PORTS = {
    20:  "FTP Data",
    21:  "FTP Control",
    22:  "SSH",
    23:  "Telnet",
    25:  "SMTP",
    53:  "DNS",
    80:  "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    4444: "⚠ Metasploit",
    8080: "HTTP-Alt",
}

# ─── Detection thresholds ────────────────────────────────────────
PORT_SCAN_THRESHOLD = 5   # Unique ports before alerting
SYN_FLOOD_THRESHOLD = 100  # SYN packet volume before alerting
DNS_EXFIL_THRESHOLD  = 50   # Domain name length before alerting
ICMP_FLOOD_THRESHOLD   = 50   # ICMP packets before alerting
BRUTE_FORCE_THRESHOLD  = 4   # SYN packets to same port before alerting

# ─── Suspicious ports ────────────────────────────────────────────
SUSPICIOUS_PORTS = {
    4444:  "Metasploit default listener",
    1337:  "Common backdoor port",
    31337: "Elite hacker port",
    6667:  "IRC — common C2 channel",
    5555:  "Android ADB / common backdoor",
    9001:  "Tor commonly uses this port",
}

# ─── IP Blacklist ─────────────────────────────────────────────────
BLACKLIST = {
    #"192.168.56.101",  # Kali attacker VM — lab test
}

# ─── IP Whitelist ─────────────────────────────────────────────────
WHITELIST = {
    "192.168.56.1",   # VirtualBox host gateway
    "127.0.0.1",      # Localhost
}

# ─── State tracking ──────────────────────────────────────────────
port_scan_tracker = defaultdict(set)  # {src_ip: {ports visited}}
syn_flood_tracker = defaultdict(int)  # {src_ip: syn_count}
arp_table          = {}               # {ip: mac} — known legitimate mappings
icmp_tracker       = defaultdict(int) # {src_ip: icmp_count}
brute_force_tracker = defaultdict(int) # {src_ip: syn_count_to_single_port}

# ─── Helpers ─────────────────────────────────────────────────────
def get_service(port):
    return PORTS.get(port, f"Port {port}")

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_alert(alert_type, message):
    timestamp = get_timestamp()
    print(f"\n{'!' * 60}")
    print(f"  [ALERT] {alert_type}")
    print(f"  Time  : {timestamp}")
    print(f"  Detail: {message}")
    print(f"{'!' * 60}\n")

    # Write alert to log file
    with open("/home/davoind/ids-project/ids_alerts.log", "a") as f:
        f.write(f"[{timestamp}] ALERT | {alert_type} | {message}\n")
        
        # ─── Detection rule: ARP Spoofing ────────────────────────────────
def detect_arp_spoofing(packet):
    """
    Watches ARP replies and flags when two different MAC addresses
    claim ownership of the same IP — the signature of ARP spoofing.
    """
    if ARP in packet and packet[ARP].op == 2:
        src_ip  = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc

        if src_mac == "00:00:00:00:00:00":
            log_alert(
                "ARP SPOOFING DETECTED",
                f"IP {src_ip} | Null/spoofed MAC detected — possible ARP poisoning attempt"
            )
            return

        if src_ip in arp_table:
            known_mac = arp_table[src_ip]
            if known_mac != src_mac:
                log_alert(
                    "ARP SPOOFING DETECTED",
                    f"IP {src_ip} claimed by TWO MACs | "
                    f"Known: {known_mac} | New: {src_mac}"
                )
                arp_table[src_ip] = src_mac
        else:
            arp_table[src_ip] = src_mac

# ─── Detection rule: ICMP Flood ──────────────────────────────────
def detect_icmp_flood(packet):
    """
    Counts ICMP packets per source IP and alerts when volume
    exceeds the threshold — indicates a ping flood DoS attempt.
    """
    if ICMP in packet and IP in packet:
        src_ip = packet[IP].src
        icmp_tracker[src_ip] += 1
        count = icmp_tracker[src_ip]

        if count == ICMP_FLOOD_THRESHOLD:
            log_alert(
                "ICMP FLOOD DETECTED",
                f"Source: {src_ip} | ICMP packets sent: {count}"
            )

# ─── Detection rule: Brute Force ─────────────────────────────────
def detect_brute_force(packet):
    """
    Detects brute force login attempts by tracking SYN packets
    from a single source IP to a single destination port.
    High SYN volume to SSH (22) or RDP (3389) = brute force indicator.
    """
    BRUTE_PORTS = {22: "SSH", 3389: "RDP", 21: "FTP", 23: "Telnet"}

    if TCP in packet and packet[TCP].flags == "S":
        dst_port = packet[TCP].dport
        if dst_port in BRUTE_PORTS:
            src_ip  = packet[IP].src
            service = BRUTE_PORTS[dst_port]
            key = f"{src_ip}:{dst_port}"
            brute_force_tracker[key] += 1
            count = brute_force_tracker[key]

            if count == BRUTE_FORCE_THRESHOLD:
                log_alert(
                    "BRUTE FORCE ATTEMPT DETECTED",
                    f"Source: {src_ip} | Target: {service} "
                    f"(port {dst_port}) | SYN count: {count}"
                )
        
        # ─── Detection rule: IP Blacklist ────────────────────────────────
def detect_blacklist(packet):
    """
    Immediately alerts on any packet from a known malicious IP.
    Checked before all other rules — highest priority.
    """
    if IP in packet:
        src_ip = packet[IP].src
        if src_ip in BLACKLIST:
            log_alert(
                "BLACKLISTED IP DETECTED",
                f"Source: {src_ip} | All traffic from this IP is flagged"
            )

# ─── Detection rule: Suspicious Ports ────────────────────────────
def detect_suspicious_ports(packet):
    """
    Flags traffic to ports associated with known attack tools.
    """
    if TCP in packet:
        dst_port = packet[TCP].dport
        if dst_port in SUSPICIOUS_PORTS:
            reason = SUSPICIOUS_PORTS[dst_port]
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            log_alert(
                "SUSPICIOUS PORT DETECTED",
                f"Source: {src_ip} --> {dst_ip}:{dst_port} | Reason: {reason}"
            )

# ─── Detection rule: Cleartext Credentials ───────────────────────
def detect_cleartext_credentials(packet):
    """
    Inspects FTP and Telnet payloads for credential keywords.
    These protocols transmit usernames and passwords in plain text.
    """
    if TCP in packet and packet[TCP].dport in [21, 23]:
        try:
            payload = bytes(packet[TCP].payload).decode(errors="ignore")
            if "USER" in payload or "PASS" in payload:
                src_ip = packet[IP].src
                log_alert(
                    "CLEARTEXT CREDENTIALS DETECTED",
                    f"Source: {src_ip} | Port: {packet[TCP].dport} | "
                    f"Data: {payload.strip()[:50]}"
                )
        except:
            pass

# ─── Detection rule: DNS Exfiltration ────────────────────────────
def detect_dns_exfiltration(packet):
    """
    Flags DNS queries with unusually long domain names.
    Malware often encodes stolen data inside DNS query strings
    to smuggle it past firewalls.
    """
    if DNS in packet and packet[DNS].qr == 0:
        try:
            query = packet[DNS].qd.qname.decode(errors="ignore")
            if len(query) > 50:
                src_ip = packet[IP].src
                log_alert(
                    "POSSIBLE DNS EXFILTRATION",
                    f"Source: {src_ip} | Query length: {len(query)} chars "
                    f"| Domain: {query[:60]}"
                )
        except:
            pass
        
        # ─── Detection rule: SYN Flood ───────────────────────────────────────
def detect_syn_flood(packet):
    """
    Flags a source IP sending an abnormally high volume of SYN packets
    to any port. Indicates a possible Denial of Service attack.
    """
    if TCP in packet and packet[TCP].flags == "S":
        src_ip = packet[IP].src
        syn_flood_tracker[src_ip] += 1
        syn_count = syn_flood_tracker[src_ip]

        # Alert once when threshold is first hit
        if syn_count == SYN_FLOOD_THRESHOLD:
            log_alert(
                "SYN FLOOD DETECTED",
                f"Source: {src_ip} | SYN packets sent: {syn_count}"
            )

# ─── Detection rule: Port Scan ───────────────────────────────────
def detect_port_scan(packet):
    """
    Flags a source IP that hits more than PORT_SCAN_THRESHOLD
    unique destination ports using SYN packets.
    """
    if TCP in packet and packet[TCP].flags == "S":
        src_ip   = packet[IP].src
        dst_port = packet[TCP].dport

        # Add this port to the set for this source IP
        port_scan_tracker[src_ip].add(dst_port)
        unique_ports = len(port_scan_tracker[src_ip])

        # Alert if threshold exceeded
        if unique_ports == PORT_SCAN_THRESHOLD:
            log_alert(
                "PORT SCAN DETECTED",
                f"Source: {src_ip} | Unique ports probed: {unique_ports}"
            )

# ─── Main packet handler ─────────────────────────────────────────
def packet_callback(packet):
    
    # ── ARP handled separately — no IP layer ──
    if ARP in packet:
        detect_arp_spoofing(packet)
        return

    if IP not in packet:
        return

    timestamp = get_timestamp()
    src_ip    = packet[IP].src
    dst_ip    = packet[IP].dst

# ── Check blacklist first on ALL packets ──
    detect_blacklist(packet)

    # ── TCP ──
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags    = packet[TCP].flags
        service  = get_service(dst_port)

        print(f"[{timestamp}] TCP | {src_ip}:{src_port} --> {dst_ip}:{dst_port} | Service: {service} | Flags: {flags}")

        
        # Run detection rules
        detect_blacklist(packet)           # Rule 1: Blacklisted IP
        detect_port_scan(packet)           # Rule 2: Port scan
        detect_syn_flood(packet)           # Rule 3: SYN flood
        detect_suspicious_ports(packet)    # Rule 4: Suspicious ports
        detect_cleartext_credentials(packet) # Rule 5: Cleartext creds
        detect_brute_force(packet)            # Rule 8: Brute force

    # ── UDP ──
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        service  = get_service(dst_port)

        if DNS in packet and packet[DNS].qr == 0:
            try:
                query = packet[DNS].qd.qname.decode(errors="ignore")
                print(f"[{timestamp}] DNS  | {src_ip} queried --> {query}")
                detect_dns_exfiltration(packet)
            except:
                pass
        else:
            print(f"[{timestamp}] UDP  | {src_ip}:{src_port} --> {dst_ip}:{dst_port} | Service: {service}")

    elif ICMP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        timestamp = get_timestamp()
        print(f"[{timestamp}] ICMP | {src_ip} --> {dst_ip}")
        detect_icmp_flood(packet)             # Rule 9: ICMP flood


# ─── Start IDS ───────────────────────────────────────────────────
print("=" * 60)
print("  INTRUSION DETECTION SYSTEM v3.0")
print(f"  Started: {get_timestamp()}")
print(f"  Monitoring: enp0s8 (Host-Only Lab Network)")
print(f"  Port scan threshold : {PORT_SCAN_THRESHOLD} unique ports")
print(f"  SYN flood threshold : {SYN_FLOOD_THRESHOLD} packets")
print(f"  Suspicious ports    : {len(SUSPICIOUS_PORTS)} monitored")
print(f"  Blacklisted IPs     : {len(BLACKLIST)} entries")
print(f"  ICMP flood threshold: {ICMP_FLOOD_THRESHOLD} packets")
print(f"  Brute force threshold: {BRUTE_FORCE_THRESHOLD} SYNs to one port")
print(f"  Alerts logged to    : ids_alerts.log")
print("=" * 60 + "\n")

try:
    sniff(prn=packet_callback, store=False, iface="enp0s8")
except KeyboardInterrupt:
    print(f"\n[{get_timestamp()}] IDS stopped by user.")
    print("Check ids_alerts.log for all recorded alerts.")
