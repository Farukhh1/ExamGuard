"""
ExamGuard - AI Cheating Prevention & Centralized Exam Monitoring System
=======================================================================
Blocks AI websites and provides real-time monitoring + alerts.

ARCHITECTURE:
  1. DNS Proxy (port 53)   - Intercepts DNS queries from hotspot clients
                              and blocks AI domains by returning the
                              instructor's IP.  Non-blocked domains are
                              forwarded to Google DNS (8.8.8.8).
  2. HTTPS Intercept (443) - Reads TLS ClientHello SNI to detect which
                              blocked domain was requested.
  3. HTTP Intercept (80)   - Serves a "blocked" page and logs the attempt.
  4. Flask Dashboard (5000)- SOC-style real-time monitoring dashboard.
  5. Background Scanner    - Periodically scans ARP for connected devices.

SETUP:
  1. Connect laptop to internet (Ethernet / Wi-Fi)
  2. Enable Windows Mobile Hotspot
  3. Run this app as Administrator:  python app.py
  4. Students connect phones/laptops to your hotspot
  5. Any attempt to access blocked AI sites triggers an instant alert

The app auto-configures your network adapter's DNS to route through the
proxy.  Original DNS settings are restored on exit.
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, emit
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import subprocess
import struct
import re
import os
import sys
import socket

import threading
import time
import atexit
import signal
from datetime import datetime

# ---------------------------------------------------------------------------
# APP CONFIGURATION
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = 'examguard-secret-key-2024'

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

USERNAME = 'admin'
PASSWORD = '1234'

BLOCKED_SITES = [
    "chatgpt.com",
    "openai.com",
    "gemini.google.com",
    "claude.ai",
    "copilot.microsoft.com",
    "bard.google.com",
    "perplexity.ai",
    "you.com",
    "poe.com",
    "huggingface.co",
]

HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'violations.txt')
UPSTREAM_DNS = '8.8.8.8'


# ---------------------------------------------------------------------------
# BLOCKED PAGE HTML (served to students on port 80)
# ---------------------------------------------------------------------------
BLOCKED_PAGE_HTML = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access Blocked - ExamGuard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#fff;font-family:-apple-system,'Segoe UI',sans-serif;
display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center}
.c{max-width:520px;padding:48px 32px}
.icon{font-size:80px;margin-bottom:24px;animation:p 2s ease-in-out infinite}
h1{color:#FF3B30;font-size:36px;font-weight:800;margin-bottom:16px}
p{color:rgba(255,255,255,0.55);font-size:15px;line-height:1.7}
.w{color:#FF3B30;margin-top:24px;font-weight:700;font-size:14px;
padding:14px;background:rgba(255,59,48,0.08);border-radius:12px;border:1px solid rgba(255,59,48,0.2)}
@keyframes p{0%,100%{transform:scale(1)}50%{transform:scale(1.08)}}
</style></head><body><div class="c">
<div class="icon">&#x1F6AB;</div>
<h1>ACCESS BLOCKED</h1>
<p>This website has been blocked by <strong>ExamGuard Firewall</strong>.
AI tools are not permitted during examinations.</p>
<p class="w">&#x26A0; This attempt has been logged and reported.</p>
</div></body></html>"""


# ---------------------------------------------------------------------------
# NETWORK UTILITIES
# ---------------------------------------------------------------------------
def get_local_ip():
    """Detect the primary local IP of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def detect_redirect_ip():
    """Best IP to redirect blocked domains to (instructor's machine)."""
    try:
        output = subprocess.check_output("ipconfig", shell=True).decode(errors='ignore')
        if '192.168.137.1' in output:
            return '192.168.137.1'
    except Exception:
        pass
    return get_local_ip()


def get_all_local_ips():
    """All IP addresses assigned to this machine."""
    ips = {'127.0.0.1', '::1'}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0])
    except Exception:
        pass
    try:
        ips.add(get_local_ip())
    except Exception:
        pass
    ips.add(REDIRECT_IP)
    return ips


def _is_valid_hostname(name):
    """Return True if name is usable — not empty and not a blocked domain."""
    if not name or not name.strip():
        return False
    name_lower = name.lower().rstrip('.')
    for site in BLOCKED_SITES:
        if (name_lower == site
                or name_lower == f'www.{site}'
                or name_lower.endswith(f'.{site}')):
            return False
    return True


def _clean_hostname(name):
    """Strip suffixes like .mshome.net / .local for a cleaner display name."""
    for suffix in ('.mshome.net', '.local', '.home', '.lan'):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
            break
    return name.strip()


# ---------------------------------------------------------------------------
# HOSTNAME CACHING  — two-level cache to avoid repeated slow lookups
# ---------------------------------------------------------------------------
# Level 1: bulk DNS cache  {ip -> hostname}  refreshed from PowerShell once
#           every _DNS_BULK_TTL seconds.  ONE PowerShell call serves ALL
#           devices instead of one per device.
_dns_bulk_cache: dict = {}
_dns_bulk_cache_time: float = 0.0
_dns_bulk_lock = threading.Lock()
_DNS_BULK_TTL = 30   # seconds between full refreshes

# Level 2: per-IP resolved-hostname cache  {ip -> (name, timestamp)}
#           Survives across DNS bulk refreshes; TTL is longer.
_hostname_cache: dict = {}
_HOSTNAME_TTL = 120  # seconds  (2 minutes)


def _build_dns_bulk_cache():
    """Run Get-DnsClientCache ONCE and build the {ip -> name} lookup dict.

    Windows ICS creates two entry kinds for hotspot DHCP clients:
      Forward A :  pixel-6.mshome.net        →  192.168.137.242
      Reverse PTR: 242.137.168.192.in-addr.arpa → Pixel-6.mshome.net
    We parse both so every device type is covered.
    """
    global _dns_bulk_cache, _dns_bulk_cache_time
    new_cache: dict = {}
    try:
        result = subprocess.run(
            'powershell -NoProfile -NonInteractive -Command '
            '"Get-DnsClientCache | Select-Object Entry, Data | '
            'ConvertTo-Csv -NoTypeInformation"',
            shell=True, capture_output=True, timeout=8,
            text=True, errors='ignore'
        )
        ip_pat = re.compile(r'^\d+\.\d+\.\d+\.\d+$')
        ptr_pat = re.compile(
            r'^(\d+)\.(\d+)\.(\d+)\.(\d+)\.in-addr\.arpa$', re.IGNORECASE
        )
        for line in result.stdout.splitlines():
            cols = [c.strip().strip('"') for c in line.split(',')]
            if len(cols) < 2:
                continue
            entry, data = cols[0].strip(), cols[1].strip()
            if not data:
                continue

            # Forward A record: data is an IP, entry is the hostname
            if ip_pat.match(data):
                name = _clean_hostname(entry)
                if _is_valid_hostname(name) and data not in new_cache:
                    new_cache[data] = name

            # Reverse PTR record: entry is x.x.x.x.in-addr.arpa
            m = ptr_pat.match(entry)
            if m:
                ip = f"{m.group(4)}.{m.group(3)}.{m.group(2)}.{m.group(1)}"
                name = _clean_hostname(data)
                if _is_valid_hostname(name) and ip not in new_cache:
                    new_cache[ip] = name

    except Exception as e:
        print(f"[DNS Bulk Cache] {e}")

    with _dns_bulk_lock:
        _dns_bulk_cache = new_cache
        _dns_bulk_cache_time = time.time()


def _get_dns_bulk(ip):
    """Return cached name for ip; refresh the bulk cache in background if stale."""
    now = time.time()
    with _dns_bulk_lock:
        age  = now - _dns_bulk_cache_time
        name = _dns_bulk_cache.get(ip)

    if age > _DNS_BULK_TTL:
        # Refresh in background — don't block the caller
        threading.Thread(target=_build_dns_bulk_cache, daemon=True,
                         name='dns-bulk-refresh').start()
    return name


def _warm_hostname_cache():
    """Pre-populate the bulk DNS cache at startup (called once in background)."""
    _build_dns_bulk_cache()


def get_hostname(ip):
    """Return the human-readable device name for a hotspot client.

    Uses a two-level cache to stay fast even with many connected devices:
      • Per-IP cache (Level 2): checked first — instant lookup, 2-min TTL.
      • Bulk DNS cache (Level 1): one PowerShell call for ALL devices every 30 s.
      • Fallback chain: gethostbyaddr → ping -a → nbtstat -A
        (only reached on first-ever lookup of a new IP).
    """
    now = time.time()

    # Level 2: per-IP cache
    cached = _hostname_cache.get(ip)
    if cached and (now - cached[1]) < _HOSTNAME_TTL:
        return cached[0]

    def _store(name):
        _hostname_cache[ip] = (name, time.time())
        return name

    # Level 1: bulk DNS cache (fast dict lookup — O(1))
    name = _get_dns_bulk(ip)
    if name:
        return _store(name)

    # Fallback 1: reverse DNS (gethostbyaddr)
    try:
        raw = socket.gethostbyaddr(ip)[0]
        if _is_valid_hostname(raw):
            return _store(_clean_hostname(raw))
    except Exception:
        pass

    # Fallback 2: ping -a  (NetBIOS name resolution, 300 ms max)
    try:
        res = subprocess.run(
            f'ping -a -n 1 -w 300 {ip}',
            shell=True, capture_output=True, timeout=2,
            text=True, errors='ignore'
        )
        m = re.search(
            r'Pinging\s+(\S+)\s+\[' + re.escape(ip) + r'\]',
            res.stdout, re.IGNORECASE
        )
        if m and _is_valid_hostname(m.group(1)):
            return _store(_clean_hostname(m.group(1)))
    except Exception:
        pass

    # Fallback 3: nbtstat -A  (direct NetBIOS query, 2 s max)
    try:
        res = subprocess.run(
            f'nbtstat -A {ip}',
            shell=True, capture_output=True, timeout=2,
            text=True, errors='ignore'
        )
        m = re.search(
            r'^\s*(\S+)\s+<00>\s+UNIQUE',
            res.stdout, re.IGNORECASE | re.MULTILINE
        )
        if m and _is_valid_hostname(m.group(1)):
            return _store(_clean_hostname(m.group(1).strip()))
    except Exception:
        pass

    # Store fallback so we don't retry the slow path until TTL expires
    return _store(f"Student-Device-{ip.split('.')[-1]}")


REDIRECT_IP = detect_redirect_ip()




# ---------------------------------------------------------------------------
# DEVICE DETECTION - ARP TABLE
# ---------------------------------------------------------------------------

# MAC address OUI prefixes belonging to virtual/hypervisor adapters.
# These are NEVER real student devices — they are VMware, VirtualBox,
# or Hyper-V virtual interfaces on the instructor's own machine.
VIRTUAL_MAC_PREFIXES = (
    '00-50-56',  # VMware
    '00-0c-29',  # VMware
    '00-1c-14',  # VMware
    '00-05-69',  # VMware
    '00-15-5d',  # Hyper-V
    '08-00-27',  # VirtualBox
    '0a-00-27',  # VirtualBox
    '52-54-00',  # QEMU / KVM
)


def get_hotspot_subnet():
    """Dynamically detect the Windows Mobile Hotspot subnet.

    Always re-checks ipconfig so it works even if the hotspot was turned on
    AFTER the app started. Windows Mobile Hotspot always uses 192.168.137.x.
    """
    try:
        output = subprocess.check_output("ipconfig", shell=True).decode(errors='ignore')
        if '192.168.137.1' in output:
            return '192.168.137.'
    except Exception:
        pass
    # Hotspot not detected — use REDIRECT_IP subnet as fallback
    if REDIRECT_IP.startswith('192.168.137.'):
        return '192.168.137.'
    parts = REDIRECT_IP.split('.')
    if len(parts) == 4:
        return '.'.join(parts[:3]) + '.'
    return None


def get_default_gateways():
    """Return a set of default gateway IPs (to exclude from device list)."""
    gateways = set()
    try:
        result = subprocess.check_output(
            'powershell -Command "(Get-NetRoute -DestinationPrefix 0.0.0.0/0).NextHop"',
            shell=True, timeout=5
        ).decode(errors='ignore')
        for line in result.splitlines():
            ip = line.strip()
            if ip and not ip.startswith('0.') and ip != '::':
                gateways.add(ip)
    except Exception:
        pass
    # Exclude our own hotspot gateway IP (192.168.137.1 = this machine)
    subnet = get_hotspot_subnet()
    if subnet:
        gateways.add(subnet + '1')   # e.g. 192.168.137.1 = instructor's laptop
    return gateways


def get_connected_devices():
    """Scan the Windows ARP table and return only REAL student hotspot devices.

    Filters applied:
      1. Only IPs on the Windows Mobile Hotspot subnet (192.168.137.x)
      2. Exclude the instructor's own machine IPs
      3. Exclude broadcast / network addresses (.0, .255)
      4. Exclude VMware / VirtualBox / Hyper-V virtual adapters by MAC OUI
      5. Exclude multicast MACs (ff-ff-ff-ff-ff-ff)
      6. Exclude default gateway IPs
    """
    devices = []
    try:
        output = subprocess.check_output("arp -a", shell=True).decode(errors='ignore')
        pattern = r'(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9-]{17})\s+(\w+)'
        matches = re.findall(pattern, output)

        local_ips = get_all_local_ips()
        gateways  = get_default_gateways()
        subnet    = get_hotspot_subnet()  # None if hotspot not active

        for ip, mac, _ in matches:
            # 1. Only hotspot subnet when hotspot is active
            if subnet and not ip.startswith(subnet):
                continue
            # 2. Skip broadcast / network addresses
            if ip.endswith('.255') or ip.endswith('.0'):
                continue
            # 3. Skip multicast / broadcast MACs
            if mac.lower() == 'ff-ff-ff-ff-ff-ff':
                continue
            # 4. Skip virtual adapter MACs (VMware, VirtualBox, Hyper-V …)
            if mac.lower().startswith(VIRTUAL_MAC_PREFIXES):
                continue
            # 5. Skip instructor's own IPs
            if ip in local_ips:
                continue
            # 6. Skip gateway IPs
            if ip in gateways:
                continue

            devices.append({
                'ip':       ip,
                'mac':      mac.upper(),
                'hostname': get_hostname(ip),
                'status':   'Connected',
            })
    except Exception as e:
        print(f"[ARP Error] {e}")
    return devices


# ---------------------------------------------------------------------------
# HOSTS FILE HELPERS
# ---------------------------------------------------------------------------
def read_hosts():
    try:
        with open(HOSTS_PATH, 'r') as f:
            return f.readlines()
    except Exception:
        return []


def site_targets(domain):
    targets = [domain]
    if not domain.startswith('www.'):
        targets.append(f'www.{domain}')
    return targets


def is_site_blocked(domain):
    lines = read_hosts()
    targets = set(site_targets(domain))
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            parts = stripped.split()
            if len(parts) >= 2 and parts[1] in targets:
                return True
    return False


def get_firewall_rules():
    return [{'domain': s, 'blocked': is_site_blocked(s)} for s in BLOCKED_SITES]


def block_website(domain):
    try:
        lines = read_hosts()
        with open(HOSTS_PATH, 'a') as f:
            for target in site_targets(domain):
                entry = f"{REDIRECT_IP} {target}"
                if not any(line.strip() == entry for line in lines):
                    f.write(f"{entry}\n")
        subprocess.run("ipconfig /flushdns", shell=True, capture_output=True, timeout=5)
        return True
    except Exception as e:
        print(f"[Block Error] {e}")
        return False


def unblock_website(domain):
    try:
        lines = read_hosts()
        targets = set(site_targets(domain))
        with open(HOSTS_PATH, 'w') as f:
            for line in lines:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    parts = stripped.split()
                    if len(parts) >= 2 and parts[1] in targets:
                        continue
                f.write(line)
        subprocess.run("ipconfig /flushdns", shell=True, capture_output=True, timeout=5)
        return True
    except Exception as e:
        print(f"[Unblock Error] {e}")
        return False


def migrate_hosts_entries():
    """Migrate all ExamGuard hosts entries to use the current REDIRECT_IP.

    This handles both the initial 127.0.0.1 → real-IP migration and the
    case where the hotspot turns on AFTER the app starts, changing REDIRECT_IP
    from the LAN IP (e.g. 192.168.10.10) to the hotspot IP (192.168.137.1).
    """
    if REDIRECT_IP == '127.0.0.1':
        return
    try:
        lines = read_hosts()
        modified = False
        new_lines = []
        for line in lines:
            stripped = line.strip()
            updated = line
            for domain in BLOCKED_SITES:
                for target in site_targets(domain):
                    # Match any existing IP entry for this target that isn't current REDIRECT_IP
                    import re as _re
                    m = _re.match(
                        r'^(\d+\.\d+\.\d+\.\d+)\s+' + _re.escape(target) + r'\s*$',
                        stripped
                    )
                    if m and m.group(1) != REDIRECT_IP:
                        updated = f"{REDIRECT_IP} {target}\n"
                        modified = True
                        break
                if updated != line:
                    break
            new_lines.append(updated)
        if modified:
            with open(HOSTS_PATH, 'w') as f:
                f.writelines(new_lines)
            subprocess.run("ipconfig /flushdns", shell=True, capture_output=True, timeout=5)
            print(f"[Hosts] Migrated all entries to {REDIRECT_IP}")
    except Exception as e:
        print(f"[Hosts Migration] {e} (run as Administrator)")


def cleanup_hosts():
    """Remove all ExamGuard-added entries from the hosts file."""
    try:
        if not os.path.exists(HOSTS_PATH):
            return
        lines = read_hosts()
        new_lines = []
        modified = False
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                parts = stripped.split()
                if len(parts) >= 2:
                    domain = parts[1].lower()
                    matched = False
                    for site in BLOCKED_SITES:
                        if domain == site or domain == f"www.{site}" or domain.endswith(f".{site}"):
                            matched = True
                            break
                    if matched:
                        modified = True
                        continue  # Skip/remove this line
            new_lines.append(line)
        if modified:
            with open(HOSTS_PATH, 'w') as f:
                f.writelines(new_lines)
            subprocess.run("ipconfig /flushdns", shell=True, capture_output=True, timeout=5)
            print("[Hosts] Cleaned up all ExamGuard entries from hosts file")
    except Exception as e:
        print(f"[Hosts Cleanup Error] {e}")


def add_firewall_rules():
    """Add Windows Firewall rules to allow incoming traffic on port 80 and 443."""
    try:
        subprocess.run(
            'netsh advfirewall firewall add rule name="ExamGuard_HTTP" dir=in action=allow protocol=TCP localport=80',
            shell=True, capture_output=True, timeout=5
        )
        subprocess.run(
            'netsh advfirewall firewall add rule name="ExamGuard_HTTPS" dir=in action=allow protocol=TCP localport=443',
            shell=True, capture_output=True, timeout=5
        )
        print("[Firewall] Allowed incoming TCP ports 80 and 443 in Windows Firewall")
    except Exception as e:
        print(f"[Firewall Error] Could not add rules: {e}")


def remove_firewall_rules():
    """Remove Windows Firewall rules for ports 80 and 443."""
    try:
        subprocess.run(
            'netsh advfirewall firewall delete rule name="ExamGuard_HTTP"',
            shell=True, capture_output=True, timeout=5
        )
        subprocess.run(
            'netsh advfirewall firewall delete rule name="ExamGuard_HTTPS"',
            shell=True, capture_output=True, timeout=5
        )
        print("[Firewall] Removed incoming TCP port rules from Windows Firewall")
    except Exception as e:
        print(f"[Firewall Error] Could not remove rules: {e}")


# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------
def save_log(message):
    try:
        with open(LOG_FILE, 'a') as f:
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{ts}] {message}\n")
    except Exception as e:
        print(f"[Log Error] {e}")


def read_logs(limit=50):
    try:
        if not os.path.exists(LOG_FILE):
            return []
        with open(LOG_FILE, 'r') as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]
        return lines[-limit:][::-1]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# ALERT SYSTEM
# ---------------------------------------------------------------------------
alert_cooldowns = {}
alert_lock = threading.Lock()


def should_alert(client_ip, domain, cooldown=30):
    key = (client_ip, domain)
    now = time.time()
    with alert_lock:
        if key in alert_cooldowns and now - alert_cooldowns[key] < cooldown:
            return False
        alert_cooldowns[key] = now
    return True


def match_blocked_domain(host):
    """Check if a hostname matches any blocked domain."""
    host = host.lower().strip().rstrip('.')
    for domain in BLOCKED_SITES:
        if host == domain or host == f'www.{domain}' or host.endswith(f'.{domain}'):
            return domain
    return None


def get_device_info_by_ip(client_ip):
    """Look up a device's hostname and MAC directly from the ARP table.

    Unlike get_connected_devices() this does NOT apply subnet or MAC filters —
    it just looks for the specific IP so alerts always get real device info.
    If the IP isn't in ARP yet, we send a single ping to populate the ARP
    entry and try again.
    """
    def arp_lookup(ip):
        try:
            out = subprocess.check_output("arp -a", shell=True).decode(errors='ignore')
            pattern = r'(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9-]{17})'
            for found_ip, mac in re.findall(pattern, out):
                if found_ip == ip:
                    return mac.upper()
        except Exception:
            pass
        return None

    mac = arp_lookup(client_ip)
    if not mac:
        # ARP entry not yet populated — ping once to force it, then retry
        try:
            subprocess.run(
                f'ping -n 1 -w 800 {client_ip}',
                shell=True, capture_output=True, timeout=2
            )
        except Exception:
            pass
        mac = arp_lookup(client_ip)

    hostname = get_hostname(client_ip)
    return {'ip': client_ip, 'mac': mac or 'N/A', 'hostname': hostname}


def trigger_alert(client_ip, domain):
    """Build and emit a security alert via SocketIO."""
    # Direct ARP lookup for the specific IP — works even if device isn't in
    # the strictly-filtered get_connected_devices() list yet.
    info = get_device_info_by_ip(client_ip)
    device_info = f"{info['hostname']} ({info['ip']} / {info['mac']})"

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    alert_msg = f"ALERT! {device_info} attempted to access {domain}"
    save_log(alert_msg)

    socketio.emit('new_alert', {
        'type': 'security_alert',
        'domain': domain,
        'device': device_info,
        'timestamp': timestamp,
        'message': alert_msg,
        'severity': 'critical',
    })
    print(f"  >> ALERT: {alert_msg}")


# ---------------------------------------------------------------------------
# DNS PROXY SERVER - The core of hotspot-level blocking
# ---------------------------------------------------------------------------
def parse_dns_name(data):
    """Extract the queried domain name from a DNS packet."""
    try:
        if len(data) < 12:
            return None
        pos = 12
        labels = []
        while pos < len(data):
            length = data[pos]
            if length == 0:
                break
            if length >= 192:  # Pointer (compression) — shouldn't happen in question
                break
            pos += 1
            labels.append(data[pos:pos + length].decode('ascii', errors='ignore'))
            pos += length
        return '.'.join(labels).lower() if labels else None
    except Exception:
        return None


def get_dns_qtype(data):
    """Get the query type from a DNS packet (1=A, 28=AAAA, etc.)."""
    try:
        pos = 12
        while pos < len(data) and data[pos] != 0:
            pos += data[pos] + 1
        pos += 1  # skip null terminator
        if pos + 2 <= len(data):
            return int.from_bytes(data[pos:pos + 2], 'big')
    except Exception:
        pass
    return None


def build_dns_a_response(query, redirect_ip):
    """Build a DNS A-record response pointing to redirect_ip."""
    try:
        resp = bytearray(query)
        resp[2] = 0x81   # QR=1, RD=1
        resp[3] = 0x80   # RA=1, RCODE=0
        resp[6] = 0x00   # ANCOUNT high
        resp[7] = 0x01   # ANCOUNT low = 1

        # Find end of question section
        pos = 12
        while pos < len(resp) and resp[pos] != 0:
            pos += resp[pos] + 1
        pos += 5  # null + QTYPE(2) + QCLASS(2)

        # Answer: pointer + A + IN + TTL=60 + RDLEN=4 + IP
        answer = b'\xc0\x0c'
        answer += struct.pack('>HHI', 1, 1, 60)
        answer += struct.pack('>H', 4)
        answer += socket.inet_aton(redirect_ip)
        return bytes(resp[:pos]) + answer
    except Exception:
        return bytes(query)


def build_dns_empty_response(query):
    """Build a DNS response with zero answers (blocks AAAA etc.)."""
    try:
        resp = bytearray(query)
        resp[2] = 0x81
        resp[3] = 0x80
        resp[6] = 0x00
        resp[7] = 0x00   # zero answers
        return bytes(resp)
    except Exception:
        return bytes(query)


def forward_dns(proxy_sock, query, client_addr, upstream):
    """Forward a DNS query to upstream and relay the response."""
    try:
        fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fwd.settimeout(3)
        fwd.sendto(query, (upstream, 53))
        response, _ = fwd.recvfrom(4096)
        proxy_sock.sendto(response, client_addr)
        fwd.close()
    except Exception:
        pass


def handle_dns_query(proxy_sock, data, client_addr):
    """Handle a single DNS query: block or forward."""
    domain = parse_dns_name(data)
    client_ip = client_addr[0]

    if domain:
        matched = match_blocked_domain(domain)
        if matched and is_site_blocked(matched):
            qtype = get_dns_qtype(data)
            if qtype == 1:  # A record
                response = build_dns_a_response(data, REDIRECT_IP)
            else:
                # Block AAAA / other queries with empty response
                response = build_dns_empty_response(data)
            proxy_sock.sendto(response, client_addr)

            # NOTE: We do NOT trigger an alert here.
            # DNS queries from hotspot clients are forwarded by Windows ICS and
            # appear to come from 127.0.0.1 (local), NOT the student's real IP.
            # The HTTP/HTTPS intercept servers (ports 80/443) receive the student's
            # REAL IP directly via TCP and are the sole alert triggers — instantly.
            return

    # Not blocked — forward to upstream DNS
    forward_dns(proxy_sock, data, client_addr, UPSTREAM_DNS)


def dns_proxy_thread():
    """Run a DNS proxy that blocks AI domains and forwards everything else."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Try binding in order of preference
    for addr in ['0.0.0.0', '127.0.0.1']:
        try:
            sock.bind((addr, 53))
            print(f"[DNS] DNS proxy ACTIVE on {addr}:53")
            break
        except OSError:
            continue
    else:
        print("[DNS] Cannot bind port 53 — another DNS service is using it")
        print("[DNS] DNS-level blocking for hotspot clients will not work")
        print("[DNS] Hosts-file blocking on this machine still works")
        return

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            threading.Thread(
                target=handle_dns_query,
                args=(sock, data, addr),
                daemon=True,
            ).start()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# DNS ADAPTER CONFIGURATION (auto-configure + restore on exit)
# ---------------------------------------------------------------------------
original_dns_config = None


def get_internet_adapter():
    """Find the internet-facing network adapter name."""
    try:
        result = subprocess.run(
            'powershell -Command "'
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0'"
            " | Sort-Object RouteMetric"
            " | Select-Object -First 1).InterfaceAlias"
            '"',
            shell=True, capture_output=True, text=True, timeout=10,
        )
        name = result.stdout.strip()
        return name if name else None
    except Exception:
        return None


def setup_dns_redirect():
    """Point the internet adapter's DNS to our local DNS proxy (127.0.0.1).

    This makes the Windows ICS DNS proxy forward queries through our
    proxy, enabling blocking for hotspot-connected devices.
    """
    global original_dns_config
    try:
        adapter = get_internet_adapter()
        if not adapter:
            print("[DNS Config] Could not detect internet adapter")
            return False

        # Save current DNS servers
        result = subprocess.run(
            f'powershell -Command "'
            f"(Get-DnsClientServerAddress"
            f" -InterfaceAlias '{adapter}'"
            f" -AddressFamily IPv4).ServerAddresses -join ','"
            f'"',
            shell=True, capture_output=True, text=True, timeout=10,
        )
        saved_dns = result.stdout.strip()

        original_dns_config = {'adapter': adapter, 'dns': saved_dns}

        # Set DNS to our local proxy
        subprocess.run(
            f'netsh interface ip set dns "{adapter}" static 127.0.0.1',
            shell=True, capture_output=True, timeout=10,
        )
        # Add Google DNS as secondary fallback
        subprocess.run(
            f'netsh interface ip add dns "{adapter}" 8.8.8.8 index=2',
            shell=True, capture_output=True, timeout=10,
        )
        subprocess.run("ipconfig /flushdns", shell=True, capture_output=True, timeout=5)

        print(f"[DNS Config] '{adapter}' DNS -> 127.0.0.1 (ExamGuard proxy)")
        print(f"[DNS Config] Original DNS: {saved_dns or 'DHCP (auto)'}")
        return True

    except Exception as e:
        print(f"[DNS Config] Auto-configuration failed: {e}")
        return False


def restore_dns():
    """Restore original DNS settings (called on exit)."""
    global original_dns_config
    if not original_dns_config:
        return
    try:
        adapter = original_dns_config['adapter']
        saved = original_dns_config['dns']

        if saved:
            first_dns = saved.split(',')[0].strip()
            subprocess.run(
                f'netsh interface ip set dns "{adapter}" static {first_dns}',
                shell=True, capture_output=True, timeout=10,
            )
            # Re-add secondary servers
            for i, dns in enumerate(saved.split(',')[1:], start=2):
                dns = dns.strip()
                if dns:
                    subprocess.run(
                        f'netsh interface ip add dns "{adapter}" {dns} index={i}',
                        shell=True, capture_output=True, timeout=10,
                    )
        else:
            # Was DHCP — restore to automatic
            subprocess.run(
                f'netsh interface ip set dns "{adapter}" dhcp',
                shell=True, capture_output=True, timeout=10,
            )

        subprocess.run("ipconfig /flushdns", shell=True, capture_output=True, timeout=5)
        print(f"[DNS Config] Restored original DNS for '{adapter}'")
        original_dns_config = None
    except Exception as e:
        print(f"[DNS Config] Could not restore DNS: {e}")
        print(f"[DNS Config] Manual fix:  netsh interface ip set dns \"{original_dns_config.get('adapter','')}\" dhcp")


# ---------------------------------------------------------------------------
# GLOBAL CLEANUP WRAPPER
# ---------------------------------------------------------------------------
def perform_global_cleanup():
    """Execute all cleanup operations (DNS, hosts, firewall rules)."""
    print("\n" + "=" * 64)
    print("   Initiating Graceful Security Operations Center Cleanup...")
    print("=" * 64)
    restore_dns()
    cleanup_hosts()
    remove_firewall_rules()
    print("=" * 64)
    print("   SOC Cleanup Complete. Internet Access Restored.")
    print("=" * 64 + "\n")


# Register cleanup
atexit.register(perform_global_cleanup)


# ---------------------------------------------------------------------------
# PROCESS SIGNAL HANDLING
# ---------------------------------------------------------------------------
def signal_handler(sig, frame):
    perform_global_cleanup()
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
if hasattr(signal, 'SIGBREAK'):
    signal.signal(signal.SIGBREAK, signal_handler)


# ---------------------------------------------------------------------------
# TLS SNI PARSER
# ---------------------------------------------------------------------------
def extract_sni(data):
    """Extract the SNI domain from a TLS ClientHello."""
    try:
        if len(data) < 5 or data[0] != 0x16:
            return None
        pos = 5
        if pos >= len(data) or data[pos] != 0x01:
            return None
        pos += 1 + 3 + 2 + 32

        if pos >= len(data):
            return None
        pos += 1 + data[pos]              # session ID

        if pos + 2 > len(data):
            return None
        pos += 2 + int.from_bytes(data[pos:pos + 2], 'big')   # cipher suites

        if pos >= len(data):
            return None
        pos += 1 + data[pos]              # compression methods

        if pos + 2 > len(data):
            return None
        ext_total = int.from_bytes(data[pos:pos + 2], 'big')
        pos += 2
        ext_end = pos + ext_total

        while pos + 4 <= ext_end and pos + 4 <= len(data):
            ext_type = int.from_bytes(data[pos:pos + 2], 'big')
            ext_len = int.from_bytes(data[pos + 2:pos + 4], 'big')
            pos += 4
            if ext_type == 0 and pos + 5 <= len(data):
                name_len = int.from_bytes(data[pos + 3:pos + 5], 'big')
                if pos + 5 + name_len <= len(data):
                    return data[pos + 5:pos + 5 + name_len].decode('ascii', errors='ignore')
            pos += ext_len
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# HTTP / HTTPS INTERCEPT SERVERS
# ---------------------------------------------------------------------------
class BlockedHTTPHandler(BaseHTTPRequestHandler):
    def _handle(self):
        host = (self.headers.get('Host') or '').split(':')[0]
        client_ip = self.client_address[0]
        matched = match_blocked_domain(host)
        if matched and should_alert(client_ip, matched):
            trigger_alert(client_ip, matched)
        self.send_response(403)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Connection', 'close')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        try:
            self.wfile.write(BLOCKED_PAGE_HTML.encode('utf-8'))
        except Exception:
            pass

    do_GET = do_POST = do_HEAD = do_PUT = do_OPTIONS = _handle

    def log_message(self, fmt, *args):
        pass


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def http_intercept_thread():
    try:
        server = ThreadedHTTPServer(('0.0.0.0', 80), BlockedHTTPHandler)
        print("[Intercept] HTTP  intercept ACTIVE on port 80")
        server.serve_forever()
    except OSError as e:
        print(f"[Intercept] Cannot bind port 80: {e}")


def https_intercept_thread():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', 443))
        sock.listen(20)
        sock.settimeout(1.0)
        print("[Intercept] HTTPS intercept ACTIVE on port 443")
        while True:
            try:
                conn, addr = sock.accept()
                conn.settimeout(3)
                client_ip = addr[0]
                try:
                    data = conn.recv(4096)
                    if data:
                        domain = extract_sni(data)
                        if domain:
                            matched = match_blocked_domain(domain)
                            if matched and should_alert(client_ip, matched):
                                trigger_alert(client_ip, matched)
                except Exception:
                    pass
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
            except socket.timeout:
                continue
    except OSError as e:
        print(f"[Intercept] Cannot bind port 443: {e}")


# ---------------------------------------------------------------------------
# FLASK ROUTES
# ---------------------------------------------------------------------------
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('username') == USERNAME and request.form.get('password') == PASSWORD:
            session['user'] = USERNAME
            save_log("SYSTEM: Administrator logged in")
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials. Access denied.')
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    devices = get_connected_devices()
    rules = get_firewall_rules()
    logs = read_logs(25)
    return render_template(
        'dashboard.html',
        devices=devices,
        count=len(devices),
        rules=rules,
        logs=logs,
        alert_count=sum(1 for l in logs if 'ALERT' in l),
        blocked_count=sum(1 for r in rules if r['blocked']),
        local_ip=get_local_ip(),
        redirect_ip=REDIRECT_IP,
    )


@app.route('/api/devices')
def api_devices():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    d = get_connected_devices()
    return jsonify({'devices': d, 'count': len(d)})


@app.route('/api/logs')
def api_logs():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    logs = read_logs(25)
    return jsonify({'logs': logs, 'alert_count': sum(1 for l in logs if 'ALERT' in l)})


@app.route('/api/rules')
def api_rules():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'rules': get_firewall_rules()})



@app.route('/toggle_site/<domain>')
def toggle_site(domain):
    if 'user' not in session:
        return redirect(url_for('login'))
    if is_site_blocked(domain):
        unblock_website(domain)
        save_log(f"UNBLOCKED: {domain}")
    else:
        block_website(domain)
        save_log(f"BLOCKED: {domain}")
    socketio.emit('firewall_update', {'rules': get_firewall_rules()})
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    save_log("SYSTEM: Administrator logged out")
    session.pop('user', None)
    return redirect(url_for('login'))


# ---------------------------------------------------------------------------
# SOCKETIO EVENTS
# ---------------------------------------------------------------------------
@socketio.on('connect')
def handle_connect():
    emit('connection_status', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    pass

@socketio.on('request_devices')
def handle_device_request():
    d = get_connected_devices()
    emit('device_update', {'devices': d, 'count': len(d)})


# ---------------------------------------------------------------------------
# BACKGROUND SCANNER
# ---------------------------------------------------------------------------
def background_scanner():
    while True:
        time.sleep(10)
        try:
            d = get_connected_devices()
            socketio.emit('device_update', {'devices': d, 'count': len(d)})
        except Exception:
            pass


# ---------------------------------------------------------------------------
# HOTSPOT MONITOR
# ---------------------------------------------------------------------------
def hotspot_monitor_thread():
    """Watch for Windows Mobile Hotspot being turned on after app start.

    REDIRECT_IP is set once at startup. If the hotspot wasn't active then,
    it gets set to the LAN IP (e.g. 192.168.10.10) instead of 192.168.137.1.
    This causes phone connections to cross subnets, Windows NATs them, and
    the HTTPS intercept sees the laptop's own LAN IP as the client IP.

    This thread polls every 10 s. The moment it detects the hotspot interface
    it updates REDIRECT_IP to 192.168.137.1 and migrates all hosts file
    entries so subsequent connections use the correct subnet.
    """
    global REDIRECT_IP
    hotspot_ip = '192.168.137.1'
    while True:
        time.sleep(10)
        try:
            if REDIRECT_IP == hotspot_ip:
                continue  # Already correct — nothing to do
            output = subprocess.check_output("ipconfig", shell=True).decode(errors='ignore')
            if hotspot_ip in output:
                old_ip = REDIRECT_IP
                REDIRECT_IP = hotspot_ip
                migrate_hosts_entries()  # rewrite hosts file to 192.168.137.1
                subprocess.run("ipconfig /flushdns", shell=True, capture_output=True, timeout=5)
                print(f"[Hotspot Monitor] Hotspot detected! REDIRECT_IP: {old_ip} -> {hotspot_ip}")
                print("[Hotspot Monitor] Hosts file migrated. Student connections now resolve correctly.")
        except Exception as e:
            print(f"[Hotspot Monitor] {e}")


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    migrate_hosts_entries()

    # Configure Windows Firewall to allow TCP ports 80 and 443
    add_firewall_rules()

    # Auto-configure DNS so hotspot clients go through our proxy
    dns_configured = setup_dns_redirect()

    # Start all background services
    services = [
        ("Device Scanner",   background_scanner),
        ("DNS Proxy",        dns_proxy_thread),
        ("HTTP Intercept",   http_intercept_thread),
        ("HTTPS Intercept",  https_intercept_thread),
        ("Hotspot Monitor",  hotspot_monitor_thread),
        ("DNS Cache Warmer", _warm_hostname_cache),   # pre-build hostname cache
    ]
    for name, fn in services:
        threading.Thread(target=fn, daemon=True, name=name).start()

    local_ip = get_local_ip()
    print()
    print("=" * 64)
    print("   EXAMGUARD - AI Cheating Prevention System")
    print(f"   Dashboard   : http://{local_ip}:5000")
    print(f"   Redirect IP : {REDIRECT_IP}")
    print("   Login       : admin / 1234")
    print("-" * 64)
    print("   DNS Proxy   : " + ("ACTIVE" if dns_configured else "manual config needed"))
    print("   Hotspot clients are monitored automatically.")
    print("=" * 64)
    if not dns_configured:
        print()
        print("   To enable hotspot blocking manually, run:")
        print('   netsh interface ip set dns "YOUR_ADAPTER" static 127.0.0.1')
    print()

    try:
        socketio.run(
            app, debug=True, host='0.0.0.0', port=5000,
            use_reloader=False, allow_unsafe_werkzeug=True,
        )
    finally:
        perform_global_cleanup()
