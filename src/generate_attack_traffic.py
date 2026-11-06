"""
generate_attack_traffic.py
--------------------------
Generate GNS3 / lab attack-traffic artifacts for all five NSL-KDD classes
(Normal, DoS, Probe, R2L, U2R):

  - Scapy-crafted pcaps under data/gns3/pcaps/<class>.pcap
  - Zeek-format conn.logs under data/gns3/conn_logs/<class>_conn.log

The conn.logs are the demo's RELIABLE path: the Docker daemon may be down and
the zeek/zeek:latest image is not pulled, so the conn.logs are always written
even if Scapy is unavailable. The pcaps are best-effort and are skipped (with a
warning) if Scapy cannot be imported. Offline wrpcap() needs no Npcap driver.

Each conn.log replicates the exact #fields header of data/logs/conn.log so it
is parseable by src/zeek_capture.py:parse_conn_log(). The rows map to the right
NSL-KDD `flag` via the Zeek `conn_state` column (SF / S0 / REJ).

Usage:
    python src/generate_attack_traffic.py
"""

import os
import random
import string
import sys

# ── Project root ───────────────────────────────────────────────────────────────
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PCAP_DIR    = os.path.join(PROJECT_ROOT, 'data', 'gns3', 'pcaps')
CONNLOG_DIR = os.path.join(PROJECT_ROOT, 'data', 'gns3', 'conn_logs')

# ── Scapy (optional; pcaps are best-effort) ─────────────────────────────────────
try:
    from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ── Zeek conn.log header definition ───────────────────────────────────────────
# Field order must match data/logs/conn.log EXACTLY (verified against the
# original file). parse_conn_log() reads #fields and tab-splits the data rows.
CONN_FIELDS = [
    'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
    'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
    'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history',
    'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
    'tunnel_parents', 'ip_proto',
]
CONN_TYPES = [
    'time', 'string', 'addr', 'port', 'addr', 'port',
    'enum', 'string', 'interval', 'count', 'count',
    'string', 'bool', 'bool', 'count', 'string',
    'count', 'count', 'count', 'count',
    'set[string]', 'count',
]

# Reproducible artifacts
random.seed(42)

# Base epoch for connection timestamps (≈ 2026-09-01 09:00 UTC)
BASE_TS = 1788291600.0
# Fixed #open / #close log timestamps (Zeek format: YYYY-MM-DD-HH-MM-SS)
OPEN_TS  = '2026-09-01-09-00-00'
CLOSE_TS = '2026-09-01-09-05-00'

# Network ranges (match the GNS3 hybrid topology)
HQ_WEB    = '10.10.0.5'      # HQ web server (victim of DoS / scan target)
HQ_DNS    = '10.10.0.53'     # HQ DNS resolver
DMZ_FTP   = '172.16.0.10'    # DMZ FTP server
DMZ_SSH   = '172.16.0.11'    # DMZ SSH server
DMZ_TEL   = '172.16.0.12'    # DMZ Telnet server
DMZ_IMAP  = '172.16.0.13'    # DMZ IMAP server
HQ_CLIENT = '10.10.0.100'    # legit HQ employee workstation (Normal source)
OUT_ATK   = '203.0.113.50'   # outside attacker
IN_ATK    = '10.20.0.100'    # inside attacker

CLASSES = ['normal', 'dos', 'probe', 'r2l', 'u2r']


def gen_uid():
    """Generate a Zeek-style random uid (base62, 18 chars)."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=18))


def ip_proto_for(proto):
    return {'tcp': 6, 'udp': 17, 'icmp': 1}.get(proto, 6)


def make_conn_row(ts, uid, src_h, src_p, dst_h, dst_p, proto, service,
                  duration, orig_bytes, resp_bytes, conn_state, history,
                  orig_pkts, resp_pkts, local_orig='F', local_resp='F',
                  missed_bytes=0, tunnel_parents='-'):
    """Build one tab-separated Zeek conn.log data row.

    IP-level byte counts are approximated as payload + 40-byte header per packet
    (Zeek counts both payload and headers in *_ip_bytes).
    """
    orig_ip_bytes = orig_bytes + 40 * max(orig_pkts, 0)
    resp_ip_bytes = resp_bytes + 40 * max(resp_pkts, 0)
    values = [
        f'{ts:.6f}', uid, src_h, str(src_p), dst_h, str(dst_p),
        proto, service, f'{duration:.6f}', str(orig_bytes), str(resp_bytes),
        conn_state, local_orig, local_resp, str(missed_bytes), history,
        str(orig_pkts), str(orig_ip_bytes), str(resp_pkts), str(resp_ip_bytes),
        tunnel_parents, str(ip_proto_for(proto)),
    ]
    return '\t'.join(values)


def write_conn_log(cls, rows):
    """Write a full Zeek-format conn.log at data/gns3/conn_logs/<cls>_conn.log."""
    path = os.path.join(CONNLOG_DIR, cls + '_conn.log')
    sep = '\t'
    with open(path, 'w', newline='') as fh:
        fh.write('#separator \\x09\n')          # literal escape representation
        fh.write(f'#set_separator{sep},\n')
        fh.write(f'#empty_field{sep}(empty)\n')
        fh.write(f'#unset_field{sep}-\n')
        fh.write(f'#path{sep}conn\n')
        fh.write(f'#open{sep}{OPEN_TS}\n')
        fh.write('#fields' + sep + sep.join(CONN_FIELDS) + '\n')
        fh.write('#types' + sep + sep.join(CONN_TYPES) + '\n')
        for row in rows:
            fh.write(row + '\n')
        fh.write(f'#close{sep}{CLOSE_TS}\n')
    return path


# ── Per-class conn.log row generators ─────────────────────────────────────────

def gen_normal_rows():
    """Normal: conn_state SF, service http/dns/ssl, modest bytes, low pkts."""
    rows = []
    ts = BASE_TS
    # HTTP / HTTPS browsing to external web servers from a legit HQ workstation
    ext_servers = [('93.184.216.34', 80, 'http'),
                   ('140.82.121.4', 80, 'http'),
                   ('151.101.1.69', 443, 'ssl')]
    for i in range(10):
        dst_h, dst_p, service = ext_servers[i % len(ext_servers)]
        ts += random.uniform(0.05, 1.5)
        rows.append(make_conn_row(
            ts, gen_uid(), HQ_CLIENT, 40000 + i, dst_h, dst_p, 'tcp', service,
            random.uniform(0.2, 3.5), random.randint(300, 900),
            random.randint(1500, 8000), 'SF', 'ShADadfF',
            random.randint(8, 20), random.randint(10, 30)))
    # DNS lookups to the HQ resolver
    for i in range(8):
        ts += random.uniform(0.02, 0.4)
        rows.append(make_conn_row(
            ts, gen_uid(), HQ_CLIENT, 33000 + i, HQ_DNS, 53, 'udp', 'dns',
            random.uniform(0.01, 0.4), random.randint(30, 60),
            random.randint(90, 200), 'SF', 'Dd', 1, 1))
    # Internal HTTPS to an intranet app
    for i in range(6):
        ts += random.uniform(0.1, 0.8)
        rows.append(make_conn_row(
            ts, gen_uid(), HQ_CLIENT, 45000 + i, '10.10.0.20', 443, 'tcp', 'ssl',
            random.uniform(0.1, 1.2), random.randint(200, 600),
            random.randint(2000, 6000), 'SF', 'ShADadfF',
            random.randint(6, 14), random.randint(8, 20)))
    return rows


def gen_dos_rows():
    """DoS: conn_state S0 (SYN flood, no completion), service '-'/'private',
    orig_bytes 0, resp_bytes 0, high orig_pkts."""
    rows = []
    ts = BASE_TS
    for i in range(25):
        ts += random.uniform(0.0005, 0.01)
        service = random.choice(['-', '-', 'private'])
        rows.append(make_conn_row(
            ts, gen_uid(), OUT_ATK, random.randint(1024, 65535), HQ_WEB, 80,
            'tcp', service, random.uniform(0.0001, 0.05),
            0, 0, 'S0', 'S', random.randint(100, 500), 0))
    return rows


def gen_probe_rows():
    """Probe: conn_state REJ, service '-', many distinct dest ports,
    orig_bytes 0, resp_bytes 0."""
    rows = []
    ts = BASE_TS
    ports = [21, 22, 23, 25, 53, 79, 80, 110, 111, 135, 139, 143, 443, 445,
             515, 587, 873, 990, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049,
             3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 27017]
    for i, dport in enumerate(ports):
        ts += random.uniform(0.01, 0.1)
        rows.append(make_conn_row(
            ts, gen_uid(), OUT_ATK, 40000 + i, HQ_WEB, dport, 'tcp', '-',
            0.0, 0, 0, 'REJ', 'Sr', 1, 0))
    return rows


def gen_r2l_rows():
    """R2L: conn_state SF to auth services (ftp/ssh/telnet/imap) with small
    payloads — remote-to-local intrusion attempts."""
    rows = []
    ts = BASE_TS
    auth_targets = [(DMZ_FTP, 21, 'ftp'), (DMZ_SSH, 22, 'ssh'),
                    (DMZ_TEL, 23, 'telnet'), (DMZ_IMAP, 143, 'imap')]
    for i in range(20):
        dst_h, dst_p, service = auth_targets[i % len(auth_targets)]
        ts += random.uniform(0.1, 0.9)
        rows.append(make_conn_row(
            ts, gen_uid(), OUT_ATK, 50000 + i, dst_h, dst_p, 'tcp', service,
            random.uniform(0.5, 4.0), random.randint(50, 300),
            random.randint(100, 600), 'SF', 'ShADadfF',
            random.randint(5, 15), random.randint(6, 18)))
    return rows


def gen_u2r_rows():
    """U2R: conn_state SF to ssh/telnet with suspicious small payloads —
    user-to-root escalation after an initial foothold."""
    rows = []
    ts = BASE_TS
    targets = [(DMZ_SSH, 22, 'ssh'), (DMZ_TEL, 23, 'telnet')]
    for i in range(18):
        dst_h, dst_p, service = targets[i % len(targets)]
        ts += random.uniform(0.2, 1.2)
        # suspicious small payloads, occasionally with elevated-priv commands
        rows.append(make_conn_row(
            ts, gen_uid(), IN_ATK, 60000 + i, dst_h, dst_p, 'tcp', service,
            random.uniform(0.3, 2.5), random.randint(40, 200),
            random.randint(60, 400), 'SF', 'ShADadfF',
            random.randint(4, 12), random.randint(5, 14)))
    return rows


ROW_GENERATORS = {
    'normal': gen_normal_rows,
    'dos':    gen_dos_rows,
    'probe':  gen_probe_rows,
    'r2l':    gen_r2l_rows,
    'u2r':    gen_u2r_rows,
}

# ── Scapy pcap generators (best-effort) ────────────────────────────────────────
CLIENT_MAC = '00:50:56:aa:00:01'
SERVER_MAC = '00:50:56:aa:00:02'


def _eth(src_mac, dst_mac, src_ip, dst_ip):
    return Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip)


def build_normal_packets():
    """Full TCP handshakes + HTTP GET + DNS queries."""
    pkts = []
    t = BASE_TS
    ext = [('93.184.216.34', 80), ('140.82.121.4', 80), ('151.101.1.69', 443)]
    for i, (dst_h, dst_p) in enumerate(ext):
        sport = 40000 + i
        seq = 1000 + i * 1000
        syn = _eth(CLIENT_MAC, SERVER_MAC, HQ_CLIENT, dst_h) / TCP(
            sport=sport, dport=dst_p, flags='S', seq=seq)
        syn.time = t; t += 0.001; pkts.append(syn)
        sa = _eth(SERVER_MAC, CLIENT_MAC, dst_h, HQ_CLIENT) / TCP(
            sport=dst_p, dport=sport, flags='SA', seq=2000, ack=seq + 1)
        sa.time = t; t += 0.001; pkts.append(sa)
        ack = _eth(CLIENT_MAC, SERVER_MAC, HQ_CLIENT, dst_h) / TCP(
            sport=sport, dport=dst_p, flags='A', seq=seq + 1, ack=2001)
        ack.time = t; t += 0.002; pkts.append(ack)
        if dst_p == 80:
            payload = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
            get = (_eth(CLIENT_MAC, SERVER_MAC, HQ_CLIENT, dst_h) /
                   TCP(sport=sport, dport=dst_p, flags='PA',
                       seq=seq + 1, ack=2001) / Raw(load=payload))
            get.time = t; t += 0.002; pkts.append(get)
    # DNS queries (UDP)
    for i in range(3):
        dns = _eth(CLIENT_MAC, SERVER_MAC, HQ_CLIENT, HQ_DNS) / UDP(
            sport=33000 + i, dport=53) / Raw(load=bytes([i, 1, 0, 0, 1, 0, 0]))
        dns.time = t; t += 0.05; pkts.append(dns)
    return pkts


def build_dos_packets():
    """SYN flood: many SYN packets to one port with no ACK."""
    pkts = []
    t = BASE_TS
    for i in range(30):
        syn = _eth(SERVER_MAC, CLIENT_MAC, OUT_ATK, HQ_WEB) / TCP(
            sport=random.randint(1024, 65535), dport=80, flags='S',
            seq=random.randint(1, 4294967295))
        syn.time = t; t += 0.001; pkts.append(syn)
    return pkts


def build_probe_packets():
    """Port scan: SYN to many sequential ports."""
    pkts = []
    t = BASE_TS
    ports = [21, 22, 23, 25, 53, 79, 80, 110, 111, 135, 139, 143, 443, 445,
             515, 587, 873, 990, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049,
             3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 27017]
    for i, dport in enumerate(ports):
        syn = _eth(SERVER_MAC, CLIENT_MAC, OUT_ATK, HQ_WEB) / TCP(
            sport=40000 + i, dport=dport, flags='S', seq=1000 + i)
        syn.time = t; t += 0.01; pkts.append(syn)
    return pkts


def build_r2l_packets():
    """Repeated TCP connects to port 21/22/23 with short payloads."""
    pkts = []
    t = BASE_TS
    targets = [(DMZ_FTP, 21, b'USER anonymous\r\nPASS a@\r\n'),
               (DMZ_SSH, 22, b'SSH-2.0-OpenSSH_7.9\r\n'),
               (DMZ_TEL, 23, b'root\r\ntoor\r\n')]
    for i, (dst_h, dst_p, payload) in enumerate(targets):
        sport = 50000 + i
        seq = 1000 + i * 1000
        syn = _eth(SERVER_MAC, CLIENT_MAC, OUT_ATK, dst_h) / TCP(
            sport=sport, dport=dst_p, flags='S', seq=seq)
        syn.time = t; t += 0.002; pkts.append(syn)
        sa = _eth(CLIENT_MAC, SERVER_MAC, dst_h, OUT_ATK) / TCP(
            sport=dst_p, dport=sport, flags='SA', seq=2000, ack=seq + 1)
        sa.time = t; t += 0.002; pkts.append(sa)
        ack = _eth(SERVER_MAC, CLIENT_MAC, OUT_ATK, dst_h) / TCP(
            sport=sport, dport=dst_p, flags='A', seq=seq + 1, ack=2001)
        ack.time = t; t += 0.002; pkts.append(ack)
        data = (_eth(SERVER_MAC, CLIENT_MAC, OUT_ATK, dst_h) /
                TCP(sport=sport, dport=dst_p, flags='PA',
                    seq=seq + 1, ack=2001) / Raw(load=payload))
        data.time = t; t += 0.01; pkts.append(data)
    return pkts


def build_u2r_packets():
    """Connects to port 22/23 with exploit-like payloads."""
    pkts = []
    t = BASE_TS
    targets = [(DMZ_SSH, 22, b'\x00\x00\x00\x1cexploit_overflow_padding'),
               (DMZ_TEL, 23, b'sudo su -\r\nwhoami\nrm /tmp/.lock\r\n')]
    for i, (dst_h, dst_p, payload) in enumerate(targets):
        for j in range(3):
            sport = 60000 + i * 10 + j
            seq = 1000 + i * 1000 + j * 500
            syn = _eth(SERVER_MAC, CLIENT_MAC, IN_ATK, dst_h) / TCP(
                sport=sport, dport=dst_p, flags='S', seq=seq)
            syn.time = t; t += 0.002; pkts.append(syn)
            sa = _eth(CLIENT_MAC, SERVER_MAC, dst_h, IN_ATK) / TCP(
                sport=dst_p, dport=sport, flags='SA', seq=2000, ack=seq + 1)
            sa.time = t; t += 0.002; pkts.append(sa)
            ack = _eth(SERVER_MAC, CLIENT_MAC, IN_ATK, dst_h) / TCP(
                sport=sport, dport=dst_p, flags='A', seq=seq + 1, ack=2001)
            ack.time = t; t += 0.002; pkts.append(ack)
            data = (_eth(SERVER_MAC, CLIENT_MAC, IN_ATK, dst_h) /
                    TCP(sport=sport, dport=dst_p, flags='PA',
                        seq=seq + 1, ack=2001) / Raw(load=payload))
            data.time = t; t += 0.01; pkts.append(data)
    return pkts


PCAP_BUILDERS = {
    'normal': build_normal_packets,
    'dos':    build_dos_packets,
    'probe':  build_probe_packets,
    'r2l':    build_r2l_packets,
    'u2r':    build_u2r_packets,
}


def write_pcap(cls, path):
    """Build and write a class pcap; return file size in bytes (0 on failure)."""
    try:
        pkts = PCAP_BUILDERS[cls]()
        wrpcap(path, pkts)
        return os.path.getsize(path) if os.path.exists(path) else 0
    except Exception as exc:  # never let pcap failure abort conn.log delivery
        print(f'  WARNING: pcap generation for {cls} failed ({exc}); '
              f'conn.log is still available as the reliable path.')
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass
        return 0


# ── Self-check: every conn.log must parse with the real parser ────────────────

def self_check():
    """Assert every generated conn.log yields > 0 rows via zeek_capture."""
    sys.path.insert(0, os.path.join(PROJECT_ROOT, 'src'))
    from zeek_capture import parse_conn_log
    print('\nSelf-check (parse_conn_log on each conn.log):')
    for cls in CLASSES:
        log_path = os.path.join(CONNLOG_DIR, cls + '_conn.log')
        n = sum(1 for _ in parse_conn_log(log_path))
        assert n > 0, f'SELF-CHECK FAILED: {cls}_conn.log yielded 0 rows'
        print(f'  {cls}_conn.log -> {n} rows parseable')


def main():
    os.makedirs(PCAP_DIR, exist_ok=True)
    os.makedirs(CONNLOG_DIR, exist_ok=True)

    if not SCAPY_AVAILABLE:
        print('WARNING: Scapy is not installed — pcap generation will be '
              'skipped. conn.logs are still written (the reliable path).')

    print('Generating attack-traffic artifacts for 5 NSL-KDD classes ...\n')
    for cls in CLASSES:
        rows = ROW_GENERATORS[cls]()
        connlog_path = write_conn_log(cls, rows)
        pcap_path = os.path.join(PCAP_DIR, cls + '.pcap')
        pcap_bytes = write_pcap(cls, pcap_path) if SCAPY_AVAILABLE else 0
        pcap_note = f'{pcap_bytes} bytes' if pcap_bytes else 'skipped'
        print(f'  {cls:6s}: {len(rows):2d} conn.log rows | '
              f'pcap {pcap_note}')
        print(f'         conn.log -> {connlog_path}')
        print(f'         pcap      -> {pcap_path}')

    self_check()
    print('\nDone. All 5 conn.logs written and parseable.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
