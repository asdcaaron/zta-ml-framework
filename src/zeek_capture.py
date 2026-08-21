"""
zeek_capture.py
---------------
Network traffic capture and feature extraction layer.

Responsibilities:
  - Capture live traffic via Zeek (or read a pcap file)
  - Parse Zeek conn.log into NSL-KDD compatible feature vectors
  - Forward each feature vector to the ML risk-scoring API
  - Log decisions for audit trail

This module sits between the raw network and the ML detection layer.
In the lab (GNS3/Packet Tracer), point it at the virtual interface
used by the simulated network.

Usage:
    # Live capture on interface eth0 for 60 seconds
    python src/zeek_capture.py --mode live --iface eth0 --duration 60

    # Analyse an existing pcap file
    python src/zeek_capture.py --mode pcap --file captures/test.pcap

    # Replay a Zeek conn.log (for testing without live traffic)
    python src/zeek_capture.py --mode log  --file logs/conn.log
"""

import argparse
import csv
import json
import logging
import os
import subprocess
import time
from datetime import datetime
from typing import Optional

import requests

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
API_URL     = os.getenv('API_URL',     'http://localhost:5000/predict')
AUDIT_LOG   = os.getenv('AUDIT_LOG',   'data/audit.jsonl')
ZEEK_BIN    = os.getenv('ZEEK_BIN',    'zeek')          # path to zeek binary

# ── NSL-KDD feature defaults (for fields Zeek cannot provide directly) ────────
FEATURE_DEFAULTS = {
    'land':                   0,
    'wrong_fragment':         0,
    'urgent':                 0,
    'hot':                    0,
    'num_failed_logins':      0,
    'logged_in':              0,
    'num_compromised':        0,
    'root_shell':             0,
    'su_attempted':           0,
    'num_root':               0,
    'num_file_creations':     0,
    'num_shells':             0,
    'num_access_files':       0,
    'num_outbound_cmds':      0,
    'is_host_login':          0,
    'is_guest_login':         0,
    'serror_rate':            0.0,
    'srv_serror_rate':        0.0,
    'rerror_rate':            0.0,
    'srv_rerror_rate':        0.0,
    'same_srv_rate':          1.0,
    'diff_srv_rate':          0.0,
    'srv_diff_host_rate':     0.0,
    'dst_host_count':         255,
    'dst_host_srv_count':     255,
    'dst_host_same_srv_rate': 1.0,
    'dst_host_diff_srv_rate': 0.0,
    'dst_host_same_src_port_rate': 0.0,
    'dst_host_srv_diff_host_rate': 0.0,
    'dst_host_serror_rate':   0.0,
    'dst_host_srv_serror_rate': 0.0,
    'dst_host_rerror_rate':   0.0,
    'dst_host_srv_rerror_rate': 0.0,
}


# ── Zeek log → feature dict ───────────────────────────────────────────────────

def parse_conn_log_row(row: dict) -> dict:
    """
    Convert one Zeek conn.log row into an NSL-KDD style feature dict.

    Zeek conn.log fields used:
      duration, proto, service, conn_state,
      orig_bytes, resp_bytes, orig_pkts, resp_pkts,
      orig_ip_bytes, resp_ip_bytes
    """
    def safe_float(val, default=0.0):
        try:
            return float(val) if val not in ('-', '', None) else default
        except (ValueError, TypeError):
            return default

    features = {
        'duration':      safe_float(row.get('duration')),
        'protocol_type': str(row.get('proto', 'tcp')).lower(),
        'service':       str(row.get('service', 'other')).lower()
                             .replace('-', 'other'),
        'flag':          str(row.get('conn_state', 'OTH')),
        'src_bytes':     safe_float(row.get('orig_bytes')),
        'dst_bytes':     safe_float(row.get('resp_bytes')),
        'count':         safe_float(row.get('orig_pkts')),
        'srv_count':     safe_float(row.get('resp_pkts')),
    }
    # Fill remaining features with defaults
    features.update(FEATURE_DEFAULTS)
    return features


def parse_conn_log(log_path: str):
    """
    Generator: yield one feature dict per row in a Zeek conn.log.
    Handles Zeek's TSV header format (#fields / #types).
    """
    fields = []
    with open(log_path, 'r') as fh:
        for line in fh:
            line = line.rstrip('\n')
            if line.startswith('#fields'):
                fields = line.split('\t')[1:]
                continue
            if line.startswith('#'):
                continue
            if not fields:
                continue
            values = line.split('\t')
            row = dict(zip(fields, values))
            yield parse_conn_log_row(row)


# ── Live capture ──────────────────────────────────────────────────────────────

def run_zeek_live(interface: str, duration: int, output_dir: str = 'logs'):
    """
    Start a Zeek live capture on `interface` for `duration` seconds.
    Writes conn.log to `output_dir`.
    Returns path to generated conn.log.
    """
    os.makedirs(output_dir, exist_ok=True)
    log.info(f"Starting Zeek on interface '{interface}' "
             f"for {duration}s → '{output_dir}/'")
    cmd = [ZEEK_BIN, '-i', interface, '-C', f'Log::default_logdir={output_dir}']
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        time.sleep(duration)
    finally:
        proc.terminate()
        proc.wait()
    conn_log = os.path.join(output_dir, 'conn.log')
    log.info(f"Capture complete. Log: {conn_log}")
    return conn_log


def run_zeek_pcap(pcap_path: str, output_dir: str = 'logs'):
    """
    Run Zeek offline analysis on a pcap file.
    Returns path to generated conn.log.
    """
    os.makedirs(output_dir, exist_ok=True)
    log.info(f"Running Zeek on pcap '{pcap_path}'...")
    cmd = [ZEEK_BIN, '-r', pcap_path,
           f'Log::default_logdir={output_dir}']
    subprocess.run(cmd, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    conn_log = os.path.join(output_dir, 'conn.log')
    log.info(f"Zeek analysis complete. Log: {conn_log}")
    return conn_log


# ── API scoring ───────────────────────────────────────────────────────────────

def score_feature(features: dict, timeout: float = 2.0) -> Optional[dict]:
    """
    Send one feature dict to the risk-scoring API.
    Returns the API response dict, or None on failure.
    """
    try:
        resp = requests.post(
            API_URL,
            json={'features': features},
            timeout=timeout
        )
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        log.error(f"API call failed: {e}")
        return None


def write_audit(record: dict):
    """Append one scored record to the JSONL audit log."""
    os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
    with open(AUDIT_LOG, 'a') as fh:
        fh.write(json.dumps(record) + '\n')


# ── Main pipeline ─────────────────────────────────────────────────────────────

def process_log(conn_log_path: str):
    """
    Read a conn.log, score every connection, log decisions.
    Prints a summary at the end.
    """
    counts = {'ALLOW': 0, 'MONITOR': 0, 'CHALLENGE_MFA': 0, 'BLOCK': 0}
    total  = 0

    log.info(f"Processing '{conn_log_path}'...")
    for features in parse_conn_log(conn_log_path):
        total += 1
        result = score_feature(features)

        if result is None:
            log.warning(f"Skipping connection #{total} (API unavailable)")
            continue

        action = result.get('action', 'ALLOW')
        counts[action] = counts.get(action, 0) + 1

        audit_record = {
            'timestamp':      datetime.utcnow().isoformat() + 'Z',
            'connection_id':  total,
            'risk_score':     result.get('risk_score'),
            'classification': result.get('classification'),
            'action':         action,
            'confidence':     result.get('confidence'),
        }
        write_audit(audit_record)

        if action in ('BLOCK', 'CHALLENGE_MFA'):
            log.warning(f"  [{action}] conn #{total}  "
                        f"class={result.get('classification')}  "
                        f"risk={result.get('risk_score')}")

    log.info("=" * 50)
    log.info(f"  Total connections : {total}")
    for a, c in counts.items():
        log.info(f"  {a:15s}: {c}")
    log.info(f"  Audit log         : {AUDIT_LOG}")
    log.info("=" * 50)


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description='Zeek traffic capture and feature forwarding'
    )
    parser.add_argument('--mode', choices=['live', 'pcap', 'log'],
                        default='log',
                        help='Capture mode')
    parser.add_argument('--iface',    default='eth0',
                        help='Network interface (live mode)')
    parser.add_argument('--duration', type=int, default=60,
                        help='Capture duration in seconds (live mode)')
    parser.add_argument('--file',     default='logs/conn.log',
                        help='Path to pcap or conn.log file')
    parser.add_argument('--outdir',   default='logs',
                        help='Directory for Zeek output logs')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()

    if args.mode == 'live':
        conn_log = run_zeek_live(args.iface, args.duration, args.outdir)
        process_log(conn_log)

    elif args.mode == 'pcap':
        conn_log = run_zeek_pcap(args.file, args.outdir)
        process_log(conn_log)

    elif args.mode == 'log':
        process_log(args.file)
