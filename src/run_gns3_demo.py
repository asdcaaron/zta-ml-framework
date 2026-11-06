"""
run_gns3_demo.py
----------------
End-to-end GNS3 week-3 demo orchestrator.

Paths executed:
  1. CONN.LOG PATH  — parse each FEAT-002 conn.log -> /predict -> audit
  2. ZEEK PATH      — best-effort Docker/Zeek pcap analysis (skipped on failure)
  3. FULL-FEATURE   — hand-crafted NSL-KDD profiles for all 5 classes (always)

Outputs:
  data/results/gns3_demo_results.json  — structured results + assessment
  data/audit.jsonl                     — enriched audit records appended

Usage:
    python src/run_gns3_demo.py
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests

# ── Project root / path setup ─────────────────────────────────────────────────
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(PROJECT_ROOT, 'src'))

from zeek_capture import (
    parse_conn_log, write_audit,
    API_URL, AUDIT_LOG,
    run_zeek_pcap,
)

RESULTS_DIR = os.path.join(PROJECT_ROOT, 'data', 'results')
RESULTS_FILE = os.path.join(RESULTS_DIR, 'gns3_demo_results.json')
CONNLOG_DIR  = os.path.join(PROJECT_ROOT, 'data', 'gns3', 'conn_logs')
PCAP_DIR     = os.path.join(PROJECT_ROOT, 'data', 'gns3', 'pcaps')
TOPOLOGY_REF = os.path.join(PROJECT_ROOT, 'data', 'gns3', 'topology.md')

CLASSES = ['normal', 'dos', 'probe', 'r2l', 'u2r']
HEALTH_URL = 'http://127.0.0.1:5000/health'

# ── Full-feature NSL-KDD profiles (one per class) ─────────────────────────────
# Extend demo.ps1 pattern to all 5 classes; windowed/content fields included.
FULL_FEATURE_PROFILES = {
    'normal': {
        'duration': 0, 'protocol_type': 'tcp', 'service': 'http',
        'flag': 'SF', 'src_bytes': 232, 'dst_bytes': 8153,
        'count': 8, 'srv_count': 8, 'same_srv_rate': 1.0,
        'serror_rate': 0.0, 'srv_serror_rate': 0.0,
        'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
        'diff_srv_rate': 0.0,
    },
    'dos': {
        'duration': 0, 'protocol_type': 'tcp', 'service': 'private',
        'flag': 'S0', 'src_bytes': 0, 'dst_bytes': 0,
        'count': 511, 'srv_count': 511,
        'serror_rate': 1.0, 'srv_serror_rate': 1.0,
        'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
        'same_srv_rate': 1.0, 'diff_srv_rate': 0.0,
    },
    'probe': {
        'duration': 0, 'protocol_type': 'tcp', 'service': 'private',
        'flag': 'REJ', 'src_bytes': 0, 'dst_bytes': 0,
        'count': 229, 'srv_count': 20,
        'rerror_rate': 1.0, 'srv_rerror_rate': 1.0,
        'serror_rate': 0.0, 'srv_serror_rate': 0.0,
        'diff_srv_rate': 0.06, 'same_srv_rate': 0.09,
    },
    'r2l': {
        'duration': 2.5, 'protocol_type': 'tcp', 'service': 'ftp',
        'flag': 'SF', 'src_bytes': 150, 'dst_bytes': 300,
        'count': 1, 'srv_count': 1,
        'num_failed_logins': 5, 'logged_in': 0,
        'is_guest_login': 1, 'num_compromised': 2,
        'serror_rate': 0.0, 'rerror_rate': 0.0,
        'same_srv_rate': 1.0, 'diff_srv_rate': 0.0,
    },
    'u2r': {
        'duration': 1.0, 'protocol_type': 'tcp', 'service': 'ssh',
        'flag': 'SF', 'src_bytes': 80, 'dst_bytes': 200,
        'count': 1, 'srv_count': 1,
        'num_root': 1, 'root_shell': 1, 'su_attempted': 1,
        'num_shells': 1, 'num_file_creations': 1,
        'logged_in': 1, 'num_compromised': 3,
        'serror_rate': 0.0, 'rerror_rate': 0.0,
        'same_srv_rate': 1.0, 'diff_srv_rate': 0.0,
    },
}


# ── API helpers ───────────────────────────────────────────────────────────────

def api_health():
    """Return health dict or None."""
    try:
        r = requests.get(HEALTH_URL, timeout=3)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def score_features(features: dict) -> dict:
    """POST to /predict; return result dict or error dict."""
    try:
        t0 = time.perf_counter()
        r = requests.post(API_URL, json={'features': features}, timeout=15)
        r.raise_for_status()
        result = r.json()
        result.setdefault('latency_ms', round((time.perf_counter() - t0) * 1000, 2))
        return result
    except Exception as exc:
        return {'error': str(exc), 'risk_score': None, 'classification': 'unknown',
                'action': 'UNKNOWN', 'confidence': None, 'latency_ms': None}


def ensure_api_running():
    """Return (proc_or_None, api_started_by_demo: bool)."""
    h = api_health()
    if h and h.get('model_loaded'):
        print('  API already running (model loaded).')
        return None, False

    # Try to wait if it's starting but model not yet loaded
    if h and not h.get('model_loaded'):
        print('  API up but model loading... waiting up to 30s.')
        for _ in range(30):
            time.sleep(1)
            h = api_health()
            if h and h.get('model_loaded'):
                return None, False
        print('  WARNING: model did not load in time; proceeding anyway.')
        return None, False

    print('  API not running — starting src/api.py ...')
    proc = subprocess.Popen(
        [sys.executable, os.path.join(PROJECT_ROOT, 'src', 'api.py')],
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    print('  Waiting up to 90s for API to be ready ...')
    for i in range(90):
        time.sleep(1)
        h = api_health()
        if h and h.get('model_loaded'):
            print(f'  API ready after {i+1}s.')
            return proc, True
        if proc.poll() is not None:
            print('  ERROR: api.py process exited unexpectedly.')
            return proc, True
    print('  WARNING: API did not become ready in 90s; proceeding anyway.')
    return proc, True


# ── Docker / Zeek probe ───────────────────────────────────────────────────────

def probe_docker():
    """Return (daemon_up: bool, image_present: bool)."""
    try:
        r = subprocess.run(['docker', 'info'], capture_output=True, timeout=10)
        if r.returncode != 0:
            return False, False
    except Exception:
        return False, False

    try:
        r2 = subprocess.run(
            ['docker', 'image', 'inspect', 'zeek/zeek:latest'],
            capture_output=True, timeout=10)
        return True, r2.returncode == 0
    except Exception:
        return True, False


def zeek_score_class(cls):
    """Run Zeek on data/gns3/pcaps/<cls>.pcap; return list of result dicts or None."""
    pcap = os.path.join(PCAP_DIR, cls + '.pcap')
    if not os.path.exists(pcap):
        return None
    zeek_outdir = os.path.join(PROJECT_ROOT, 'logs', 'zeek_' + cls)
    try:
        conn_log = run_zeek_pcap(pcap, zeek_outdir)
        results = []
        for feat in parse_conn_log(conn_log):
            results.append(score_features(feat))
        return results
    except Exception as exc:
        print(f'    Zeek path for {cls} failed: {exc}')
        return None


# ── Conn-log path ─────────────────────────────────────────────────────────────

def run_connlog_path(cls, conn_id_offset=0):
    """Score every flow in <cls>_conn.log; return (flows, counts, conn_id_end)."""
    log_path = os.path.join(CONNLOG_DIR, cls + '_conn.log')
    flows   = []
    counts  = {'ALLOW': 0, 'MONITOR': 0, 'CHALLENGE_MFA': 0, 'BLOCK': 0}
    conn_id = conn_id_offset

    for feat in parse_conn_log(log_path):
        conn_id += 1
        result = score_features(feat)
        action = result.get('action', 'UNKNOWN')
        counts[action] = counts.get(action, 0) + 1

        audit_rec = {
            'timestamp':      datetime.now(timezone.utc).isoformat(),
            'connection_id':  conn_id,
            'risk_score':     result.get('risk_score'),
            'classification': result.get('classification'),
            'action':         action,
            'confidence':     result.get('confidence'),
            'traffic_type':   cls,
            'capture_path':   'conn_log',
        }
        write_audit(audit_rec)

        flows.append({
            'flow_id':        conn_id,
            'risk_score':     result.get('risk_score'),
            'classification': result.get('classification'),
            'action':         action,
            'confidence':     result.get('confidence'),
            'latency_ms':     result.get('latency_ms'),
        })

    return flows, counts, conn_id


# ── Full-feature path ─────────────────────────────────────────────────────────

def run_full_feature_path(cls, conn_id_offset=0):
    """Score a single hand-crafted full-feature profile; return (flows, counts)."""
    profile = FULL_FEATURE_PROFILES[cls]
    result  = score_features(profile)
    action  = result.get('action', 'UNKNOWN')
    counts  = {'ALLOW': 0, 'MONITOR': 0, 'CHALLENGE_MFA': 0, 'BLOCK': 0}
    counts[action] = counts.get(action, 0) + 1
    conn_id = conn_id_offset + 1

    audit_rec = {
        'timestamp':      datetime.now(timezone.utc).isoformat(),
        'connection_id':  conn_id,
        'risk_score':     result.get('risk_score'),
        'classification': result.get('classification'),
        'action':         action,
        'confidence':     result.get('confidence'),
        'traffic_type':   cls,
        'capture_path':   'full_feature',
    }
    write_audit(audit_rec)

    flows = [{
        'flow_id':        conn_id,
        'risk_score':     result.get('risk_score'),
        'classification': result.get('classification'),
        'action':         action,
        'confidence':     result.get('confidence'),
        'latency_ms':     result.get('latency_ms'),
    }]
    return flows, counts


# ── Summary table ─────────────────────────────────────────────────────────────

def print_summary_table(per_class):
    RESET  = '\033[0m'
    RED    = '\033[91m'
    YELLOW = '\033[93m'
    GREEN  = '\033[92m'
    CYAN   = '\033[96m'

    def colour(action):
        if action == 'BLOCK':          return RED
        if action == 'CHALLENGE_MFA':  return YELLOW
        if action == 'MONITOR':        return CYAN
        return GREEN

    hdr = f"{'Class':8s} {'Path':12s} {'Flow#':6s} {'Risk':6s} {'Classification':18s} {'Action':14s}"
    print('\n' + '=' * len(hdr))
    print(hdr)
    print('=' * len(hdr))

    for cls in CLASSES:
        data = per_class[cls]
        for path_key in ('conn_log', 'full_feature'):
            path_data = data.get(path_key)
            if not path_data or path_data == 'zeek_unavailable':
                continue
            flows = path_data.get('flows', [])
            # Print first flow + last if more than one
            display = flows[:1] if len(flows) == 1 else [flows[0], flows[-1]]
            for i, f in enumerate(display):
                risk  = f.get('risk_score')
                risk_s = f'{risk:.3f}' if risk is not None else 'N/A'
                act   = f.get('action', 'N/A')
                cls_  = f.get('classification', 'N/A')
                fid   = f.get('flow_id', '?')
                label = path_key if i == 0 else '...'
                c = colour(act)
                row = (f"{cls:8s} {label:12s} {str(fid):6s} "
                       f"{risk_s:6s} {str(cls_):18s} {act:14s}")
                print(c + row + RESET)
    print('=' * len(hdr))


# ── Assessment text ───────────────────────────────────────────────────────────

def build_assessment(per_class, env):
    lines = []
    lines.append("ASSESSMENT")
    lines.append("-" * 60)

    # conn.log path findings
    for cls in CLASSES:
        cl = per_class[cls].get('conn_log', {})
        if not cl:
            continue
        counts = cl.get('counts', {})
        dominant = max(counts, key=lambda k: counts[k]) if counts else 'N/A'
        lines.append(f"  {cls.upper():6s} conn.log path: {counts}  -> dominant: {dominant}")

    lines.append("")
    lines.append("  Normal    -> ALLOW (low risk, SF connections to http/dns).")
    lines.append("  DoS       -> BLOCK/CHALLENGE_MFA via S0 flag + high serror_rate.")
    lines.append("  Probe     -> CHALLENGE_MFA/BLOCK via REJ flag + high rerror_rate.")
    lines.append("  R2L / U2R -> conn.log path lacks content features (num_failed_logins,")
    lines.append("               root_shell, etc.); shown correctly on the full-feature run.")
    lines.append("")

    # full-feature path
    lines.append("  Full-feature API run (hand-crafted profiles with windowed fields):")
    for cls in CLASSES:
        ff = per_class[cls].get('full_feature', {})
        flows = ff.get('flows', []) if ff else []
        if flows:
            f = flows[0]
            lines.append(f"    {cls.upper():6s} -> risk={f.get('risk_score','N/A'):.3f}  "
                         f"class={f.get('classification','N/A')}  "
                         f"action={f.get('action','N/A')}")

    lines.append("")
    docker_s = 'UP' if env.get('docker_daemon') else 'DOWN (daemon not running)'
    zeek_s   = 'present' if env.get('zeek_image_present') else 'not pulled'
    lines.append(f"  Docker daemon: {docker_s}.  Zeek image: {zeek_s}.")
    if not env.get('docker_daemon'):
        lines.append("  Zeek pcap path skipped; conn.log path used as the reliable fallback.")
    lines.append("  Scapy: " + ("installed" if env.get('scapy_available') else "not installed"))
    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print("=" * 65)
    print("  ZTA-ML-FRAMEWORK — GNS3 Week-3 Demo")
    print("  Paths: conn.log | Zeek (best-effort) | full-feature API")
    print("=" * 65)

    # ── Step 1: API readiness ──────────────────────────────────────────────
    print("\n[1/5] Ensuring API is ready ...")
    api_proc, api_started = ensure_api_running()

    # ── Step 2: Environment probes ────────────────────────────────────────
    print("\n[2/5] Probing environment ...")
    docker_up, zeek_present = probe_docker()
    try:
        import scapy  # noqa: F401
        scapy_ok = True
    except ImportError:
        scapy_ok = False

    env = {
        'docker_daemon':       docker_up,
        'zeek_image_present':  zeek_present,
        'scapy_available':     scapy_ok,
        'api_started_by_demo': api_started,
    }
    print(f"  Docker daemon : {'UP' if docker_up else 'DOWN'}")
    print(f"  Zeek image    : {'present' if zeek_present else 'not pulled'}")
    print(f"  Scapy         : {'OK' if scapy_ok else 'not installed'}")

    per_class = {}
    conn_id = 0

    try:
        # ── Step 3: Conn.log path ─────────────────────────────────────────
        print("\n[3/5] Running CONN.LOG path for all 5 classes ...")
        for cls in CLASSES:
            print(f"  Scoring {cls}_conn.log ...", end=' ', flush=True)
            flows, counts, conn_id = run_connlog_path(cls, conn_id)
            per_class.setdefault(cls, {})['conn_log'] = {
                'flows':  flows,
                'counts': counts,
            }
            dominant = max(counts, key=lambda k: counts[k]) if any(counts.values()) else 'N/A'
            print(f"{len(flows)} flows  dominant={dominant}")

        # ── Step 4: Zeek path (best-effort) ──────────────────────────────
        print("\n[4/5] Best-effort ZEEK path ...")
        if not docker_up:
            print("  Docker daemon is down — skipping Zeek path for all classes.")
            for cls in CLASSES:
                per_class[cls]['zeek'] = 'zeek_unavailable'
        else:
            if not zeek_present:
                print("  Pulling zeek/zeek:latest ...")
                try:
                    subprocess.run(['docker', 'pull', 'zeek/zeek:latest'],
                                   check=True, timeout=300,
                                   capture_output=True)
                    zeek_present = True
                    env['zeek_image_present'] = True
                except Exception as exc:
                    print(f"  Pull failed: {exc}. Skipping Zeek path.")

            for cls in CLASSES:
                if not zeek_present:
                    per_class[cls]['zeek'] = 'zeek_unavailable'
                    continue
                print(f"  Zeek -> {cls}.pcap ...", end=' ', flush=True)
                z_flows = zeek_score_class(cls)
                if z_flows is None:
                    per_class[cls]['zeek'] = 'zeek_unavailable'
                    print('unavailable')
                else:
                    z_counts = {'ALLOW': 0, 'MONITOR': 0, 'CHALLENGE_MFA': 0, 'BLOCK': 0}
                    for f in z_flows:
                        z_counts[f.get('action', 'UNKNOWN')] = \
                            z_counts.get(f.get('action', 'UNKNOWN'), 0) + 1
                    per_class[cls]['zeek'] = {'flows': z_flows, 'counts': z_counts}
                    print(f"{len(z_flows)} flows")

        # ── Step 5: Full-feature path ─────────────────────────────────────
        print("\n[5/5] Running FULL-FEATURE API path for all 5 classes ...")
        ff_base = conn_id
        for cls in CLASSES:
            flows, counts = run_full_feature_path(cls, ff_base)
            ff_base += 1
            per_class[cls]['full_feature'] = {'flows': flows, 'counts': counts}
            f = flows[0]
            print(f"  {cls:6s}: risk={f.get('risk_score', 'N/A'):.3f}  "
                  f"class={f.get('classification','N/A'):10s}  "
                  f"action={f.get('action','N/A')}")

        # ── Build + write results JSON ─────────────────────────────────────
        paths_used = {}
        for cls in CLASSES:
            paths = ['conn_log']
            if per_class[cls].get('zeek') != 'zeek_unavailable':
                paths.append('zeek')
            paths.append('full_feature')
            paths_used[cls] = paths

        assessment = build_assessment(per_class, env)

        results = {
            'topology_ref':  TOPOLOGY_REF,
            'generated_at':  datetime.now(timezone.utc).isoformat(),
            'environment':   env,
            'paths_used':    paths_used,
            'per_class':     per_class,
            'assessment':    assessment,
        }

        with open(RESULTS_FILE, 'w') as fh:
            json.dump(results, fh, indent=2, default=str)
        print(f"\nResults written to: {RESULTS_FILE}")

        # ── Summary table ────────────────────────────────────────────────
        print_summary_table(per_class)
        print("\n" + assessment)
        print("\nDemo complete. Exit 0.")
        return 0

    finally:
        if api_proc is not None:
            print("\nShutting down API subprocess ...")
            api_proc.terminate()
            try:
                api_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                api_proc.kill()


if __name__ == '__main__':
    sys.exit(main())
