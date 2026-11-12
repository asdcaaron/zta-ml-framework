"""
api.py
------
Flask REST API that serves real-time risk scores to the
Zero Trust policy engine.

Endpoints:
  POST /predict        - score a single traffic feature vector
  POST /predict/batch  - score a batch of feature vectors
  GET  /health         - liveness check
  GET  /model/info     - model metadata

The ZTA policy engine calls POST /predict for every connection
request and uses the returned 'action' field to ALLOW, MONITOR,
CHALLENGE_MFA, or BLOCK the session.

Usage:
    python src/api.py
    # or via gunicorn for production:
    # gunicorn -w 4 -b 0.0.0.0:5000 src.api:app
"""

import os
import sys
import time
import logging
import numpy as np
import json
import pandas as pd
from datetime import datetime

# Allow running from project root: python src/api.py
sys.path.insert(0, os.path.dirname(__file__))

# Silence TensorFlow logs before importing tf
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL']  = '3'

import tensorflow as tf
tf.get_logger().setLevel('ERROR')
from flask import Flask, request, jsonify, abort, send_file
from flask_cors import CORS

from preprocess import preprocess_single_sample, FEATURE_COLS, COLUMNS, ATTACK_MAP
from model import score_to_risk, CLASS_NAMES
from autoencoder import load_autoencoder, predict_anomaly

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
log = logging.getLogger(__name__)

# ── App init ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

# ── Load model at startup ─────────────────────────────────────────────────────
MODEL_PATH      = os.getenv('MODEL_PATH',      'data/cnn_gru_model.keras')
ARTIFACTS_DIR   = os.getenv('ARTIFACTS_DIR',   'data')
RISK_THRESHOLD  = float(os.getenv('RISK_THRESHOLD', '0.5'))
AE_MODEL_PATH   = os.path.join(ARTIFACTS_DIR, 'autoencoder_model.keras')

model = None
model_load_time = None

ae_model = None
ae_threshold = None
ae_model_load_time = None

# ── Demo session state ────────────────────────────────────────────────────────
_session_stats = {
    'total': 0,
    'by_decision': {'ALLOW': 0, 'MONITOR': 0, 'CHALLENGE_MFA': 0, 'BLOCK': 0},
    'by_class':    {'Normal': 0, 'DoS': 0, 'Probe': 0, 'R2L': 0, 'U2R': 0},
}
_audit_log = []   # list of dicts, capped at 200
AUDIT_LOG_PATH = os.path.join('data', 'audit.jsonl')


def _append_audit(entry: dict):
    """Append entry to in-memory audit log and persist to data/audit.jsonl."""
    _audit_log.append(entry)
    if len(_audit_log) > 200:
        _audit_log.pop(0)
    try:
        os.makedirs('data', exist_ok=True)
        with open(AUDIT_LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')
    except Exception as e:
        log.warning(f'audit write failed: {e}')


def load_model():
    global model, model_load_time
    global ae_model, ae_threshold, ae_model_load_time

    # ── Load CNN-GRU ──────────────────────────────────────────────────────
    if not os.path.exists(MODEL_PATH):
        log.warning(f"Model file not found at '{MODEL_PATH}'. "
                    "Run src/train.py first.")
    else:
        log.info(f"Loading CNN-GRU model from '{MODEL_PATH}'...")
        model = tf.keras.models.load_model(MODEL_PATH)
        model_load_time = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        log.info("CNN-GRU model loaded successfully.")

    # ── Load Autoencoder ──────────────────────────────────────────────────
    try:
        log.info(f"Loading autoencoder from '{AE_MODEL_PATH}'...")
        autoencoder, encoder, threshold = load_autoencoder(ARTIFACTS_DIR)
        ae_model = autoencoder
        ae_threshold = float(threshold)
        ae_model_load_time = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        log.info(f"Autoencoder loaded. Threshold: {ae_threshold:.6f}")
    except FileNotFoundError as e:
        log.warning(f"Autoencoder not found: {e}. "
                    "Run src/train_autoencoder.py first.")


# Load models in a background thread so Flask starts immediately
import threading
threading.Thread(target=load_model, daemon=True).start()

# ── Helper ────────────────────────────────────────────────────────────────────

def _validate_features(data: dict) -> dict:
    """Return cleaned feature dict; raise 400 if required keys missing."""
    if 'features' not in data:
        abort(400, description="Request body must contain a 'features' key.")
    features = data['features']
    if not isinstance(features, dict):
        abort(400, description="'features' must be a JSON object (dict).")
    # Fill missing features with 0
    cleaned = {col: features.get(col, 0) for col in FEATURE_COLS}
    return cleaned


def _run_inference(sample: np.ndarray) -> dict:
    """
    Run dual-model inference (CNN-GRU + Autoencoder) and return scored result.

    # NOTE: This API returns policy decision labels. Actual network enforcement
    # (firewall rules, session termination, MFA triggers) requires integration
    # with an enforcement plane (e.g., firewall API, ZTNA controller). This
    # prototype demonstrates the decision layer only.
    """
    if model is None:
        abort(503, description="CNN-GRU model not loaded. Run train.py first.")
    if ae_model is None:
        abort(503, description="Autoencoder not loaded. Run train_autoencoder.py first.")

    t0 = time.perf_counter()

    # ── CNN-GRU inference ─────────────────────────────────────────────────
    probs = model.predict(sample, verbose=0)[0]          # shape (5,)
    cnn_risk = float(1.0 - probs[0])                     # 1 - P(Normal)

    # ── Autoencoder inference ─────────────────────────────────────────────
    # Flatten sample from (1, 40, 1) to (1, 40) for the autoencoder
    flat_sample = sample.reshape(1, -1)                  # (1, 40)
    errors, is_anomaly, risk_scores = predict_anomaly(
        ae_model, flat_sample, ae_threshold
    )
    ae_reconstruction_error = float(errors[0])
    ae_is_anomaly = bool(is_anomaly[0])
    ae_risk = float(risk_scores[0])

    # ── Fuse: take the more conservative (higher) risk score ─────────────
    combined_risk = float(max(cnn_risk, ae_risk))

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    # score_to_risk uses the CNN-GRU probs to derive action/classification
    result = score_to_risk(probs.tolist())

    return {
        # Backward-compatible field (combined risk for policy decisions)
        'risk_score':             combined_risk,
        'classification':         result['classification'],
        'confidence':             result['confidence'],
        'action':                 result['action'],
        'latency_ms':             latency_ms,
        'probabilities':          {CLASS_NAMES[i]: round(float(p), 4)
                                   for i, p in enumerate(probs)},
        # Dual-model detail fields
        'cnn_risk':               round(cnn_risk, 6),
        'ae_risk':                round(ae_risk, 6),
        'combined_risk':          round(combined_risk, 6),
        'ae_reconstruction_error': round(ae_reconstruction_error, 8),
        'ae_is_anomaly':          ae_is_anomaly,
        # ZTA alias for action — explicit field for policy engine consumers
        'zta_decision':           result['action'],
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/', methods=['GET'])
def dashboard():
    """Browser-friendly dashboard showing API status and endpoints."""
    model_status = "Loaded" if model is not None else "NOT LOADED"
    ae_status    = "Loaded" if ae_model is not None else "NOT LOADED"
    color     = "#2ecc71" if model is not None else "#e74c3c"
    ae_color  = "#2ecc71" if ae_model is not None else "#e74c3c"
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ZTA + ML Risk Scoring API</title>
        <style>
            body {{ font-family: Arial, sans-serif; max-width: 860px;
                   margin: 40px auto; padding: 0 20px; background: #f5f5f5; }}
            h1   {{ color: #2c3e50; }}
            h2   {{ color: #34495e; border-bottom: 2px solid #3498db;
                   padding-bottom: 6px; }}
            .badge {{ display: inline-block; padding: 4px 12px;
                     border-radius: 12px; color: white;
                     background: {color}; font-weight: bold; }}
            .ae-badge {{ display: inline-block; padding: 4px 12px;
                        border-radius: 12px; color: white;
                        background: {ae_color}; font-weight: bold; }}
            table {{ border-collapse: collapse; width: 100%;
                    background: white; border-radius: 8px;
                    box-shadow: 0 2px 6px rgba(0,0,0,0.1); }}
            th    {{ background: #3498db; color: white;
                    padding: 10px 14px; text-align: left; }}
            td    {{ padding: 9px 14px; border-bottom: 1px solid #eee; }}
            tr:last-child td {{ border-bottom: none; }}
            code  {{ background: #ecf0f1; padding: 2px 6px;
                    border-radius: 4px; font-size: 0.9em; }}
            .box  {{ background: white; border-radius: 8px; padding: 16px 20px;
                    margin-bottom: 20px;
                    box-shadow: 0 2px 6px rgba(0,0,0,0.1); }}
        </style>
    </head>
    <body>
        <h1>ZTA + ML Risk Scoring API</h1>
        <p><strong>Author:</strong> Okado Aaron Obbo &mdash; S24B23/015<br>
           <strong>Uganda Christian University</strong> &mdash;
           Systems, Infrastructure &amp; Cybersecurity</p>

        <div class="box">
            <strong>CNN-GRU Status:</strong>
            <span class="badge">{model_status}</span>
            &nbsp;&nbsp;
            <strong>Loaded at:</strong> {model_load_time or 'N/A'}
            <br><br>
            <strong>Autoencoder Status:</strong>
            <span class="ae-badge">{ae_status}</span>
            &nbsp;&nbsp;
            <strong>Loaded at:</strong> {ae_model_load_time or 'N/A'}
            <br><br>
            <strong>Input:</strong> (40, 1) NSL-KDD features
            &nbsp;&nbsp;
            <strong>Classes:</strong> Normal, DoS, Probe, R2L, U2R
        </div>

        <h2>Available Endpoints</h2>
        <table>
            <tr><th>Method</th><th>Endpoint</th><th>Description</th></tr>
            <tr><td>GET</td>
                <td><a href="/health"><code>/health</code></a></td>
                <td>API liveness check</td></tr>
            <tr><td>GET</td>
                <td><a href="/model/info"><code>/model/info</code></a></td>
                <td>Model metadata and risk thresholds</td></tr>
            <tr><td>POST</td>
                <td><code>/predict</code></td>
                <td>Score a single traffic connection (JSON body)</td></tr>
            <tr><td>POST</td>
                <td><code>/predict/batch</code></td>
                <td>Score multiple connections in one request</td></tr>
        </table>

        <h2>Quick Test — POST /predict</h2>
        <div class="box">
            <p>Paste this into PowerShell to score a connection:</p>
            <pre><code>$body = '{{\"features\": {{\"duration\": 0, \"protocol_type\": \"tcp\",
  \"service\": \"http\", \"flag\": \"SF\",
  \"src_bytes\": 232, \"dst_bytes\": 8153}}}}'
Invoke-RestMethod -Uri http://127.0.0.1:5000/predict `
  -Method POST -Body $body -ContentType \"application/json\"</code></pre>
        </div>

        <h2>Risk Score Actions</h2>
        <table>
            <tr><th>Risk Score</th><th>Action</th><th>Meaning</th></tr>
            <tr><td>&gt; 0.8</td>
                <td style="color:#e74c3c"><strong>BLOCK</strong></td>
                <td>High confidence attack — session terminated</td></tr>
            <tr><td>0.5 – 0.8</td>
                <td style="color:#e67e22"><strong>CHALLENGE_MFA</strong></td>
                <td>Suspicious — re-authentication required</td></tr>
            <tr><td>0.3 – 0.5</td>
                <td style="color:#f1c40f"><strong>MONITOR</strong></td>
                <td>Anomalous — flagged and watched</td></tr>
            <tr><td>&lt; 0.3</td>
                <td style="color:#2ecc71"><strong>ALLOW</strong></td>
                <td>Normal traffic — permitted</td></tr>
        </table>
    </body>
    </html>
    """, 200


@app.route('/health', methods=['GET'])
def health():
    """Liveness check for load balancers / k8s probes."""
    return jsonify({
        'status':          'ok',
        'model_loaded':    model is not None,
        'ae_model_loaded': ae_model is not None,
        'timestamp':       time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    })


@app.route('/model/info', methods=['GET'])
def model_info():
    """Return metadata about the currently loaded model."""
    if model is None:
        return jsonify({'error': 'No CNN-GRU model loaded'}), 503
    return jsonify({
        'model_path':        MODEL_PATH,
        'loaded_at':         model_load_time,
        'input_shape':       str(model.input_shape),
        'output_classes':    CLASS_NAMES,
        'risk_threshold':    RISK_THRESHOLD,
        'ae_model_path':     AE_MODEL_PATH,
        'ae_loaded_at':      ae_model_load_time,
        'ae_threshold':      ae_threshold,
    })


@app.route('/predict', methods=['POST'])
def predict():
    """
    Score a single traffic connection using the dual-model pipeline.

    # NOTE: This API returns policy decision labels. Actual network enforcement
    # (firewall rules, session termination, MFA triggers) requires integration
    # with an enforcement plane (e.g., firewall API, ZTNA controller). This
    # prototype demonstrates the decision layer only.

    Request body (JSON):
    {
        "features": {
            "duration": 0,
            "protocol_type": "tcp",
            "service": "http",
            "flag": "SF",
            "src_bytes": 232,
            "dst_bytes": 8153,
            ... (any of the 40 NSL-KDD features)
        }
    }

    Response:
    {
        "risk_score": 0.12,          // combined risk (max of cnn_risk, ae_risk)
        "classification": "Normal",
        "confidence": 0.88,
        "action": "ALLOW",
        "latency_ms": 3.4,
        "probabilities": { "Normal": 0.88, "DoS": 0.05, ... },
        "cnn_risk": 0.12,
        "ae_risk": 0.05,
        "combined_risk": 0.12,
        "ae_reconstruction_error": 0.00123456,
        "ae_is_anomaly": false,
        "zta_decision": "ALLOW"
    }
    """
    data = request.get_json(force=True, silent=True)
    if not data:
        abort(400, description="Invalid or missing JSON body.")

    features = _validate_features(data)
    sample   = preprocess_single_sample(features, ARTIFACTS_DIR)
    result   = _run_inference(sample)

    log.info(f"[/predict] action={result['action']}  "
             f"risk={result['risk_score']}  "
             f"cnn_risk={result['cnn_risk']}  "
             f"ae_risk={result['ae_risk']}  "
             f"class={result['classification']}  "
             f"latency={result['latency_ms']}ms")

    return jsonify(result), 200


@app.route('/predict/batch', methods=['POST'])
def predict_batch():
    """
    Score a batch of traffic connections using the dual-model pipeline.

    Request body (JSON):
    {
        "samples": [
            { "features": { ... } },
            { "features": { ... } }
        ]
    }

    Response:
    {
        "results": [ { ...scored result... }, ... ],
        "total": 2,
        "blocked": 0,
        "challenged": 0,
        "monitored": 1,
        "allowed": 1
    }
    """
    data = request.get_json(force=True, silent=True)
    if not data or 'samples' not in data:
        abort(400, description="Request body must contain a 'samples' list.")

    samples_data = data['samples']
    if not isinstance(samples_data, list) or len(samples_data) == 0:
        abort(400, description="'samples' must be a non-empty list.")

    results   = []
    action_counts = {'BLOCK': 0, 'CHALLENGE_MFA': 0,
                     'MONITOR': 0, 'ALLOW': 0}

    for item in samples_data:
        features = _validate_features(item)
        sample   = preprocess_single_sample(features, ARTIFACTS_DIR)
        result   = _run_inference(sample)
        results.append(result)
        action_counts[result['action']] = \
            action_counts.get(result['action'], 0) + 1

    return jsonify({
        'results':    results,
        'total':      len(results),
        'blocked':    action_counts['BLOCK'],
        'challenged': action_counts['CHALLENGE_MFA'],
        'monitored':  action_counts['MONITOR'],
        'allowed':    action_counts['ALLOW'],
    }), 200


# ── Demo scenario endpoints ───────────────────────────────────────────────────

SCENARIO_META = {
    'normal': {
        'source_ip':  '10.20.0.50',
        'dest_ip':    '10.10.0.10',
        'segment':    'Branch Office → HQ Server',
        'label':      0,
        'label_name': 'Normal',
    },
    'dos': {
        'source_ip':  '203.0.113.10',
        'dest_ip':    '10.10.0.0/24',
        'segment':    'Internet Attacker → HQ Network',
        'label':      1,
        'label_name': 'DoS',
    },
    'probe': {
        'source_ip':  '10.20.0.50',
        'dest_ip':    '172.16.0.0/24',
        'segment':    'Branch-Compromised-Host → DMZ',
        'label':      2,
        'label_name': 'Probe',
    },
    'r2l': {
        'source_ip':  '0.0.0.0',
        'dest_ip':    '10.10.0.1',
        'segment':    'Remote User → ZTA Gateway',
        'label':      3,
        'label_name': 'R2L',
    },
    'u2r': {
        'source_ip':  '10.10.0.99',
        'dest_ip':    '10.10.0.1',
        'segment':    'Internal Host → ZTA Gateway',
        'label':      4,
        'label_name': 'U2R',
    },
}

# Pre-load the test CSV once to avoid re-reading per request
_test_df_cache = None

def _get_test_df():
    global _test_df_cache
    if _test_df_cache is None:
        test_path = os.path.join('data', 'NSL_KDD_Test.csv')
        df = pd.read_csv(test_path, names=COLUMNS)
        df['label'] = df['label'].str.strip().str.lower().map(
            lambda x: ATTACK_MAP.get(x, 0)
        )
        _test_df_cache = df
    return _test_df_cache


@app.route('/demo/scenario/<scenario_name>', methods=['GET'])
def demo_scenario(scenario_name):
    """Run a pre-defined demo scenario sampled from NSL-KDD test data."""
    if scenario_name not in SCENARIO_META:
        return jsonify({'error': f"Unknown scenario '{scenario_name}'. "
                        "Valid: normal, dos, probe, r2l, u2r"}), 400
    if model is None or ae_model is None:
        return jsonify({'error': 'Models not loaded yet. '
                        'Wait for startup or run train.py first.'}), 503

    meta = SCENARIO_META[scenario_name]
    df = _get_test_df()

    # Filter rows matching the target label
    subset = df[df['label'] == meta['label']]
    if subset.empty:
        # Fallback: use any row and override label_name
        subset = df.sample(1)
    else:
        subset = subset.sample(1)

    row = subset.iloc[0]

    # Build feature dict from FEATURE_COLS (excludes label, difficulty, DROP_COLS)
    feature_dict = {col: row[col] for col in FEATURE_COLS}

    # Raw feature values for display (40 values — keep strings for categoricals)
    from preprocess import CATEGORICAL_COLS as _CAT_COLS
    feature_vector = []
    for col in FEATURE_COLS:
        if col not in row.index:
            feature_vector.append(0.0)
        elif col in _CAT_COLS:
            feature_vector.append(str(row[col]))
        else:
            try:
                feature_vector.append(float(row[col]))
            except (ValueError, TypeError):
                feature_vector.append(str(row[col]))

    sample = preprocess_single_sample(feature_dict, ARTIFACTS_DIR)
    result = _run_inference(sample)

    # Update session stats
    decision = result['zta_decision']
    traffic_class = meta['label_name']
    _session_stats['total'] += 1
    if decision in _session_stats['by_decision']:
        _session_stats['by_decision'][decision] += 1
    if traffic_class in _session_stats['by_class']:
        _session_stats['by_class'][traffic_class] += 1

    # Build audit entry
    audit_entry = {
        'timestamp':    datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'scenario':     scenario_name,
        'source_ip':    meta['source_ip'],
        'dest_ip':      meta['dest_ip'],
        'segment':      meta['segment'],
        'traffic_class_label': traffic_class,
        'cnn_risk':     result['cnn_risk'],
        'ae_risk':      result['ae_risk'],
        'combined_risk': result['combined_risk'],
        'zta_decision': decision,
        'classification': result['classification'],
        'confidence':   result['confidence'],
    }
    _append_audit(audit_entry)

    log.info(f"[/demo/scenario/{scenario_name}] decision={decision} "
             f"risk={result['combined_risk']} class={traffic_class}")

    return jsonify({
        **result,
        'scenario':            scenario_name,
        'source_ip':           meta['source_ip'],
        'dest_ip':             meta['dest_ip'],
        'segment':             meta['segment'],
        'traffic_class_label': traffic_class,
        'feature_vector':      feature_vector,
    }), 200


@app.route('/demo/stats', methods=['GET'])
def demo_stats():
    """Return current session statistics."""
    return jsonify(_session_stats), 200


@app.route('/demo/log', methods=['GET'])
def demo_log():
    """Return last 50 audit log entries."""
    return jsonify(_audit_log[-50:]), 200


@app.route('/dashboard')
def serve_dashboard():
    """Serve the live demo dashboard HTML file."""
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'demo_dashboard.html')
    return send_file(path)


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(400)
def bad_request(e):
    return jsonify({'error': 'Bad Request', 'message': str(e.description)}), 400

@app.errorhandler(503)
def service_unavailable(e):
    return jsonify({'error': 'Service Unavailable',
                    'message': str(e.description)}), 503


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    log.info(f"Starting ZTA Risk Scoring API on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=False)
