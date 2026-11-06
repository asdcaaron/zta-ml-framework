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

# Allow running from project root: python src/api.py
sys.path.insert(0, os.path.dirname(__file__))

# Silence TensorFlow logs before importing tf
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL']  = '3'

import tensorflow as tf
tf.get_logger().setLevel('ERROR')
from flask import Flask, request, jsonify, abort
from flask_cors import CORS

from preprocess import preprocess_single_sample, FEATURE_COLS
from model import score_to_risk, CLASS_NAMES

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

model = None
model_load_time = None

def load_model():
    global model, model_load_time
    if not os.path.exists(MODEL_PATH):
        log.warning(f"Model file not found at '{MODEL_PATH}'. "
                    "Run src/train.py first.")
        return
    log.info(f"Loading model from '{MODEL_PATH}'...")
    model = tf.keras.models.load_model(MODEL_PATH)
    model_load_time = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    log.info("Model loaded successfully.")

# Load model in a background thread so Flask starts immediately
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
    """Run model inference and return scored result."""
    if model is None:
        abort(503, description="Model not loaded. Run train.py first.")
    t0 = time.perf_counter()
    probs = model.predict(sample, verbose=0)[0].tolist()
    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    result = score_to_risk(probs)
    result['latency_ms'] = latency_ms
    result['probabilities'] = {CLASS_NAMES[i]: round(p, 4)
                               for i, p in enumerate(probs)}
    return result


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/', methods=['GET'])
def dashboard():
    """Browser-friendly dashboard showing API status and endpoints."""
    model_status = "Loaded" if model is not None else "NOT LOADED"
    color = "#2ecc71" if model is not None else "#e74c3c"
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
            <strong>Model Status:</strong>
            <span class="badge">{model_status}</span>
            &nbsp;&nbsp;
            <strong>Loaded at:</strong> {model_load_time or 'N/A'}
            &nbsp;&nbsp;
            <strong>Input:</strong> (41, 1) NSL-KDD features
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
        'status':       'ok',
        'model_loaded': model is not None,
        'timestamp':    time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    })


@app.route('/model/info', methods=['GET'])
def model_info():
    """Return metadata about the currently loaded model."""
    if model is None:
        return jsonify({'error': 'No model loaded'}), 503
    return jsonify({
        'model_path':      MODEL_PATH,
        'loaded_at':       model_load_time,
        'input_shape':     str(model.input_shape),
        'output_classes':  CLASS_NAMES,
        'risk_threshold':  RISK_THRESHOLD,
    })


@app.route('/predict', methods=['POST'])
def predict():
    """
    Score a single traffic connection.

    Request body (JSON):
    {
        "features": {
            "duration": 0,
            "protocol_type": "tcp",
            "service": "http",
            "flag": "SF",
            "src_bytes": 232,
            "dst_bytes": 8153,
            ... (any of the 41 NSL-KDD features)
        }
    }

    Response:
    {
        "risk_score": 0.12,
        "classification": "Normal",
        "confidence": 0.88,
        "action": "ALLOW",
        "latency_ms": 3.4,
        "probabilities": { "Normal": 0.88, "DoS": 0.05, ... }
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
             f"class={result['classification']}  "
             f"latency={result['latency_ms']}ms")

    return jsonify(result), 200


@app.route('/predict/batch', methods=['POST'])
def predict_batch():
    """
    Score a batch of traffic connections.

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
        'results':   results,
        'total':     len(results),
        'blocked':   action_counts['BLOCK'],
        'challenged': action_counts['CHALLENGE_MFA'],
        'monitored': action_counts['MONITOR'],
        'allowed':   action_counts['ALLOW'],
    }), 200


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
