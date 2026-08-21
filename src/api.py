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
import time
import logging
import numpy as np
import tensorflow as tf
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
MODEL_PATH      = os.getenv('MODEL_PATH',      'data/cnn_gru_model.h5')
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

load_model()

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
