"""
final_demo.py
-------------
Week 6 standalone live demo — loads both trained models and scores one sample
from each NSL-KDD class (Normal, DoS, Probe, R2L, U2R) directly without
starting the Flask API or making any HTTP calls.

Usage (run from project root):
    python src/final_demo.py

Outputs:
    Console: formatted per-sample predictions + summary table
    data/results/final_demo_output.json: full structured results

Author : Okado Aaron Obbo  S24B23/015
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import tensorflow as tf
tf.get_logger().setLevel('ERROR')

import numpy as np
import json
import joblib
from datetime import datetime, timezone
from preprocess import load_and_preprocess, FEATURE_COLS

# ── Constants ─────────────────────────────────────────────────────────────────
CLASS_NAMES = {0: 'Normal', 1: 'DoS', 2: 'Probe', 3: 'R2L', 4: 'U2R'}

DATA_DIR     = os.path.join(os.path.dirname(__file__), '..', 'data')
RESULTS_DIR  = os.path.join(DATA_DIR, 'results')
CNN_GRU_PATH = os.path.join(DATA_DIR, 'cnn_gru_model.keras')
AE_PATH      = os.path.join(DATA_DIR, 'autoencoder_model.keras')
THRESH_PATH  = os.path.join(DATA_DIR, 'ae_threshold.pkl')
SCALER_PATH  = os.path.join(DATA_DIR, 'scaler.pkl')
ENCODERS_PATH = os.path.join(DATA_DIR, 'encoders.pkl')
TRAIN_CSV    = os.path.join(DATA_DIR, 'NSL_KDD_Train.csv')
TEST_CSV     = os.path.join(DATA_DIR, 'NSL_KDD_Test.csv')
OUTPUT_JSON  = os.path.join(RESULTS_DIR, 'final_demo_output.json')


def zta_decision(risk_score: float) -> str:
    """Map combined risk score to ZTA policy decision."""
    if risk_score > 0.8:
        return 'BLOCK'
    elif risk_score > 0.5:
        return 'CHALLENGE_MFA'
    elif risk_score > 0.3:
        return 'MONITOR'
    else:
        return 'ALLOW'


def print_banner():
    print()
    print('=' * 64)
    print('  ZTA + ML Framework — Live Demo')
    print('  Risk-Adaptive Zero Trust with Dual-Layer ML')
    print('  Author: Okado Aaron Obbo  |  S24B23/015  |  UCU')
    print('=' * 64)
    print()


def load_models():
    """Load CNN-GRU, autoencoder, threshold, scaler, encoders."""
    print('[1/5] Loading models and artifacts...')

    print(f'  Loading CNN-GRU from {CNN_GRU_PATH}')
    cnn_gru = tf.keras.models.load_model(CNN_GRU_PATH)
    print(f'  CNN-GRU ready  — output shape: {cnn_gru.output_shape}')

    print(f'  Loading Autoencoder from {AE_PATH}')
    autoencoder = tf.keras.models.load_model(AE_PATH)
    print(f'  Autoencoder ready — output shape: {autoencoder.output_shape}')

    threshold = joblib.load(THRESH_PATH)
    print(f'  AE threshold loaded: {threshold:.6f}')

    scaler = joblib.load(SCALER_PATH)
    print(f'  Scaler loaded: {len(scaler.scale_)} features')

    encoders = joblib.load(ENCODERS_PATH)
    print(f'  Encoders loaded: {list(encoders.keys())}')

    print('  All artifacts ready.')
    print()
    return cnn_gru, autoencoder, float(threshold), scaler, encoders


def load_test_data():
    """Load NSL-KDD test set and return X_test (N,40,1), y_test."""
    print('[2/5] Loading NSL-KDD test set...')
    # save_artifacts=False so we don't overwrite the saved scaler with a
    # re-fitted one; instead we use the already-saved artifacts
    X_train, X_test, y_train, y_test = load_and_preprocess(
        TRAIN_CSV, TEST_CSV, save_artifacts=False
    )
    print(f'  Test set shape: {X_test.shape}, labels: {y_test.shape}')
    print()
    return X_test, y_test


def pick_class_samples(X_test: np.ndarray, y_test: np.ndarray) -> dict:
    """Pick the first sample index for each of the 5 classes."""
    print('[3/5] Selecting one sample per class...')
    samples = {}
    for class_id, class_name in CLASS_NAMES.items():
        indices = np.where(y_test == class_id)[0]
        if len(indices) == 0:
            raise ValueError(f'No samples found for class {class_id} ({class_name})')
        idx = int(indices[0])
        samples[class_id] = {
            'class_id': class_id,
            'class_name': class_name,
            'test_index': idx,
            'sample': X_test[idx]   # shape (40, 1)
        }
        print(f'  Class {class_id} ({class_name:6s}): test index {idx}')
    print()
    return samples


def run_predictions(samples: dict, cnn_gru, autoencoder, threshold: float) -> list:
    """Run both models on each sample and compute risk scores."""
    print('[4/5] Running predictions...')
    print()

    results = []

    for class_id in sorted(samples.keys()):
        info        = samples[class_id]
        class_name  = info['class_name']
        sample_3d   = info['sample']          # shape (40, 1)
        sample_flat = sample_3d.flatten()     # shape (40,)

        # ── CNN-GRU prediction ────────────────────────────────────────────
        cnn_input = sample_3d.reshape(1, 40, 1)              # (1, 40, 1)
        cnn_probs = cnn_gru.predict(cnn_input, verbose=0)    # (1, 5)
        cnn_probs = cnn_probs[0]                              # (5,)
        cnn_class_id   = int(np.argmax(cnn_probs))
        cnn_class_name = CLASS_NAMES[cnn_class_id]
        cnn_confidence = float(cnn_probs[cnn_class_id])
        cnn_risk_score = float(1.0 - cnn_probs[0])           # 1 - P(Normal)

        # ── Autoencoder prediction ────────────────────────────────────────
        ae_input       = sample_flat.reshape(1, 40)            # (1, 40)
        ae_recon       = autoencoder.predict(ae_input, verbose=0)  # (1, 40)
        recon_error    = float(np.mean((sample_flat - ae_recon[0]) ** 2))
        ae_anomaly     = recon_error > threshold
        ae_risk_score  = float(min(recon_error / (3.0 * threshold), 1.0))

        # ── Combined risk score ───────────────────────────────────────────
        combined_risk = float(max(cnn_risk_score, ae_risk_score))

        # ── ZTA policy decision ───────────────────────────────────────────
        decision = zta_decision(combined_risk)

        # ── Console output ────────────────────────────────────────────────
        print(f'  ┌─ Sample: {class_name} (true class={class_id}) ─────────────────')
        print(f'  │  CNN-GRU  → class: {cnn_class_name:<8s}  '
              f'confidence: {cnn_confidence:.4f}  '
              f'risk(1-P_normal): {cnn_risk_score:.4f}')
        print(f'  │  AE error → {recon_error:.6f}  '
              f'threshold: {threshold:.6f}  '
              f'anomaly: {"YES" if ae_anomaly else "NO "}  '
              f'ae_risk: {ae_risk_score:.4f}')
        print(f'  │  Combined risk score : {combined_risk:.4f}')
        print(f'  │  ZTA decision        : {decision}')
        print(f'  └──────────────────────────────────────────────────────────')
        print()

        results.append({
            'class_id':         class_id,
            'class_name':       class_name,
            'test_index':       info['test_index'],
            'cnn_gru': {
                'predicted_class_id':   cnn_class_id,
                'predicted_class_name': cnn_class_name,
                'confidence':           round(cnn_confidence, 6),
                'risk_score':           round(cnn_risk_score, 6),
                'probabilities':        [round(float(p), 6) for p in cnn_probs],
            },
            'autoencoder': {
                'reconstruction_error': round(recon_error, 8),
                'threshold':            round(threshold, 8),
                'is_anomaly':           bool(ae_anomaly),
                'ae_risk_score':        round(ae_risk_score, 6),
            },
            'combined_risk_score': round(combined_risk, 6),
            'zta_decision':        decision,
        })

    return results


def print_summary_table(results: list):
    """Print a formatted 5-row summary table."""
    print('[5/5] Summary table')
    print()
    print(f'  {"Class":<8} {"CNN-GRU Pred":<14} {"AE Error":<12} '
          f'{"AE Anomaly":<12} {"Risk Score":<12} {"ZTA Decision"}')
    print(f'  {"-"*8} {"-"*14} {"-"*12} {"-"*12} {"-"*12} {"-"*16}')

    summary_rows = []
    for r in results:
        row = {
            'class':       r['class_name'],
            'cnn_pred':    r['cnn_gru']['predicted_class_name'],
            'ae_error':    r['autoencoder']['reconstruction_error'],
            'ae_anomaly':  'YES' if r['autoencoder']['is_anomaly'] else 'NO',
            'risk_score':  r['combined_risk_score'],
            'zta_decision': r['zta_decision'],
        }
        summary_rows.append(row)
        print(f'  {row["class"]:<8} {row["cnn_pred"]:<14} '
              f'{row["ae_error"]:<12.6f} {row["ae_anomaly"]:<12} '
              f'{row["risk_score"]:<12.4f} {row["zta_decision"]}')

    print()
    return summary_rows


def save_json(results: list, summary_rows: list):
    """Save full results to data/results/final_demo_output.json."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    payload = {
        'timestamp':     datetime.now(timezone.utc).isoformat(),
        'models': {
            'cnn_gru':     CNN_GRU_PATH,
            'autoencoder': AE_PATH,
            'threshold':   results[0]['autoencoder']['threshold'],
        },
        'samples':       results,
        'summary_table': summary_rows,
    }
    with open(OUTPUT_JSON, 'w') as fh:
        json.dump(payload, fh, indent=2)
    print(f'Results saved to: {OUTPUT_JSON}')
    print()


def main():
    print_banner()

    cnn_gru, autoencoder, threshold, scaler, encoders = load_models()
    X_test, y_test = load_test_data()
    samples        = pick_class_samples(X_test, y_test)
    results        = run_predictions(samples, cnn_gru, autoencoder, threshold)
    summary_rows   = print_summary_table(results)
    save_json(results, summary_rows)

    print('=' * 64)
    print('  Demo complete — all 5 classes scored.')
    print('=' * 64)
    print()


if __name__ == '__main__':
    main()
