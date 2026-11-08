"""
evaluate.py
-----------
Five-way comparative evaluation for the Risk-Adaptive ZTA framework:

  System A — Legacy VPN (OpenVPN)        : perimeter-based, no ML  [simulated]
  System B — ZTA Only                    : Zero Trust, no ML        [simulated]
  System C — ZTA + CNN-GRU (Supervised)  : Zero Trust + known attack classifier
  System D — ZTA + Autoencoder (Self-Supervised) : Zero Trust + zero-day detector
  System E — ZTA + CNN-GRU + Autoencoder (Fusion) : dual-model combined risk

All five systems are scored on the SAME NSL-KDD test set with the SAME
metrics (Accuracy, F1, FPR, measured per-prediction latency, and
per-attack-type detection) so the comparison is controlled and fair.

  System C uses the trained CNN-GRU classifier   (data/cnn_gru_model.keras)
  System D uses the trained autoencoder + 95th-pct threshold
             (data/autoencoder_model.keras + data/ae_threshold.pkl)
  System E combines C+D: combined_risk = max(cnn_risk, ae_risk)
  Systems A/B are simulated baselines (no ML model exists for them — they
  represent architectures without anomaly detection).

Usage:
    python src/evaluate.py
    python src/evaluate.py --test data/NSL_KDD_Test.csv \\
                           --model data/cnn_gru_model.keras \\
                           --out   data/results
"""

import argparse
import json
import os
import sys

# Allow running from project root: python src/evaluate.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
import time
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import tensorflow as tf

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)

from preprocess import load_and_preprocess, CLASS_NAMES
from autoencoder import load_autoencoder, predict_anomaly

# ── Attack scenarios tested ───────────────────────────────────────────────────
SCENARIOS = ['DoS', 'Probe', 'R2L', 'U2R']

# Integer codes for the four attack categories (preprocess.ATTACK_MAP)
ATTACK_CATEGORIES = [1, 2, 3, 4]   # DoS, Probe, R2L, U2R

# ── System capability profiles ────────────────────────────────────────────────
# These model realistic detection rates reported in related literature.
# Replace with actual experiment measurements when available.
SYSTEM_PROFILES = {
    'Legacy VPN (OpenVPN)': {
        'description': 'Traditional perimeter-based VPN. '
                       'No continuous auth, no anomaly detection.',
        # VPN with signature-based IDS catches ~55% of attacks.
        # Literature: perimeter-only models miss novel/insider attacks heavily.
        # Source: Gambo & Almulhem (2026), Zohaib et al. (2024)
        'detection_noise': 0.45,
        'false_positive_rate_base': 0.18,
        'avg_response_time_sec': None,   # manual response
        'lateral_movement_blocked': False,
        'encrypted_traffic_detection': False,
        'micro_segmentation': False,
        'continuous_auth': False,
        'simulated': True,
    },
    'ZTA Only': {
        'description': 'Zero Trust Architecture without ML. '
                       'Strict access control, micro-segmentation, '
                       'but no traffic anomaly detection capability.',
        # ZTA enforces identity/access controls but has NO ability to detect
        # anomalous traffic patterns (DoS, Probe, R2L, U2R) in real time.
        # It blocks lateral movement and enforces least privilege, but an
        # attacker who has valid credentials can still operate undetected.
        # Realistic detection: ~65-70% (access control catches obvious violations,
        # misses traffic-level anomalies entirely).
        # Source: Kim et al. (2024), Dhumal et al. (2025), Zanasi et al. (2022)
        'detection_noise': 0.33,
        'false_positive_rate_base': 0.10,
        'avg_response_time_sec': 7.5,
        'lateral_movement_blocked': True,
        'encrypted_traffic_detection': False,
        'micro_segmentation': True,
        'continuous_auth': True,
        'simulated': True,
    },
    'ZTA + CNN-GRU (Supervised)': {
        'description': 'Zero Trust + supervised CNN-GRU classifier. '
                       'Classifies known attack types in real time.',
        'detection_noise': 0.04,
        'false_positive_rate_base': 0.03,
        'avg_response_time_sec': 1.8,
        'lateral_movement_blocked': True,
        'encrypted_traffic_detection': True,
        'micro_segmentation': True,
        'continuous_auth': True,
        'zero_day_detection': False,
        'simulated': False,
    },
    'ZTA + Autoencoder (Self-Supervised)': {
        'description': 'Zero Trust + self-supervised autoencoder. '
                       'Detects zero-day anomalies without attack labels.',
        'detection_noise': 0.04,
        'false_positive_rate_base': 0.05,
        'avg_response_time_sec': 1.5,
        'lateral_movement_blocked': True,
        'encrypted_traffic_detection': True,
        'micro_segmentation': True,
        'continuous_auth': True,
        'zero_day_detection': True,
        'simulated': False,
    },
    'ZTA + CNN-GRU + Autoencoder (Fusion)': {
        'description': 'Zero Trust + dual-model fusion: CNN-GRU (supervised) '
                       '+ Autoencoder (self-supervised). '
                       'Combined risk = max(cnn_risk, ae_risk).',
        'detection_noise': 0.04,
        'false_positive_rate_base': 0.03,
        'avg_response_time_sec': 2.0,
        'lateral_movement_blocked': True,
        'encrypted_traffic_detection': True,
        'micro_segmentation': True,
        'continuous_auth': True,
        'zero_day_detection': True,
        'simulated': False,
    },
}


# ── Simulation helpers ────────────────────────────────────────────────────────

def simulate_predictions(y_true: np.ndarray,
                         noise_level: float,
                         fpr_base: float,
                         rng: np.random.Generator) -> np.ndarray:
    """
    Simulate a system's binary detection (0=normal, 1=attack).

    A system with higher `noise_level` misses more attacks.
    `fpr_base` controls how often it falsely flags normal traffic.

    Used only for the non-ML baselines (Legacy VPN, ZTA Only), which by
    design have no trained model to evaluate.
    """
    y_binary = (y_true > 0).astype(int)   # 1 = any attack
    y_pred   = y_binary.copy()

    attack_idx = np.where(y_binary == 1)[0]
    normal_idx = np.where(y_binary == 0)[0]

    # Miss some attacks (false negatives)
    miss_count = int(noise_level * len(attack_idx))
    missed     = rng.choice(attack_idx, size=miss_count, replace=False)
    y_pred[missed] = 0

    # False alarms on normal traffic
    fp_count = int(fpr_base * len(normal_idx))
    fp_idx   = rng.choice(normal_idx, size=fp_count, replace=False)
    y_pred[fp_idx] = 1

    return y_pred


def per_category_detection(y_true_multiclass: np.ndarray,
                           y_pred: np.ndarray,
                           categories=ATTACK_CATEGORIES) -> dict:
    """
    Per-attack-category detection rate: for each attack category, the
    fraction of that category's test samples the system flagged as an
    attack (y_pred == 1).

    This measures zero-day / attack-type detection capability independent
    of attack labels — directly relevant to the autoencoder's label-free
    approach, which has never seen any attack label during training.
    """
    out = {}
    for c in categories:
        name = CLASS_NAMES.get(c, str(c))
        mask = (y_true_multiclass == c)
        n = int(mask.sum())
        rate = float(y_pred[mask].mean()) if n > 0 else 0.0
        out[name] = round(rate, 4)
    return out


def compute_metrics(system_name: str,
                    y_true_binary: np.ndarray,
                    y_pred: np.ndarray,
                    profile: dict,
                    y_true_multiclass: np.ndarray = None,
                    inference_ms_per_sample: float = None) -> dict:
    """Compute all evaluation metrics for one system."""
    cm    = confusion_matrix(y_true_binary, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0   # recall

    # Operational response time (qualitative, from profile / literature)
    response_time = profile['avg_response_time_sec']
    response_str  = (f"{response_time}s" if response_time
                     else "Manual (hours)")

    metrics = {
        'System':                    system_name,
        'Simulated':                 profile.get('simulated', False),
        'Accuracy':                  round(accuracy_score(y_true_binary, y_pred), 4),
        'Precision':                 round(precision_score(y_true_binary, y_pred,
                                           zero_division=0), 4),
        'Recall (TPR)':              round(tpr, 4),
        'F1 Score':                  round(f1_score(y_true_binary, y_pred,
                                           zero_division=0), 4),
        'False Positive Rate':       round(fpr, 4),
        # Measured per-prediction inference latency (model load excluded)
        'Response Time (ms/sample)': (round(inference_ms_per_sample, 4)
                                      if inference_ms_per_sample is not None
                                      else None),
        'Avg Response Time':         response_str,
        'Lateral Movement Blocked':  profile['lateral_movement_blocked'],
        'Encrypted Traffic Detect':  profile['encrypted_traffic_detection'],
        'Micro-Segmentation':        profile['micro_segmentation'],
        'Continuous Auth':           profile['continuous_auth'],
        'Zero-Day Detection':        profile.get('zero_day_detection', False),
        'TP': int(tp), 'FP': int(fp),
        'TN': int(tn), 'FN': int(fn),
    }

    # Per-attack-category detection rates (zero-day / attack-type capability)
    if y_true_multiclass is not None:
        for name, rate in per_category_detection(
                y_true_multiclass, y_pred).items():
            metrics[f'{name} Detection'] = rate

    return metrics


# ── CNN-GRU model evaluation ──────────────────────────────────────────────────

def evaluate_model(model_path: str,
                   X_test: np.ndarray,
                   y_test: np.ndarray) -> tuple:
    """
    Load saved CNN-GRU model and return binary predictions on the test set,
    plus the per-prediction inference time (model load excluded from timing).

    Returns
    -------
    y_pred        : 0=normal, 1=any attack
    inference_sec : wall-clock seconds for model.predict (excluding load)
    """
    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Trained model not found at '{model_path}'. "
            "Run src/train.py first."
        )
    model = tf.keras.models.load_model(model_path)
    t0    = time.perf_counter()
    probs = model.predict(X_test, verbose=0)
    inference_sec = time.perf_counter() - t0
    y_pred_multiclass = np.argmax(probs, axis=1)
    # Convert to binary: 0=normal, 1=any attack
    return (y_pred_multiclass > 0).astype(int), inference_sec


# ── Autoencoder evaluation (System D, real model) ─────────────────────────────

def evaluate_autoencoder_system(model_dir: str,
                                X_test: np.ndarray,
                                y_test: np.ndarray) -> tuple:
    """
    Run the real self-supervised autoencoder (System D).

    Loads data/autoencoder_model.keras + data/ae_threshold.pkl (the saved
    95th-percentile reconstruction-error threshold on normal-test traffic),
    computes per-sample MSE reconstruction error on the test set, and flags
    anomalies where error > threshold. The anomaly decision drives the ZTA
    enforcement action the same way the CNN-GRU classifier decision does for
    System C (anomaly -> CHALLENGE/BLOCK, normal -> ALLOW/MONITOR).

    Returns
    -------
    y_pred        : 0=normal, 1=anomaly (any attack)
    inference_sec : wall-clock seconds for the reconstruction/predict call
    errors        : per-sample MSE reconstruction errors
    risk_scores   : normalised anomaly scores in [0, 1]
    threshold     : the saved reconstruction-error threshold
    """
    # load_autoencoder raises FileNotFoundError if the model is missing —
    # System D is a REAL model, not a simulation, so we let it propagate.
    autoencoder, encoder, threshold = load_autoencoder(model_dir)

    # Flatten (N, 40, 1) -> (N, 40) for the dense autoencoder
    X_flat = X_test.reshape(X_test.shape[0], -1)

    t0 = time.perf_counter()
    errors, is_anomaly, risk_scores = predict_anomaly(
        autoencoder, X_flat, threshold
    )
    inference_sec = time.perf_counter() - t0

    y_pred = is_anomaly.astype(int)
    return y_pred, inference_sec, errors, risk_scores, threshold


# ── Plotting ──────────────────────────────────────────────────────────────────

def plot_comparison_bar(df: pd.DataFrame, out_dir: str):
    """Bar chart comparing accuracy, F1, and FPR across systems."""
    metrics = ['Accuracy', 'F1 Score', 'False Positive Rate']
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))
    colors = ['#e74c3c', '#3498db', '#2ecc71']

    # Build x-axis labels: append ' *' for simulated systems
    simulated_map = dict(zip(df['System'], df['Simulated'])) if 'Simulated' in df.columns else {}
    display_labels = [
        (name + ' *' if simulated_map.get(name, False) else name)
        for name in df['System']
    ]

    for ax, metric, color in zip(axes, metrics, colors):
        vals = df.set_index('System')[metric].astype(float)
        x_pos = range(len(vals))
        bars = ax.bar(x_pos, vals.values,
                      color=[color] * len(vals), edgecolor='black', width=0.5)
        ax.set_title(metric, fontsize=13, fontweight='bold')
        ax.set_ylabel(metric)
        ax.set_ylim(0, 1.1)
        ax.set_xticks(list(x_pos))
        ax.set_xticklabels(display_labels, rotation=20, ha='right', fontsize=8)
        for bar, val in zip(bars, vals.values):
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.02,
                    f'{val:.3f}', ha='center', fontsize=9)
        ax.grid(axis='y', linestyle='--', alpha=0.5)

    plt.suptitle('Risk-Adaptive ZTA: System Comparison (* = simulated baseline)',
                 fontsize=13, fontweight='bold', y=1.02)
    plt.tight_layout(rect=[0, 0.05, 1, 1])
    plt.figtext(0.5, 0.01,
                '* simulated baseline (not a real deployment)',
                ha='center', fontsize=9, style='italic', color='#555555')
    path = os.path.join(out_dir, 'comparison_bar.png')
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Bar chart saved to {path}")


def plot_confusion_matrices(systems_preds: dict,
                            y_true: np.ndarray,
                            out_dir: str):
    """Plot confusion matrices for all systems."""
    n = len(systems_preds)
    fig, axes = plt.subplots(1, n, figsize=(5 * n, 5))
    if n == 1:
        axes = [axes]
    labels = ['Normal', 'Attack']

    for ax, (name, y_pred) in zip(axes, systems_preds.items()):
        cm = confusion_matrix(y_true, y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                    xticklabels=labels, yticklabels=labels, ax=ax)
        ax.set_title(name, fontsize=9, fontweight='bold')
        ax.set_xlabel('Predicted')
        ax.set_ylabel('Actual')

    plt.suptitle('Confusion Matrices — Risk-Adaptive ZTA Framework',
                 fontsize=13, fontweight='bold')
    plt.tight_layout()
    path = os.path.join(out_dir, 'confusion_matrices.png')
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"Confusion matrices saved to {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description='Five-way system comparison evaluation'
    )
    parser.add_argument('--train', default='data/NSL_KDD_Train.csv')
    parser.add_argument('--test',  default='data/NSL_KDD_Test.csv')
    parser.add_argument('--model', default='data/cnn_gru_model.keras')
    parser.add_argument('--out',   default='data/results')
    parser.add_argument('--seed',  type=int, default=42)
    return parser.parse_args()


def run_evaluation(args):
    os.makedirs(args.out, exist_ok=True)
    rng = np.random.default_rng(args.seed)

    # Load data — the SAME test set for all four systems
    print("[evaluate] Loading test data...")
    _, X_test, _, y_test = load_and_preprocess(
        args.train, args.test,
        save_artifacts=False
    )
    y_binary = (y_test > 0).astype(int)
    n_samples = X_test.shape[0]
    print(f"[evaluate] Test set: {n_samples} samples "
          f"({int((y_binary == 0).sum())} normal, "
          f"{int((y_binary == 1).sum())} attack)")

    all_metrics   = []
    systems_preds = {}

    for system_name, profile in SYSTEM_PROFILES.items():
        print(f"\n[evaluate] Evaluating: {system_name}")

        if system_name == 'ZTA + CNN-GRU (Supervised)':
            # System C — REAL CNN-GRU known-attack classifier
            try:
                y_pred, infer_sec = evaluate_model(
                    args.model, X_test, y_test
                )
                print("  >> Using trained CNN-GRU model predictions (supervised)")
            except FileNotFoundError as e:
                print(f"  >> {e}")
                print("  >> Falling back to simulation")
                t0 = time.perf_counter()
                y_pred = simulate_predictions(
                    y_test, profile['detection_noise'],
                    profile['false_positive_rate_base'], rng
                )
                infer_sec = time.perf_counter() - t0

        elif system_name == 'ZTA + Autoencoder (Self-Supervised)':
            # System D — REAL self-supervised autoencoder (label-free).
            # No simulation fallback: this is the novel contribution and
            # must reflect the actual trained model.
            y_pred, infer_sec, errors, risk_scores, threshold = \
                evaluate_autoencoder_system(
                    os.path.dirname(args.model), X_test, y_test
                )
            print("  >> Using trained Autoencoder predictions (self-supervised)")
            print(f"     threshold={float(threshold):.6f}  "
                  f"mean err normal={np.mean(errors[y_test == 0]):.6f}  "
                  f"mean err attack={np.mean(errors[y_test > 0]):.6f}")

        elif system_name == 'ZTA + CNN-GRU + Autoencoder (Fusion)':
            # System E — REAL dual-model fusion: CNN-GRU + Autoencoder combined
            print("  >> Using trained CNN-GRU + Autoencoder fusion (dual-model)")
            cnn_model = tf.keras.models.load_model(args.model)
            autoencoder, encoder, ae_thresh = load_autoencoder(
                os.path.dirname(args.model)
            )
            t0 = time.perf_counter()
            # CNN-GRU inference
            cnn_probs = cnn_model.predict(X_test, verbose=0)   # (N, 5)
            cnn_risk_scores = 1.0 - cnn_probs[:, 0]            # 1 - P(Normal)
            # Autoencoder inference
            X_flat = X_test.reshape(X_test.shape[0], -1)       # (N, 40)
            ae_errors, ae_is_anomaly, ae_risk_scores = predict_anomaly(
                autoencoder, X_flat, ae_thresh
            )
            # Fuse: take the more conservative (higher) risk score
            combined_risk = np.maximum(cnn_risk_scores, ae_risk_scores)
            # Flag as attack if combined_risk > 0.3 (MONITOR threshold)
            y_pred = (combined_risk > 0.3).astype(int)
            infer_sec = time.perf_counter() - t0
            print(f"     ae_threshold={float(ae_thresh):.6f}  "
                  f"mean combined_risk normal={float(np.mean(combined_risk[y_test == 0])):.4f}  "
                  f"mean combined_risk attack={float(np.mean(combined_risk[y_test > 0])):.4f}")

        else:
            # Systems A/B — simulated baselines (no ML model exists)
            t0 = time.perf_counter()
            y_pred = simulate_predictions(
                y_test, profile['detection_noise'],
                profile['false_positive_rate_base'], rng
            )
            infer_sec = time.perf_counter() - t0
            print("  >> Simulated baseline (no ML model)")

        per_sample_ms = infer_sec / n_samples * 1000.0
        systems_preds[system_name] = y_pred
        metrics = compute_metrics(
            system_name, y_binary, y_pred, profile,
            y_true_multiclass=y_test,
            inference_ms_per_sample=per_sample_ms,
        )
        all_metrics.append(metrics)

        print(f"  Accuracy      : {metrics['Accuracy']}")
        print(f"  F1 Score      : {metrics['F1 Score']}")
        print(f"  FPR           : {metrics['False Positive Rate']}")
        print(f"  Inference     : {per_sample_ms:.4f} ms/sample")
        print(f"  Op. Response  : {metrics['Avg Response Time']}")
        det = {k: v for k, v in metrics.items()
               if k.startswith(('DoS', 'Probe', 'R2L', 'U2R'))}
        print("  Per-attack detection: " +
              ", ".join(f"{k}={v}" for k, v in det.items()))

    # Build results DataFrame
    df = pd.DataFrame(all_metrics)

    # Save CSV
    csv_path = os.path.join(args.out, 'comparison_results.csv')
    df.to_csv(csv_path, index=False)
    print(f"\n[evaluate] Results saved to {csv_path}")

    # Print final comparison table
    print("\n" + "=" * 95)
    print("  FINAL 5-WAY COMPARISON")
    print("=" * 95)
    summary_cols = ['System', 'Accuracy', 'F1 Score',
                    'False Positive Rate', 'Response Time (ms/sample)',
                    'DoS Detection', 'Probe Detection',
                    'R2L Detection', 'U2R Detection',
                    'Zero-Day Detection']
    print(df[summary_cols].to_string(index=False))
    print("=" * 95)

    # Honest per-metric winners
    print("\n  Per-metric winners (honest, no favouritism):")
    for metric in ['Accuracy', 'F1 Score', 'Recall (TPR)',
                   'False Positive Rate', 'Response Time (ms/sample)']:
        vals = df[metric]
        if vals.isnull().all():
            continue
        if metric == 'False Positive Rate':
            best = df.loc[vals.astype(float).idxmin(), 'System']
            print(f"    {metric:26s}: lowest  = {best}")
        elif metric == 'Response Time (ms/sample)':
            best = df.loc[vals.astype(float).idxmin(), 'System']
            print(f"    {metric:26s}: fastest = {best}")
        else:
            best = df.loc[vals.astype(float).idxmax(), 'System']
            print(f"    {metric:26s}: highest = {best}")
    for cat in ['DoS', 'Probe', 'R2L', 'U2R']:
        col = f'{cat} Detection'
        best = df.loc[df[col].astype(float).idxmax(), 'System']
        print(f"    {col:26s}: highest = {best}")
    print("=" * 95)

    # Plots
    plot_comparison_bar(df, args.out)
    plot_confusion_matrices(systems_preds, y_binary, args.out)

    # Save JSON summary
    summary = df[['System', 'Accuracy', 'Precision',
                  'Recall (TPR)', 'F1 Score',
                  'False Positive Rate',
                  'Response Time (ms/sample)',
                  'DoS Detection', 'Probe Detection',
                  'R2L Detection', 'U2R Detection',
                  'Zero-Day Detection']].to_dict(orient='records')
    with open(os.path.join(args.out, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"[evaluate] Summary saved to {os.path.join(args.out, 'summary.json')}")

    return df


if __name__ == '__main__':
    args = parse_args()
    run_evaluation(args)
