"""
threshold_sensitivity.py
------------------------
Week 4 — Threshold Sensitivity Analysis

Sweeps the autoencoder anomaly threshold across percentiles [70..99] of
normal-test reconstruction errors and records precision, recall, F1, FPR,
accuracy, and per-class detection rates (DoS, Probe, R2L, U2R).

Usage:
    python src/threshold_sensitivity.py
"""

import matplotlib
matplotlib.use('Agg')

import os
import sys
import json

# Allow imports from src/
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt

from preprocess import (
    COLUMNS, FEATURE_COLS, DROP_COLS, LOG_SCALE_COLS,
    CATEGORICAL_COLS, ATTACK_MAP
)
from autoencoder import load_autoencoder

# ── Paths ─────────────────────────────────────────────────────────────────────
PROJECT_ROOT  = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DATA_DIR      = os.path.join(PROJECT_ROOT, 'data')
RESULTS_DIR   = os.path.join(DATA_DIR, 'results')
TEST_CSV      = os.path.join(DATA_DIR, 'NSL_KDD_Test.csv')

os.makedirs(RESULTS_DIR, exist_ok=True)

PERCENTILES = [70, 75, 80, 85, 90, 95, 97, 99]
CURRENT_PCT  = 95   # the threshold baked into ae_threshold.pkl


# ── Preprocessing (replays train_autoencoder.py pipeline) ────────────────────

def load_test_data(test_path: str, artifacts_dir: str):
    """
    Load the NSL-KDD test set using the SAVED scaler/encoders.
    Returns X_test (N, 40) and y_test (N,).
    """
    print("[threshold_sensitivity] Loading test data…")
    test_df = pd.read_csv(test_path, names=COLUMNS)

    # Map labels
    test_df['label'] = test_df['label'].str.strip().str.lower()
    test_df['label'] = test_df['label'].map(lambda x: ATTACK_MAP.get(x, 0))

    # Drop zero-variance feature
    test_df = test_df.drop(columns=DROP_COLS, errors='ignore')

    # Log1p scale extreme-outlier features
    for col in LOG_SCALE_COLS:
        if col in test_df.columns:
            test_df[col] = np.log1p(test_df[col].clip(lower=0))

    # Apply SAVED categorical encoders (transform only)
    encoders = joblib.load(os.path.join(artifacts_dir, 'encoders.pkl'))
    for col in CATEGORICAL_COLS:
        le = encoders[col]
        test_df[col] = test_df[col].astype(str).map(
            lambda x, le=le: le.transform([x])[0] if x in le.classes_ else 0
        )

    # Apply SAVED MinMaxScaler (transform only — NEVER fit_transform)
    scaler  = joblib.load(os.path.join(artifacts_dir, 'scaler.pkl'))
    X_test  = scaler.transform(test_df[FEATURE_COLS].values)
    y_test  = test_df['label'].values.astype(np.int32)

    print(f"[threshold_sensitivity] X_test shape: {X_test.shape}  "
          f"y_test shape: {y_test.shape}")
    return X_test, y_test


# ── Metric computation ────────────────────────────────────────────────────────

def compute_metrics(errors: np.ndarray, y_test: np.ndarray,
                    threshold: float) -> dict:
    """
    Binary (attack vs normal) + per-class detection metrics at a threshold.
    """
    y_binary = (y_test > 0).astype(int)
    y_pred   = (errors > threshold).astype(int)

    tp = int(np.sum((y_binary == 1) & (y_pred == 1)))
    fp = int(np.sum((y_binary == 0) & (y_pred == 1)))
    fn = int(np.sum((y_binary == 1) & (y_pred == 0)))
    tn = int(np.sum((y_binary == 0) & (y_pred == 0)))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    accuracy  = (tp + tn) / len(y_test) if len(y_test) > 0 else 0.0

    # Per-class detection rates
    dos_det   = float(np.mean(errors[y_test == 1] > threshold)) \
                if np.any(y_test == 1) else 0.0
    probe_det = float(np.mean(errors[y_test == 2] > threshold)) \
                if np.any(y_test == 2) else 0.0
    r2l_det   = float(np.mean(errors[y_test == 3] > threshold)) \
                if np.any(y_test == 3) else 0.0
    u2r_det   = float(np.mean(errors[y_test == 4] > threshold)) \
                if np.any(y_test == 4) else 0.0

    return {
        'precision':     round(precision,  4),
        'recall':        round(recall,     4),
        'f1':            round(f1,         4),
        'fpr':           round(fpr,        4),
        'accuracy':      round(accuracy,   4),
        'dos_detection': round(dos_det,    4),
        'probe_detection': round(probe_det, 4),
        'r2l_detection': round(r2l_det,    4),
        'u2r_detection': round(u2r_det,    4),
    }


# ── Plotting helpers ──────────────────────────────────────────────────────────

def plot_sensitivity(rows: list, out_path: str):
    """2-row multi-panel sensitivity figure."""
    df = pd.DataFrame(rows)
    pcts = df['percentile'].values

    metrics_top    = ['precision', 'recall', 'f1', 'fpr']
    labels_top     = ['Precision', 'Recall', 'F1 Score', 'FPR']
    metrics_bottom = ['dos_detection', 'probe_detection',
                      'r2l_detection', 'u2r_detection']
    labels_bottom  = ['DoS Detection', 'Probe Detection',
                      'R2L Detection', 'U2R Detection']
    colors = ['#2980b9', '#27ae60', '#e67e22', '#c0392b']

    fig, axes = plt.subplots(2, 4, figsize=(18, 8))
    fig.suptitle('Threshold Sensitivity Analysis — NSL-KDD Test Set',
                 fontsize=14, fontweight='bold')

    for i, (metric, label, color) in enumerate(
            zip(metrics_top, labels_top, colors)):
        ax = axes[0, i]
        ax.plot(pcts, df[metric].values, marker='o', color=color,
                linewidth=2, markersize=6)
        ax.axvline(x=CURRENT_PCT, color='red', linestyle='--',
                   linewidth=1.5, label='Current (95th)')
        ax.set_title(label, fontsize=11, fontweight='bold')
        ax.set_xlabel('Percentile')
        ax.set_ylabel(label)
        ax.set_xticks(pcts)
        ax.grid(True, alpha=0.4)
        ax.legend(fontsize=8)

    for i, (metric, label, color) in enumerate(
            zip(metrics_bottom, labels_bottom, colors)):
        ax = axes[1, i]
        ax.plot(pcts, df[metric].values, marker='s', color=color,
                linewidth=2, markersize=6)
        ax.axvline(x=CURRENT_PCT, color='red', linestyle='--',
                   linewidth=1.5, label='Current (95th)')
        ax.set_title(label, fontsize=11, fontweight='bold')
        ax.set_xlabel('Percentile')
        ax.set_ylabel('Detection Rate')
        ax.set_xticks(pcts)
        ax.set_ylim(0, 1.05)
        ax.grid(True, alpha=0.4)
        ax.legend(fontsize=8)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"[threshold_sensitivity] Saved: {out_path}")


def plot_roc(rows: list, out_path: str):
    """ROC curve: one point per percentile."""
    df  = pd.DataFrame(rows)
    fprs = df['fpr'].values
    tprs = df['recall'].values
    pcts = df['percentile'].values

    fig, ax = plt.subplots(figsize=(7, 6))
    ax.plot([0, 1], [0, 1], 'k--', linewidth=1, label='Random (AUC=0.5)')
    ax.plot(fprs, tprs, 'b-o', linewidth=2, markersize=7)
    for fpr_val, tpr_val, p in zip(fprs, tprs, pcts):
        ax.annotate(f'{p}th', xy=(fpr_val, tpr_val),
                    xytext=(fpr_val + 0.005, tpr_val - 0.02),
                    fontsize=9, color='#2c3e50')
    ax.set_title('ROC Curve — Threshold Sensitivity\n'
                 '(each point = one percentile threshold)', fontsize=12)
    ax.set_xlabel('False Positive Rate (FPR)')
    ax.set_ylabel('True Positive Rate (Recall)')
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.02, 1.05)
    ax.legend()
    ax.grid(True, alpha=0.4)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"[threshold_sensitivity] Saved: {out_path}")


def plot_pr(rows: list, out_path: str):
    """Precision-Recall curve: one point per percentile."""
    df       = pd.DataFrame(rows)
    recalls  = df['recall'].values
    precs    = df['precision'].values
    pcts     = df['percentile'].values

    fig, ax = plt.subplots(figsize=(7, 6))
    ax.plot(recalls, precs, 'g-o', linewidth=2, markersize=7)
    for rec, prec, p in zip(recalls, precs, pcts):
        ax.annotate(f'{p}th', xy=(rec, prec),
                    xytext=(rec + 0.003, prec - 0.015),
                    fontsize=9, color='#2c3e50')
    ax.set_title('Precision-Recall Curve — Threshold Sensitivity\n'
                 '(each point = one percentile threshold)', fontsize=12)
    ax.set_xlabel('Recall')
    ax.set_ylabel('Precision')
    ax.set_xlim(-0.02, 1.05)
    ax.set_ylim(-0.02, 1.05)
    ax.grid(True, alpha=0.4)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"[threshold_sensitivity] Saved: {out_path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # 1. Load autoencoder + saved threshold
    print("[threshold_sensitivity] Loading autoencoder…")
    autoencoder, encoder, saved_threshold = load_autoencoder(DATA_DIR)
    print(f"[threshold_sensitivity] Saved threshold (95th pct): "
          f"{saved_threshold:.6f}")

    # 2. Load and preprocess test set
    X_test, y_test = load_test_data(TEST_CSV, DATA_DIR)

    # 3. Compute per-sample MSE reconstruction error (single pass, 2D input)
    print("[threshold_sensitivity] Computing reconstruction errors…")
    errors = np.mean(
        np.square(X_test - autoencoder.predict(X_test, verbose=0)),
        axis=1
    )
    print(f"[threshold_sensitivity] Error shape: {errors.shape}  "
          f"min={errors.min():.6f}  max={errors.max():.6f}")

    # 4. Normal-test errors for percentile sweep
    normal_errors = errors[y_test == 0]
    print(f"[threshold_sensitivity] Normal test samples: {len(normal_errors)}")

    # 5. Sweep thresholds
    rows = []
    for p in PERCENTILES:
        thr = float(np.percentile(normal_errors, p))
        m   = compute_metrics(errors, y_test, thr)
        row = {
            'percentile':      p,
            'threshold_value': round(thr, 8),
            **m
        }
        rows.append(row)

    # 6. Print table
    df = pd.DataFrame(rows)
    col_order = ['percentile', 'threshold_value', 'precision', 'recall',
                 'f1', 'fpr', 'accuracy',
                 'dos_detection', 'probe_detection',
                 'r2l_detection', 'u2r_detection']
    df = df[col_order]

    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', 160)
    print("\n" + "=" * 120)
    print("  THRESHOLD SENSITIVITY TABLE")
    print("=" * 120)
    print(df.to_string(index=False))
    print("=" * 120)

    # 7. Best-F1 row
    best_idx  = df['f1'].idxmax()
    best_row  = df.iloc[best_idx]
    print(f"\n  Best F1 = {best_row['f1']:.4f}  at percentile "
          f"{int(best_row['percentile'])}  "
          f"(threshold = {best_row['threshold_value']:.8f})")
    print(f"  precision={best_row['precision']:.4f}  "
          f"recall={best_row['recall']:.4f}  "
          f"fpr={best_row['fpr']:.4f}  "
          f"accuracy={best_row['accuracy']:.4f}")

    # 8. Save CSV
    csv_path = os.path.join(RESULTS_DIR, 'threshold_sensitivity.csv')
    df.to_csv(csv_path, index=False)
    print(f"\n[threshold_sensitivity] Saved: {csv_path}")

    # 9. Plots
    plot_sensitivity(rows, os.path.join(RESULTS_DIR, 'threshold_sensitivity.png'))
    plot_roc(rows,         os.path.join(RESULTS_DIR, 'threshold_roc_curve.png'))
    plot_pr(rows,          os.path.join(RESULTS_DIR, 'threshold_pr_curve.png'))

    print("\n[threshold_sensitivity] All outputs saved. Done.")
    sys.exit(0)


if __name__ == '__main__':
    main()
