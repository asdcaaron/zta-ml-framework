"""
robustness_analysis.py
-----------------------
Week-4: Threshold sensitivity sweep and zero-day recall analysis.

Two analyses:
  1. THRESHOLD SWEEP
     Vary the autoencoder anomaly threshold from the 70th to the 99th
     percentile of normal-traffic reconstruction errors (computed fresh
     from the test-set normal samples, so it is independent of the saved
     ae_threshold.pkl).  For each percentile record:
       precision, recall, F1, FPR, accuracy, TP, FP, TN, FN.
     Plot the precision-recall trade-off and the F1/FPR curves.

  2. ZERO-DAY RECALL (leave-one-class-out)
     Simulate "unseen" attack types by evaluating the autoencoder on each
     attack class independently.  The autoencoder was trained on NORMAL only,
     so it has never seen any attack class — this tests whether it can flag
     each class as anomalous purely from reconstruction error.
     Report per-class recall, mean reconstruction error, and the ratio of
     attack error to normal error (separation ratio).

Outputs (written to data/results/):
  threshold_sweep.png          -- precision / recall / F1 / FPR vs percentile
  zero_day_recall.png          -- bar chart of per-class recall
  robustness_report.json       -- all numeric results for the report

Usage:
    python src/robustness_analysis.py

Do NOT retrain or modify any model, scaler, or encoder.
"""

import json
import os
import sys
import time

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

# ── project root on path ──────────────────────────────────────────────────────
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(PROJECT_ROOT, 'src'))

os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL']  = '3'

from preprocess import load_and_preprocess, CLASS_NAMES
from autoencoder import load_autoencoder, compute_threshold

RESULTS_DIR = os.path.join(PROJECT_ROOT, 'data', 'results')
DATA_DIR    = os.path.join(PROJECT_ROOT, 'data')

# Percentile range for the sweep
PERCENTILES = list(range(70, 100))   # 70th … 99th inclusive

# Integer → name map (same as CLASS_NAMES in preprocess.py)
CLASS_LABEL = {0: 'Normal', 1: 'DoS', 2: 'Probe', 3: 'R2L', 4: 'U2R'}
ATTACK_CLASSES = [1, 2, 3, 4]


# ── helpers ───────────────────────────────────────────────────────────────────

def binary_metrics(y_true_binary, y_pred_binary):
    """Return dict of precision, recall, F1, FPR, accuracy, TP, FP, TN, FN."""
    tp = int(np.sum((y_pred_binary == 1) & (y_true_binary == 1)))
    fp = int(np.sum((y_pred_binary == 1) & (y_true_binary == 0)))
    tn = int(np.sum((y_pred_binary == 0) & (y_true_binary == 0)))
    fn = int(np.sum((y_pred_binary == 0) & (y_true_binary == 1)))
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    accuracy  = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0.0
    return dict(precision=round(precision, 4), recall=round(recall, 4),
                f1=round(f1, 4), fpr=round(fpr, 4), accuracy=round(accuracy, 4),
                tp=tp, fp=fp, tn=tn, fn=fn)


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # ── 1. Load data ──────────────────────────────────────────────────────
    print("[1/5] Loading and preprocessing NSL-KDD test set ...")
    t0 = time.perf_counter()
    X_train, X_test, y_train, y_test = load_and_preprocess(
        os.path.join(DATA_DIR, 'NSL_KDD_Train.csv'),
        os.path.join(DATA_DIR, 'NSL_KDD_Test.csv'),
        save_artifacts=False,
        artifacts_dir=DATA_DIR,
    )
    print(f"  Test set: {X_test.shape[0]:,} samples  "
          f"({int(np.sum(y_test==0)):,} normal, "
          f"{int(np.sum(y_test>0)):,} attack)  "
          f"loaded in {time.perf_counter()-t0:.1f}s")

    # Flatten (N,40,1) -> (N,40) for autoencoder
    X_test_flat = X_test.reshape(X_test.shape[0], -1)

    # ── 2. Load autoencoder ───────────────────────────────────────────────
    print("[2/5] Loading autoencoder ...")
    autoencoder, encoder, saved_threshold = load_autoencoder(DATA_DIR)
    print(f"  Saved threshold (95th pct): {saved_threshold:.6f}")

    # Compute fresh reconstruction errors on the full test set
    print("  Computing reconstruction errors on test set ...")
    t0 = time.perf_counter()
    recon = autoencoder.predict(X_test_flat, verbose=0)
    errors = np.mean(np.square(X_test_flat - recon), axis=1)
    print(f"  Done in {time.perf_counter()-t0:.1f}s")

    # Normal / attack error stats
    normal_errors = errors[y_test == 0]
    attack_errors = errors[y_test > 0]
    mean_normal   = float(np.mean(normal_errors))
    mean_attack   = float(np.mean(attack_errors))
    separation    = mean_attack / mean_normal if mean_normal > 0 else 0
    print(f"  Mean normal error : {mean_normal:.6f}")
    print(f"  Mean attack error : {mean_attack:.6f}")
    print(f"  Separation ratio  : {separation:.1f}x")

    y_binary = (y_test > 0).astype(int)

    # ── 3. Threshold sweep ────────────────────────────────────────────────
    print(f"\n[3/5] Threshold sweep: {PERCENTILES[0]}th – {PERCENTILES[-1]}th percentile ...")
    sweep_results = []
    for pct in PERCENTILES:
        thr = float(np.percentile(normal_errors, pct))
        y_pred = (errors > thr).astype(int)
        m = binary_metrics(y_binary, y_pred)
        m['percentile'] = pct
        m['threshold']  = round(thr, 8)
        sweep_results.append(m)

    # Find optimal (max F1)
    best = max(sweep_results, key=lambda x: x['f1'])
    print(f"  Best F1 {best['f1']:.4f} at {best['percentile']}th pct "
          f"(thr={best['threshold']:.6f}  "
          f"precision={best['precision']:.4f}  "
          f"recall={best['recall']:.4f}  "
          f"fpr={best['fpr']:.4f})")

    # ── 4. Zero-day recall ────────────────────────────────────────────────
    print(f"\n[4/5] Zero-day recall — per attack class (threshold = saved 95th pct) ...")
    zero_day = {}
    for cls_id in ATTACK_CLASSES:
        cls_name = CLASS_LABEL[cls_id]
        mask = (y_test == cls_id)
        n_samples = int(np.sum(mask))
        if n_samples == 0:
            zero_day[cls_name] = {'n_samples': 0, 'recall': 0.0,
                                  'mean_error': 0.0, 'separation_ratio': 0.0}
            continue
        cls_errors = errors[mask]
        cls_detected = int(np.sum(cls_errors > saved_threshold))
        cls_recall   = cls_detected / n_samples
        cls_mean_err = float(np.mean(cls_errors))
        cls_sep      = cls_mean_err / mean_normal if mean_normal > 0 else 0
        zero_day[cls_name] = {
            'n_samples':       n_samples,
            'detected':        cls_detected,
            'recall':          round(cls_recall, 4),
            'mean_error':      round(cls_mean_err, 6),
            'separation_ratio': round(cls_sep, 2),
        }
        print(f"  {cls_name:6s}: {n_samples:5d} samples  "
              f"recall={cls_recall:.4f}  "
              f"mean_err={cls_mean_err:.6f}  "
              f"sep={cls_sep:.1f}x")

    # ── 5. Save plots and report ──────────────────────────────────────────
    print("\n[5/5] Saving charts and report ...")

    # -- Plot A: Threshold sweep curves -----------------------------------
    pcts       = [r['percentile'] for r in sweep_results]
    precisions = [r['precision']  for r in sweep_results]
    recalls    = [r['recall']     for r in sweep_results]
    f1s        = [r['f1']         for r in sweep_results]
    fprs       = [r['fpr']        for r in sweep_results]
    thresholds = [r['threshold']  for r in sweep_results]

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle('Autoencoder Threshold Sensitivity Analysis\n'
                 'NSL-KDD Test Set  |  ZTA-ML Framework', fontsize=13)

    ax = axes[0]
    ax.plot(pcts, precisions, 'o-', color='#2196F3', label='Precision', linewidth=2)
    ax.plot(pcts, recalls,    's-', color='#4CAF50', label='Recall',    linewidth=2)
    ax.plot(pcts, f1s,        '^-', color='#FF9800', label='F1 Score',  linewidth=2, zorder=5)
    ax.axvline(best['percentile'], color='red', linestyle='--', linewidth=1.2,
               label=f"Best F1 pct={best['percentile']}")
    ax.axvline(95, color='grey', linestyle=':', linewidth=1,
               label='Saved threshold (95th)')
    ax.set_xlabel('Threshold Percentile (of normal errors)')
    ax.set_ylabel('Score')
    ax.set_title('Precision / Recall / F1 vs Threshold')
    ax.set_ylim(0, 1.05)
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3)

    ax2 = axes[1]
    ax2.plot(pcts, fprs,  'd-', color='#E53935', label='FPR',     linewidth=2)
    ax2.plot(pcts, f1s,   '^-', color='#FF9800', label='F1 Score', linewidth=2)
    ax2.axvline(best['percentile'], color='red', linestyle='--', linewidth=1.2,
                label=f"Best F1 pct={best['percentile']}")
    ax2.axvline(95, color='grey', linestyle=':', linewidth=1,
                label='Saved threshold (95th)')
    ax2.set_xlabel('Threshold Percentile (of normal errors)')
    ax2.set_ylabel('Score')
    ax2.set_title('F1 Score and FPR vs Threshold')
    ax2.set_ylim(0, 1.05)
    ax2.legend(fontsize=8)
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    sweep_plot = os.path.join(RESULTS_DIR, 'threshold_sweep.png')
    plt.savefig(sweep_plot, dpi=150)
    plt.close()
    print(f"  Saved: {sweep_plot}")

    # -- Plot B: Zero-day recall bar chart --------------------------------
    cls_names   = list(zero_day.keys())
    cls_recalls = [zero_day[c]['recall'] for c in cls_names]
    cls_seps    = [zero_day[c]['separation_ratio'] for c in cls_names]
    bar_colors  = ['#4CAF50' if r >= 0.7 else '#FF9800' if r >= 0.4 else '#E53935'
                   for r in cls_recalls]

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle('Zero-Day Recall by Attack Class\n'
                 'Autoencoder  |  Threshold = 95th pct of normal errors', fontsize=13)

    ax = axes[0]
    bars = ax.bar(cls_names, cls_recalls, color=bar_colors, edgecolor='white',
                  linewidth=0.8, zorder=3)
    ax.axhline(0.7, color='green', linestyle='--', linewidth=1.2,
               label='Good recall (0.70)')
    ax.axhline(0.4, color='orange', linestyle='--', linewidth=1.2,
               label='Acceptable recall (0.40)')
    for bar, val in zip(bars, cls_recalls):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                f'{val:.3f}', ha='center', va='bottom', fontsize=9, fontweight='bold')
    ax.set_ylabel('Recall')
    ax.set_title('Detection Recall per Attack Class')
    ax.set_ylim(0, 1.1)
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3, axis='y')

    ax2 = axes[1]
    sep_colors = ['#4CAF50' if s >= 10 else '#FF9800' if s >= 5 else '#E53935'
                  for s in cls_seps]
    bars2 = ax2.bar(cls_names, cls_seps, color=sep_colors, edgecolor='white',
                    linewidth=0.8, zorder=3)
    for bar, val in zip(bars2, cls_seps):
        ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                 f'{val:.1f}x', ha='center', va='bottom', fontsize=9, fontweight='bold')
    ax2.set_ylabel('Error Ratio (attack / normal mean)')
    ax2.set_title('Reconstruction Error Separation Ratio')
    ax2.grid(True, alpha=0.3, axis='y')

    plt.tight_layout()
    zd_plot = os.path.join(RESULTS_DIR, 'zero_day_recall.png')
    plt.savefig(zd_plot, dpi=150)
    plt.close()
    print(f"  Saved: {zd_plot}")

    # -- JSON report -------------------------------------------------------
    report = {
        'generated_at': __import__('datetime').datetime.now(
            __import__('datetime').timezone.utc).isoformat(),
        'test_set': {
            'total_samples':  int(len(y_test)),
            'normal_samples': int(np.sum(y_test == 0)),
            'attack_samples': int(np.sum(y_test > 0)),
        },
        'reconstruction_errors': {
            'mean_normal':      round(mean_normal, 6),
            'mean_attack':      round(mean_attack, 6),
            'separation_ratio': round(separation, 2),
        },
        'saved_threshold': {
            'percentile':  95,
            'value':       round(saved_threshold, 8),
            'metrics_at_saved_threshold': binary_metrics(
                y_binary, (errors > saved_threshold).astype(int)),
        },
        'threshold_sweep': sweep_results,
        'best_threshold': best,
        'zero_day_recall': zero_day,
        'summary': (
            f"Threshold sweep over {PERCENTILES[0]}–{PERCENTILES[-1]}th percentiles. "
            f"Best F1={best['f1']:.4f} at {best['percentile']}th pct "
            f"(precision={best['precision']:.4f}, recall={best['recall']:.4f}, "
            f"fpr={best['fpr']:.4f}). "
            f"Saved 95th-pct threshold: F1="
            f"{binary_metrics(y_binary,(errors>saved_threshold).astype(int))['f1']:.4f}. "
            f"Zero-day recall: "
            + ", ".join(f"{c}={zero_day[c]['recall']:.3f}" for c in zero_day)
            + f". Weakest class: "
            + min(zero_day, key=lambda c: zero_day[c]['recall'])
            + f" (R2L connections reconstruct like normal traffic)."
        ),
    }

    report_path = os.path.join(RESULTS_DIR, 'robustness_report.json')
    with open(report_path, 'w') as fh:
        json.dump(report, fh, indent=2)
    print(f"  Saved: {report_path}")

    # ── Summary to console ────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  ROBUSTNESS ANALYSIS SUMMARY")
    print("=" * 65)
    print(f"  Test samples     : {len(y_test):,} "
          f"({int(np.sum(y_test==0)):,} normal + {int(np.sum(y_test>0)):,} attack)")
    print(f"  Separation ratio : {separation:.1f}x  "
          f"(attack/normal mean reconstruction error)")
    print(f"  Saved thr (95th) : {saved_threshold:.6f}  "
          f"-> F1={binary_metrics(y_binary,(errors>saved_threshold).astype(int))['f1']:.4f}")
    print(f"  Best F1 thr      : {best['percentile']}th pct ({best['threshold']:.6f})"
          f"  -> F1={best['f1']:.4f}  "
          f"precision={best['precision']:.4f}  recall={best['recall']:.4f}")
    print()
    print("  Zero-day recall per class:")
    for c, v in zero_day.items():
        bar = '█' * int(v['recall'] * 20)
        print(f"    {c:6s}: {v['recall']:.4f}  {bar}  "
              f"(sep={v['separation_ratio']:.1f}x, n={v['n_samples']:,})")
    print("=" * 65)
    print(f"\nOutputs in {RESULTS_DIR}/")
    print("  threshold_sweep.png")
    print("  zero_day_recall.png")
    print("  robustness_report.json")
    return 0


if __name__ == '__main__':
    sys.exit(main())
