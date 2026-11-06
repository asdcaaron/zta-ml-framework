"""
train_autoencoder.py
--------------------
Standalone training script for the self-supervised autoencoder
(zero-day anomaly detection layer).

Trains ONLY the autoencoder on NORMAL traffic from NSL-KDD, leaving the
CNN-GRU model untouched. It reuses the SAVED scaler/encoders produced by
src/preprocess.py (run via src/train.py) so the autoencoder consumes the
exact same 40-feature space as the CNN-GRU model — the two detectors are
compatible by construction.

Pipeline:
  1. Load NSL-KDD with the existing scaler/encoders (transform, NOT refit)
  2. Train the autoencoder on normal-train traffic only (MSE reconstruction)
  3. Compute the 95th-percentile threshold on NORMAL-TEST traffic
  4. Evaluate separation: recall on attacks, FPR on normal
  5. Save model (.keras + .h5), threshold, error-distribution plot, results JSON

Usage:
    python src/train_autoencoder.py
    python src/train_autoencoder.py --epochs 50 --batch 256
"""

import argparse
import os
import sys
import json

# Allow running from project root: python src/train_autoencoder.py
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use('Agg')   # non-interactive backend for servers
import tensorflow as tf

from preprocess import (
    COLUMNS, FEATURE_COLS, DROP_COLS, LOG_SCALE_COLS,
    CATEGORICAL_COLS, ATTACK_MAP
)
from autoencoder import (
    build_autoencoder, compile_autoencoder, compute_threshold,
    evaluate_autoencoder, plot_reconstruction_errors, _plot_ae_history
)


# ── Data loading (replays preprocess.py with SAVED artifacts) ────────────────

def load_data_with_existing_scaler(train_path: str,
                                    test_path: str,
                                    artifacts_dir: str = 'data'):
    """
    Load NSL-KDD and replay preprocess.py's pipeline using the SAVED
    scaler/encoders (transform, NOT refit), so the autoencoder consumes
    the exact same 40-feature space as the CNN-GRU model.

    Returns 2D arrays of shape (N, 40) — no reshape — for the autoencoder.
    """
    print("[autoencoder-train] Loading data (reusing saved scaler/encoders)...")

    train_df = pd.read_csv(train_path, names=COLUMNS)
    test_df  = pd.read_csv(test_path,  names=COLUMNS)

    # ── Map string labels → integer categories (same as preprocess.py) ────
    train_df['label'] = train_df['label'].str.strip().str.lower()
    test_df['label']  = test_df['label'].str.strip().str.lower()
    train_df['label'] = train_df['label'].map(lambda x: ATTACK_MAP.get(x, 0))
    test_df['label']  = test_df['label'].map(lambda x: ATTACK_MAP.get(x, 0))

    # ── Drop zero-variance feature ────────────────────────────────────────
    train_df = train_df.drop(columns=DROP_COLS, errors='ignore')
    test_df  = test_df.drop(columns=DROP_COLS,  errors='ignore')

    # ── Log1p extreme-outlier features (before scaling) ───────────────────
    for col in LOG_SCALE_COLS:
        if col in train_df.columns:
            train_df[col] = np.log1p(train_df[col].clip(lower=0))
            test_df[col]  = np.log1p(test_df[col].clip(lower=0))

    # ── Apply SAVED categorical encoders (transform, never fit) ───────────
    encoders = joblib.load(os.path.join(artifacts_dir, 'encoders.pkl'))
    for col in CATEGORICAL_COLS:
        le = encoders[col]
        train_df[col] = train_df[col].astype(str).map(
            lambda x, le=le: le.transform([x])[0] if x in le.classes_ else 0
        )
        test_df[col] = test_df[col].astype(str).map(
            lambda x, le=le: le.transform([x])[0] if x in le.classes_ else 0
        )

    # ── Apply SAVED MinMaxScaler (transform, never fit) ───────────────────
    scaler = joblib.load(os.path.join(artifacts_dir, 'scaler.pkl'))
    X_train = scaler.transform(train_df[FEATURE_COLS].values)
    X_test  = scaler.transform(test_df[FEATURE_COLS].values)

    y_train = train_df['label'].values.astype(np.int32)
    y_test  = test_df['label'].values.astype(np.int32)

    print(f"[autoencoder-train] Train: {X_train.shape}  Test: {X_test.shape}")
    return X_train, X_test, y_train, y_test


# ── Argument parsing ──────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description='Train the self-supervised autoencoder for zero-day '
                    'anomaly detection (normal traffic only).'
    )
    parser.add_argument('--train',         default='data/NSL_KDD_Train.csv',
                        help='Path to training CSV')
    parser.add_argument('--test',          default='data/NSL_KDD_Test.csv',
                        help='Path to test CSV')
    parser.add_argument('--artifacts-dir',  default='data',
                        help='Directory with saved scaler.pkl/encoders.pkl')
    parser.add_argument('--out',           default='data',
                        help='Output directory for models and artifacts')
    parser.add_argument('--results-dir',    default='data/results',
                        help='Directory for plots')
    parser.add_argument('--epochs',        type=int, default=50,
                        help='Max training epochs')
    parser.add_argument('--batch',         type=int, default=256,
                        help='Batch size')
    parser.add_argument('--encoding-dim',   type=int, default=16,
                        help='Bottleneck dimension')
    parser.add_argument('--lr',            type=float, default=0.001,
                        help='Initial learning rate')
    return parser.parse_args()


# ── Training ──────────────────────────────────────────────────────────────────

def main(args):
    os.makedirs(args.out, exist_ok=True)
    os.makedirs(args.results_dir, exist_ok=True)

    # ── 1. Load data with the SAME preprocessing (saved scaler/encoders) ───
    print("=" * 60)
    print("  Autoencoder Training — Self-Supervised Anomaly Detection")
    print("  (trains on NORMAL traffic only — no attack labels used)")
    print("=" * 60)
    X_train, X_test, y_train, y_test = load_data_with_existing_scaler(
        args.train, args.test, artifacts_dir=args.artifacts_dir
    )

    # ── 2. Self-supervised: train on NORMAL traffic only ──────────────────
    normal_mask = (y_train == 0)
    X_normal = X_train[normal_mask]
    print(f"[autoencoder-train] Training on {X_normal.shape[0]:,} normal samples")
    print(f"[autoencoder-train] Input dim: {X_normal.shape[1]}  "
          f"Encoding dim: {args.encoding_dim}")

    # Validation split from normal-train (10%)
    val_size = int(0.1 * len(X_normal))
    X_val_ae = X_normal[:val_size]
    X_tr_ae  = X_normal[val_size:]

    # Build and compile
    autoencoder, encoder = build_autoencoder(
        input_dim=X_normal.shape[1], encoding_dim=args.encoding_dim
    )
    autoencoder = compile_autoencoder(autoencoder, learning_rate=args.lr)
    autoencoder.summary()

    callbacks = [
        tf.keras.callbacks.EarlyStopping(
            monitor='val_loss', patience=8,
            restore_best_weights=True, verbose=1
        ),
        tf.keras.callbacks.ReduceLROnPlateau(
            monitor='val_loss', factor=0.5,
            patience=4, min_lr=1e-6, verbose=1
        ),
        tf.keras.callbacks.ModelCheckpoint(
            filepath=os.path.join(args.out, 'best_autoencoder.keras'),
            monitor='val_loss', save_best_only=True, verbose=0
        ),
    ]

    history = autoencoder.fit(
        X_tr_ae, X_tr_ae,          # input = target (reconstruction task)
        validation_data=(X_val_ae, X_val_ae),
        epochs=args.epochs,
        batch_size=args.batch,
        callbacks=callbacks,
        verbose=1
    )

    # ── 3. Compute threshold on NORMAL-TEST traffic (95th percentile) ─────
    # FPR on normal is ~5% by construction here; the honest separation
    # evidence is recall on attacks and the histogram overlap.
    X_normal_test = X_test[y_test == 0]
    threshold = compute_threshold(autoencoder, X_normal_test, percentile=95)
    print(f"[autoencoder-train] Anomaly threshold (95th pct, normal-test): "
          f"{threshold:.6f}")

    # ── 4. Save models (.keras primary + .h5 project convention) ──────────
    autoencoder.save(os.path.join(args.out, 'autoencoder_model.keras'))
    encoder.save(os.path.join(args.out, 'encoder_model.keras'))
    try:
        autoencoder.save(os.path.join(args.out, 'autoencoder_model.h5'))
        encoder.save(os.path.join(args.out, 'encoder_model.h5'))
    except Exception as e:
        print(f"[autoencoder-train] WARNING: .h5 save skipped ({e})")
    joblib.dump(threshold, os.path.join(args.out, 'ae_threshold.pkl'))
    print(f"[autoencoder-train] Models saved to '{args.out}/'")

    # ── 5. Plot training curves ───────────────────────────────────────────
    _plot_ae_history(history, args.out)

    # ── 6. Evaluate separation on the full test set ───────────────────────
    print("\n" + "=" * 60)
    print("  Autoencoder Evaluation on Test Set")
    print("=" * 60)
    ae_results = evaluate_autoencoder(autoencoder, X_test, y_test, threshold)

    # ── 7. Error-distribution plot (Normal vs attack, threshold marked) ───
    plot_reconstruction_errors(
        autoencoder, X_test, y_test, threshold,
        out_dir=args.results_dir,
        filename='autoencoder_error_distribution.png'
    )

    # ── 8. Record results JSON (matching training_results.json style) ────
    final_train_loss = float(history.history['loss'][-1])
    final_val_loss   = float(history.history['val_loss'][-1])
    epochs_trained   = len(history.history['loss'])

    results = {
        'final_train_loss':       round(final_train_loss, 6),
        'final_val_loss':         round(final_val_loss, 6),
        'epochs_trained':         epochs_trained,
        'threshold_95pct':        round(threshold, 6),
        'threshold_source':       'normal_test_95th_percentile',
        'mean_normal_test_error': ae_results['mean_normal_error'],
        'mean_attack_test_error': ae_results['mean_attack_error'],
        'recall_on_attacks':      ae_results['recall'],
        'fpr_on_normal':          ae_results['false_positive_rate'],
        'accuracy':               ae_results['accuracy'],
        'precision':              ae_results['precision'],
        'f1_score':               ae_results['f1_score'],
        'normal_train_samples':   int(X_normal.shape[0]),
        'normal_test_samples':    int(X_normal_test.shape[0]),
        'attack_test_samples':    int(X_test[y_test > 0].shape[0]),
        'input_dim':              int(X_normal.shape[1]),
        'encoding_dim':           int(args.encoding_dim),
    }
    results_path = os.path.join(args.out, 'autoencoder_training_results.json')
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"[autoencoder-train] Results saved to {results_path}")

    # ── 9. Final summary ──────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  TRAINING SUMMARY")
    print("=" * 60)
    print(f"  Final train loss (MSE)  : {final_train_loss:.6f}")
    print(f"  Final val loss   (MSE)   : {final_val_loss:.6f}")
    print(f"  Epochs trained           : {epochs_trained}")
    print(f"  95th-pct threshold       : {threshold:.6f}")
    print(f"  Recall on attacks         : {ae_results['recall']}")
    print(f"  FPR on normal             : {ae_results['false_positive_rate']}")
    print(f"  Mean error (normal test)  : {ae_results['mean_normal_error']}")
    print(f"  Mean error (attack test)  : {ae_results['mean_attack_error']}")
    print("=" * 60)

    return autoencoder, encoder, threshold, results


if __name__ == '__main__':
    args = parse_args()
    main(args)
