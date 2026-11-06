"""
train.py
--------
End-to-end training script for the Risk-Adaptive ZTA framework.

Trains two complementary models:

  Model 1 — CNN-GRU (Supervised)
    Classifies KNOWN attack types: Normal, DoS, Probe, R2L, U2R
    Trained on all labelled NSL-KDD samples with class weighting

  Model 2 — Autoencoder (Self-Supervised)
    Detects UNKNOWN / zero-day anomalies without any attack labels
    Trained on NORMAL traffic only — learns to reconstruct normal patterns
    High reconstruction error at inference = anomaly

Together they form the dual-layer Risk-Adaptive detection system:
  CNN-GRU     → known attack classification + risk score
  Autoencoder → self-supervised anomaly score (label-free)
  Combined    → ZTA enforcement action (ALLOW/MONITOR/CHALLENGE/BLOCK)

Usage:
    python src/train.py
    python src/train.py --train data/NSL_KDD_Train.csv \\
                        --test  data/NSL_KDD_Test.csv  \\
                        --epochs 50 --ae-epochs 50 --batch 256
"""

import argparse
import os
import sys
import json

# Allow running from project root: python src/train.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')   # non-interactive backend for servers
import matplotlib.pyplot as plt

import tensorflow as tf
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score
)
from sklearn.utils.class_weight import compute_class_weight

from preprocess import load_and_preprocess, CLASS_NAMES
from model import build_cnn_gru_model, compile_model, get_callbacks
from autoencoder import (train_autoencoder, evaluate_autoencoder,
                         plot_reconstruction_errors)


# ── Argument parsing ──────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description='Train Risk-Adaptive ZTA dual-layer detection models'
    )
    parser.add_argument('--train',      default='data/NSL_KDD_Train.csv',
                        help='Path to training CSV')
    parser.add_argument('--test',       default='data/NSL_KDD_Test.csv',
                        help='Path to test CSV')
    parser.add_argument('--epochs',     type=int, default=50,
                        help='Max epochs for CNN-GRU')
    parser.add_argument('--ae-epochs',  type=int, default=50,
                        help='Max epochs for autoencoder')
    parser.add_argument('--batch',      type=int, default=256,
                        help='Batch size')
    parser.add_argument('--lr',         type=float, default=0.001,
                        help='Initial learning rate')
    parser.add_argument('--out',        default='data',
                        help='Output directory for models and plots')
    parser.add_argument('--skip-ae',    action='store_true',
                        help='Skip autoencoder training')
    return parser.parse_args()


# ── Training ──────────────────────────────────────────────────────────────────

def train(args):
    os.makedirs(args.out, exist_ok=True)

    # 1. Preprocess
    print("=" * 60)
    print("  STEP 1: Data Preprocessing")
    print("=" * 60)
    X_train, X_test, y_train, y_test = load_and_preprocess(
        args.train, args.test,
        save_artifacts=True,
        artifacts_dir=args.out
    )

    # Class weights to handle NSL-KDD imbalance (U2R is rare)
    classes = np.unique(y_train)
    weights = compute_class_weight('balanced', classes=classes, y=y_train)
    class_weight_dict = dict(zip(classes, weights))
    print(f"\nClass weights: {class_weight_dict}")

    # Validation split from training data
    val_size = int(0.1 * len(X_train))
    X_val,   X_train = X_train[:val_size],  X_train[val_size:]
    y_val,   y_train = y_train[:val_size],  y_train[val_size:]

    # 2. Build model
    print("\n" + "=" * 60)
    print("  STEP 2: Building CNN-GRU Model")
    print("=" * 60)
    model = build_cnn_gru_model(
        input_shape=(X_train.shape[1], 1), num_classes=5
    )
    model = compile_model(model, learning_rate=args.lr)
    model.summary()

    # 3. Train
    print("\n" + "=" * 60)
    print("  STEP 3: Training")
    print("=" * 60)
    callbacks = get_callbacks(
        checkpoint_path=os.path.join(args.out, 'best_model.keras')
    )

    history = model.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=args.epochs,
        batch_size=args.batch,
        class_weight=class_weight_dict,
        callbacks=callbacks,
        verbose=1
    )

    # 4. Evaluate
    print("\n" + "=" * 60)
    print("  STEP 4: Evaluation on Test Set")
    print("=" * 60)
    y_pred_probs = model.predict(X_test, verbose=0)
    y_pred = np.argmax(y_pred_probs, axis=1)

    acc = accuracy_score(y_test, y_pred)
    f1  = f1_score(y_test, y_pred, average='weighted')

    print(f"\nTest Accuracy : {acc:.4f}")
    print(f"Weighted F1   : {f1:.4f}")
    print("\nClassification Report:")
    print(classification_report(
        y_test, y_pred,
        target_names=[CLASS_NAMES[i] for i in range(5)]
    ))

    # Save results summary
    results = {
        'test_accuracy':   round(acc, 4),
        'weighted_f1':     round(f1, 4),
        'epochs_trained':  len(history.history['loss']),
        'final_val_loss':  round(float(history.history['val_loss'][-1]), 4),
        'final_val_acc':   round(float(history.history.get('val_accuracy', [0])[-1]), 4),
    }
    with open(os.path.join(args.out, 'training_results.json'), 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {args.out}/training_results.json")

    # 5. Save model
    model_path = os.path.join(args.out, 'cnn_gru_model.keras')
    model.save(model_path)
    print(f"Model saved to {model_path}")

    # 6. Plot CNN-GRU training curves
    _plot_history(history, args.out)

    # ── PART 2: Self-Supervised Autoencoder ───────────────────────────────
    if not args.skip_ae:
        print("\n" + "=" * 60)
        print("  STEP 5: Self-Supervised Autoencoder Training")
        print("  (trains on NORMAL traffic only — no attack labels used)")
        print("=" * 60)

        # Restore full training set (before val split) for autoencoder
        X_train_full, X_test_full, y_train_full, y_test_full = \
            load_and_preprocess(
                args.train, args.test,
                save_artifacts=False,
                artifacts_dir=args.out
            )

        ae, enc, ae_history, threshold = train_autoencoder(
            X_train_full, y_train_full,
            out_dir=args.out,
            epochs=args.ae_epochs,
            batch_size=args.batch,
        )

        print("\n" + "=" * 60)
        print("  STEP 6: Autoencoder Evaluation on Test Set")
        print("=" * 60)
        ae_results = evaluate_autoencoder(ae, X_test_full,
                                          y_test_full, threshold)

        # Save autoencoder results
        results['autoencoder'] = ae_results
        with open(os.path.join(args.out, 'training_results.json'), 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nFull results saved to {args.out}/training_results.json")

        # Plot reconstruction error distribution
        plot_reconstruction_errors(ae, X_test_full, y_test_full,
                                   threshold, args.out)

    return model, history, results


def _plot_history(history, out_dir: str):
    """Save accuracy and loss training curves."""
    hist = history.history
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    # Accuracy
    axes[0].plot(hist.get('accuracy', []),     label='Train Accuracy')
    axes[0].plot(hist.get('val_accuracy', []), label='Val Accuracy')
    axes[0].set_title('Model Accuracy')
    axes[0].set_xlabel('Epoch')
    axes[0].set_ylabel('Accuracy')
    axes[0].legend()
    axes[0].grid(True)

    # Loss
    axes[1].plot(hist.get('loss', []),     label='Train Loss')
    axes[1].plot(hist.get('val_loss', []), label='Val Loss')
    axes[1].set_title('Model Loss')
    axes[1].set_xlabel('Epoch')
    axes[1].set_ylabel('Loss')
    axes[1].legend()
    axes[1].grid(True)

    plt.tight_layout()
    path = os.path.join(out_dir, 'training_curves.png')
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"Training curves saved to {path}")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    args = parse_args()
    train(args)
