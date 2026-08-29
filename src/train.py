"""
train.py
--------
End-to-end training script for the CNN-GRU intrusion detection model.

Steps:
  1. Load and preprocess the NSL-KDD dataset
  2. Build and compile the CNN-GRU model
  3. Train with early stopping and LR scheduling
  4. Evaluate on test set and print classification report
  5. Save the trained model and training history

Usage:
    python src/train.py
    python src/train.py --train data/NSL_KDD_Train.csv \
                        --test  data/NSL_KDD_Test.csv  \
                        --epochs 50 --batch 256
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


# ── Argument parsing ──────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description='Train CNN-GRU IDS model on NSL-KDD'
    )
    parser.add_argument('--train',   default='data/NSL_KDD_Train.csv',
                        help='Path to training CSV')
    parser.add_argument('--test',    default='data/NSL_KDD_Test.csv',
                        help='Path to test CSV')
    parser.add_argument('--epochs',  type=int, default=50,
                        help='Maximum training epochs')
    parser.add_argument('--batch',   type=int, default=256,
                        help='Batch size')
    parser.add_argument('--lr',      type=float, default=0.001,
                        help='Initial learning rate')
    parser.add_argument('--out',     default='data',
                        help='Output directory for model and plots')
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
    model = build_cnn_gru_model(input_shape=(41, 1), num_classes=5)
    model = compile_model(model, learning_rate=args.lr)
    model.summary()

    # 3. Train
    print("\n" + "=" * 60)
    print("  STEP 3: Training")
    print("=" * 60)
    callbacks = get_callbacks(
        checkpoint_path=os.path.join(args.out, 'best_model.h5')
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
    model_path = os.path.join(args.out, 'cnn_gru_model.h5')
    model.save(model_path)
    print(f"Model saved to {model_path}")

    # 6. Plot training curves
    _plot_history(history, args.out)

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
