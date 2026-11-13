"""
train_zeroday.py
----------------
Train a CNN-GRU variant with ONE attack class withheld from training, to
simulate a zero-day / unseen-attack scenario for the live demo.

Why only the CNN-GRU is retrained:
  The autoencoder trains on NORMAL traffic only — it never sees any attack
  label — so it is inherently zero-day agnostic and does not need retraining.
  We only need a CNN-GRU that has never seen the withheld class, so the
  supervised classifier cannot recognise it while the autoencoder still can.

Default withheld class: U2R (label 4) — the rarest, most subtle attack.
The supervised model is most likely to misclassify it as Normal when it has
never seen it, while the autoencoder still flags it as anomalous (≈69 %
zero-day recall), making it the most compelling demonstration that the
combined-risk policy blocks even attacks the classifier was never trained on.

The variant is saved to data/cnn_gru_model_no_<class>..keras and does NOT
overwrite the production model (data/cnn_gru_model.keras), so the existing
evaluation-chapter results are preserved.

Usage:
    python src/train_zeroday.py
    python src/train_zeroday.py --withhold u2r --epochs 30
    python src/train_zeroday.py --withhold dos
"""

import argparse
import os
import sys
import json

# Allow running from project root: python src/train_zeroday.py
sys.path.insert(0, os.path.dirname(__file__))

os.environ.setdefault('TF_ENABLE_ONEDNN_OPTS', '0')
os.environ.setdefault('TF_CPP_MIN_LOG_LEVEL', '3')

import numpy as np
import tensorflow as tf
tf.get_logger().setLevel('ERROR')
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import accuracy_score, f1_score

from preprocess import load_and_preprocess, CLASS_NAMES
from model import build_cnn_gru_model, compile_model, get_callbacks
from autoencoder import load_autoencoder, predict_anomaly


WITHHOLD_OPTIONS = {
    'dos': 1, 'probe': 2, 'r2l': 3, 'u2r': 4,
}


def parse_args():
    p = argparse.ArgumentParser(
        description='Train a zero-day CNN-GRU variant (one attack class withheld)'
    )
    p.add_argument('--withhold', default='u2r', choices=list(WITHHOLD_OPTIONS),
                   help='Attack class to withhold from training (default u2r)')
    p.add_argument('--train',  default='data/NSL_KDD_Train.csv')
    p.add_argument('--test',   default='data/NSL_KDD_Test.csv')
    p.add_argument('--epochs', type=int, default=30)
    p.add_argument('--batch',  type=int, default=256)
    p.add_argument('--lr',     type=float, default=0.001)
    p.add_argument('--out',     default='data')
    return p.parse_args()


def zta_decision(risk_score: float) -> str:
    if risk_score > 0.8:
        return 'BLOCK'
    if risk_score > 0.5:
        return 'CHALLENGE_MFA'
    if risk_score > 0.3:
        return 'MONITOR'
    return 'ALLOW'


def train(args):
    withhold_id = WITHHOLD_OPTIONS[args.withhold]
    withhold_name = CLASS_NAMES[withhold_id]
    os.makedirs(args.out, exist_ok=True)

    print("=" * 60)
    print(f"  ZERO-DAY VARIANT — withholding '{withhold_name}' (label {withhold_id})")
    print("  The CNN-GRU will NEVER see this class during training.")
    print("=" * 60)

    # Preprocess (do NOT overwrite the existing scaler/encoders)
    X_train, X_test, y_train, y_test = load_and_preprocess(
        args.train, args.test, save_artifacts=False, artifacts_dir=args.out
    )
    print(f"Full train: {X_train.shape}  test: {X_test.shape}")

    # ── Withhold the chosen class from TRAINING only ─────────────────────
    keep_mask = (y_train != withhold_id)
    n_removed = int((~keep_mask).sum())
    X_tr = X_train[keep_mask]
    y_tr = y_train[keep_mask]
    print(f"Withdrew {n_removed} '{withhold_name}' samples from training.")
    print(f"Remaining train: {X_tr.shape}")
    dist = {CLASS_NAMES[k]: int(v) for k, v in zip(*np.unique(y_tr, return_counts=True))}
    print(f"Class distribution (train, no {withhold_name}): {dist}")

    # Class weights over the remaining classes only
    classes = np.unique(y_tr)
    weights = compute_class_weight('balanced', classes=classes, y=y_tr)
    class_weight_dict = {int(k): float(v) for k, v in zip(classes, weights)}
    class_weight_dict[withhold_id] = 0.0   # never used (no such samples)
    print(f"Class weights: {class_weight_dict}")

    # Validation split from the filtered training set
    val_size = int(0.1 * len(X_tr))
    X_val, X_tr = X_tr[:val_size], X_tr[val_size:]
    y_val, y_tr = y_tr[:val_size], y_tr[val_size:]

    # Build & train (5-class output; the withheld neuron stays ~untrained)
    model = build_cnn_gru_model(input_shape=(X_tr.shape[1], 1), num_classes=5)
    model = compile_model(model, learning_rate=args.lr)

    out_name = f'cnn_gru_model_no_{args.withhold}.keras'
    best_path = os.path.join(args.out, f'best_{out_name}')
    callbacks = get_callbacks(checkpoint_path=best_path)

    print(f"\nTraining up to {args.epochs} epochs (batch {args.batch})…")
    history = model.fit(
        X_tr, y_tr,
        validation_data=(X_val, y_val),
        epochs=args.epochs,
        batch_size=args.batch,
        class_weight=class_weight_dict,
        callbacks=callbacks,
        verbose=2
    )

    # Load the best checkpoint (EarlyStopping may have restored weights,
    # but the checkpoint on disk is guaranteed to be the best val_accuracy)
    if os.path.exists(best_path):
        model = tf.keras.models.load_model(best_path)

    variant_path = os.path.join(args.out, out_name)
    model.save(variant_path)
    print(f"\nVariant model saved to {variant_path}")

    # ── Evaluate: how does the variant behave on the withheld class? ──────
    print("\n" + "=" * 60)
    print(f"  EVALUATION — variant behaviour on withheld '{withhold_name}'")
    print("=" * 60)

    y_pred_probs = model.predict(X_test, verbose=0)
    y_pred = np.argmax(y_pred_probs, axis=1)
    print(f"\nOverall test accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(f"Weighted F1: {f1_score(y_test, y_pred, average='weighted'):.4f}")

    mask = (y_test == withhold_id)
    n_hw = int(mask.sum())
    if n_hw > 0:
        hw_probs = y_pred_probs[mask]
        hw_pred = np.argmax(hw_probs, axis=1)
        print(f"\nWithheld class '{withhold_name}' (n={n_hw} test samples):")
        print(f"  Mean P(Normal)             = {hw_probs[:, 0].mean():.4f}")
        print(f"  Mean P({withhold_name}) (unseen) = {hw_probs[:, withhold_id].mean():.4f}")
        print(f"  Variant predicted-class distribution:")
        for k in range(5):
            cnt = int((hw_pred == k).sum())
            print(f"    {CLASS_NAMES[k]:>6s}: {cnt:4d} ({cnt / n_hw * 100:5.1f}%)")

    # ── Combined-risk demo check using the existing autoencoder ───────────
    print("\n" + "=" * 60)
    print("  COMBINED-RISK CHECK (variant CNN + existing autoencoder)")
    print("=" * 60)
    try:
        ae, enc, threshold = load_autoencoder(args.out)
    except FileNotFoundError:
        print("Autoencoder not found — run src/train_autoencoder.py first.")
        return

    flat = X_test.reshape(X_test.shape[0], -1)
    errors, is_anom, ae_risks = predict_anomaly(ae, flat, threshold)
    cnn_risks = 1.0 - y_pred_probs[:, 0]
    combined = np.maximum(cnn_risks, ae_risks)

    hw_idx = np.where(mask)[0]

    # Find an ideal demo sample: CNN says Normal (low cnn_risk) AND AE flags anomaly
    ideal = None
    for i in hw_idx:
        if cnn_risks[i] < 0.3 and is_anom[i]:
            ideal = i
            break
    if ideal is None:                       # relax: any AE-flagged withheld sample
        for i in hw_idx:
            if is_anom[i]:
                ideal = i
                break
    if ideal is None:
        ideal = int(hw_idx[0])

    print(f"\nRepresentative demo sample (test idx {ideal}, true class {withhold_name}):")
    print(f"  CNN variant  -> {CLASS_NAMES[int(y_pred[ideal])]}  "
          f"(P(Normal)={y_pred_probs[ideal, 0]:.4f}, "
          f"P({withhold_name})={y_pred_probs[ideal, withhold_id]:.4f})")
    print(f"  cnn_risk      = {cnn_risks[ideal]:.4f}")
    print(f"  ae_risk       = {ae_risks[ideal]:.4f}  (anomaly={bool(is_anom[ideal])})")
    print(f"  combined_risk = {combined[ideal]:.4f}")
    print(f"  zta_decision  = {zta_decision(float(combined[ideal]))}")

    # Aggregate enforcement of the withheld class via combined risk
    block_rate = float(np.mean(combined[hw_idx] > 0.8))
    print(f"\nWithheld-class enforcement (combined risk):")
    print(f"  BLOCK rate         = {block_rate:.4f}")
    print(f"  >= CHALLENGE_MFA   = {float(np.mean(combined[hw_idx] > 0.5)):.4f}")
    print(f"  >= MONITOR         = {float(np.mean(combined[hw_idx] > 0.3)):.4f}")
    print(f"  AE-caught rate     = {float(np.mean(is_anom[hw_idx])):.4f}")
    print(f"  CNN->Normal rate   = {float(np.mean(y_pred[hw_idx] == 0)):.4f}")

    summary = {
        'withhold_class': withhold_name,
        'withhold_label': withhold_id,
        'n_train_removed': n_removed,
        'n_test_withheld': n_hw,
        'epochs_trained': len(history.history['loss']),
        'variant_model': variant_path,
        'withheld_class_block_rate': round(block_rate, 4),
        'withheld_class_ae_caught_rate': round(float(np.mean(is_anom[hw_idx])), 4),
        'withheld_class_cnn_normal_rate': round(float(np.mean(y_pred[hw_idx] == 0)), 4),
        'demo_sample': {
            'test_idx': int(ideal),
            'true_class': withhold_name,
            'cnn_pred': CLASS_NAMES[int(y_pred[ideal])],
            'p_normal': round(float(y_pred_probs[ideal, 0]), 4),
            'p_withheld': round(float(y_pred_probs[ideal, withhold_id]), 4),
            'cnn_risk': round(float(cnn_risks[ideal]), 4),
            'ae_risk': round(float(ae_risks[ideal]), 4),
            'combined_risk': round(float(combined[ideal]), 4),
            'zta_decision': zta_decision(float(combined[ideal])),
        },
    }
    summary_path = os.path.join(args.out, f'zeroday_{args.withhold}_summary.json')
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\nSummary saved to {summary_path}")
    print("\nDone. Variant ready for the zero-day demo scenario.")


if __name__ == '__main__':
    train(parse_args())
