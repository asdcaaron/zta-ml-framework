"""
autoencoder.py
--------------
Self-supervised anomaly detection via a deep autoencoder.

How it works (self-supervised learning):
  - Trained ONLY on normal traffic (no attack labels needed)
  - Learns to compress and reconstruct normal connection patterns
  - At inference: high reconstruction error = anomaly (unknown/zero-day attack)
  - Low reconstruction error = normal traffic

This complements the supervised CNN-GRU model:
  CNN-GRU   → classifies KNOWN attacks (DoS, Probe, R2L, U2R)
  Autoencoder → detects UNKNOWN/zero-day anomalies without any labels

Together they form the "Risk-Adaptive" dual-layer detection system:

  Raw traffic features
        │
        ├──► CNN-GRU ──────► known attack class + risk score
        │
        └──► Autoencoder ──► reconstruction error → anomaly score
                │
                └──► Combined risk score → ZTA enforcement action

Classes:
  None — fully unsupervised / self-supervised

Usage:
    from src.autoencoder import build_autoencoder, train_autoencoder
    from src.autoencoder import compute_threshold, predict_anomaly
"""

import os
import numpy as np
import tensorflow as tf
from tensorflow.keras import layers, Model, regularizers
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


# ── Model definition ──────────────────────────────────────────────────────────

def build_autoencoder(input_dim: int = 40,
                      encoding_dim: int = 16,
                      dropout_rate: float = 0.2) -> Model:
    """
    Build a deep autoencoder for self-supervised anomaly detection.

    Architecture:
      Encoder: input_dim → 32 → 16 → encoding_dim
      Decoder: encoding_dim → 16 → 32 → input_dim

    Parameters
    ----------
    input_dim    : number of input features (40 after noise removal)
    encoding_dim : bottleneck dimension — forces compact representation
    dropout_rate : dropout for regularisation

    Returns
    -------
    autoencoder : full model (encoder + decoder)
    encoder     : just the encoder half (for feature extraction)
    """
    # ── Encoder ───────────────────────────────────────────────────────────
    enc_input = tf.keras.Input(shape=(input_dim,), name='encoder_input')

    x = layers.Dense(128, activation='relu',
                     kernel_regularizer=regularizers.l2(1e-4),
                     name='enc_dense1')(enc_input)
    x = layers.BatchNormalization(name='enc_bn1')(x)
    x = layers.Dropout(dropout_rate, name='enc_drop1')(x)

    x = layers.Dense(64, activation='relu',
                     kernel_regularizer=regularizers.l2(1e-4),
                     name='enc_dense2')(x)
    x = layers.BatchNormalization(name='enc_bn2')(x)
    x = layers.Dropout(dropout_rate, name='enc_drop2')(x)

    x = layers.Dense(32, activation='relu',
                     name='enc_dense3')(x)

    encoded = layers.Dense(encoding_dim, activation='relu',
                           name='bottleneck')(x)

    encoder = Model(enc_input, encoded, name='Encoder')

    # ── Decoder ───────────────────────────────────────────────────────────
    dec_input = tf.keras.Input(shape=(encoding_dim,), name='decoder_input')

    x = layers.Dense(32, activation='relu',
                     name='dec_dense1')(dec_input)

    x = layers.Dense(64, activation='relu',
                     kernel_regularizer=regularizers.l2(1e-4),
                     name='dec_dense2')(x)
    x = layers.BatchNormalization(name='dec_bn1')(x)
    x = layers.Dropout(dropout_rate, name='dec_drop1')(x)

    x = layers.Dense(128, activation='relu',
                     kernel_regularizer=regularizers.l2(1e-4),
                     name='dec_dense3')(x)
    x = layers.BatchNormalization(name='dec_bn2')(x)
    x = layers.Dropout(dropout_rate, name='dec_drop2')(x)

    decoded = layers.Dense(input_dim, activation='sigmoid',
                           name='reconstruction')(x)

    decoder = Model(dec_input, decoded, name='Decoder')

    # ── Full autoencoder ───────────────────────────────────────────────────
    ae_input = tf.keras.Input(shape=(input_dim,), name='ae_input')
    encoded_repr = encoder(ae_input)
    reconstructed = decoder(encoded_repr)

    autoencoder = Model(ae_input, reconstructed, name='Autoencoder_IDS')

    return autoencoder, encoder


def compile_autoencoder(autoencoder: Model,
                        learning_rate: float = 0.001) -> Model:
    """
    Compile the autoencoder with MSE reconstruction loss.
    MSE measures how different the reconstruction is from the original.
    High MSE = anomaly.
    """
    autoencoder.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=learning_rate),
        loss='mse',
        metrics=['mae']
    )
    return autoencoder


# ── Training ──────────────────────────────────────────────────────────────────

def train_autoencoder(X_train: np.ndarray,
                      y_train: np.ndarray,
                      out_dir: str = 'data',
                      epochs: int = 50,
                      batch_size: int = 256,
                      encoding_dim: int = 16) -> tuple:
    """
    Train the autoencoder on NORMAL traffic only (self-supervised).

    The model never sees attack labels — it learns purely from
    the structure of normal connection patterns.

    Parameters
    ----------
    X_train    : full training set (N, 40, 1) or (N, 40)
    y_train    : labels — used ONLY to filter normal samples
    out_dir    : directory to save model and artifacts
    epochs     : max training epochs
    batch_size : batch size

    Returns
    -------
    autoencoder, encoder, history, threshold
    """
    os.makedirs(out_dir, exist_ok=True)

    # Flatten if coming from CNN-GRU format (N, 40, 1) → (N, 40)
    if X_train.ndim == 3:
        X_flat = X_train.reshape(X_train.shape[0], -1)
    else:
        X_flat = X_train.copy()

    input_dim = X_flat.shape[1]

    # ── Self-supervised: train on NORMAL samples only ──────────────────────
    normal_mask = (y_train == 0)
    X_normal    = X_flat[normal_mask]
    print(f"[autoencoder] Training on {X_normal.shape[0]:,} normal samples "
          f"(self-supervised — no attack labels used)")
    print(f"[autoencoder] Input dim: {input_dim}  Encoding dim: {encoding_dim}")

    # Validation split from normal samples
    val_size  = int(0.1 * len(X_normal))
    X_val_ae  = X_normal[:val_size]
    X_tr_ae   = X_normal[val_size:]

    # Build and compile
    autoencoder, encoder = build_autoencoder(
        input_dim=input_dim, encoding_dim=encoding_dim
    )
    autoencoder = compile_autoencoder(autoencoder)
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
            filepath=os.path.join(out_dir, 'best_autoencoder.keras'),
            monitor='val_loss', save_best_only=True, verbose=0
        ),
    ]

    history = autoencoder.fit(
        X_tr_ae, X_tr_ae,          # input = target (reconstruction task)
        validation_data=(X_val_ae, X_val_ae),
        epochs=epochs,
        batch_size=batch_size,
        callbacks=callbacks,
        verbose=1
    )

    # ── Compute anomaly threshold ──────────────────────────────────────────
    # Threshold = 95th percentile of reconstruction errors on normal traffic
    # Anything above this is flagged as anomalous
    threshold = compute_threshold(autoencoder, X_normal, percentile=95)
    print(f"[autoencoder] Anomaly threshold (95th pct): {threshold:.6f}")

    # Save
    autoencoder.save(os.path.join(out_dir, 'autoencoder_model.keras'))
    encoder.save(os.path.join(out_dir, 'encoder_model.keras'))
    joblib.dump(threshold, os.path.join(out_dir, 'ae_threshold.pkl'))
    print(f"[autoencoder] Models saved to '{out_dir}/'")

    # Plot training curves
    _plot_ae_history(history, out_dir)

    return autoencoder, encoder, history, threshold


# ── Threshold computation ─────────────────────────────────────────────────────

def compute_threshold(autoencoder: Model,
                      X_normal: np.ndarray,
                      percentile: int = 95) -> float:
    """
    Compute the anomaly detection threshold from normal traffic.

    Sets threshold at the Nth percentile of reconstruction errors
    on the training normal set. Connections above this threshold
    are considered anomalous.

    percentile=95 means 95% of normal traffic is below the threshold,
    giving a ~5% false positive rate on normal data.
    """
    recon = autoencoder.predict(X_normal, verbose=0)
    errors = np.mean(np.square(X_normal - recon), axis=1)
    threshold = float(np.percentile(errors, percentile))
    return threshold


# ── Inference ─────────────────────────────────────────────────────────────────

def predict_anomaly(autoencoder: Model,
                    X: np.ndarray,
                    threshold: float) -> tuple:
    """
    Predict whether each sample is anomalous.

    Parameters
    ----------
    autoencoder : trained autoencoder model
    X           : input samples shape (N, input_dim)
    threshold   : reconstruction error threshold

    Returns
    -------
    errors      : per-sample MSE reconstruction errors
    is_anomaly  : boolean array, True = anomaly detected
    risk_scores : normalised anomaly scores in [0, 1]
    """
    if X.ndim == 3:
        X = X.reshape(X.shape[0], -1)

    recon  = autoencoder.predict(X, verbose=0)
    errors = np.mean(np.square(X - recon), axis=1)

    is_anomaly = errors > threshold

    # Normalise to [0,1] risk score — capped at 3× threshold for stability
    risk_scores = np.clip(errors / (3.0 * threshold + 1e-9), 0, 1)

    return errors, is_anomaly, risk_scores


def load_autoencoder(out_dir: str = 'data') -> tuple:
    """Load saved autoencoder model, encoder, and threshold."""
    ae_path  = os.path.join(out_dir, 'autoencoder_model.keras')
    enc_path = os.path.join(out_dir, 'encoder_model.keras')
    thr_path = os.path.join(out_dir, 'ae_threshold.pkl')

    if not os.path.exists(ae_path):
        raise FileNotFoundError(
            f"Autoencoder not found at '{ae_path}'. "
            "Run src/train.py first."
        )

    autoencoder = tf.keras.models.load_model(ae_path)
    encoder     = tf.keras.models.load_model(enc_path)
    threshold   = joblib.load(thr_path)

    return autoencoder, encoder, threshold


# ── Evaluation helper ─────────────────────────────────────────────────────────

def evaluate_autoencoder(autoencoder: Model,
                         X_test: np.ndarray,
                         y_test: np.ndarray,
                         threshold: float) -> dict:
    """
    Evaluate autoencoder on the test set.
    Treats any attack (y > 0) as positive (anomaly).
    """
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, confusion_matrix
    )

    if X_test.ndim == 3:
        X_flat = X_test.reshape(X_test.shape[0], -1)
    else:
        X_flat = X_test.copy()

    errors, is_anomaly, risk_scores = predict_anomaly(
        autoencoder, X_flat, threshold
    )

    y_binary = (y_test > 0).astype(int)
    y_pred   = is_anomaly.astype(int)

    cm = confusion_matrix(y_binary, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2,2) else (0,0,0,0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    results = {
        'accuracy':          round(accuracy_score(y_binary, y_pred), 4),
        'precision':         round(precision_score(y_binary, y_pred,
                                   zero_division=0), 4),
        'recall':            round(recall_score(y_binary, y_pred,
                                   zero_division=0), 4),
        'f1_score':          round(f1_score(y_binary, y_pred,
                                   zero_division=0), 4),
        'false_positive_rate': round(fpr, 4),
        'threshold':         round(threshold, 6),
        'mean_normal_error': round(float(np.mean(errors[y_test == 0])), 6),
        'mean_attack_error': round(float(np.mean(errors[y_test > 0])), 6),
    }

    print("\n[autoencoder] Evaluation Results:")
    print(f"  Accuracy  : {results['accuracy']}")
    print(f"  Precision : {results['precision']}")
    print(f"  Recall    : {results['recall']}")
    print(f"  F1 Score  : {results['f1_score']}")
    print(f"  FPR       : {results['false_positive_rate']}")
    print(f"  Mean reconstruction error (normal) : {results['mean_normal_error']}")
    print(f"  Mean reconstruction error (attack) : {results['mean_attack_error']}")

    return results


# ── Plot helpers ──────────────────────────────────────────────────────────────

def _plot_ae_history(history, out_dir: str):
    hist = history.history
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(hist.get('loss', []),     label='Train Loss (MSE)', linewidth=2)
    ax.plot(hist.get('val_loss', []), label='Val Loss (MSE)',   linewidth=2)
    ax.set_title('Autoencoder Training — Reconstruction Loss', fontsize=13)
    ax.set_xlabel('Epoch')
    ax.set_ylabel('MSE Loss')
    ax.legend()
    ax.grid(True)
    plt.tight_layout()
    path = os.path.join(out_dir, 'autoencoder_training_curves.png')
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"[autoencoder] Training curves saved to {path}")


def plot_reconstruction_errors(autoencoder: Model,
                               X_test: np.ndarray,
                               y_test: np.ndarray,
                               threshold: float,
                               out_dir: str = 'data'):
    """
    Plot reconstruction error distributions for normal vs attack traffic.
    Shows visually how well the threshold separates the two.
    """
    if X_test.ndim == 3:
        X_flat = X_test.reshape(X_test.shape[0], -1)
    else:
        X_flat = X_test.copy()

    recon  = autoencoder.predict(X_flat, verbose=0)
    errors = np.mean(np.square(X_flat - recon), axis=1)

    normal_errors = errors[y_test == 0]
    attack_errors = errors[y_test > 0]

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.hist(normal_errors, bins=100, alpha=0.6,
            label='Normal Traffic', color='#2ecc71', density=True)
    ax.hist(attack_errors, bins=100, alpha=0.6,
            label='Attack Traffic', color='#e74c3c', density=True)
    ax.axvline(threshold, color='#2c3e50', linestyle='--',
               linewidth=2, label=f'Threshold = {threshold:.5f}')
    ax.set_title('Autoencoder Reconstruction Error Distribution\n'
                 'Self-Supervised Anomaly Detection', fontsize=13)
    ax.set_xlabel('Reconstruction Error (MSE)')
    ax.set_ylabel('Density')
    ax.legend()
    ax.set_xlim(0, min(threshold * 5, errors.max()))
    ax.grid(True, alpha=0.4)
    plt.tight_layout()
    path = os.path.join(out_dir, 'reconstruction_error_distribution.png')
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"[autoencoder] Error distribution plot saved to {path}")


# ── Quick sanity check ────────────────────────────────────────────────────────
if __name__ == '__main__':
    ae, enc = build_autoencoder(input_dim=40)
    ae = compile_autoencoder(ae)
    ae.summary()
    dummy = np.random.rand(8, 40).astype(np.float32)
    recon = ae.predict(dummy, verbose=0)
    errors = np.mean(np.square(dummy - recon), axis=1)
    print(f"\nDummy reconstruction errors: {errors.round(4)}")
    print("Autoencoder build OK")
