"""
model.py
--------
CNN-GRU hybrid neural network for network intrusion detection.

Architecture:
  Input (41, 1)
    → Conv1D block  (extract local feature patterns)
    → GRU block     (capture sequential / temporal patterns)
    → Dense head    (5-class softmax output)

Classes:
  0 = Normal
  1 = DoS
  2 = Probe
  3 = R2L
  4 = U2R

Usage:
    from src.model import build_cnn_gru_model
    model = build_cnn_gru_model()
    model.summary()
"""

import tensorflow as tf
from tensorflow.keras import layers, Model, regularizers


# ── Model definition ──────────────────────────────────────────────────────────

def build_cnn_gru_model(input_shape: tuple = (40, 1),
                        num_classes: int = 5,
                        dropout_rate: float = 0.3,
                        l2_reg: float = 1e-4) -> Model:
    """
    Build and return the CNN-GRU hybrid model.

    Parameters
    ----------
    input_shape  : (timesteps, channels) — (41, 1) for NSL-KDD
    num_classes  : number of output classes (5)
    dropout_rate : dropout probability for regularisation
    l2_reg       : L2 regularisation factor

    Returns
    -------
    tf.keras.Model (uncompiled)
    """
    inputs = tf.keras.Input(shape=input_shape, name='network_features')

    # ── CNN Block 1: local pattern extraction ─────────────────────────────
    x = layers.Conv1D(
        filters=64,
        kernel_size=3,
        padding='same',
        activation='relu',
        kernel_regularizer=regularizers.l2(l2_reg),
        name='conv1'
    )(inputs)
    x = layers.BatchNormalization(name='bn1')(x)
    x = layers.Dropout(dropout_rate, name='drop1')(x)

    # ── CNN Block 2: deeper feature extraction ────────────────────────────
    x = layers.Conv1D(
        filters=128,
        kernel_size=3,
        padding='same',
        activation='relu',
        kernel_regularizer=regularizers.l2(l2_reg),
        name='conv2'
    )(x)
    x = layers.BatchNormalization(name='bn2')(x)
    x = layers.MaxPooling1D(pool_size=2, name='pool1')(x)
    x = layers.Dropout(dropout_rate, name='drop2')(x)

    # ── CNN Block 3: high-level feature maps ──────────────────────────────
    x = layers.Conv1D(
        filters=256,
        kernel_size=3,
        padding='same',
        activation='relu',
        kernel_regularizer=regularizers.l2(l2_reg),
        name='conv3'
    )(x)
    x = layers.BatchNormalization(name='bn3')(x)
    x = layers.Dropout(dropout_rate, name='drop3')(x)

    # ── GRU Block 1: sequence modelling ───────────────────────────────────
    x = layers.GRU(
        128,
        return_sequences=True,
        kernel_regularizer=regularizers.l2(l2_reg),
        name='gru1'
    )(x)
    x = layers.Dropout(dropout_rate, name='drop4')(x)

    # ── GRU Block 2: final context summarisation ──────────────────────────
    x = layers.GRU(
        64,
        return_sequences=False,
        kernel_regularizer=regularizers.l2(l2_reg),
        name='gru2'
    )(x)
    x = layers.Dropout(dropout_rate, name='drop5')(x)

    # ── Dense classification head ─────────────────────────────────────────
    x = layers.Dense(
        128,
        activation='relu',
        kernel_regularizer=regularizers.l2(l2_reg),
        name='dense1'
    )(x)
    x = layers.Dropout(dropout_rate / 2, name='drop6')(x)

    x = layers.Dense(
        64,
        activation='relu',
        kernel_regularizer=regularizers.l2(l2_reg),
        name='dense2'
    )(x)

    outputs = layers.Dense(
        num_classes,
        activation='softmax',
        name='output'
    )(x)

    model = Model(inputs=inputs, outputs=outputs, name='CNN_GRU_IDS')
    return model


def compile_model(model: Model,
                  learning_rate: float = 0.001) -> Model:
    """
    Compile the model with Adam optimizer and categorical cross-entropy.

    Parameters
    ----------
    model         : uncompiled Keras model
    learning_rate : initial learning rate

    Returns
    -------
    compiled Keras model
    """
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=learning_rate),
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
        # Precision/Recall computed post-training via sklearn
        # (Keras 3 built-in P/R metrics conflict with sparse multi-class labels)
    )
    return model


def get_callbacks(checkpoint_path: str = 'data/best_model.h5',
                  patience_es: int = 10,
                  patience_lr: int = 5) -> list:
    """
    Return standard training callbacks:
      - EarlyStopping
      - ReduceLROnPlateau
      - ModelCheckpoint
    """
    callbacks = [
        tf.keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=patience_es,
            restore_best_weights=True,
            verbose=1
        ),
        tf.keras.callbacks.ReduceLROnPlateau(
            monitor='val_loss',
            factor=0.5,
            patience=patience_lr,
            min_lr=1e-6,
            verbose=1
        ),
        tf.keras.callbacks.ModelCheckpoint(
            filepath=checkpoint_path,
            monitor='val_accuracy',
            save_best_only=True,
            verbose=1
        ),
    ]
    return callbacks


# ── Risk scoring helper ───────────────────────────────────────────────────────

CLASS_NAMES = {
    0: 'Normal',
    1: 'DoS',
    2: 'Probe',
    3: 'R2L',
    4: 'U2R'
}


def score_to_risk(probabilities: list) -> dict:
    """
    Convert model output probabilities to a risk score and ZTA action.

    Parameters
    ----------
    probabilities : list of 5 floats (softmax output)

    Returns
    -------
    dict with risk_score, classification, confidence, action
    """
    import numpy as np
    probs = np.array(probabilities)
    predicted_class = int(np.argmax(probs))
    risk_score = float(1.0 - probs[0])   # 1 - P(Normal)

    if risk_score > 0.8:
        action = 'BLOCK'
    elif risk_score > 0.5:
        action = 'CHALLENGE_MFA'
    elif risk_score > 0.3:
        action = 'MONITOR'
    else:
        action = 'ALLOW'

    return {
        'risk_score':     round(risk_score, 4),
        'classification': CLASS_NAMES[predicted_class],
        'confidence':     round(float(np.max(probs)), 4),
        'action':         action
    }


# ── Quick sanity check ────────────────────────────────────────────────────────

if __name__ == '__main__':
    model = build_cnn_gru_model()
    model = compile_model(model)
    model.summary()

    # Dummy forward pass
    import numpy as np
    dummy = np.random.rand(4, 40, 1).astype(np.float32)
    preds = model.predict(dummy, verbose=0)
    print(f"\nDummy prediction shape: {preds.shape}")
    print(f"Sample risk score: {score_to_risk(preds[0])}")
