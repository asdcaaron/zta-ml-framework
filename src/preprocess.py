"""
preprocess.py
-------------
NSL-KDD dataset loading, cleaning, encoding, and splitting.
Produces train/test arrays ready for the CNN-GRU model.

Usage:
    from src.preprocess import load_and_preprocess
    X_train, X_test, y_train, y_test = load_and_preprocess(
        'data/NSL_KDD_Train.csv',
        'data/NSL_KDD_Test.csv'
    )
"""

import pandas as pd
import numpy as np
import joblib
import os
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split

# ── Column names for the NSL-KDD dataset ──────────────────────────────────────
COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
    'label', 'difficulty'
]

FEATURE_COLS = [c for c in COLUMNS if c not in ['label', 'difficulty']]

CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']

# ── Attack-to-category mapping (5-class problem) ──────────────────────────────
ATTACK_MAP = {
    # Normal
    'normal':           0,
    # DoS
    'neptune':          1, 'back':          1, 'land':        1,
    'pod':              1, 'smurf':         1, 'teardrop':    1,
    'apache2':          1, 'udpstorm':      1, 'processtable':1,
    'worm':             1, 'mailbomb':      1,
    # Probe
    'ipsweep':          2, 'nmap':          2, 'portsweep':   2,
    'satan':            2, 'mscan':         2, 'saint':       2,
    # R2L
    'ftp_write':        3, 'guess_passwd':  3, 'imap':        3,
    'multihop':         3, 'phf':           3, 'spy':         3,
    'warezclient':      3, 'warezmaster':   3, 'sendmail':    3,
    'named':            3, 'snmpgetattack': 3, 'snmpguess':   3,
    'xlock':            3, 'xsnoop':        3, 'httptunnel':  3,
    # U2R
    'buffer_overflow':  4, 'loadmodule':    4, 'perl':        4,
    'rootkit':          4, 'ps':            4, 'sqlattack':   4,
    'xterm':            4,
}

CLASS_NAMES = {
    0: 'Normal',
    1: 'DoS',
    2: 'Probe',
    3: 'R2L',
    4: 'U2R'
}


def load_and_preprocess(train_path: str,
                        test_path: str,
                        save_artifacts: bool = True,
                        artifacts_dir: str = 'data'):
    """
    Load NSL-KDD train and test CSVs, encode, scale, and reshape.

    Parameters
    ----------
    train_path     : path to KDDTrain+.csv
    test_path      : path to KDDTest+.csv
    save_artifacts : if True, saves scaler and encoders to disk
    artifacts_dir  : directory to save/load preprocessing artifacts

    Returns
    -------
    X_train, X_test : np.ndarray of shape (N, 41, 1)
    y_train, y_test : np.ndarray of integer class labels
    """
    print("[preprocess] Loading data...")
    train_df = pd.read_csv(train_path, names=COLUMNS)
    test_df  = pd.read_csv(test_path,  names=COLUMNS)

    # ── Map string labels to integer categories ────────────────────────────
    train_df['label'] = train_df['label'].str.strip().str.lower()
    test_df['label']  = test_df['label'].str.strip().str.lower()

    train_df['label'] = train_df['label'].map(
        lambda x: ATTACK_MAP.get(x, 0)
    )
    test_df['label'] = test_df['label'].map(
        lambda x: ATTACK_MAP.get(x, 0)
    )

    # ── Encode categorical columns ─────────────────────────────────────────
    encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        train_df[col] = le.fit_transform(train_df[col].astype(str))
        # Handle unseen categories in test set
        test_df[col] = test_df[col].astype(str).map(
            lambda x, le=le: le.transform([x])[0]
            if x in le.classes_ else 0
        )
        encoders[col] = le

    # ── Scale numerical features ───────────────────────────────────────────
    scaler = MinMaxScaler()
    X_train = scaler.fit_transform(train_df[FEATURE_COLS].values)
    X_test  = scaler.transform(test_df[FEATURE_COLS].values)

    y_train = train_df['label'].values.astype(np.int32)
    y_test  = test_df['label'].values.astype(np.int32)

    # ── Reshape for CNN-GRU: (samples, timesteps, channels) ───────────────
    X_train = X_train.reshape(-1, 41, 1)
    X_test  = X_test.reshape(-1, 41, 1)

    # ── Save artifacts ─────────────────────────────────────────────────────
    if save_artifacts:
        os.makedirs(artifacts_dir, exist_ok=True)
        joblib.dump(scaler,   os.path.join(artifacts_dir, 'scaler.pkl'))
        joblib.dump(encoders, os.path.join(artifacts_dir, 'encoders.pkl'))
        print(f"[preprocess] Artifacts saved to '{artifacts_dir}/'")

    print(f"[preprocess] Train: {X_train.shape}, Test: {X_test.shape}")
    print(f"[preprocess] Class distribution (train): "
          f"{ {CLASS_NAMES[k]: int(v) for k, v in zip(*np.unique(y_train, return_counts=True))} }")

    return X_train, X_test, y_train, y_test


def preprocess_single_sample(feature_dict: dict,
                              artifacts_dir: str = 'data') -> np.ndarray:
    """
    Preprocess a single live traffic sample for real-time inference.

    Parameters
    ----------
    feature_dict  : dict with keys matching FEATURE_COLS
    artifacts_dir : directory containing saved scaler and encoders

    Returns
    -------
    np.ndarray of shape (1, 41, 1)
    """
    scaler   = joblib.load(os.path.join(artifacts_dir, 'scaler.pkl'))
    encoders = joblib.load(os.path.join(artifacts_dir, 'encoders.pkl'))

    row = []
    for col in FEATURE_COLS:
        val = feature_dict.get(col, 0)
        if col in CATEGORICAL_COLS:
            le = encoders[col]
            val = le.transform([str(val)])[0] if str(val) in le.classes_ else 0
        row.append(float(val))

    sample = np.array(row).reshape(1, -1)
    sample = scaler.transform(sample)
    sample = sample.reshape(1, 41, 1)
    return sample


if __name__ == '__main__':
    # Quick test — expects data files to exist
    X_tr, X_te, y_tr, y_te = load_and_preprocess(
        'data/NSL_KDD_Train.csv',
        'data/NSL_KDD_Test.csv'
    )
    print("Preprocessing complete.")
    print(f"X_train: {X_tr.shape}  y_train: {y_tr.shape}")
    print(f"X_test:  {X_te.shape}  y_test:  {y_te.shape}")
