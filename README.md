# Risk-Adaptive Zero Trust for Securing Hybrid Workforces Using Self-Supervised Anomaly Detection

A dual-layer ML framework that combines a supervised CNN-GRU and a self-supervised autoencoder inside a Zero Trust policy engine to detect known and zero-day attacks in hybrid workforce networks.

**Author:** Okado Aaron Obbo — Reg No: S24B23/015 | Student No: B29782
**Degree:** BSc Computer Science | Uganda Christian University, Department of Computing & Technology
**Contact:** aaronobbo22@gmail.com | +256-750985280
**GitHub:** [github.com/asdcaaron/zta-ml-framework](https://github.com/asdcaaron/zta-ml-framework)

---

## Research Context

Hybrid workforces expose enterprise networks to ransomware, lateral movement, insider attacks, and zero-day exploits that traditional VPN perimeters cannot block. Zero Trust Architecture (ZTA) enforces strict identity and device verification, but access-layer policies are blind to traffic-level anomalies.

This project addresses the gap by pairing ZTA with two complementary ML layers:

| Layer | Model | Type | Purpose |
|---|---|---|---|
| Layer 1 | **CNN-GRU** | Supervised | Classifies known attacks: DoS, Probe, R2L, U2R |
| Layer 2 | **Autoencoder** | Self-Supervised | Detects unknown / zero-day anomalies without labels |

The dual-layer output feeds a combined **risk score (0–1)** into the ZTA policy engine, which maps each connection to an ALLOW / MONITOR / CHALLENGE_MFA / BLOCK decision in real time. The system is evaluated in a controlled four-way comparison against Legacy VPN, ZTA-Only, and ZTA+CNN-GRU baselines on the NSL-KDD benchmark dataset.

---

## System Architecture

```
  Hybrid Workforce Traffic (Remote / Office / IoT)
                │
                ▼
  ┌─────────────────────────────────────────────────┐
  │          ZTA ACCESS CONTROL LAYER               │
  │   Keycloak MFA  +  Device Posture Check         │
  │   OpenZiti      +  VLAN Micro-segmentation      │
  └─────────────────────┬───────────────────────────┘
                        │
                        ▼
  ┌─────────────────────────────────────────────────┐
  │          NETWORK MONITORING LAYER               │
  │   Zeek (Docker) → conn.log                      │
  │   40 NSL-KDD features per connection            │
  └───────────────┬─────────────────┬───────────────┘
                  │                 │
                  ▼                 ▼
       ┌──────────────┐    ┌─────────────────────┐
       │  CNN-GRU     │    │  Autoencoder         │
       │  Supervised  │    │  Self-Supervised     │
       │  Known       │    │  Zero-day / Unknown  │
       │  Attacks     │    │  Anomaly Detection   │
       └──────┬───────┘    └──────────┬───────────┘
              │                       │
              └───────────┬───────────┘
                          │
                          ▼
                 Combined Risk Score (0–1)
                          │
           ┌──────────────┼──────────────┬──────────┐
           ▼              ▼              ▼           ▼
         > 0.8         0.5–0.8        0.3–0.5      < 0.3
         BLOCK       CHALLENGE        MONITOR      ALLOW
                       MFA
```

---

## Quick start

### 1. Install dependencies

```powershell
cd "c:\Users\AARON\Desktop\Final Year Project Prototype\zta-ml-framework"
pip install -r requirements.txt
```

### 2. Download NSL-KDD dataset

Download from the University of New Brunswick:  
https://www.unb.ca/cic/datasets/nsl.html

Place in `data/`:
- `data/NSL_KDD_Train.csv`
- `data/NSL_KDD_Test.csv`

> **Note:** If the models are already trained (`.keras` files present in `data/`), skip straight to step 5.

### 3. Train both models

```powershell
python src/train.py
```

Training produces: `data/cnn_gru_model.keras`, `data/autoencoder_model.keras`, `data/ae_threshold.pkl`, `data/scaler.pkl`, `data/encoders.pkl`.

### 4. Run the four-way evaluation

```powershell
python src/evaluate.py
```

### 5. Start the risk-scoring API

```powershell
python src/api.py
# Open http://127.0.0.1:5000 in your browser
```

---

## How to Run Each Component

### Training

```powershell
# Train CNN-GRU (supervised) + Autoencoder (self-supervised) together
python src/train.py

# Train autoencoder only
python src/train_autoencoder.py
```

### Evaluation (four-way comparison)

```powershell
python src/evaluate.py
# Outputs: data/results/comparison_results.csv, comparison_bar.png, confusion_matrices.png
```

### Live Demo (Week 6 final demo)

```powershell
python src/final_demo.py
# Loads both models, runs predictions on one sample per class (5 classes),
# prints a formatted results table, and saves data/results/final_demo_output.json
```

### Threshold Sensitivity Analysis

```powershell
python src/threshold_sensitivity.py
# Sweeps anomaly threshold from 70th to 99th percentile
# Outputs: data/results/threshold_sensitivity.csv, threshold_sensitivity.png
```

### Zero-Day Recall Analysis

```powershell
python src/zeroday_recall.py
# Leave-one-class-out experiment on autoencoder zero-day detection
# Outputs: data/results/zeroday_recall.csv, zeroday_recall.png
```

### Robustness Analysis

```powershell
python src/robustness_analysis.py
# Full robustness report: threshold sweep + zero-day recall
# Outputs: data/results/robustness_report.json
```

### GNS3 / Attack Traffic Demo

```powershell
python src/generate_attack_traffic.py   # generate pcaps and conn.logs
python src/run_gns3_demo.py             # end-to-end demo orchestrator
```

### PDF Report Generators

```powershell
python generate_progress_pdf.py           # living progress report
python generate_evaluation_chapter.py     # full evaluation chapter
python generate_poster.py                 # A3 research poster
python generate_final_summary.py          # 2-page A4 final summary
```

---

## Key Results

Four-way comparison on NSL-KDD (22,543 test samples):

| System | Accuracy | F1 Score | FPR | Latency | Zero-Day |
|---|---|---|---|---|---|
| **ZTA + Autoencoder** | **0.8443** | **0.8482** | 0.0501 | **0.0656 ms/sample** | **✓** |
| ZTA + CNN-GRU | 0.7945 | 0.7886 | **0.0452** | 0.5889 ms/sample | — |
| ZTA Only | 0.7691 | 0.7677 | — | — | — |
| Legacy VPN | 0.6664 | 0.6524 | — | — | — |

**Key findings:**
- ZTA + Autoencoder achieves the highest accuracy and F1, and is ~9× faster than CNN-GRU at inference.
- The self-supervised autoencoder detects zero-day attacks without any attack labels in training.
- R2L recall is 0.287 — those connections reconstruct like normal traffic (documented limitation).
- CNN-GRU wins on FPR (0.0452 vs 0.0501).
- Both ML systems substantially outperform Legacy VPN and ZTA-Only.

---

## File and Directory Structure

```
zta-ml-framework/
├── src/
│   ├── preprocess.py              ← NSL-KDD loading, noise removal, scaling (40 features)
│   ├── model.py                   ← CNN-GRU architecture (supervised)
│   ├── autoencoder.py             ← Autoencoder architecture (self-supervised)
│   ├── train.py                   ← Trains CNN-GRU + autoencoder sequentially
│   ├── train_autoencoder.py       ← Trains autoencoder only
│   ├── evaluate.py                ← 4-way system comparison
│   ├── api.py                     ← Flask risk-scoring API (port 5000)
│   ├── zeek_capture.py            ← Zeek traffic capture + feature forwarding
│   ├── generate_attack_traffic.py ← Scapy-crafted pcaps + Zeek conn.logs
│   ├── run_gns3_demo.py           ← End-to-end GNS3 demo orchestrator
│   ├── robustness_analysis.py     ← Threshold sweep + zero-day recall analysis
│   ├── threshold_sensitivity.py   ← Autoencoder threshold sensitivity sweep
│   ├── zeroday_recall.py          ← Zero-day recall by attack class
│   └── final_demo.py              ← Week 6 standalone live demo script
├── data/
│   ├── NSL_KDD_Train.csv          ← Download separately (see Quick start)
│   ├── NSL_KDD_Test.csv
│   ├── cnn_gru_model.keras        ← Trained CNN-GRU model
│   ├── autoencoder_model.keras    ← Trained autoencoder model
│   ├── encoder_model.keras        ← Encoder sub-model
│   ├── ae_threshold.pkl           ← 95th-percentile anomaly threshold
│   ├── scaler.pkl                 ← MinMaxScaler fitted on training data
│   ├── encoders.pkl               ← LabelEncoders for categorical features
│   ├── training_results.json      ← CNN-GRU training metrics
│   ├── autoencoder_training_results.json
│   ├── training_curves.png
│   ├── autoencoder_training_curves.png
│   ├── reconstruction_error_distribution.png
│   ├── Midsemester_Summary_Okado_Aaron_Obbo.pdf
│   ├── Evaluation_Chapter_Okado_Aaron_Obbo.pdf
│   ├── Research_Poster_Okado_Aaron_Obbo.pdf
│   ├── Progress_Okado_Aaron_Obbo.pdf
│   ├── Final_Summary_Okado_Aaron_Obbo.pdf
│   ├── SUBMISSION_MANIFEST.md
│   └── results/
│       ├── comparison_results.csv
│       ├── comparison_bar.png
│       ├── confusion_matrices.png
│       ├── summary.json
│       ├── robustness_report.json
│       ├── threshold_sensitivity.csv / .png
│       ├── zeroday_recall.csv / .png
│       └── final_demo_output.json
├── notebooks/
│   ├── analysis.ipynb
│   └── week4_robustness_analysis.ipynb
├── zta/
│   ├── policies/access_policy.json
│   ├── keycloak_config/
│   └── openziti_config/
├── vpn/
│   └── openvpn_config/ (server.conf, setup.sh)
├── logs/                           ← Runtime logs
├── generate_progress_pdf.py        ← Living progress PDF generator
├── generate_midsem_pdf.py          ← Mid-semester summary PDF
├── generate_evaluation_chapter.py  ← Full evaluation chapter PDF
├── generate_poster.py              ← A3 research poster PDF
├── generate_final_summary.py       ← 2-page final summary PDF
├── demo.ps1                        ← PowerShell presentation script
├── demo_dashboard.html             ← Browser-based demo dashboard
├── requirements.txt
└── README.md
```

---

## Model Details

### CNN-GRU (Supervised — Layer 1)

| Component | Detail |
|---|---|
| Input | 40 NSL-KDD features (after noise removal) |
| Architecture | Conv1D(64→128→256) + GRU(128→64) + Dense(128→64→5) |
| Parameters | ~327,685 (1.25 MB) |
| Output | 5-class softmax: Normal, DoS, Probe, R2L, U2R |
| Training | 125,973 labelled samples, class-weighted, 50 epochs |
| Test accuracy | 0.7945 |

### Autoencoder (Self-Supervised — Layer 2)

| Component | Detail |
|---|---|
| Input | 40 features (flattened) |
| Architecture | Encoder: 40→128→64→16 | Decoder: 16→64→128→40 |
| Training data | Normal traffic only (67,343 samples — no attack labels) |
| Threshold | 95th percentile of normal reconstruction errors (0.002682) |
| Anomaly rule | MSE reconstruction error > threshold → ANOMALY |
| Test accuracy | 0.8443 |

---

## API Reference

### `POST /predict`

```json
{
  "features": {
    "duration": 0, "protocol_type": "tcp",
    "service": "http", "flag": "SF",
    "src_bytes": 232, "dst_bytes": 8153
  }
}
```

**Response:**

```json
{
  "risk_score": 0.12,
  "classification": "Normal",
  "confidence": 0.88,
  "action": "ALLOW",
  "latency_ms": 3.4
}
```

### Risk Score → ZTA Action

| Risk Score | Action | Meaning |
|---|---|---|
| > 0.8 | **BLOCK** | High-confidence attack — session terminated |
| 0.5 – 0.8 | **CHALLENGE_MFA** | Suspicious — re-authentication required |
| 0.3 – 0.5 | **MONITOR** | Anomalous — flagged and watched |
| < 0.3 | **ALLOW** | Normal traffic — permitted |

Other endpoints: `GET /` (dashboard), `GET /health`, `GET /model/info`, `POST /predict/batch`.

---

## References

1. Gambo & Almulhem (2026). Zero Trust Architecture: A Systematic Literature Review. *Journal of Network and Systems Management*, 34(1).
2. Zohaib et al. (2024). Zero Trust VPN (ZT-VPN). *Information*, 15(11).
3. Bakhshi & Ghita (2021). Anomaly Detection in Encrypted Internet Traffic Using Hybrid Deep Learning. *Security and Communication Networks*.
4. Kim et al. (2024). Exploring Effective Zero Trust Architecture for Defense Cybersecurity. *KSII Transactions on Internet and Information Systems*, 18(7).
5. Abdelhady et al. (2026). Hybrid ML Anomaly Detection and Lightweight ZTA for LoRaWAN. *IEEE Access*, 14.
6. Tian et al. (2024). S4: Self-Supervised Learning with Sparse-Dense Sampling. *Knowledge-Based Systems*.
7. Dhumal et al. (2025). ZTA for Ransomware Defense in Virtualized Environments. *IEEE/ACM BigData*.

---

## Author and Acknowledgements

**Okado Aaron Obbo**
Reg No: S24B23/015 | Student No: B29782
BSc Computer Science
Uganda Christian University, Department of Computing & Technology
GitHub: [github.com/asdcaaron/zta-ml-framework](https://github.com/asdcaaron/zta-ml-framework)

Submitted as academic research at Uganda Christian University. For research and educational use only.

Thanks to the University of New Brunswick for the NSL-KDD dataset, and to the UCU Department of Computing & Technology for supervision and support throughout this project.
