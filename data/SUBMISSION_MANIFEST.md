# Submission Manifest

**Project:** Risk-Adaptive Zero Trust for Securing Hybrid Workforces Using Self-Supervised Anomaly Detection
**Author:** Okado Aaron Obbo | Reg No: S24B23/015 | Student No: B29782
**Degree:** BSc Computer Science | Uganda Christian University
**Submitted:** Week 6 — Final Prototype Submission

---

## Source Files (`src/`)

| File | Description | Status |
|---|---|---|
| `src/preprocess.py` | NSL-KDD loading, noise removal (drop zero-variance), log1p scaling, MinMax normalisation. Produces 40 clean features. Exports `load_and_preprocess`, `FEATURE_COLS`. | Complete |
| `src/model.py` | CNN-GRU architecture: Conv1D(64→128→256) + GRU(128→64) + Dense(128→64→5). ~327K parameters. 5-class softmax output. | Complete |
| `src/autoencoder.py` | Self-supervised autoencoder: Encoder 40→128→64→16, Decoder 16→64→128→40. Trained on normal traffic only. | Complete |
| `src/train.py` | Trains CNN-GRU and autoencoder sequentially on NSL-KDD. Saves all model artifacts to `data/`. | Complete |
| `src/train_autoencoder.py` | Standalone autoencoder training script. Computes 95th-percentile reconstruction-error threshold on normal test traffic. | Complete |
| `src/evaluate.py` | Four-way comparison: Legacy VPN vs ZTA Only vs ZTA+CNN-GRU vs ZTA+Autoencoder. Metrics: Accuracy, F1, FPR, Response Time, Zero-Day. | Complete |
| `src/api.py` | Flask REST API on port 5000. Endpoints: `/predict`, `/predict/batch`, `/health`, `/model/info`. Loads both models, computes combined risk score, enforces ZTA policy. | Complete |
| `src/zeek_capture.py` | Zeek (Docker) traffic capture pipeline: pcap → conn.log → Flask API → audit.jsonl. | Complete |
| `src/generate_attack_traffic.py` | Scapy-crafted pcaps and Zeek-format conn.logs for all 5 NSL-KDD classes. Used in GNS3 lab demo. | Complete |
| `src/run_gns3_demo.py` | End-to-end GNS3 hybrid-workforce demo orchestrator. Scores traffic via three paths: conn.log, Zeek-Docker, and direct API. | Complete |
| `src/robustness_analysis.py` | Threshold sensitivity sweep (70th–99th percentile) and zero-day recall by class. Full robustness report. | Complete |
| `src/threshold_sensitivity.py` | Autoencoder anomaly threshold sensitivity analysis with PR and ROC curves. | Complete |
| `src/zeroday_recall.py` | Leave-one-class-out zero-day recall experiment per NSL-KDD attack class. | Complete |
| `src/final_demo.py` | Week 6 standalone live demo. Loads both models, scores one sample per class, prints summary table, saves `data/results/final_demo_output.json`. | Complete |

---

## Trained Model Files (`data/`)

| File | Description | Status |
|---|---|---|
| `data/cnn_gru_model.keras` | Trained CNN-GRU classifier. Test accuracy 0.7945, F1 0.7886. 4.0 MB. | Complete |
| `data/autoencoder_model.keras` | Trained self-supervised autoencoder. Test accuracy 0.8443, F1 0.8482. 450 KB. | Complete |
| `data/encoder_model.keras` | Encoder sub-model (first half of autoencoder). Used for embedding extraction. | Complete |
| `data/ae_threshold.pkl` | 95th-percentile reconstruction-error threshold (0.002682) for anomaly detection. | Complete |
| `data/scaler.pkl` | MinMaxScaler fitted on NSL-KDD training data. Applied to all 40 features. | Complete |
| `data/encoders.pkl` | LabelEncoders for categorical features: protocol_type, service, flag. | Complete |
| `data/n_features.pkl` | Saved feature count (40). Used for consistent model loading. | Complete |

---

## Results Files (`data/results/`)

| File | Description | Status |
|---|---|---|
| `data/results/comparison_results.csv` | Four-way evaluation metrics table: Accuracy, F1, FPR, Latency, Zero-Day. | Complete |
| `data/results/summary.json` | JSON summary of four-way comparison results. | Complete |
| `data/results/comparison_bar.png` | Bar chart comparing all four systems on Accuracy and F1. | Complete |
| `data/results/confusion_matrices.png` | Confusion matrices for CNN-GRU and Autoencoder systems. | Complete |
| `data/results/robustness_report.json` | Full robustness analysis: threshold sweep + per-class zero-day recall. | Complete |
| `data/results/threshold_sensitivity.csv` | Threshold sweep data (70th–99th percentile): Precision, Recall, F1, FPR at each point. | Complete |
| `data/results/threshold_sensitivity.png` | Threshold sensitivity line chart. | Complete |
| `data/results/zeroday_recall.csv` | Zero-day recall per attack class (DoS, Probe, R2L, U2R). | Complete |
| `data/results/zeroday_recall.png` | Zero-day recall bar chart by attack class. | Complete |
| `data/results/final_demo_output.json` | Week 6 live demo output: 5 class predictions with CNN-GRU, AE, risk scores, ZTA decisions. | Complete |
| `data/results/gns3_demo_results.json` | GNS3 end-to-end demo results: 122 flows scored across all 5 classes. | Complete |

---

## Training Artifacts (`data/`)

| File | Description | Status |
|---|---|---|
| `data/training_results.json` | CNN-GRU training metrics: accuracy, loss, class report. | Complete |
| `data/autoencoder_training_results.json` | Autoencoder training metrics: train/val loss, threshold, recall, FPR, accuracy, F1. | Complete |
| `data/training_curves.png` | CNN-GRU loss/accuracy curves over 50 epochs. | Complete |
| `data/autoencoder_training_curves.png` | Autoencoder train/val loss curves. | Complete |
| `data/results/autoencoder_error_distribution.png` | Reconstruction error distribution: normal vs attack traffic histogram. | Complete |

---

## PDF Documents (`data/`)

| File | Description | Status |
|---|---|---|
| `data/Midsemester_Summary_Okado_Aaron_Obbo.pdf` | One-page A4 mid-semester research summary. Submitted 14 October 2026. | Complete |
| `data/Evaluation_Chapter_Okado_Aaron_Obbo.pdf` | Full evaluation chapter PDF (8 sections, multi-page A4). Week 5 deliverable. | Complete |
| `data/Research_Poster_Okado_Aaron_Obbo.pdf` | A3-landscape research poster, 3-column layout, all key results. Week 5 deliverable. | Complete |
| `data/Progress_Okado_Aaron_Obbo.pdf` | Living multi-page progress report. Updated at every milestone (Week 1 through Week 6). | Complete |
| `data/Final_Summary_Okado_Aaron_Obbo.pdf` | 2-page A4 final project summary. Week 6 deliverable. | Complete |

---

## Notebooks (`notebooks/`)

| File | Description | Status |
|---|---|---|
| `notebooks/analysis.ipynb` | Exploratory data analysis on NSL-KDD: feature distributions, class balance, correlation heatmap. | Complete |
| `notebooks/week4_robustness_analysis.ipynb` | Interactive Week 4 robustness analysis: threshold sweep and zero-day recall visualisations. | Complete |

---

## Root-Level Scripts and Configuration

| File | Description | Status |
|---|---|---|
| `generate_progress_pdf.py` | Living progress PDF generator. Append new milestones and re-run to update. | Complete |
| `generate_midsem_pdf.py` | Mid-semester summary PDF generator. | Complete |
| `generate_evaluation_chapter.py` | Full evaluation chapter PDF generator (8 sections). | Complete |
| `generate_poster.py` | A3 research poster PDF generator. | Complete |
| `generate_final_summary.py` | 2-page A4 final summary PDF generator. Week 6 deliverable. | Complete |
| `generate_proposal_pdf.py` | Original research proposal PDF generator. | Complete |
| `demo.ps1` | PowerShell presentation script for live demo walkthrough. | Complete |
| `demo_dashboard.html` | Browser-based visual demo dashboard (HTML/CSS/JS). | Complete |
| `requirements.txt` | All Python dependencies with pinned versions. | Complete |
| `README.md` | Full project README with architecture, quick start, results table, file structure. | Complete |

---

## Submission Checklist

- [x] Both models trained and saved: `data/cnn_gru_model.keras`, `data/autoencoder_model.keras`
- [x] Four-way evaluation complete: `data/results/comparison_results.csv`
- [x] Key results confirmed: ZTA+Autoencoder acc=0.8443, F1=0.8482; ZTA+CNN-GRU acc=0.7945, F1=0.7886
- [x] Zero-day detection validated: DoS=0.91, Probe=0.88, U2R=0.69, R2L=0.29
- [x] Threshold sensitivity analysis complete: `data/results/threshold_sensitivity.csv`
- [x] Flask API operational: `/predict`, `/health`, `/model/info`
- [x] GNS3 hybrid topology documented and artifacts generated
- [x] Week 6 live demo complete: `src/final_demo.py` → `data/results/final_demo_output.json`
- [x] All PDF deliverables generated and non-empty
- [x] Progress PDF updated to show all 6 weeks complete
- [x] Submission manifest complete (this file)
- [x] README.md updated with all Week 6 deliverables
- [x] requirements.txt verified with all packages pinned

**The prototype is submission-ready. All 6 weekly milestones are complete.**
