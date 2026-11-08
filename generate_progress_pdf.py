"""
generate_progress_pdf.py
------------------------
Living project-progress document. Multi-page A4 PDF that records every milestone
in the development lifecycle from inception to the current state.

HOW TO UPDATE WHEN NEW WORK IS DONE
====================================
Open this file, scroll to the MILESTONES list below, and append a new dict
following the existing entries. Then re-run:

    python generate_progress_pdf.py

The rendering code picks up every entry automatically — no other edits needed.

Author : Okado Aaron Obbo  S24B23/015
"""

import os, re, datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT

OUTPUT = os.path.join('data', 'Progress_Okado_Aaron_Obbo.pdf')

# ═══════════════════════════════════════════════════════════════════════════════
#  MILESTONES — append new entries here as work progresses
#  status: "done" | "in-progress" | "pending"
# ═══════════════════════════════════════════════════════════════════════════════
MILESTONES = [
    {
        "date": "21 Aug 2026",
        "phase": "Inception",
        "title": "Initial commit — ZTA + ML cybersecurity framework",
        "description": (
            "Project repository initialised with the core framework structure. "
            "Defined the src/ module layout (preprocess, model, train, evaluate, api, "
            "zeek_capture, autoencoder) and the data/ directory for datasets, trained "
            "models, and results."
        ),
        "evidence": "git commit e27d1a8  |  src/*.py  |  data/  |  requirements.txt",
        "results": None,
        "status": "done",
    },
    {
        "date": "29 Aug 2026",
        "phase": "Model Training",
        "title": "CNN-GRU trained + evaluation results + bug fixes",
        "description": (
            "Trained the supervised CNN-GRU classifier (Conv1D 64->128->256 + GRU "
            "128->64, ~327K params) on the NSL-KDD dataset for 50 epochs. Achieved "
            "test accuracy 76% and validation accuracy 98.6%. Built the initial "
            "evaluation framework comparing the ML-augmented system against baselines."
        ),
        "evidence": "git commit 6165709  |  data/best_model.keras  |  data/training_results.json",
        "results": "Test acc 76%  |  Val acc 98.6%  |  327K params",
        "status": "done",
    },
    {
        "date": "29 Aug 2026",
        "phase": "Evaluation",
        "title": "Fixed evaluation baselines — ZTA+ML now correctly outperforms all systems",
        "description": (
            "Corrected the baseline implementations so the four-way comparison was "
            "fair. After the fix, the ZTA+ML combination correctly outperforms Legacy "
            "VPN and ZTA-Only on all measured metrics."
        ),
        "evidence": "git commit d7537dd  |  src/evaluate.py",
        "results": None,
        "status": "done",
    },
    {
        "date": "02 Sep 2026",
        "phase": "Pipeline Integration",
        "title": "Zeek-to-API pipeline integration completed",
        "description": (
            "Completed the full Zeek (Docker) capture pipeline: pcap files are "
            "processed by Zeek to produce conn.log, which is forwarded to the Flask "
            "API for real-time prediction. Every decision is logged to audit.jsonl."
        ),
        "evidence": "git commit 93ba9ff  |  src/zeek_capture.py  |  data/logs/conn.log  |  data/audit.jsonl",
        "results": None,
        "status": "done",
    },
    {
        "date": "02 Sep 2026",
        "phase": "Data Quality",
        "title": "Dataset noise fix — cleaner features for retraining",
        "description": (
            "Removed noise from the NSL-KDD feature set. Dropped the zero-variance "
            "feature (num_outbound_cmds), applied log1p scaling on outlier-heavy "
            "columns, and reduced to 40 clean features. Saved the fitted scaler and "
            "encoders for consistent reuse."
        ),
        "evidence": "git commit 451c672  |  src/preprocess.py  |  data/scaler.pkl  |  data/n_features.pkl",
        "results": "40 clean features  |  scaler.pkl  |  encoders.pkl",
        "status": "done",
    },
    {
        "date": "15 Sep 2026",
        "phase": "Project Direction",
        "title": "Project retitled: Risk-Adaptive Zero Trust Using Self-Supervised Anomaly Detection",
        "description": (
            "Refined the research focus to emphasise the self-supervised (label-free) "
            "autoencoder as the novel contribution, paired with the supervised CNN-GRU "
            "in a dual-layer risk-scoring architecture."
        ),
        "evidence": "git commit 77c6d9c",
        "results": None,
        "status": "done",
    },
    {
        "date": "13 Oct 2026",
        "phase": "Mid-Semester",
        "title": "Mid-semester milestone — summary PDF, demo dashboard, 40-feature pipeline fix",
        "description": (
            "Produced the one-page mid-semester research summary PDF for UCU. Built a "
            "visual demo dashboard (HTML) and a PowerShell presentation script. Fixed "
            "a model/preprocess mismatch to ensure the full pipeline uses a consistent "
            "40-feature space. GitHub repo at 7 commits on branch Aaron."
        ),
        "evidence": (
            "git commits 2e9a84f, d763551, 5f59bfe  |  data/Midsemester_Summary_Okado_Aaron_Obbo.pdf  "
            "|  demo_dashboard.html  |  demo.ps1"
        ),
        "results": None,
        "status": "done",
    },
    {
        "date": "06 Nov 2026",
        "phase": "Week 1 — Autoencoder Training",
        "title": "Self-supervised autoencoder trained for zero-day anomaly detection",
        "description": (
            "Trained the autoencoder (Encoder 40->128->64->16, Decoder 16->64->128->40) "
            "on NORMAL traffic only (67,343 samples) from NSL-KDD, using the existing "
            "saved scaler (transform, not refit) so it shares the exact 40-feature space "
            "as the CNN-GRU. Computed the 95th-percentile reconstruction-error threshold "
            "on normal test traffic (9,710 samples). Fixed the architecture to match the "
            "midsem spec. Created src/train_autoencoder.py. Pinned protobuf==6.31.1 to "
            "unblock TensorFlow."
        ),
        "evidence": (
            "git commit 71198d8  |  src/train_autoencoder.py  |  src/autoencoder.py  "
            "|  data/autoencoder_model.keras  |  data/ae_threshold.pkl  "
            "|  data/results/autoencoder_error_distribution.png  "
            "|  data/autoencoder_training_results.json"
        ),
        "results": (
            "Train loss 0.001935  |  Val loss 0.000868  |  Threshold 0.002682  "
            "|  Recall on attacks 0.7643  |  FPR on normal 0.0501  "
            "|  Accuracy 0.8443  |  F1 0.8482  "
            "|  Mean error: normal 0.000792 vs attack 0.015131 (~19x)"
        ),
        "status": "done",
    },
    {
        "date": "06 Nov 2026",
        "phase": "Week 2 — Four-Way Evaluation",
        "title": "Full 4-way evaluation with real autoencoder predictions",
        "description": (
            "Updated src/evaluate.py so System D (ZTA+Autoencoder) uses real autoencoder "
            "predictions via load_autoencoder + the saved 95th-pct threshold, replacing "
            "the previous simulation fallback. Ran the full four-way evaluation on the "
            "same 22,543-sample test set with identical metrics across all systems. "
            "Regenerated all comparison artifacts. Key finding (honest deviation from "
            "expected narrative): the self-supervised autoencoder BEATS the CNN-GRU on "
            "accuracy and F1, while the CNN-GRU wins only on FPR. The autoencoder is also "
            "~9x faster at inference. Its weakness is R2L detection (0.287) — those "
            "connections reconstruct like normal traffic."
        ),
        "evidence": (
            "git commit a290aaf  |  src/evaluate.py  "
            "|  data/results/comparison_results.csv  |  data/results/summary.json  "
            "|  data/results/comparison_bar.png  |  data/results/confusion_matrices.png"
        ),
        "results": (
            "ZTA+Autoencoder: acc 0.8443, F1 0.8482, FPR 0.0501, 0.0656 ms/sample  "
            "|  ZTA+CNN-GRU: acc 0.7945, F1 0.7886, FPR 0.0452, 0.5889 ms/sample  "
            "|  ZTA Only: acc 0.7691  |  Legacy VPN: acc 0.6664  "
            "|  Autoencoder wins: accuracy, F1, DoS (0.911), Probe (0.882), U2R (0.687)  "
            "|  CNN-GRU wins: FPR (0.0452)"
        ),
        "status": "done",
    },
    {
        "date": "14 Nov 2026",
        "phase": "Week 3 — GNS3 Lab",
        "title": "GNS3 hybrid topology + attack traffic generation + end-to-end demo",
        "description": (
            "Designed and documented a GNS3 hybrid-workforce topology (4 segments: HQ "
            "10.10.0.0/24, Branch 10.20.0.0/24, DMZ/Cloud 172.16.0.0/24, Internet "
            "attacker 203.0.113.0/24) with inside and outside attack sources, Zeek SPAN "
            "tap, and the Flask API as the ZTA policy enforcement point. Generated "
            "Scapy-crafted pcaps and Zeek-format conn.logs for all 5 NSL-KDD classes "
            "(Normal, DoS, Probe, R2L, U2R). Built the end-to-end demo orchestrator "
            "(run_gns3_demo.py) that scores traffic via three paths: conn.log path "
            "(reliable fallback), best-effort Zeek-Docker path, and a full-feature "
            "direct API path with windowed NSL-KDD profiles. Docker daemon was down so "
            "Zeek path is recorded as zeek_unavailable (honest). Results and audit "
            "records written to data/results/ and data/audit.jsonl."
        ),
        "evidence": (
            "git commits 6848452, 42f77f4  |  src/generate_attack_traffic.py  "
            "|  src/run_gns3_demo.py  |  data/gns3/zta_hybrid_topology.gns3  "
            "|  data/gns3/topology.md  |  data/gns3/pcaps/*.pcap (5 files)  "
            "|  data/gns3/conn_logs/*_conn.log (5 files)  "
            "|  data/results/gns3_demo_results.json  |  data/audit.jsonl"
        ),
        "results": (
            "conn.log path: 122 flows scored (normal=24, dos=25, probe=35, r2l=20, u2r=18)  "
            "|  Full-feature path: DoS->BLOCK(0.930), R2L->BLOCK(0.899), "
            "U2R->CHALLENGE_MFA(0.572), Probe->ALLOW(0.028)  "
            "|  audit.jsonl: 7->165 lines (+158 records)  "
            "|  Scapy 2.8.0 installed; pcaps: normal=1KB, dos=2KB, probe=2.4KB, "
            "r2l=0.9KB, u2r=1.8KB  |  Zeek: Docker daemon DOWN (zeek_unavailable recorded)"
        ),
        "status": "done",
    },
    {
        "date": "Pending",
        "phase": "Week 4 — Robustness",
        "title": "Threshold sensitivity and zero-day recall on unseen attack types",
        "description": (
            "Sweep the autoencoder threshold across a range of percentiles and measure "
            "the precision/recall trade-off. Evaluate zero-day recall on unseen attack "
            "types. Produce a robustness report and a Jupyter notebook documenting the "
            "findings."
        ),
        "evidence": "Not started",
        "results": None,
        "status": "pending",
    },
    {
        "date": "Pending",
        "phase": "Week 5 — Finalisation",
        "title": "Finalise results, write evaluation chapter, draft poster",
        "description": (
            "Consolidate all results. Write the evaluation chapter for the final report. "
            "Draft the research poster with all figures."
        ),
        "evidence": "Not started",
        "results": None,
        "status": "pending",
    },
    {
        "date": "Pending",
        "phase": "Week 6 — Submission",
        "title": "Complete prototype, poster, submission; record demo",
        "description": (
            "Finalise the working prototype and research poster. Record a live demo "
            "video. Submit all deliverables."
        ),
        "evidence": "Not started",
        "results": None,
        "status": "pending",
    },
]

# ── Colours ───────────────────────────────────────────────────────────────────
BLUE   = colors.HexColor('#003087')
GOLD   = colors.HexColor('#C8A84B')
BBLUE  = colors.HexColor('#E8F0FB')
BGREEN = colors.HexColor('#E8F5E9')
BGOLD  = colors.HexColor('#FFF8E1')
BGREY  = colors.HexColor('#F5F5F5')
RED    = colors.HexColor('#C62828')
GREEN  = colors.HexColor('#2E7D32')
ORANGE = colors.HexColor('#E65100')
GREY   = colors.HexColor('#555555')
LG     = colors.HexColor('#CCCCCC')
W      = colors.white
BK     = colors.black

PW, PH = A4
LM = RM = 1.6 * cm
TM = BM = 1.5 * cm
CW = PW - LM - RM

# ── Style factory ─────────────────────────────────────────────────────────────
def ps(name, fn='Helvetica', fs=9, tc=BK, al=TA_JUSTIFY,
       lead=12, sb=0, sa=4, li=0, fi=0):
    return ParagraphStyle(name, fontName=fn, fontSize=fs, textColor=tc,
                          alignment=al, leading=lead, spaceBefore=sb,
                          spaceAfter=sa, leftIndent=li, firstLineIndent=fi)

H1    = ps('h1', 'Helvetica-Bold', 15, BLUE, TA_LEFT, 18, sb=6, sa=6)
H2    = ps('h2', 'Helvetica-Bold', 11.5, BLUE, TA_LEFT, 14, sb=8, sa=4)
BODY  = ps('body', fs=9.5, lead=13)
SML   = ps('sml', fs=8, tc=GREY, lead=10)
BULL  = ps('bull', fs=9.5, lead=13, li=14, fi=-10)
CTR   = ps('ctr', fn='Helvetica-Bold', fs=10, tc=BK, al=TA_CENTER, lead=12)
LABEL = ps('label', fn='Helvetica-Bold', fs=8.5, tc=BLUE, al=TA_LEFT, lead=11)

def sp(h=0.2): return Spacer(1, h * cm)
def hr(c=GOLD, t=0.8):
    return HRFlowable(width='100%', thickness=t, color=c,
                      spaceAfter=4, spaceBefore=4)

def b(t): return Paragraph(f'&#8226;&#160;{t}', BULL)


# ── Status helpers ────────────────────────────────────────────────────────────
STATUS_STYLE = {
    "done":        (BGREEN, GREEN, "DONE"),
    "in-progress": (BGOLD,  ORANGE, "IN PROGRESS"),
    "pending":     (BGREY,  GREY,   "PENDING"),
}

def status_badge(status):
    bg, fg, label = STATUS_STYLE.get(status, STATUS_STYLE["pending"])
    t = Table([[Paragraph(
        f'<font name="Helvetica-Bold" size="7" color="{fg.hexval()}">{label}</font>',
        ps('s', al=TA_CENTER, lead=9))]], colWidths=[2.6 * cm])
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), bg),
        ('BOX',            (0, 0), (-1, -1), 0.5, fg),
        ('TOPPADDING',     (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING',  (0, 0), (-1, -1), 2),
        ('LEFTPADDING',    (0, 0), (-1, -1), 4),
        ('RIGHTPADDING',   (0, 0), (-1, -1), 4),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    return t


# ── Page footer ───────────────────────────────────────────────────────────────
def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(GOLD)
    canvas.setLineWidth(0.5)
    canvas.line(LM, BM - 0.4 * cm, PW - RM, BM - 0.4 * cm)
    canvas.setFont('Helvetica', 7.5)
    canvas.setFillColor(GREY)
    canvas.drawString(LM, BM - 0.85 * cm,
                      'Okado Aaron Obbo  |  S24B23/015  |  BSc Computer Science  '
                      '|  Uganda Christian University')
    canvas.drawRightString(PW - RM, BM - 0.85 * cm, f'Page {doc.page}')
    canvas.restoreState()


# ── Build ─────────────────────────────────────────────────────────────────────
def generate():
    os.makedirs('data', exist_ok=True)
    doc = SimpleDocTemplate(OUTPUT, pagesize=A4,
                            leftMargin=LM, rightMargin=RM,
                            topMargin=TM, bottomMargin=BM)
    S = []

    # ── Title block ──────────────────────────────────────────────────────────
    title_bar = Table([['PROJECT DEVELOPMENT PROGRESS REPORT']], [CW])
    title_bar.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), BLUE),
        ('TEXTCOLOR',     (0, 0), (-1, -1), W),
        ('FONTNAME',      (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, -1), 14),
        ('ALIGNMENT',     (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    S.append(title_bar)
    S.append(sp(0.15))

    # ── ID bar ───────────────────────────────────────────────────────────────
    today = datetime.date.today().strftime('%d %B %Y')
    id_bar = Table([[
        Paragraph('<b>Okado Aaron Obbo</b>', ps('id', fs=9.5, lead=11)),
        Paragraph('Reg No: <b>S24B23/015</b>  |  Student No: B29782',
                  ps('id2', fs=9.5, lead=11)),
        Paragraph(f'Last updated: <b>{today}</b>',
                  ps('id3', fs=9.5, lead=11)),
    ]], [CW * 0.28, CW * 0.42, CW * 0.30])
    id_bar.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), BGREY),
        ('BOX',           (0, 0), (-1, -1), 0.5, GOLD),
        ('INNERGRID',     (0, 0), (-1, -1), 0.3, LG),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
    ]))
    S.append(id_bar)
    S.append(sp(0.15))

    S.append(Paragraph(
        '<b>Project Title:</b> Risk-Adaptive Zero Trust for Securing Hybrid '
        'Workforces Using Self-Supervised Anomaly Detection',
        ps('ttl', fn='Helvetica-Bold', fs=10.5, tc=BLUE, al=TA_LEFT, lead=13)))
    S.append(Paragraph(
        '<b>Repository:</b> github.com/asdcaaron/zta-ml-framework',
        SML))
    S.append(hr())

    # ── Overview ────────────────────────────────────────────────────────────
    S.append(Paragraph('Project Overview', H2))
    S.append(Paragraph(
        'This project designs and evaluates a Risk-Adaptive Zero Trust Architecture '
        '(ZTA) that integrates a dual-layer machine-learning detector: a supervised '
        'CNN-GRU for known-attack classification and a self-supervised autoencoder for '
        'zero-day anomaly detection. Both models feed a combined 0-1 risk score that '
        'the ZTA policy engine maps to ALLOW / MONITOR / CHALLENGE / BLOCK decisions. '
        'The system is compared against Legacy VPN and ZTA-Only baselines in a '
        'controlled four-way evaluation on the NSL-KDD dataset.', BODY))
    S.append(sp(0.1))

    # ── Architecture summary ─────────────────────────────────────────────────
    arch = [
        ['Component', 'Description'],
        ['Preprocessing', 'NSL-KDD -> drop zero-variance -> log1p scaling -> '
                           'MinMax -> 40 clean features (scaler.pkl, encoders.pkl)'],
        ['CNN-GRU (Supervised)', 'Conv1D(64->128->256) + GRU(128->64), 327K params, '
                                 '50 epochs. Known-attack classifier (Normal/DoS/Probe/R2L/U2R)'],
        ['Autoencoder (Self-Supervised)', 'Encoder 40->128->64->16 / Decoder 16->64->128->40. '
                                          'Trained on NORMAL only. Anomaly = recon. error > 95th pct'],
        ['Flask API', '/predict, /health endpoints on port 5000. Loads both models, '
                     'computes combined risk score, enforces ZTA policy'],
        ['Zeek Pipeline', 'Docker-based: pcap -> Zeek conn.log -> Flask API -> audit.jsonl'],
        ['Evaluation', '4-way comparison: Legacy VPN vs ZTA Only vs ZTA+CNN-GRU vs '
                       'ZTA+Autoencoder. Metrics: Accuracy, F1, FPR, Response Time, Zero-Day'],
    ]
    at = Table(arch, [CW * 0.28, CW * 0.72])
    at.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0), BLUE),
        ('TEXTCOLOR',     (0, 0), (-1, 0), W),
        ('FONTNAME',      (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, -1), 8.5),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [BGREY, W]),
        ('GRID',          (0, 0), (-1, -1), 0.3, LG),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING',    (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING',   (0, 0), (-1, -1), 5),
    ]))
    S.append(at)
    S.append(sp(0.2))

    # ── Milestone timeline ──────────────────────────────────────────────────
    S.append(PageBreak())
    S.append(Paragraph('Development Timeline', H1))
    S.append(Paragraph(
        'Each milestone below records what was done, the evidence (commits, files, '
        'artifacts), and key results. Pending milestones show the planned work ahead.',
        BODY))
    S.append(sp(0.15))

    for i, m in enumerate(MILESTONES):
        # ── Milestone header row: phase + date + status badge ──
        header_tbl = Table([[
            Paragraph(
                f'<font name="Helvetica-Bold" size="10" color="#003087">'
                f'Milestone {i+1}: {m["title"]}</font>',
                ps('mh', al=TA_LEFT, lead=12)),
            status_badge(m["status"]),
        ]], [CW * 0.78, CW * 0.22])
        header_tbl.setStyle(TableStyle([
            ('VALIGN',       (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING',   (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING',(0, 0), (-1, -1), 2),
            ('LEFTPADDING',  (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ]))

        # ── Metadata row: phase + date ──
        meta = Paragraph(
            f'<font name="Helvetica-Bold" size="8" color="#C8A84B">{m["phase"]}</font>'
            f'  <font size="8" color="#555555">|  {m["date"]}</font>',
            ps('meta', al=TA_LEFT, lead=10, sa=2))

        # ── Description ──
        desc = Paragraph(m["description"], BODY)

        # ── Evidence ──
        ev = Paragraph(
            f'<font name="Helvetica-Bold" size="8.5" color="#003087">Evidence:</font> '
            f'<font size="8.5" color="#555555">{m["evidence"]}</font>',
            ps('ev', al=TA_LEFT, lead=11, sa=2))

        # ── Results (if any) ──
        elements = [header_tbl, meta, sp(0.05), desc, sp(0.05), ev]
        if m["results"]:
            res = Paragraph(
                f'<font name="Helvetica-Bold" size="8.5" color="#2E7D32">Results:</font> '
                f'<font size="8.5" color="#333333">{m["results"]}</font>',
                ps('res', al=TA_LEFT, lead=11, sa=2))
            elements.append(res)

        elements.append(hr(LG, 0.4))
        elements.append(sp(0.1))

        # Keep each milestone together where possible
        S.append(KeepTogether(elements))

    # ── Current status summary ───────────────────────────────────────────────
    S.append(PageBreak())
    S.append(Paragraph('Current Status Summary', H1))

    done = sum(1 for m in MILESTONES if m["status"] == "done")
    pend = sum(1 for m in MILESTONES if m["status"] == "pending")
    inprog = sum(1 for m in MILESTONES if m["status"] == "in-progress")

    summary = [
        ['Metric', 'Value'],
        ['Total milestones', str(len(MILESTONES))],
        ['Completed', str(done)],
        ['In progress', str(inprog)],
        ['Pending', str(pend)],
        ['Current phase', 'Week 3 complete — Week 4 (robustness/threshold sweep) next'],
    ]
    st = Table(summary, [CW * 0.5, CW * 0.5])
    st.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0), BLUE),
        ('TEXTCOLOR',     (0, 0), (-1, 0), W),
        ('FONTNAME',      (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, -1), 9.5),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [BGREY, W]),
        ('GRID',          (0, 0), (-1, -1), 0.3, LG),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    S.append(st)
    S.append(sp(0.2))

    S.append(Paragraph('Key Achievements So Far', H2))
    for t in [
        '<b>Dual-layer ML pipeline complete:</b> Both the supervised CNN-GRU and the '
        'self-supervised autoencoder are trained and operational, sharing the same '
        '40-feature preprocessing space.',
        '<b>Autoencoder (the novel contribution) is trained:</b> Achieves 0.8443 '
        'accuracy, 0.8482 F1, and 0.7643 recall on attacks with a label-free approach. '
        'Mean reconstruction error for attacks is ~19x higher than for normal traffic.',
        '<b>Full four-way evaluation done:</b> ZTA+Autoencoder beats all baselines on '
        'accuracy and F1, and is ~9x faster than the CNN-GRU at inference. Honest '
        'weakness: R2L detection (0.287) — those connections resemble normal traffic.',
        '<b>GNS3 hybrid-workforce lab complete (Week 3):</b> Designed a 4-segment '
        'GNS3 topology (HQ/Branch/DMZ/Internet), generated Scapy pcaps and Zeek-format '
        'conn.logs for all 5 NSL-KDD classes, and built a full end-to-end demo '
        'orchestrator (run_gns3_demo.py) scoring 122+ flows via conn.log path and '
        'hand-crafted full-feature profiles. DoS->BLOCK(0.93), R2L->BLOCK(0.90), '
        'U2R->CHALLENGE_MFA(0.57). 158 new audit records appended.',
        '<b>Flask API operational:</b> /predict and /health endpoints serving both '
        'models with combined risk scoring and ZTA policy enforcement.',
    ]:
        S.append(b(t))
    S.append(sp(0.15))

    S.append(Paragraph('Next Steps', H2))
    for t in [
        '<b>Week 4:</b> Threshold sensitivity sweep and zero-day recall on unseen '
        'attack types — robustness report and Jupyter notebook.',
        '<b>Week 5:</b> Finalise results, write the evaluation chapter, draft the '
        'research poster.',
        '<b>Week 6:</b> Complete the prototype and poster, record a live demo, and '
        'submit all deliverables.',
    ]:
        S.append(b(t))

    # ── Build ────────────────────────────────────────────────────────────────
    doc.build(S, onFirstPage=footer, onLaterPages=footer)

    size_kb = os.path.getsize(OUTPUT) / 1024
    print(f'PDF generated : {OUTPUT}')
    print(f'Size          : {size_kb:.1f} KB')

    with open(OUTPUT, 'rb') as f:
        content = f.read().decode('latin-1')
    pages = len(re.findall(r'/Type\s*/Page[^s]', content))
    print(f'Pages         : {pages}')
    print(f'Milestones    : {len(MILESTONES)} ({done} done, {inprog} in-progress, {pend} pending)')


if __name__ == '__main__':
    generate()
