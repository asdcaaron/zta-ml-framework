"""
generate_midsem_pdf.py
----------------------
ONE-PAGE A4 mid-semester research summary.
UCU Mid-Semester Research Project Milestone — 14 October 2026

Author : Okado Aaron Obbo  S24B23/015
"""

import os, re
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT

OUTPUT = os.path.join('data', 'Midsemester_Summary_Okado_Aaron_Obbo.pdf')

# ── Colours ───────────────────────────────────────────────────────────────────
BLUE   = colors.HexColor('#003087')
GOLD   = colors.HexColor('#C8A84B')
BBLUE  = colors.HexColor('#E8F0FB')
BGREEN = colors.HexColor('#E8F5E9')
BGOLD  = colors.HexColor('#FFF8E1')
BGREY  = colors.HexColor('#F5F5F5')
RED    = colors.HexColor('#C62828')
GREY   = colors.HexColor('#555555')
LG     = colors.HexColor('#CCCCCC')
W      = colors.white
BK     = colors.black

PW, PH = A4
LM = RM = 1.1 * cm
TM = BM = 0.8 * cm
CW = PW - LM - RM   # content width ≈ 169mm

# ── Style factory ─────────────────────────────────────────────────────────────
def ps(name, fn='Helvetica', fs=7.5, tc=BK, al=TA_JUSTIFY,
       lead=9.5, sb=0, sa=1, li=0, fi=0):
    return ParagraphStyle(name, fontName=fn, fontSize=fs, textColor=tc,
                          alignment=al, leading=lead, spaceBefore=sb,
                          spaceAfter=sa, leftIndent=li, firstLineIndent=fi)

SEC  = ps('sec', 'Helvetica-Bold', 7.8, BLUE, TA_LEFT, 9.5, 1, 1)
BODY = ps('body', fs=7.2, lead=9.2)
BULL = ps('bull', fs=7.2, lead=9.2, li=7, fi=-6)
SML  = ps('sml',  fs=6.6, tc=GREY, lead=8.2)
CTR  = ps('ctr',  fn='Helvetica-Bold', fs=6.8, tc=BK, al=TA_CENTER, lead=8.5)
CTRS = ps('ctrs', fs=6.5, al=TA_CENTER, lead=8)
NEW  = ps('new',  fn='Helvetica-Bold', fs=6.2, tc=RED, al=TA_CENTER, lead=7.5)

def sp(h=0.12): return Spacer(1, h*cm)
def hr(c=GOLD, t=0.7): return HRFlowable(
    width='100%', thickness=t, color=c, spaceAfter=1, spaceBefore=1)

def b(t):  return Paragraph(f'&#8226;&#160;{t}', BULL)
def arr(): return Paragraph(
    '<font size="9" color="#999999">&#8595;</font>',
    ps('a', al=TA_CENTER, lead=9))

def cell(txt, bg=BGREY, bold=False, fs=6.8, red=False):
    fn = 'Helvetica-Bold' if bold else 'Helvetica'
    tc = '#C62828' if red else '#212121'
    return Paragraph(
        f'<font name="{fn}" size="{fs}" color="{tc}">{txt}</font>',
        ps('c', al=TA_CENTER, lead=8.5))

def tbl(data, widths, style_extra=None):
    base = [
        ('FONTSIZE',      (0,0), (-1,-1), 7),
        ('TOPPADDING',    (0,0), (-1,-1), 2),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ('LEFTPADDING',   (0,0), (-1,-1), 3),
        ('RIGHTPADDING',  (0,0), (-1,-1), 3),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]
    if style_extra:
        base += style_extra
    t = Table(data, colWidths=widths)
    t.setStyle(TableStyle(base))
    return t


# ── Pipeline ──────────────────────────────────────────────────────────────────
def pipeline():
    flow = []

    # INPUT
    r0 = [[cell('INPUT: Live network traffic  |  NSL-KDD 125,973 train / 22,543 test  '
                '|  Zeek conn.log (Docker)  |  pcap files', BGREY, bold=True)]]
    flow.append(tbl(r0, [CW], [
        ('BACKGROUND', (0,0), (-1,-1), BGREY),
        ('BOX', (0,0), (-1,-1), 0.5, BLUE),
    ]))
    flow.append(arr())

    # PREPROCESS
    r1 = [[cell('PREPROCESS (src/preprocess.py)  — Drop zero-variance feature  |  '
                'log1p outlier scaling  |  MinMax  |  40 clean features', BGOLD, bold=True)]]
    flow.append(tbl(r1, [CW], [
        ('BACKGROUND', (0,0), (-1,-1), BGOLD),
        ('BOX', (0,0), (-1,-1), 0.5, GOLD),
    ]))
    flow.append(arr())

    # Two model boxes
    W2 = (CW - 0.3*cm) / 2
    cnn = [[cell('CNN-GRU  (Supervised)', BBLUE, bold=True)],
           [cell('Conv1D(64→128→256) + GRU(128→64)\n'
                 '327K params | Test acc 76% | Val acc 98.6%\n'
                 'Classes: Normal / DoS / Probe / R2L / U2R', BBLUE)],
           [Paragraph('<font name="Helvetica-Bold" size="6" color="#003087">'
                      'Known attack classifier</font>',
                      ps('x', al=TA_CENTER, lead=8))]]
    tc = tbl(cnn, [W2], [
        ('BACKGROUND', (0,0), (-1,-1), BBLUE),
        ('BOX', (0,0), (-1,-1), 0.8, BLUE),
    ])

    ae = [[cell('Autoencoder  (Self-Supervised ★)', BGREEN, bold=True)],
          [cell('Encoder 40→128→64→16  Decoder 16→64→128→40\n'
                'Trains on NORMAL only — NO attack labels\n'
                'Anomaly = recon. error > 95th percentile', BGREEN)],
          [Paragraph('<font name="Helvetica-Bold" size="6" color="#2e7d32">'
                     'Zero-day anomaly detector  [NEW]</font>',
                     ps('y', al=TA_CENTER, lead=8))]]
    ta = tbl(ae, [W2], [
        ('BACKGROUND', (0,0), (-1,-1), BGREEN),
        ('BOX', (0,0), (-1,-1), 0.8, colors.HexColor('#2e7d32')),
    ])

    split = tbl([[tc, ta]], [W2, W2], [
        ('LEFTPADDING',  (0,0), (-1,-1), 0),
        ('RIGHTPADDING', (0,0), (-1,-1), 0),
        ('TOPPADDING',   (0,0), (-1,-1), 0),
        ('BOTTOMPADDING',(0,0), (-1,-1), 0),
        ('VALIGN',       (0,0), (-1,-1), 'TOP'),
    ])
    flow.append(split)
    flow.append(arr())

    # Combined risk score
    r3 = [[cell('COMBINED RISK SCORE (0–1)  →  Flask API  →  ZTA Policy Engine',
                BGOLD, bold=True)]]
    flow.append(tbl(r3, [CW], [
        ('BACKGROUND', (0,0), (-1,-1), BGOLD),
        ('BOX', (0,0), (-1,-1), 0.5, GOLD),
    ]))
    flow.append(arr())

    # Actions
    W4 = CW / 4
    acts = [[
        cell('>0.8\nBLOCK', colors.HexColor('#FFEBEE'), bold=True),
        cell('0.5–0.8\nCHALLENGE MFA', colors.HexColor('#FFF3E0'), bold=True),
        cell('0.3–0.5\nMONITOR', colors.HexColor('#FFFDE7'), bold=True),
        cell('<0.3\nALLOW', BGREEN, bold=True),
    ]]
    flow.append(tbl(acts, [W4]*4, [
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#FFEBEE')),
        ('BACKGROUND', (1,0), (1,-1), colors.HexColor('#FFF3E0')),
        ('BACKGROUND', (2,0), (2,-1), colors.HexColor('#FFFDE7')),
        ('BACKGROUND', (3,0), (3,-1), BGREEN),
        ('BOX',        (0,0), (-1,-1), 0.4, LG),
        ('INNERGRID',  (0,0), (-1,-1), 0.3, LG),
    ]))
    flow.append(arr())

    # Evaluation
    r5 = [[cell('EVALUATION: 4-way comparison  (Legacy VPN vs ZTA Only vs ZTA+CNN-GRU vs ZTA+Autoencoder)\n'
                'Metrics: Accuracy | F1 Score | FPR | Response Time | Zero-Day Detection', BGREY)]]
    flow.append(tbl(r5, [CW], [
        ('BACKGROUND', (0,0), (-1,-1), BGREY),
        ('BOX', (0,0), (-1,-1), 0.4, LG),
    ]))
    return flow


# ── Build ─────────────────────────────────────────────────────────────────────
def generate():
    os.makedirs('data', exist_ok=True)
    doc = SimpleDocTemplate(OUTPUT, pagesize=A4,
                            leftMargin=LM, rightMargin=RM,
                            topMargin=TM, bottomMargin=BM)
    S = []

    # ── Header ────────────────────────────────────────────────────────────────
    hd = tbl([['MID-SEMESTER RESEARCH PROJECT MILESTONE  |  14 October 2026  '
               '|  Uganda Christian University']], [CW], [
        ('BACKGROUND',    (0,0), (-1,-1), BLUE),
        ('TEXTCOLOR',     (0,0), (-1,-1), W),
        ('FONTNAME',      (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,-1), 9),
        ('ALIGNMENT',     (0,0), (-1,-1), 'CENTER'),
        ('TOPPADDING',    (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ])
    S.append(hd); S.append(sp(0.15))

    # ── ID bar ────────────────────────────────────────────────────────────────
    id_row = tbl([[
        Paragraph('<b>Okado Aaron Obbo</b>', ps('id', fs=7.5, lead=9)),
        Paragraph('Reg No: <b>S24B23/015</b>  |  Student No: B29782',
                  ps('id2', fs=7.5, lead=9)),
        Paragraph('BSc Computer Science', ps('id3', fs=7.5, lead=9)),
    ]], [CW*0.32, CW*0.40, CW*0.28], [
        ('BACKGROUND',    (0,0), (-1,-1), BGREY),
        ('BOX',           (0,0), (-1,-1), 0.5, GOLD),
        ('INNERGRID',     (0,0), (-1,-1), 0.3, LG),
        ('TOPPADDING',    (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING',   (0,0), (-1,-1), 5),
    ])
    S.append(id_row); S.append(sp(0.1))
    S.append(Paragraph(
        '<b>Title:</b> Risk-Adaptive Zero Trust for Securing Hybrid Workforces '
        'Using Self-Supervised Anomaly Detection',
        ps('ttl', fn='Helvetica-Bold', fs=8.2, tc=BLUE, al=TA_LEFT, lead=10)))
    S.append(hr())

    # ── Problem & Objective ───────────────────────────────────────────────────
    S.append(Paragraph('Problem and Research Objective', SEC))
    S.append(Paragraph(
        'Hybrid workforces expose enterprise networks to ransomware, insider attacks, '
        'lateral movement and zero-day exploits that legacy VPNs cannot address. '
        'ZTA-only systems enforce access control but remain blind to traffic-level '
        'anomalies. Neither detects unknown threats without pre-labelled attack data.',
        BODY))
    S.append(Paragraph(
        '<b>Objective:</b> Design and evaluate a Risk-Adaptive ZTA integrating '
        '(1) a supervised CNN-GRU for known attack classification and (2) a '
        'self-supervised autoencoder for zero-day anomaly detection — compared '
        'against three baselines in a controlled four-way evaluation.', BODY))
    S.append(hr(LG, 0.4))

    # ── Existing research & gap ───────────────────────────────────────────────
    S.append(Paragraph('Existing Research and Gap', SEC))
    S.append(Paragraph(
        'Gambo &amp; Almulhem (2026) reviewed ZTA systematically — strong access control, '
        'but no real-time traffic anomaly detection. Bakhshi &amp; Ghita (2021) showed '
        'deep learning detects anomalies in encrypted traffic but requires labelled data, '
        'failing on novel attacks. Abdelhady et al. (2026) combined lightweight ZTA with ML '
        'for IoT but did not address zero-day detection or hybrid workforces. '
        '<b>Gap:</b> No existing work pairs ZTA with a self-supervised (label-free) '
        'anomaly detector in a comparative, hybrid workforce study.', BODY))
    S.append(hr(LG, 0.4))

    # ── Proposed contribution ─────────────────────────────────────────────────
    S.append(Paragraph('Proposed Contribution', SEC))
    for t in [
        '<b>Dual-layer ML:</b> CNN-GRU (known attacks) + Autoencoder (zero-day) — '
        'combined into one risk score. Neither alone achieves both.',
        '<b>Self-supervised anomaly detection:</b> Autoencoder trained on NORMAL '
        'traffic only. Threshold sensitivity and zero-day separation quality are '
        'under investigation — not just accuracy reporting.',
        '<b>Four-way controlled evaluation:</b> Same test set across all systems. '
        'Evidence includes FPR, response time and zero-day capability — not '
        'accuracy alone.',
    ]:
        S.append(b(t))
    S.append(hr(LG, 0.4))

    # ── Pipeline ──────────────────────────────────────────────────────────────
    S.append(Paragraph('Full Technical Pipeline / Architecture', SEC))
    for e in pipeline():
        S.append(e)
    S.append(hr(LG, 0.4))

    # ── Progress ──────────────────────────────────────────────────────────────
    S.append(Paragraph('Progress to Date', SEC))
    prog = [
        ['Completed', 'Evidence'],
        ['NSL-KDD dataset: cleaned, 40 features (noise removed)',
         'src/preprocess.py | scaler.pkl | n_features.pkl'],
        ['CNN-GRU trained: 50 epochs — test acc 76%, val 98.6%',
         'data/best_model.keras (3.84 MB) | training_results.json'],
        ['Flask API live: /predict, /health, dashboard',
         'src/api.py | confirmed working on port 5000'],
        ['Zeek Docker pipeline: pcap → conn.log → API → audit',
         'data/logs/conn.log | data/audit.jsonl'],
        ['4-way eval framework built; CNN-GRU uses real predictions',
         'src/evaluate.py | data/results/comparison_results.csv'],
        ['GitHub: 7 commits on branch Aaron',
         'github.com/asdcaaron/zta-ml-framework'],
        ['Autoencoder architecture built — training PENDING',
         'src/autoencoder.py | autoencoder_model.keras NOT YET generated'],
    ]
    pt = tbl(prog, [CW*0.52, CW*0.48], [
        ('BACKGROUND',    (0,0), (-1,0), BLUE),
        ('TEXTCOLOR',     (0,0), (-1,0), W),
        ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,-1), 6.8),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [BGREY, W]),
        ('GRID',          (0,0), (-1,-1), 0.3, LG),
        ('BACKGROUND',    (0,8), (-1,8), colors.HexColor('#FFF9C4')),
        ('TEXTCOLOR',     (0,8), (0,8),  RED),
        ('FONTNAME',      (0,8), (0,8),  'Helvetica-BoldOblique'),
    ])
    S.append(pt)
    S.append(hr(LG, 0.4))

    # ── Next 6 weeks ──────────────────────────────────────────────────────────
    S.append(Paragraph('Next Six Weeks and Expected Prototype', SEC))
    weeks = [
        ['Wk', 'Activity', 'Deliverable'],
        ['W1', 'Train autoencoder on normal traffic; validate 95th-pct threshold',
         'autoencoder_model.keras | error distribution plot'],
        ['W2', 'Full 4-way evaluation with real autoencoder; compare all systems',
         'Final comparison_results.csv | confusion matrices'],
        ['W3', 'GNS3 lab: hybrid topology; live Zeek capture on simulated attacks',
         'Live pipeline demo with real attack traffic'],
        ['W4', 'Threshold sensitivity; zero-day recall on unseen attack types',
         'Robustness report | Jupyter notebook'],
        ['W5', 'Finalise results; write evaluation chapter; draft poster',
         'Research poster draft | all figures'],
        ['W6', 'Complete prototype, poster, submission; record demo',
         'Working prototype + poster submitted'],
    ]
    wt = tbl(weeks, [CW*0.08, CW*0.54, CW*0.38], [
        ('BACKGROUND',    (0,0), (-1,0), BLUE),
        ('TEXTCOLOR',     (0,0), (-1,0), W),
        ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,-1), 6.8),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [BBLUE, W]),
        ('GRID',          (0,0), (-1,-1), 0.3, LG),
    ])
    S.append(wt)
    S.append(sp(0.1))
    S.append(Paragraph(
        '<b>Prototype:</b> Live pipeline — Zeek (Docker) captures traffic, '
        'forwards 40 features to Flask API, CNN-GRU + Autoencoder produce a '
        'combined risk score, ZTA policy engine enforces ALLOW/MONITOR/CHALLENGE/'
        'BLOCK, every decision logged to audit.jsonl. Demonstrable in GNS3 with '
        'real simulated attack traffic.', BODY))
    S.append(hr(LG, 0.4))

    # ── References ────────────────────────────────────────────────────────────
    S.append(Paragraph('Key References', SEC))
    S.append(Paragraph(
        '[1] Gambo &amp; Almulhem (2026). Zero Trust Architecture: A Systematic Literature Review. '
        '<i>Journal of Network and Systems Management</i>, 34(1).  '
        '[2] Bakhshi &amp; Ghita (2021). Anomaly Detection in Encrypted Internet Traffic Using '
        'Hybrid Deep Learning. <i>Security and Communication Networks</i>.  '
        '[3] Abdelhady et al. (2026). Hybrid ML Anomaly Detection and Lightweight Zero Trust '
        'Authentication for LoRaWAN Networks. <i>IEEE Access</i>, 14, 18387–18407.', SML))

    def no_deco(canvas, doc): pass
    doc.build(S, onFirstPage=no_deco, onLaterPages=no_deco)

    size_kb = os.path.getsize(OUTPUT) / 1024
    print(f'PDF generated : {OUTPUT}')
    print(f'Size          : {size_kb:.1f} KB')

    # Page count check
    with open(OUTPUT, 'rb') as f:
        content = f.read().decode('latin-1')
    pages = len(re.findall(r'/Type\s*/Page[^s]', content))
    print(f'Pages         : {pages}')


if __name__ == '__main__':
    generate()
