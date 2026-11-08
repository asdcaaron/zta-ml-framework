"""
generate_final_summary.py
-------------------------
2-page A4 final project summary PDF.

Page 1: Title block, student details, abstract, architecture diagram, key
        results table (4-way comparison).
Page 2: Contributions, limitations, future work, references, footer.

Matches the project PDF style: BLUE=#003087, GOLD=#C8A84B, Helvetica fonts.

Usage:
    python generate_final_summary.py

Output:
    data/Final_Summary_Okado_Aaron_Obbo.pdf

Author : Okado Aaron Obbo  S24B23/015
"""

import os
import re
import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT

OUTPUT = os.path.join('data', 'Final_Summary_Okado_Aaron_Obbo.pdf')

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


H1   = ps('h1', 'Helvetica-Bold', 14, BLUE, TA_LEFT,  17, sb=8, sa=4)
H2   = ps('h2', 'Helvetica-Bold', 11, BLUE, TA_LEFT,  14, sb=6, sa=3)
BODY = ps('body', fs=9.5, lead=13)
SML  = ps('sml',  fs=8,   tc=GREY, lead=10)
BULL = ps('bull', fs=9.5, lead=13, li=14, fi=-10)

def sp(h=0.2):  return Spacer(1, h * cm)
def hr(c=GOLD, t=0.8):
    return HRFlowable(width='100%', thickness=t, color=c,
                      spaceAfter=4, spaceBefore=4)
def b(t):       return Paragraph(f'&#8226;&#160;{t}', BULL)


# ── Page footer ───────────────────────────────────────────────────────────────
def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(GOLD)
    canvas.setLineWidth(0.5)
    canvas.line(LM, BM - 0.4 * cm, PW - RM, BM - 0.4 * cm)
    canvas.setFont('Helvetica', 7.5)
    canvas.setFillColor(GREY)
    canvas.drawString(
        LM, BM - 0.85 * cm,
        'Okado Aaron Obbo  |  S24B23/015  |  BSc Computer Science  '
        '|  Uganda Christian University')
    canvas.drawRightString(PW - RM, BM - 0.85 * cm, f'Page {doc.page}')
    canvas.restoreState()


# ── Build ─────────────────────────────────────────────────────────────────────
def generate():
    os.makedirs('data', exist_ok=True)
    doc = SimpleDocTemplate(
        OUTPUT, pagesize=A4,
        leftMargin=LM, rightMargin=RM,
        topMargin=TM, bottomMargin=BM)
    S = []

    # ════════════════════════════════════════════════════════════════════════
    # PAGE 1
    # ════════════════════════════════════════════════════════════════════════

    # ── Title block (BLUE background, white text) ─────────────────────────
    title_bar = Table([[
        Paragraph(
            '<font name="Helvetica-Bold" size="13" color="#FFFFFF">'
            'Risk-Adaptive Zero Trust for Securing Hybrid Workforces'
            '</font>',
            ps('t1', fn='Helvetica-Bold', fs=13, tc=W, al=TA_CENTER,
               lead=16, sa=2)),
        ]], [CW])
    title_bar.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), BLUE),
        ('TOPPADDING',    (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING',   (0, 0), (-1, -1), 8),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
    ]))
    sub_bar = Table([[
        Paragraph(
            '<font name="Helvetica-Bold" size="11" color="#FFFFFF">'
            'Using Self-Supervised Anomaly Detection'
            '</font>',
            ps('t2', fn='Helvetica-Bold', fs=11, tc=W, al=TA_CENTER,
               lead=14, sa=0)),
        ]], [CW])
    sub_bar.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), BLUE),
        ('TOPPADDING',    (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING',   (0, 0), (-1, -1), 8),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
    ]))
    S.append(title_bar)
    S.append(sub_bar)
    S.append(sp(0.15))

    # ── Student details ───────────────────────────────────────────────────
    today = datetime.date.today().strftime('%d %B %Y')
    det = Table([[
        Paragraph('<b>Okado Aaron Obbo</b>', ps('d1', fs=9.5, lead=11)),
        Paragraph('Reg No: <b>S24B23/015</b>  |  Student No: B29782',
                  ps('d2', fs=9.5, lead=11)),
        Paragraph(f'Date: <b>{today}</b>',
                  ps('d3', fs=9.5, lead=11)),
    ]], [CW * 0.28, CW * 0.44, CW * 0.28])
    det.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), BGREY),
        ('BOX',           (0, 0), (-1, -1), 0.5, GOLD),
        ('INNERGRID',     (0, 0), (-1, -1), 0.3, LG),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
    ]))
    S.append(det)
    S.append(sp(0.08))
    det2 = Table([[
        Paragraph('BSc Computer Science  |  Uganda Christian University',
                  ps('d4', fs=9, tc=BLUE, al=TA_CENTER, lead=11)),
    ]], [CW])
    det2.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), BBLUE),
        ('BOX',           (0, 0), (-1, -1), 0.4, BLUE),
        ('TOPPADDING',    (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    S.append(det2)
    S.append(sp(0.15))
    S.append(hr())

    # ── Abstract ──────────────────────────────────────────────────────────
    S.append(Paragraph('Abstract', H2))
    S.append(Paragraph(
        'Hybrid workforces expose enterprise networks to ransomware, lateral movement, '
        'insider attacks, and zero-day exploits that legacy VPN perimeters cannot block. '
        'This project designs and evaluates a risk-adaptive Zero Trust Architecture (ZTA) '
        'that integrates a dual-layer machine-learning pipeline: a supervised CNN-GRU '
        'for known-attack classification and a self-supervised autoencoder for zero-day '
        'anomaly detection trained on normal traffic only — requiring no attack labels. '
        'Both models feed a combined risk score (0–1) into the ZTA policy engine, which '
        'maps each network connection to an ALLOW, MONITOR, CHALLENGE_MFA, or BLOCK '
        'decision in real time. '
        'A controlled four-way comparison on the NSL-KDD benchmark dataset (22,543 test '
        'samples) shows that the ZTA+Autoencoder system achieves 0.8443 accuracy and '
        '0.8482 F1, outperforming ZTA+CNN-GRU (0.7945 / 0.7886), ZTA-Only (0.7691 / '
        '0.7677), and Legacy VPN (0.6664 / 0.6524), while being ~9× faster at inference '
        '(0.0656 ms/sample) and detecting zero-day attack classes the CNN-GRU was never '
        'trained on.', BODY))
    S.append(sp(0.1))
    S.append(hr(LG, 0.4))

    # ── Architecture diagram (text-based, inside a box) ───────────────────
    S.append(Paragraph('System Architecture', H2))
    arch_text = (
        'Hybrid Workforce Traffic (Remote / Office / IoT)\n'
        '         |\n'
        '         v\n'
        '+-------------------------------------------+\n'
        '|       ZTA ACCESS CONTROL LAYER            |\n'
        '|  Keycloak MFA  +  Device Posture Check    |\n'
        '|  OpenZiti      +  VLAN Micro-segmentation |\n'
        '+-------------------+-----------------------+\n'
        '                    |\n'
        '                    v\n'
        '+-------------------------------------------+\n'
        '|       NETWORK MONITORING LAYER            |\n'
        '|  Zeek (Docker) --> conn.log               |\n'
        '|  40 NSL-KDD features per connection       |\n'
        '+--------+--------------------+-------------+\n'
        '         |                    |\n'
        '         v                    v\n'
        '+----------------+   +------------------------+\n'
        '| CNN-GRU        |   | Autoencoder            |\n'
        '| Supervised     |   | Self-Supervised        |\n'
        '| Known Attacks  |   | Zero-day Detection     |\n'
        '| (DoS/Probe/    |   | (Reconstruction error  |\n'
        '|  R2L/U2R)      |   |  > 95th-pct threshold) |\n'
        '+-------+--------+   +-----------+------------+\n'
        '        |                        |\n'
        '        +----------+-------------+\n'
        '                   |\n'
        '                   v\n'
        '          Combined Risk Score (0-1)\n'
        '                   |\n'
        '   ----------------+----------------\n'
        '   |        |           |          |\n'
        ' >0.8    0.5-0.8     0.3-0.5    <0.3\n'
        ' BLOCK  CHALLENGE    MONITOR    ALLOW\n'
        '          MFA'
    )
    arch_tbl = Table([[
        Paragraph(
            f'<font name="Courier" size="7.5">{arch_text.replace(chr(10), "<br/>")}</font>',
            ps('arch', fn='Courier', fs=7.5, al=TA_LEFT, lead=9.5, sa=0))
    ]], [CW])
    arch_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), BGREY),
        ('BOX',           (0, 0), (-1, -1), 0.8, BLUE),
        ('TOPPADDING',    (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING',   (0, 0), (-1, -1), 8),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
    ]))
    S.append(arch_tbl)
    S.append(sp(0.15))
    S.append(hr(LG, 0.4))

    # ── Key results table ─────────────────────────────────────────────────
    S.append(Paragraph('Key Results — Four-Way Comparison (NSL-KDD, 22,543 test samples)', H2))

    results_data = [
        ['System', 'Accuracy', 'F1 Score', 'FPR', 'Latency', 'Zero-Day'],
        ['ZTA + Autoencoder', '0.8443', '0.8482', '0.0501', '0.0656 ms', '✓'],
        ['ZTA + CNN-GRU',     '0.7945', '0.7886', '0.0452', '0.5889 ms', '—'],
        ['ZTA Only',          '0.7691', '0.7677', 'N/A',    'N/A',       '—'],
        ['Legacy VPN',        '0.6664', '0.6524', 'N/A',    'N/A',       '—'],
    ]

    col_w = [CW * 0.28, CW * 0.13, CW * 0.13, CW * 0.12, CW * 0.18, CW * 0.16]
    rt = Table(results_data, colWidths=col_w)
    rt.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0), BLUE),
        ('TEXTCOLOR',     (0, 0), (-1, 0), W),
        ('FONTNAME',      (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, -1), 9),
        ('ALIGNMENT',     (0, 0), (-1, -1), 'CENTER'),
        ('ALIGNMENT',     (0, 0), (0, -1),  'LEFT'),
        ('BACKGROUND',    (0, 1), (-1, 1), BGREEN),
        ('FONTNAME',      (0, 1), (-1, 1), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS',(0, 2), (-1, -1), [BGREY, W]),
        ('GRID',          (0, 0), (-1, -1), 0.4, LG),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING',   (0, 0), (0, -1),  5),
    ]))
    S.append(rt)
    S.append(sp(0.1))
    S.append(Paragraph(
        '<b>Note:</b> ZTA+Autoencoder achieves the highest accuracy and F1 and is ~9× '
        'faster than CNN-GRU at inference. R2L recall is 0.287 — those connections '
        'resemble normal traffic to the autoencoder (documented limitation). CNN-GRU '
        'achieves the lowest FPR (0.0452).', SML))

    # ════════════════════════════════════════════════════════════════════════
    # PAGE 2
    # ════════════════════════════════════════════════════════════════════════
    S.append(PageBreak())

    # ── Contributions ─────────────────────────────────────────────────────
    S.append(Paragraph('Research Contributions', H1))
    for t in [
        '<b>Dual-layer ML pipeline:</b> Novel combination of a supervised CNN-GRU '
        '(Conv1D 64→128→256 + GRU 128→64, ~327K params) and a self-supervised '
        'autoencoder (Encoder 40→128→64→16, Decoder 16→64→128→40) into a single '
        'unified risk scoring system. Neither model alone achieves both known-attack '
        'classification and zero-day detection.',
        '<b>Self-supervised zero-day detection:</b> The autoencoder is trained on '
        'normal traffic only (67,343 samples, no attack labels). It achieves 0.8443 '
        'accuracy by measuring reconstruction error against a 95th-percentile '
        'threshold. Mean reconstruction error for attacks is ~19× higher than for '
        'normal traffic. Zero-day recall: DoS=0.911, Probe=0.882, U2R=0.687. '
        'The autoencoder uses reconstruction-based anomaly detection — a self-supervised '
        'approach where the model learns to reconstruct normal traffic; samples with high '
        'reconstruction error are flagged as anomalies without requiring attack labels.',
        '<b>Flask REST API:</b> Production-ready risk-scoring API with /predict, '
        '/predict/batch, /health, and /model/info endpoints. Loads both models at '
        'startup, computes the combined risk score, and enforces ZTA policy (ALLOW / '
        'MONITOR / CHALLENGE_MFA / BLOCK) per connection in real time.',
        '<b>Four-way evaluation framework:</b> Rigorous controlled comparison of '
        'Legacy VPN, ZTA-Only, ZTA+CNN-GRU, and ZTA+Autoencoder on the same 22,543-'
        'sample NSL-KDD test set with identical metrics (Accuracy, F1, FPR, Latency, '
        'Zero-Day capability). Results are honest — weaknesses are reported alongside '
        'strengths.',
    ]:
        S.append(b(t))
    S.append(sp(0.1))
    S.append(hr(LG, 0.4))

    # ── Limitations ───────────────────────────────────────────────────────
    S.append(Paragraph('Limitations', H2))
    for t in [
        '<b>R2L recall: 0.287.</b> Remote-to-Local attacks reconstruct like normal '
        'traffic in the autoencoder, producing reconstruction errors below the '
        '95th-percentile threshold. Their connection-level features (duration, '
        'byte counts, flag patterns) do not deviate significantly from benign traffic, '
        'making them the hardest class for reconstruction-based detection.',
        '<b>No live network deployment.</b> The system is evaluated on the NSL-KDD '
        'static benchmark dataset and a GNS3-simulated hybrid network. Performance on '
        'live enterprise traffic — with encrypted connections, adversarial evasion, '
        'and concept drift — has not been validated.',
        '<b>Threshold is static.</b> The 95th-percentile anomaly threshold is computed '
        'once at training time. It does not adapt online to shifts in normal traffic '
        'behaviour or seasonal drift.',
    ]:
        S.append(b(t))
    S.append(sp(0.1))
    S.append(hr(LG, 0.4))

    # ── Future Work ───────────────────────────────────────────────────────
    S.append(Paragraph('Future Work', H2))
    for t in [
        '<b>Adversarial robustness:</b> Evaluate the system against adversarial '
        'examples crafted to evade the autoencoder — e.g., minimal-perturbation '
        'DoS packets designed to reconstruct within the normal error range.',
        '<b>Federated learning for privacy:</b> Extend the autoencoder to a '
        'federated training scheme so distributed enterprise nodes can contribute '
        'to the normal-traffic model without sharing raw connection data.',
        '<b>Online / incremental learning:</b> Replace the static threshold with '
        'an adaptive anomaly detector that updates its normal-traffic distribution '
        'continuously, handling concept drift and evolving attack patterns without '
        'periodic full retraining.',
    ]:
        S.append(b(t))
    S.append(sp(0.1))
    S.append(hr(LG, 0.4))

    # ── References ────────────────────────────────────────────────────────
    S.append(Paragraph('References', H2))
    refs = [
        ('[1]', 'Gambo & Almulhem (2026). Zero Trust Architecture: A Systematic '
                'Literature Review. <i>Journal of Network and Systems Management</i>, '
                '34(1).'),
        ('[2]', 'Zohaib et al. (2024). Zero Trust VPN (ZT-VPN). <i>Information</i>, '
                '15(11).'),
        ('[3]', 'Bakhshi & Ghita (2021). Anomaly Detection in Encrypted Internet '
                'Traffic Using Hybrid Deep Learning. '
                '<i>Security and Communication Networks</i>.'),
        ('[4]', 'Kim et al. (2024). Exploring Effective Zero Trust Architecture for '
                'Defense Cybersecurity. <i>KSII Transactions on Internet and '
                'Information Systems</i>, 18(7).'),
        ('[5]', 'Abdelhady et al. (2026). Hybrid ML Anomaly Detection and Lightweight '
                'ZTA for LoRaWAN Networks. <i>IEEE Access</i>, 14.'),
        ('[6]', 'Tian et al. (2024). S4: Self-Supervised Learning with Sparse-Dense '
                'Sampling. <i>Knowledge-Based Systems</i>.'),
        ('[7]', 'Dhumal et al. (2025). ZTA for Ransomware Defense in Virtualized '
                'Environments. <i>IEEE/ACM BigData</i>.'),
    ]
    ref_tbl_data = [
        [Paragraph(r[0], ps('rk', fn='Helvetica-Bold', fs=8.5, al=TA_LEFT, lead=11)),
         Paragraph(r[1], ps('rv', fs=8.5, al=TA_JUSTIFY, lead=11))]
        for r in refs
    ]
    ref_tbl = Table(ref_tbl_data, colWidths=[CW * 0.07, CW * 0.93])
    ref_tbl.setStyle(TableStyle([
        ('VALIGN',       (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING',   (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING',(0, 0), (-1, -1), 2),
        ('LEFTPADDING',  (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
    ]))
    S.append(ref_tbl)
    S.append(sp(0.15))
    S.append(hr())

    # ── Closing block ─────────────────────────────────────────────────────
    closing = Table([[
        Paragraph(
            '<b>Okado Aaron Obbo</b>  |  Reg No: S24B23/015  |  Student No: B29782  |  '
            'BSc Computer Science  |  Uganda Christian University  |  '
            'github.com/asdcaaron/zta-ml-framework',
            ps('cl', fs=8.5, tc=BLUE, al=TA_CENTER, lead=11))
    ]], [CW])
    closing.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), BBLUE),
        ('BOX',           (0, 0), (-1, -1), 0.5, BLUE),
        ('TOPPADDING',    (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    S.append(closing)

    # ── Build ─────────────────────────────────────────────────────────────
    doc.build(S, onFirstPage=footer, onLaterPages=footer)

    size_kb = os.path.getsize(OUTPUT) / 1024
    print(f'PDF generated : {OUTPUT}')
    print(f'Size          : {size_kb:.1f} KB')

    with open(OUTPUT, 'rb') as fh:
        content = fh.read().decode('latin-1')
    pages = len(re.findall(r'/Type\s*/Page[^s]', content))
    print(f'Pages         : {pages}')


if __name__ == '__main__':
    generate()
