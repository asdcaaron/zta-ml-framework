"""
generate_poster.py
-------------------
A3-landscape research poster for:
  Risk-Adaptive Zero Trust for Securing Hybrid Workforces
  Using Self-Supervised Anomaly Detection

Author : Okado Aaron Obbo  S24B23/015  |  B29782
         BSc Computer Science, Uganda Christian University

Layout : Full-width header → 3-column body → full-width footer
Output : data/Research_Poster_Okado_Aaron_Obbo.pdf
Run    : python generate_poster.py
"""

import os
from reportlab.lib.pagesizes import A3, landscape
from reportlab.lib.units import cm, mm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph,
    Spacer, HRFlowable, Image
)

OUTPUT = os.path.join('data', 'Research_Poster_Okado_Aaron_Obbo.pdf')

# ── Colours ───────────────────────────────────────────────────────────────────
BLUE   = colors.HexColor('#003087')
GOLD   = colors.HexColor('#C8A84B')
BBLUE  = colors.HexColor('#E8F0FB')
BGREEN = colors.HexColor('#E8F5E9')
BGOLD  = colors.HexColor('#FFF8E1')
BGREY  = colors.HexColor('#F5F5F5')
RED    = colors.HexColor('#C62828')
GREEN  = colors.HexColor('#2E7D32')
GREY   = colors.HexColor('#555555')
LG     = colors.HexColor('#CCCCCC')
W      = colors.white
BK     = colors.black
DARK_GOLD = colors.HexColor('#A07830')

# ── Page setup (A3 landscape) ─────────────────────────────────────────────────
PW, PH = landscape(A3)   # 420mm × 297mm  →  ~1190 × 842 pt
LM = RM = 0.9 * cm
TM = BM = 0.7 * cm
CW = PW - LM - RM        # full content width

# Column widths (3 equal columns with small gutters)
GAP   = 0.4 * cm
NCOLS = 3
COL_W = (CW - (NCOLS - 1) * GAP) / NCOLS
# Inner usable width inside a column (accounting for cell padding)
INNER_W = COL_W - 0.4 * cm


# ── Style factory ─────────────────────────────────────────────────────────────
def ps(name, fn='Helvetica', fs=7.5, tc=BK, al=TA_JUSTIFY,
       lead=10, sb=0, sa=2, li=0, fi=0):
    return ParagraphStyle(name, fontName=fn, fontSize=fs, textColor=tc,
                          alignment=al, leading=lead, spaceBefore=sb,
                          spaceAfter=sa, leftIndent=li, firstLineIndent=fi)

PTITLE  = ps('ptitle', 'Helvetica-Bold', 15, W, TA_CENTER, 19, sa=3)
PSUB    = ps('psub',   'Helvetica-Bold', 8.5, W, TA_CENTER, 11, sa=2)
PAUTH   = ps('pauth',  'Helvetica',      8,   W, TA_CENTER, 10, sa=2)
SEC     = ps('sec',    'Helvetica-Bold', 8.5, BLUE, TA_LEFT, 11, sb=2, sa=2)
BODY    = ps('body',   fs=7.2, lead=9.8, sa=2)
BODYJ   = ps('bodyj',  fs=7.2, lead=9.8, sa=2, al=TA_JUSTIFY)
BULL    = ps('bull',   fs=7.0, lead=9.5, li=8, fi=-7, sa=1)
SMCTR   = ps('smctr',  fs=6.8, tc=GREY, al=TA_CENTER, lead=8.5, sa=2)
BOLD_BL = ps('bbl',    'Helvetica-Bold', 8.0, BLUE, al=TA_CENTER, lead=10)
BOLD_GR = ps('bgr',    'Helvetica-Bold', 8.0, GREEN, al=TA_CENTER, lead=10)
CAPTN   = ps('captn',  fn='Helvetica-Oblique', fs=6.5, tc=GREY, al=TA_CENTER, lead=8.5, sa=2)

def sp(h=0.15): return Spacer(1, h * cm)
def hr(c=GOLD, t=0.7, w='100%'):
    return HRFlowable(width=w, thickness=t, color=c, spaceAfter=2, spaceBefore=2)

def b(t, sty=None):
    if sty is None:
        sty = BULL
    return Paragraph(f'&#8226;&#160;{t}', sty)


# ── Figure helper ──────────────────────────────────────────────────────────────
def poster_image(path, max_w, max_h, caption=''):
    """Return list of flowables for a figure (image + caption)."""
    items = []
    if os.path.exists(path):
        img = Image(path)
        iw, ih = img.imageWidth, img.imageHeight
        scale = min(max_w / iw, max_h / ih, 1.0)
        img.drawWidth  = iw * scale
        img.drawHeight = ih * scale
        items.append(img)
    else:
        fname = os.path.basename(path)
        items.append(Paragraph(
            f'<i>[Figure: {fname} — not found]</i>',
            ps('ph', fn='Helvetica-Oblique', fs=7, tc=GREY, al=TA_CENTER, lead=9)))
    if caption:
        items.append(Paragraph(f'<i>{caption}</i>', CAPTN))
    return items


# ── Section heading ───────────────────────────────────────────────────────────
def sec_heading(title, col_w=None):
    """BLUE background section heading with GOLD underline border."""
    if col_w is None:
        col_w = INNER_W
    t = Table([[Paragraph(
        f'<font name="Helvetica-Bold" size="8.5" color="#FFFFFF">{title}</font>',
        ps('h', al=TA_LEFT, lead=10))]],
        [col_w])
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), BLUE),
        ('TOPPADDING',    (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING',   (0, 0), (-1, -1), 5),
        ('LINEBELOW',     (0, 0), (-1, -1), 1.0, GOLD),
    ]))
    return t


# ── Bordered box ──────────────────────────────────────────────────────────────
def box(content_rows, col_w=None, bg=BGOLD, border=GOLD, pad=5):
    if col_w is None:
        col_w = INNER_W
    inner = col_w - 2 * pad / 28.35  # subtract padding from inner width
    t = Table([[c] for c in content_rows], [col_w])
    t.setStyle(TableStyle([
        ('BACKGROUND',   (0, 0), (-1, -1), bg),
        ('BOX',          (0, 0), (-1, -1), 0.8, border),
        ('TOPPADDING',   (0, 0), (-1, -1), pad),
        ('BOTTOMPADDING',(0, 0), (-1, -1), pad),
        ('LEFTPADDING',  (0, 0), (-1, -1), pad),
        ('RIGHTPADDING', (0, 0), (-1, -1), pad),
        ('VALIGN',       (0, 0), (-1, -1), 'TOP'),
    ]))
    return t


# ── Compact data table ────────────────────────────────────────────────────────
def compact_table(rows, widths, hdr_bg=BLUE, hdr_tc=W,
                  row_bgs=None, extra=None):
    if row_bgs is None:
        row_bgs = [BGREY, W]
    base = [
        ('BACKGROUND',    (0, 0), (-1, 0),  hdr_bg),
        ('TEXTCOLOR',     (0, 0), (-1, 0),  hdr_tc),
        ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, -1), 6.5),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), row_bgs),
        ('GRID',          (0, 0), (-1, -1), 0.25, LG),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('LEFTPADDING',   (0, 0), (-1, -1), 2),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 2),
    ]
    if extra:
        base += extra
    t = Table(rows, colWidths=widths)
    t.setStyle(TableStyle(base))
    return t


def tc(txt, bold=False, clr=BK, sz=6.5, al=TA_CENTER):
    fn = 'Helvetica-Bold' if bold else 'Helvetica'
    return Paragraph(
        f'<font name="{fn}" size="{sz}" color="{clr.hexval()}">{txt}</font>',
        ps('tc', al=al, lead=9))


# ────────────────────────────────────────────────────────────────────────────
#  COLUMN BUILDERS
# ────────────────────────────────────────────────────────────────────────────
def build_col1():
    """Left column: Brief Summary, Research Objective, Methodology."""
    items = []

    # ── Brief Summary (Why / How / What) ─────────────────────────────────────
    items.append(sec_heading('Brief Summary'))
    items.append(sp(0.08))

    summary_rows = [
        [Paragraph('<font name="Helvetica-Bold" size="8" color="#003087">WHY</font>',
                   ps('sw', al=TA_CENTER, lead=10)),
         Paragraph(
             'Hybrid workforces create new attack surfaces that legacy VPNs and '
             'rule-based ZTA cannot defend alone. Unknown (zero-day) threats cannot '
             'be detected without labelled attack data.',
             ps('sb', fs=7.8, lead=10.5, sa=0))],
        [Paragraph('<font name="Helvetica-Bold" size="8" color="#2E7D32">HOW</font>',
                   ps('sh', al=TA_CENTER, lead=10)),
         Paragraph(
             'A dual-layer ML pipeline pairs a supervised CNN-GRU classifier '
             '(known attacks) with a self-supervised autoencoder '
             '(reconstruction-based; no attack labels needed) inside a ZTA '
             'policy engine. Both scores fuse into one risk value: '
             'ALLOW / MONITOR / CHALLENGE MFA / BLOCK.',
             ps('sb2', fs=7.8, lead=10.5, sa=0))],
        [Paragraph('<font name="Helvetica-Bold" size="8" color="#C8A84B">WHAT</font>',
                   ps('swt', al=TA_CENTER, lead=10)),
         Paragraph(
             'A working Risk-Adaptive ZTA prototype evaluated in a controlled '
             '5-way comparison on NSL-KDD. The combined system achieves '
             '<b>accuracy 0.889, F1 0.900</b> with zero-day detection capability '
             '— the only configuration that detects unseen attack types without '
             'prior labelling.',
             ps('sb3', fs=7.8, lead=10.5, sa=0))],
    ]
    summary_tbl = Table(summary_rows, colWidths=[COL_W * 0.14, COL_W * 0.86])
    summary_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (0, 0), colors.HexColor('#E8F0FB')),
        ('BACKGROUND',    (0, 1), (0, 1), colors.HexColor('#E8F5E9')),
        ('BACKGROUND',    (0, 2), (0, 2), colors.HexColor('#FFF8E1')),
        ('BOX',           (0, 0), (-1, -1), 0.8, GOLD),
        ('INNERGRID',     (0, 0), (-1, -1), 0.3, LG),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING',   (0, 0), (-1, -1), 5),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 5),
    ]))
    items.append(summary_tbl)
    items.append(sp(0.15))

    # ── Research Objective ────────────────────────────────────────────────────
    items.append(sec_heading('Research Objective'))
    items.append(sp(0.08))
    items.append(Paragraph(
        'Design, implement and experimentally evaluate a <b>Risk-Adaptive Zero Trust '
        'Architecture</b> that integrates:', BODYJ))
    for t in [
        'A <b>supervised CNN-GRU</b> for known-attack classification '
        '(Normal, DoS, Probe, R2L, U2R)',
        'A <b>self-supervised autoencoder</b> (reconstruction-based; trained on '
        'normal traffic only — no attack labels required) for zero-day anomaly detection',
        'A <b>risk fusion engine</b> combining both scores into adaptive '
        'ZTA policy decisions',
        'A <b>controlled 5-way comparison</b> against Legacy VPN and ZTA-only baselines '
        'on the same test set',
    ]:
        items.append(b(t))
    items.append(sp(0.08))
    items.append(box([
        Paragraph(
            '<i>"No existing work pairs Zero Trust Architecture with a self-supervised '
            '(label-free) anomaly detector in a comparative, hybrid workforce study."</i>',
            ps('gq', fn='Helvetica-Oblique', fs=7.8, tc=BLUE, al=TA_CENTER, lead=10.5, sa=0)),
    ], col_w=COL_W, bg=BGOLD, border=GOLD))
    items.append(sp(0.15))

    # ── Methodology ───────────────────────────────────────────────────────────
    items.append(sec_heading('Methodology'))
    items.append(sp(0.08))

    meth_rows = [
        [Paragraph('<font name="Helvetica-Bold" size="7.5" color="#FFFFFF">Step</font>',
                   ps('mh0', al=TA_CENTER, lead=10)),
         Paragraph('<font name="Helvetica-Bold" size="7.5" color="#FFFFFF">Action</font>',
                   ps('mh1', al=TA_LEFT, lead=10))],
        [Paragraph('<font name="Helvetica-Bold" size="7.5" color="#003087">1</font>',
                   ps('mn', al=TA_CENTER, lead=10)),
         Paragraph('<b>Data:</b> NSL-KDD (125,973 train / 22,543 test). '
                   'Preprocessing: drop zero-variance, log1p scaling, '
                   'LabelEncode (3 categorical), MinMaxScaler → 40 clean features.',
                   ps('mb', fs=7.5, lead=10, sa=0))],
        [Paragraph('<font name="Helvetica-Bold" size="7.5" color="#003087">2</font>',
                   ps('mn2', al=TA_CENTER, lead=10)),
         Paragraph('<b>CNN-GRU training:</b> Conv1D(64→128→256) + GRU(128→64), '
                   '327K params, 50 epochs, supervised on 5 classes.',
                   ps('mb2', fs=7.5, lead=10, sa=0))],
        [Paragraph('<font name="Helvetica-Bold" size="7.5" color="#2E7D32">3</font>',
                   ps('mn3', al=TA_CENTER, lead=10)),
         Paragraph('<b>Autoencoder training:</b> Encoder 40→128→64→16 / Decoder '
                   '16→64→128→40. Trained on NORMAL traffic only (67,343 samples). '
                   'Threshold = 95th pct of reconstruction error on validation normals.',
                   ps('mb3', fs=7.5, lead=10, sa=0))],
        [Paragraph('<font name="Helvetica-Bold" size="7.5" color="#C8A84B">4</font>',
                   ps('mn4', al=TA_CENTER, lead=10)),
         Paragraph('<b>Risk fusion:</b> combined_risk = max(CNN_risk, AE_risk). '
                   'Flask API serves real-time decisions. Zeek Docker pipeline: '
                   'pcap → conn.log → API → audit.jsonl.',
                   ps('mb4', fs=7.5, lead=10, sa=0))],
        [Paragraph('<font name="Helvetica-Bold" size="7.5" color="#555555">5</font>',
                   ps('mn5', al=TA_CENTER, lead=10)),
         Paragraph('<b>Evaluation:</b> 5-way controlled comparison on identical '
                   '22,543-sample test set. Metrics: Accuracy, F1, FPR, '
                   'Response Time, Zero-Day Detection, per-class recall.',
                   ps('mb5', fs=7.5, lead=10, sa=0))],
    ]
    meth_tbl = Table(meth_rows, colWidths=[COL_W * 0.08, COL_W * 0.92])
    meth_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  BLUE),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [BGREY, W, BGREEN, BGOLD, BGREY]),
        ('GRID',          (0, 0), (-1, -1), 0.3, LG),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING',    (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING',   (0, 0), (-1, -1), 4),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 4),
    ]))
    items.append(meth_tbl)

    return items


def build_col2():
    """Centre column: Results & Benchmarking, Dataset & Baselines, Pipeline."""
    items = []

    # ── Results & Benchmarking ────────────────────────────────────────────────
    items.append(sec_heading('Results & Benchmarking'))
    items.append(sp(0.06))
    items.append(Paragraph(
        'All 5 systems evaluated on the <b>same 22,543 NSL-KDD test samples</b>. '
        '* = simulated baseline (not a live deployment).',
        ps('note', fs=7, tc=GREY, al=TA_LEFT, lead=9, sa=3)))

    def hdr(t):
        return Paragraph(
            f'<font name="Helvetica-Bold" size="7" color="#FFFFFF">{t}</font>',
            ps('ch', al=TA_CENTER, lead=9))

    def val(t, bold=False, clr=BK):
        fn = 'Helvetica-Bold' if bold else 'Helvetica'
        return Paragraph(
            f'<font name="{fn}" size="7" color="{clr.hexval()}">{t}</font>',
            ps('cv', al=TA_CENTER, lead=9))

    W1 = COL_W * 0.36
    W2 = COL_W * 0.13
    W3 = COL_W * 0.13
    W4 = COL_W * 0.13
    W5 = COL_W * 0.25

    comp_rows = [
        [hdr('System'), hdr('Acc'), hdr('F1'), hdr('FPR'), hdr('Zero-Day')],
        [Paragraph('<font size="7">Legacy VPN *</font>', ps('r1', al=TA_LEFT, lead=9)),
         val('0.666'), val('0.652'), val('0.180'), val('No')],
        [Paragraph('<font size="7">ZTA Only *</font>', ps('r2', al=TA_LEFT, lead=9)),
         val('0.769'), val('0.768'), val('0.100'), val('No')],
        [Paragraph('<font size="7">ZTA + CNN-GRU</font>', ps('r3', al=TA_LEFT, lead=9)),
         val('0.795'), val('0.789'), val('0.045'), val('No')],
        [Paragraph('<font size="7">ZTA + Autoencoder</font>', ps('r4', al=TA_LEFT, lead=9)),
         val('0.858'), val('0.865'), val('0.061'),
         val('YES ✓', bold=True, clr=BLUE)],
        [Paragraph('<font name="Helvetica-Bold" size="7">ZTA + CNN-GRU + AE ★</font>',
                   ps('r5', fn='Helvetica-Bold', al=TA_LEFT, lead=9)),
         val('0.889', bold=True, clr=BLUE),
         val('0.900', bold=True, clr=BLUE),
         val('0.099'),
         val('YES ✓', bold=True, clr=BLUE)],
    ]
    comp_tbl = Table(comp_rows, colWidths=[W1, W2, W3, W4, W5])
    comp_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  BLUE),
        ('BACKGROUND',    (0, 5), (-1, 5),  BBLUE),
        ('BOX',           (0, 5), (-1, 5),  1.0, BLUE),
        ('FONTSIZE',      (0, 0), (-1, -1), 7),
        ('ROWBACKGROUNDS',(0, 1), (-1, 4),  [BGREY, W, BGREY, W]),
        ('GRID',          (0, 0), (-1, -1), 0.25, LG),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING',   (0, 0), (-1, -1), 3),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 3),
    ]))
    items.append(comp_tbl)
    items.append(Paragraph(
        '<i>★ ZTA+CNN-GRU+AE Fusion: best on accuracy and F1; zero-day capable.</i>',
        CAPTN))
    items.append(sp(0.1))

    # Per-class detection
    W_a = COL_W * 0.22
    W_b = COL_W * 0.24
    W_c = COL_W * 0.24
    W_d = COL_W * 0.30

    pc_rows = [
        [hdr('Class'), hdr('CNN-GRU'), hdr('Autoencoder'), hdr('Zero-Day Recall')],
        [tc('DoS'),   tc('0.817'), tc('0.912', bold=True, clr=BLUE), tc('91.1% ✓', bold=True, clr=BLUE)],
        [tc('Probe'), tc('0.571'), tc('0.947', bold=True, clr=BLUE), tc('88.2% ✓', bold=True, clr=BLUE)],
        [tc('U2R'),   tc('0.358'), tc('0.687', bold=True, clr=BLUE), tc('68.7% ✓', bold=True, clr=BLUE)],
        [tc('R2L'),   tc('0.394', bold=True, clr=BLUE),
         tc('0.379', clr=RED),
         Paragraph('<font name="Helvetica-Bold" size="7" color="#C62828">28.7% ⚠</font>',
                   ps('rl', al=TA_CENTER, lead=9))],
    ]
    items.append(compact_table(pc_rows, [W_a, W_b, W_c, W_d]))
    items.append(Paragraph(
        '<i>R2L weakness: those connections share statistical features with normal traffic.</i>',
        CAPTN))
    items.append(sp(0.15))

    # ── Dataset & Baselines ───────────────────────────────────────────────────
    items.append(sec_heading('Dataset & Baselines'))
    items.append(sp(0.06))

    ds_rows = [
        [hdr('Property'), hdr('Value')],
        [tc('Dataset', al=TA_LEFT), tc('NSL-KDD (cleaned, benchmark IDS dataset)', al=TA_LEFT)],
        [tc('Training samples', al=TA_LEFT), tc('125,973 (67,343 normal + 58,630 attacks)', al=TA_LEFT)],
        [tc('Test samples', al=TA_LEFT), tc('22,543 (9,710 normal + 12,833 attacks)', al=TA_LEFT)],
        [tc('Attack classes', al=TA_LEFT), tc('DoS, Probe, R2L, U2R', al=TA_LEFT)],
        [tc('Features', al=TA_LEFT), tc('40 (after preprocessing pipeline)', al=TA_LEFT)],
        [tc('Baseline A', al=TA_LEFT), tc('Legacy VPN — simulated, no ML', al=TA_LEFT)],
        [tc('Baseline B', al=TA_LEFT), tc('ZTA Only — simulated, no ML', al=TA_LEFT)],
        [tc('Baseline C', al=TA_LEFT), tc('ZTA + CNN-GRU — supervised only', al=TA_LEFT)],
        [tc('Baseline D', al=TA_LEFT), tc('ZTA + Autoencoder — unsupervised only', al=TA_LEFT)],
        [tc('System E ★', al=TA_LEFT), tc('ZTA + CNN-GRU + AE Fusion — proposed system', al=TA_LEFT)],
    ]
    ds_tbl = Table(ds_rows, colWidths=[COL_W * 0.38, COL_W * 0.62])
    ds_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  BLUE),
        ('FONTSIZE',      (0, 0), (-1, -1), 7),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [BGREY, W]),
        ('GRID',          (0, 0), (-1, -1), 0.25, LG),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('LEFTPADDING',   (0, 0), (-1, -1), 3),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 3),
        # Highlight System E row
        ('BACKGROUND',    (0, 10), (-1, 10), BBLUE),
        ('BOX',           (0, 10), (-1, 10), 0.8, BLUE),
    ]))
    items.append(ds_tbl)
    items.append(sp(0.15))

    # ── Pipeline ──────────────────────────────────────────────────────────────
    items.append(sec_heading('System Pipeline'))
    items.append(sp(0.08))

    box_w = COL_W - 0.2 * cm
    half_w = (box_w - 0.15 * cm) / 2

    def pipe_box(lbl, bg, border_c, fs=7.5):
        t = Table([[Paragraph(
            f'<font name="Helvetica-Bold" size="{fs}" color="{border_c.hexval()}">'
            f'{lbl}</font>',
            ps('pb', al=TA_CENTER, lead=10))]],
            [box_w])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), bg),
            ('BOX',           (0, 0), (-1, -1), 0.8, border_c),
            ('TOPPADDING',    (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('ALIGNMENT',     (0, 0), (-1, -1), 'CENTER'),
        ]))
        return t

    def arr():
        return Paragraph(
            '<font size="9" color="#999999">&#8595;</font>',
            ps('ar', al=TA_CENTER, lead=11))

    def split_boxes(lbl1, bg1, c1, lbl2, bg2, c2):
        t1 = Table([[Paragraph(
            f'<font name="Helvetica-Bold" size="7" color="{c1.hexval()}">'
            f'{lbl1}</font>',
            ps('sb1', al=TA_CENTER, lead=9))]],
            [half_w])
        t1.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), bg1),
            ('BOX',           (0, 0), (-1, -1), 0.8, c1),
            ('TOPPADDING',    (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        t2 = Table([[Paragraph(
            f'<font name="Helvetica-Bold" size="7" color="{c2.hexval()}">'
            f'{lbl2}</font>',
            ps('sb2', al=TA_CENTER, lead=9))]],
            [half_w])
        t2.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), bg2),
            ('BOX',           (0, 0), (-1, -1), 0.8, c2),
            ('TOPPADDING',    (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        outer = Table([[t1, t2]], [half_w, half_w])
        outer.setStyle(TableStyle([
            ('LEFTPADDING',  (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING',   (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING',(0, 0), (-1, -1), 0),
            ('VALIGN',       (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        return outer

    items.append(pipe_box('INPUT: Live traffic | NSL-KDD | Zeek conn.log | pcap',
                          BGREY, GREY))
    items.append(arr())
    items.append(pipe_box('PREPROCESS: drop zero-var → log1p → LabelEncode → MinMax → 40 features',
                          BGOLD, GOLD))
    items.append(arr())
    items.append(split_boxes(
        'CNN-GRU (Supervised)\nConv1D 64→128→256\n+ GRU 128→64 | 327K params\nKnown attack classifier',
        BBLUE, BLUE,
        'Autoencoder ★ (Self-Sup.)\nEncoder 40→128→64→16\nDecoder 16→64→128→40\nZero-day detector',
        BGREEN, GREEN))
    items.append(arr())
    items.append(pipe_box('RISK FUSION: combined = max(CNN_risk, AE_risk) → Flask API',
                          BGOLD, GOLD))
    items.append(arr())

    # Decision boxes
    W4 = box_w / 4
    acts = Table([[
        Paragraph('<font name="Helvetica-Bold" size="7" color="#C62828">&gt;0.8\nBLOCK</font>',
                  ps('a1', al=TA_CENTER, lead=9)),
        Paragraph('<font name="Helvetica-Bold" size="7" color="#E65100">0.5–0.8\nCHALLENGE</font>',
                  ps('a2', al=TA_CENTER, lead=9)),
        Paragraph('<font name="Helvetica-Bold" size="7" color="#C8A84B">0.3–0.5\nMONITOR</font>',
                  ps('a3', al=TA_CENTER, lead=9)),
        Paragraph('<font name="Helvetica-Bold" size="7" color="#2E7D32">&lt;0.3\nALLOW</font>',
                  ps('a4', al=TA_CENTER, lead=9)),
    ]], [W4, W4, W4, W4])
    acts.setStyle(TableStyle([
        ('BACKGROUND',  (0, 0), (0, -1), colors.HexColor('#FFEBEE')),
        ('BACKGROUND',  (1, 0), (1, -1), colors.HexColor('#FFF3E0')),
        ('BACKGROUND',  (2, 0), (2, -1), colors.HexColor('#FFFDE7')),
        ('BACKGROUND',  (3, 0), (3, -1), BGREEN),
        ('BOX',         (0, 0), (-1, -1), 0.4, LG),
        ('INNERGRID',   (0, 0), (-1, -1), 0.3, LG),
        ('TOPPADDING',  (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING',(0,0), (-1, -1), 3),
    ]))
    items.append(acts)

    return items


def build_col3():
    """Right column: Conclusion (impact), Alignment (SDG/NDP IV/Vision 2040), References."""
    items = []

    # ── Conclusion / Impact ───────────────────────────────────────────────────
    items.append(sec_heading('Conclusion & Impact'))
    items.append(sp(0.08))
    items.append(Paragraph(
        'The ZTA + CNN-GRU + Autoencoder fusion system demonstrates that combining '
        'supervised and self-supervised ML inside a Zero Trust framework produces '
        'measurably stronger security outcomes than any single approach alone.',
        BODYJ))
    items.append(sp(0.06))

    impact_rows = [
        [Paragraph('<font name="Helvetica-Bold" size="7.5" color="#FFFFFF">Finding</font>',
                   ps('ih0', al=TA_LEFT, lead=10)),
         Paragraph('<font name="Helvetica-Bold" size="7.5" color="#FFFFFF">Impact</font>',
                   ps('ih1', al=TA_LEFT, lead=10))],
        [Paragraph('<font size="7.5" color="#003087"><b>Best accuracy 0.889 &amp; F1 0.900</b></font>',
                   ps('if1', al=TA_LEFT, lead=10)),
         Paragraph('Outperforms all baselines including CNN-GRU alone — fusion adds value.',
                   ps('iv1', fs=7.5, lead=10, sa=0))],
        [Paragraph('<font size="7.5" color="#2E7D32"><b>Zero-day detection ✓</b></font>',
                   ps('if2', al=TA_LEFT, lead=10)),
         Paragraph('Only system that flags unseen attack types without prior labelling. '
                   'DoS 91%, Probe 88% recall.',
                   ps('iv2', fs=7.5, lead=10, sa=0))],
        [Paragraph('<font size="7.5" color="#003087"><b>9× faster inference</b></font>',
                   ps('if3', al=TA_LEFT, lead=10)),
         Paragraph('Autoencoder: 0.066 ms/sample vs CNN-GRU: 0.589 ms — suitable '
                   'for real-time ZTA enforcement.',
                   ps('iv3', fs=7.5, lead=10, sa=0))],
        [Paragraph('<font size="7.5" color="#C62828"><b>R2L limitation ⚠</b></font>',
                   ps('if4', al=TA_LEFT, lead=10)),
         Paragraph('R2L recall 28.7% — connections resemble normal sessions. '
                   'Hybrid supervised+unsupervised approach recommended.',
                   ps('iv4', fs=7.5, lead=10, sa=0))],
        [Paragraph('<font size="7.5" color="#555555"><b>Practical prototype</b></font>',
                   ps('if5', al=TA_LEFT, lead=10)),
         Paragraph('Live Flask API + Zeek Docker pipeline demonstrated end-to-end. '
                   'Policy decisions logged to audit trail.',
                   ps('iv5', fs=7.5, lead=10, sa=0))],
    ]
    impact_tbl = Table(impact_rows, colWidths=[COL_W * 0.36, COL_W * 0.64])
    impact_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  BLUE),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [BGREY, W, BGREEN, colors.HexColor('#FFF0F0'), BGREY]),
        ('GRID',          (0, 0), (-1, -1), 0.3, LG),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING',    (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING',   (0, 0), (-1, -1), 4),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 4),
    ]))
    items.append(impact_tbl)
    items.append(sp(0.15))

    # ── Alignment ─────────────────────────────────────────────────────────────
    items.append(sec_heading('Strategic Alignment'))
    items.append(sp(0.08))

    align_rows = [
        [Paragraph('<font name="Helvetica-Bold" size="7.5" color="#FFFFFF">Framework</font>',
                   ps('ah0', al=TA_LEFT, lead=10)),
         Paragraph('<font name="Helvetica-Bold" size="7.5" color="#FFFFFF">Alignment</font>',
                   ps('ah1', al=TA_LEFT, lead=10))],
        [Paragraph('<font name="Helvetica-Bold" size="7.5" color="#003087">'
                   'SDG 9</font>',
                   ps('a1l', al=TA_LEFT, lead=10)),
         Paragraph('<b>Industry, Innovation &amp; Infrastructure:</b> Builds resilient '
                   'digital infrastructure with AI-driven security for hybrid enterprises.',
                   ps('a1r', fs=7.5, lead=10, sa=0))],
        [Paragraph('<font name="Helvetica-Bold" size="7.5" color="#003087">'
                   'SDG 16</font>',
                   ps('a2l', al=TA_LEFT, lead=10)),
         Paragraph('<b>Peace, Justice &amp; Strong Institutions:</b> Strengthens '
                   'institutional cybersecurity posture through adaptive, evidence-based '
                   'access control.',
                   ps('a2r', fs=7.5, lead=10, sa=0))],
        [Paragraph('<font name="Helvetica-Bold" size="7.5" color="#2E7D32">'
                   'NDP V</font>',
                   ps('a3l', al=TA_LEFT, lead=10)),
         Paragraph('<b>Digital Transformation:</b> Contributes to Uganda\'s National '
                   'Development Plan priority of secure, trusted digital services and '
                   'ICT infrastructure.',
                   ps('a3r', fs=7.5, lead=10, sa=0))],
        [Paragraph('<font name="Helvetica-Bold" size="7.5" color="#C8A84B">'
                   'Vision 2040</font>',
                   ps('a4l', al=TA_LEFT, lead=10)),
         Paragraph('<b>Knowledge Economy:</b> Supports Uganda\'s Vision 2040 goal of '
                   'transitioning to a knowledge-based economy by advancing local '
                   'AI and cybersecurity capability.',
                   ps('a4r', fs=7.5, lead=10, sa=0))],
    ]
    align_tbl = Table(align_rows, colWidths=[COL_W * 0.20, COL_W * 0.80])
    align_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  BLUE),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [BBLUE, W, BGREEN, BGOLD]),
        ('GRID',          (0, 0), (-1, -1), 0.3, LG),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING',    (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING',   (0, 0), (-1, -1), 4),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 4),
    ]))
    items.append(align_tbl)
    items.append(sp(0.15))

    # ── Key References ────────────────────────────────────────────────────────
    items.append(sec_heading('Key References'))
    items.append(sp(0.06))
    for ref in [
        '[1] Gambo &amp; Almulhem (2026). Zero Trust Architecture: A Systematic '
        'Literature Review. <i>J. Network and Systems Mgmt.</i>, 34(1).',
        '[2] Bakhshi &amp; Ghita (2021). Anomaly Detection in Encrypted Internet '
        'Traffic Using Hybrid Deep Learning. <i>Security and Comm. Networks.</i>',
        '[3] Abdelhady et al. (2026). Hybrid ML Anomaly Detection and Lightweight '
        'ZTA for LoRaWAN. <i>IEEE Access</i>, 14, 18387–18407.',
        '[4] NIST SP 800-207 (2020). Zero Trust Architecture. National Institute '
        'of Standards and Technology.',
    ]:
        items.append(Paragraph(ref, ps(f'ref{ref[1]}', fs=7, lead=9.5,
                                       al=TA_JUSTIFY, sa=2)))
    items.append(sp(0.12))

    # ── QR / GitHub ───────────────────────────────────────────────────────────
    qr_box = Table([[
        Paragraph(
            '<font name="Helvetica-Bold" size="8" color="#555555">'
            'GitHub Repository</font>',
            ps('qr1', al=TA_CENTER, lead=11)),
        Paragraph(
            '<font name="Helvetica-Bold" size="9" color="#C8A84B">'
            '&#9633;&#9633;&#9633;<br/>&#9633; QR &#9633;<br/>&#9633;&#9633;&#9633;</font>',
            ps('qrimg', al=TA_CENTER, lead=11)),
        Paragraph(
            '<font size="7.5" color="#555555">'
            'github.com/asdcaaron/<br/>zta-ml-framework</font>',
            ps('qr2', fn='Helvetica-Oblique', al=TA_CENTER, lead=10)),
    ]], [COL_W * 0.35, COL_W * 0.22, COL_W * 0.43])
    qr_box.setStyle(TableStyle([
        ('BACKGROUND',   (0, 0), (-1, -1), BGREY),
        ('BOX',          (0, 0), (-1, -1), 1.2, GOLD),
        ('TOPPADDING',   (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING',(0, 0), (-1, -1), 6),
        ('LEFTPADDING',  (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('VALIGN',       (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    items.append(qr_box)

    return items


# ────────────────────────────────────────────────────────────────────────────
#  UCU BADGE (drawn with ReportLab canvas — no external image needed)
# ────────────────────────────────────────────────────────────────────────────
from reportlab.platypus import Flowable

class UCUBadge(Flowable):
    """Shield-shaped UCU crest drawn programmatically."""
    def __init__(self, size=52):
        super().__init__()
        self.size = size
        self.width  = size
        self.height = size

    def draw(self):
        c = self.canv
        s = self.size
        cx = s / 2

        # Shield outline (deep blue)
        SHIELD_BLUE = colors.HexColor('#003087')
        SHIELD_RED  = colors.HexColor('#CC0033')
        SHIELD_GOLD = colors.HexColor('#C8A84B')

        # Draw shield shape
        c.setFillColor(SHIELD_BLUE)
        c.setStrokeColor(SHIELD_GOLD)
        c.setLineWidth(1.2)
        p = c.beginPath()
        p.moveTo(cx, s * 0.04)          # top-left
        p.lineTo(s * 0.96, s * 0.04)    # top-right
        p.lineTo(s * 0.96, s * 0.62)    # right shoulder
        p.curveTo(s * 0.96, s * 0.85, cx, s * 0.98, cx, s * 0.98)  # right arc to bottom
        p.curveTo(cx, s * 0.98, s * 0.04, s * 0.85, s * 0.04, s * 0.62)  # left arc
        p.lineTo(s * 0.04, s * 0.04)    # top-left
        p.close()
        c.drawPath(p, fill=1, stroke=1)

        # Cross (white)
        c.setFillColor(colors.white)
        bar_w = s * 0.10
        # Vertical bar
        c.rect(cx - bar_w / 2, s * 0.14, bar_w, s * 0.56, fill=1, stroke=0)
        # Horizontal bar
        c.rect(s * 0.18, s * 0.44, s * 0.64, bar_w, fill=1, stroke=0)

        # Alpha (Α) top-left quadrant — gold text
        c.setFillColor(SHIELD_GOLD)
        c.setFont('Helvetica-Bold', s * 0.16)
        c.drawCentredString(cx - s * 0.22, s * 0.56, 'A')

        # Omega (Ω) top-right quadrant — gold text
        c.drawCentredString(cx + s * 0.22, s * 0.56, '\u03A9')

        # Bottom banner (gold)
        c.setFillColor(SHIELD_GOLD)
        p2 = c.beginPath()
        p2.moveTo(s * 0.08, s * 0.14)
        p2.lineTo(s * 0.92, s * 0.14)
        p2.lineTo(s * 0.92, s * 0.08)
        p2.lineTo(s * 0.08, s * 0.08)
        p2.close()
        c.drawPath(p2, fill=1, stroke=0)

        # "UCU" text on banner
        c.setFillColor(SHIELD_BLUE)
        c.setFont('Helvetica-Bold', s * 0.10)
        c.drawCentredString(cx, s * 0.09, 'UCU')


# ────────────────────────────────────────────────────────────────────────────
#  FULL-WIDTH HEADER
# ────────────────────────────────────────────────────────────────────────────
def build_header():
    badge = UCUBadge(size=56)

    # Left cell: UCU badge
    badge_cell = Table([[badge]], [1.8 * cm])
    badge_cell.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), BLUE),
        ('TOPPADDING',    (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING',   (0, 0), (-1, -1), 8),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 4),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
    ]))

    # Centre cell: title + author
    title_w = CW - 3.6 * cm
    title_cell = Table([
        [Paragraph(
            'Uganda Christian University  |  BSc Computer Science  '
            '|  A Centre of Excellence in the Heart of Africa',
            ps('hu', fn='Helvetica', fs=8, tc=colors.HexColor('#C8A84B'),
               al=TA_CENTER, lead=10))],
        [Paragraph(
            'Risk-Adaptive Zero Trust for Securing Hybrid Workforces<br/>'
            'Using Self-Supervised Anomaly Detection',
            ps('ht', fn='Helvetica-Bold', fs=17, tc=W, al=TA_CENTER, lead=21))],
        [Paragraph(
            'Okado Aaron Obbo  |  Reg No: S24B23/015  |  Student No: B29782',
            ps('ha', fn='Helvetica', fs=8.5, tc=W, al=TA_CENTER, lead=11))],
    ], [title_w])
    title_cell.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), BLUE),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING',   (0, 0), (-1, -1), 0),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
    ]))

    # Right cell: mirror badge for symmetry
    badge_r = UCUBadge(size=56)
    badge_r_cell = Table([[badge_r]], [1.8 * cm])
    badge_r_cell.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), BLUE),
        ('TOPPADDING',    (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING',   (0, 0), (-1, -1), 4),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
    ]))

    header_tbl = Table([[badge_cell, title_cell, badge_r_cell]],
                       [1.8 * cm, title_w, 1.8 * cm])
    header_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), BLUE),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('LINEBELOW',     (0, 0), (-1, -1), 2.5, GOLD),
        ('TOPPADDING',    (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('LEFTPADDING',   (0, 0), (-1, -1), 0),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
    ]))
    return header_tbl


# ────────────────────────────────────────────────────────────────────────────
#  FULL-WIDTH FOOTER
# ────────────────────────────────────────────────────────────────────────────
def build_footer():
    footer_tbl = Table([[
        Paragraph(
            'Uganda Christian University  |  BSc Computer Science  |  '
            'Okado Aaron Obbo  |  S24B23/015',
            ps('ft', fs=8, tc=GREY, al=TA_CENTER, lead=10))
    ]], [CW])
    footer_tbl.setStyle(TableStyle([
        ('BACKGROUND',   (0, 0), (-1, -1), BGREY),
        ('LINETOP',      (0, 0), (-1, -1), 1.5, GOLD),
        ('TOPPADDING',   (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING',(0, 0), (-1, -1), 5),
    ]))
    return footer_tbl


# ────────────────────────────────────────────────────────────────────────────
#  ASSEMBLE COLUMNS INTO A ROW TABLE
# ────────────────────────────────────────────────────────────────────────────
def assemble_body(col1_items, col2_items, col3_items):
    """
    Wrap each column's list of flowables into a single Table cell.
    ReportLab nested tables let us place independent stacks side-by-side.
    """
    def col_table(items, w):
        rows = [[item] for item in items]
        t = Table(rows, colWidths=[w])
        t.setStyle(TableStyle([
            ('TOPPADDING',    (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
            ('LEFTPADDING',   (0, 0), (-1, -1), 0),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ]))
        return t

    c1 = col_table(col1_items, INNER_W)
    c2 = col_table(col2_items, INNER_W)
    c3 = col_table(col3_items, INNER_W)

    half_gap = int(GAP * 28.35 / 2)

    body = Table([[c1, c2, c3]],
                 colWidths=[COL_W, COL_W, COL_W],
                 rowHeights=None)
    body.setStyle(TableStyle([
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING',    (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('LEFTPADDING',   (0, 0), (-1, -1), 2),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 2),
        # Thin vertical dividers
        ('LINEAFTER',     (0, 0), (1, -1),  0.5, LG),
        # Column gutter spacing
        ('LEFTPADDING',   (1, 0), (1, -1),  half_gap),
        ('RIGHTPADDING',  (0, 0), (0, -1),  half_gap),
        ('LEFTPADDING',   (2, 0), (2, -1),  half_gap),
        ('RIGHTPADDING',  (1, 0), (1, -1),  half_gap),
    ]))
    return body


# ────────────────────────────────────────────────────────────────────────────
#  GENERATE
# ────────────────────────────────────────────────────────────────────────────
def generate():
    os.makedirs('data', exist_ok=True)

    doc = SimpleDocTemplate(
        OUTPUT,
        pagesize=landscape(A3),
        leftMargin=LM, rightMargin=RM,
        topMargin=TM, bottomMargin=BM)

    S = []

    S.append(build_header())
    S.append(Spacer(1, 0.25 * cm))

    col1 = build_col1()
    col2 = build_col2()
    col3 = build_col3()

    S.append(assemble_body(col1, col2, col3))

    S.append(Spacer(1, 0.25 * cm))
    S.append(build_footer())

    doc.build(S)

    size_kb = os.path.getsize(OUTPUT) / 1024
    print(f'Poster generated : {OUTPUT}')
    print(f'Size             : {size_kb:.1f} KB')


if __name__ == '__main__':
    generate()
