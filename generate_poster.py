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
LM = RM = 0.8 * cm
TM = BM = 0.8 * cm
CW = PW - LM - RM        # full content width

# Column widths (3 equal columns with small gutters)
GAP   = 0.35 * cm
NCOLS = 3
COL_W = (CW - (NCOLS - 1) * GAP) / NCOLS


# ── Style factory ─────────────────────────────────────────────────────────────
def ps(name, fn='Helvetica', fs=8.5, tc=BK, al=TA_JUSTIFY,
       lead=11, sb=0, sa=3, li=0, fi=0):
    return ParagraphStyle(name, fontName=fn, fontSize=fs, textColor=tc,
                          alignment=al, leading=lead, spaceBefore=sb,
                          spaceAfter=sa, leftIndent=li, firstLineIndent=fi)

PTITLE  = ps('ptitle', 'Helvetica-Bold', 16, W, TA_CENTER, 20, sa=4)
PSUB    = ps('psub',   'Helvetica-Bold', 9,  W, TA_CENTER, 12, sa=2)
PAUTH   = ps('pauth',  'Helvetica',      8,  W, TA_CENTER, 11, sa=2)
SEC     = ps('sec',    'Helvetica-Bold', 9.5, BLUE, TA_LEFT, 12, sb=2, sa=2)
BODY    = ps('body',   fs=7.8, lead=10.5, sa=2)
BODYJ   = ps('bodyj',  fs=7.8, lead=10.5, sa=2, al=TA_JUSTIFY)
BULL    = ps('bull',   fs=7.5, lead=10, li=9, fi=-8, sa=1)
SMCTR   = ps('smctr',  fs=7,   tc=GREY, al=TA_CENTER, lead=9, sa=2)
BOLD_BL = ps('bbl',    'Helvetica-Bold', 8.5, BLUE, al=TA_CENTER, lead=11)
BOLD_GR = ps('bgr',    'Helvetica-Bold', 8.5, GREEN, al=TA_CENTER, lead=11)
CAPTN   = ps('captn',  fn='Helvetica-Oblique', fs=7, tc=GREY, al=TA_CENTER, lead=9, sa=2)

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
        col_w = COL_W
    t = Table([[Paragraph(
        f'<font name="Helvetica-Bold" size="9" color="#FFFFFF">{title}</font>',
        ps('h', al=TA_LEFT, lead=11))]],
        [col_w])
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), BLUE),
        ('TOPPADDING',    (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ('LINEBELOW',     (0, 0), (-1, -1), 1.0, GOLD),
    ]))
    return t


# ── Bordered box ──────────────────────────────────────────────────────────────
def box(content_rows, col_w=None, bg=BGOLD, border=GOLD, pad=6):
    if col_w is None:
        col_w = COL_W
    t = Table([[c] for c in content_rows], [col_w - 2])
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
        ('FONTSIZE',      (0, 0), (-1, -1), 7),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), row_bgs),
        ('GRID',          (0, 0), (-1, -1), 0.25, LG),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('LEFTPADDING',   (0, 0), (-1, -1), 3),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 3),
    ]
    if extra:
        base += extra
    t = Table(rows, colWidths=widths)
    t.setStyle(TableStyle(base))
    return t


def tc(txt, bold=False, clr=BK, sz=7, al=TA_CENTER):
    fn = 'Helvetica-Bold' if bold else 'Helvetica'
    return Paragraph(
        f'<font name="{fn}" size="{sz}" color="{clr.hexval()}">{txt}</font>',
        ps('tc', al=al, lead=9.5))


# ────────────────────────────────────────────────────────────────────────────
#  COLUMN BUILDERS
# ────────────────────────────────────────────────────────────────────────────
def build_col1():
    """Left column: Introduction, Research Gap, Architecture Pipeline."""
    items = []

    # -- Introduction / Problem
    items.append(sec_heading('Introduction / Problem'))
    items.append(sp(0.1))
    items.append(Paragraph(
        'Hybrid workforces (remote + on-premise users) expose enterprise networks to '
        'ransomware, insider threats, lateral movement, and zero-day exploits.', BODYJ))
    for t in [
        'Legacy VPNs provide only perimeter-based access — no traffic inspection.',
        'Zero Trust Architecture (ZTA) improves access control but cannot detect '
        'novel, unseen attack patterns.',
        'Self-supervised ML can detect zero-day anomalies without labelled attack data.',
    ]:
        items.append(b(t))
    items.append(sp(0.1))

    # -- Research Gap (highlighted box)
    items.append(sec_heading('Research Gap'))
    items.append(sp(0.08))
    gap_box = box([
        Paragraph(
            '<i>"No existing work pairs Zero Trust Architecture with a self-supervised '
            '(label-free) anomaly detector in a comparative, hybrid workforce study."</i>',
            ps('gq', fn='Helvetica-Oblique', fs=8, tc=BLUE, al=TA_CENTER, lead=11, sa=2)),
        Paragraph(
            'Gambo &amp; Almulhem (2026): ZTA reviewed — no zero-day ML.  '
            'Bakhshi &amp; Ghita (2021): DL anomaly detection — requires attack labels.  '
            'Abdelhady et al. (2026): ZTA + ML for IoT — no hybrid workforce scope.',
            ps('gr', fs=7, tc=GREY, al=TA_JUSTIFY, lead=9.5, sa=0)),
    ], col_w=COL_W, bg=BGOLD, border=GOLD)
    items.append(gap_box)
    items.append(sp(0.15))

    # -- System Architecture pipeline
    items.append(sec_heading('System Architecture Pipeline'))
    items.append(sp(0.08))

    box_w = (COL_W - 0.4 * cm)
    half_w = (box_w - 0.2 * cm) / 2

    def pipe_box(lbl, bg, border_c):
        t = Table([[Paragraph(
            f'<font name="Helvetica-Bold" size="7.5" color="{border_c.hexval()}">'
            f'{lbl}</font>',
            ps('pb', al=TA_CENTER, lead=10))]],
            [box_w])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), bg),
            ('BOX',           (0, 0), (-1, -1), 0.8, border_c),
            ('TOPPADDING',    (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('ALIGNMENT',     (0, 0), (-1, -1), 'CENTER'),
        ]))
        return t

    def arr():
        return Paragraph(
            '<font size="10" color="#999999">&#8595;</font>',
            ps('ar', al=TA_CENTER, lead=12))

    def split_boxes(lbl1, bg1, c1, lbl2, bg2, c2):
        t1 = Table([[Paragraph(
            f'<font name="Helvetica-Bold" size="7" color="{c1.hexval()}">'
            f'{lbl1}</font>',
            ps('sb1', al=TA_CENTER, lead=9))]],
            [half_w])
        t1.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), bg1),
            ('BOX', (0, 0), (-1, -1), 0.8, c1),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        t2 = Table([[Paragraph(
            f'<font name="Helvetica-Bold" size="7" color="{c2.hexval()}">'
            f'{lbl2}</font>',
            ps('sb2', al=TA_CENTER, lead=9))]],
            [half_w])
        t2.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), bg2),
            ('BOX', (0, 0), (-1, -1), 0.8, c2),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
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

    items.append(pipe_box('INPUT: NSL-KDD dataset (125,973 train / 22,543 test)',
                          BGREY, GREY))
    items.append(arr())
    items.append(pipe_box('PREPROCESS: drop zero-variance | log1p | LabelEncode | MinMax → 40 features',
                          BGOLD, GOLD))
    items.append(arr())
    items.append(split_boxes(
        'CNN-GRU\n(Supervised)\nConv1D 64→128→256\n+ GRU 128→64\n327K params',
        BBLUE, BLUE,
        'Autoencoder ★\n(Self-Supervised)\nEncoder 40→128→64→16\nDecoder 16→64→128→40',
        BGREEN, GREEN))
    items.append(arr())
    items.append(pipe_box('COMBINED RISK SCORE (0–1) → Flask API → ZTA Policy Engine',
                          BGOLD, GOLD))
    items.append(arr())
    items.append(pipe_box('DECISION: ALLOW | MONITOR | CHALLENGE MFA | BLOCK',
                          BGREY, GREY))

    # Error distribution figure
    items.append(sp(0.12))
    for fi in poster_image(
            'data/results/autoencoder_error_distribution.png',
            max_w=COL_W, max_h=4.5 * cm,
            caption='Reconstruction error: normal vs attack traffic (19× separation)'):
        items.append(fi)

    return items


def build_col2():
    """Centre column: Key Results, Per-Class Detection, Threshold Sensitivity."""
    items = []

    # -- 4-Way Comparison Table
    items.append(sec_heading('Key Results — 4-Way Comparison'))
    items.append(sp(0.08))
    items.append(Paragraph(
        'All systems evaluated on the same 22,543 NSL-KDD test samples.', SMCTR))
    items.append(sp(0.06))

    W1 = COL_W * 0.34
    W2 = COL_W * 0.14
    W3 = COL_W * 0.14
    W4 = COL_W * 0.14
    W5 = COL_W * 0.24

    def hdr(t):
        return Paragraph(
            f'<font name="Helvetica-Bold" size="7" color="#FFFFFF">{t}</font>',
            ps('ch', al=TA_CENTER, lead=9))

    def val(t, bold=False, clr=BK):
        fn = 'Helvetica-Bold' if bold else 'Helvetica'
        return Paragraph(
            f'<font name="{fn}" size="7" color="{clr.hexval()}">{t}</font>',
            ps('cv', al=TA_CENTER, lead=9))

    comp_rows = [
        [hdr('System'), hdr('Acc'), hdr('F1'), hdr('FPR'), hdr('Zero-Day')],
        [Paragraph('<font size="7">Legacy VPN</font>', ps('r1', al=TA_LEFT, lead=9)),
         val('0.666'), val('0.652'), val('0.180'), val('No')],
        [Paragraph('<font size="7">ZTA Only</font>', ps('r2', al=TA_LEFT, lead=9)),
         val('0.769'), val('0.768'), val('0.100'), val('No')],
        [Paragraph('<font size="7">ZTA+CNN-GRU</font>', ps('r3', al=TA_LEFT, lead=9)),
         val('0.795'), val('0.789'), val('0.045'), val('No')],
        [Paragraph('<font name="Helvetica-Bold" size="7">ZTA+Autoencoder</font>',
                   ps('r4', fn='Helvetica-Bold', al=TA_LEFT, lead=9)),
         val('0.844', bold=True, clr=BLUE),
         val('0.848', bold=True, clr=BLUE),
         val('0.050'),
         val('YES ✓', bold=True, clr=BLUE)],
    ]

    comp_tbl = Table(comp_rows, colWidths=[W1, W2, W3, W4, W5])
    comp_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  BLUE),
        ('BACKGROUND',    (0, 4), (-1, 4),  BBLUE),
        ('BOX',           (0, 4), (-1, 4),  0.8, BLUE),
        ('FONTSIZE',      (0, 0), (-1, -1), 7),
        ('ROWBACKGROUNDS',(0, 1), (-1, 3),  [BGREY, W, BGREY]),
        ('GRID',          (0, 0), (-1, -1), 0.25, LG),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING',   (0, 0), (-1, -1), 3),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 3),
    ]))
    items.append(comp_tbl)
    items.append(Paragraph(
        '<i>ZTA+Autoencoder: best accuracy, best F1, only zero-day system.</i>',
        CAPTN))
    items.append(sp(0.15))

    # -- Per-Class Detection Rates
    items.append(sec_heading('Per-Class Detection Rates'))
    items.append(sp(0.06))

    W_a = COL_W * 0.24
    W_b = COL_W * 0.26
    W_c = COL_W * 0.30
    W_d = COL_W * 0.20

    pc_rows = [
        [hdr('Class'), hdr('CNN-GRU'), hdr('Autoencoder'), hdr('Winner')],
        [tc('DoS'),     tc('0.817'), tc('0.911', bold=True, clr=BLUE), tc('AE ★', bold=True, clr=BLUE)],
        [tc('Probe'),   tc('0.571'), tc('0.882', bold=True, clr=BLUE), tc('AE ★', bold=True, clr=BLUE)],
        [tc('R2L'),     tc('0.394', bold=True, clr=BLUE), tc('0.287', clr=RED), tc('CNN', bold=True, clr=BLUE)],
        [tc('U2R'),     tc('0.358'), tc('0.687', bold=True, clr=BLUE), tc('AE ★', bold=True, clr=BLUE)],
    ]
    items.append(compact_table(pc_rows, [W_a, W_b, W_c, W_d]))
    items.append(Paragraph(
        '<i>AE = Autoencoder. R2L is the autoencoder\'s documented weakness.</i>',
        CAPTN))
    items.append(sp(0.15))

    # -- Threshold Sensitivity
    items.append(sec_heading('Threshold Sensitivity'))
    items.append(sp(0.06))
    items.append(Paragraph(
        'Threshold sweep: 70th–99th percentile of normal reconstruction errors.',
        BODY))
    items.append(sp(0.04))

    W_p = COL_W * 0.18
    W_q = COL_W * 0.16
    W_r = COL_W * 0.16
    W_s = COL_W * 0.16
    W_t = COL_W * 0.16
    W_u = COL_W * 0.18

    sens_rows = [
        [hdr('Pct'), hdr('Prec'), hdr('Recall'), hdr('F1'), hdr('FPR'), hdr('Note')],
        [tc('70th'), tc('0.813'), tc('0.990'), tc('0.893'), tc('0.300'), tc('high recall')],
        [tc('80th ★'), tc('0.866'), tc('0.981'),
         tc('0.920', bold=True, clr=BLUE), tc('0.200'), tc('optimal F1')],
        [tc('95th'), tc('0.953'), tc('0.764'),
         tc('0.848'), tc('0.050'), tc('current')],
        [tc('99th'), tc('0.979'), tc('0.357'), tc('0.523'), tc('0.010'), tc('high prec')],
    ]
    sens_tbl = Table(sens_rows, colWidths=[W_p, W_q, W_r, W_s, W_t, W_u])
    sens_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  BLUE),
        ('FONTSIZE',      (0, 0), (-1, -1), 7),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [BGREY, W, BGREY, W]),
        ('GRID',          (0, 0), (-1, -1), 0.25, LG),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('LEFTPADDING',   (0, 0), (-1, -1), 3),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 3),
        # Highlight 80th row (optimal) in BBLUE
        ('BACKGROUND',    (0, 2), (-1, 2),  BBLUE),
        ('BOX',           (0, 2), (-1, 2),  0.8, BLUE),
        # Highlight 95th row (current) in BGREEN
        ('BACKGROUND',    (0, 3), (-1, 3),  BGREEN),
        ('BOX',           (0, 3), (-1, 3),  0.6, GREEN),
    ]))
    items.append(sens_tbl)
    items.append(sp(0.08))

    # Recommendation box
    rec_box = box([
        Paragraph(
            '<font name="Helvetica-Bold" size="7.5" color="#003087">Deployment Recommendation</font>',
            ps('rb1', al=TA_CENTER, lead=10, sa=1)),
        Paragraph(
            '80th pct → F1=0.920 — use for incident-response / high-recall mode.  '
            '95th pct → F1=0.848, FPR=0.050 — use for steady-state low-alert environments.',
            ps('rb2', fs=7.5, lead=10.5, al=TA_JUSTIFY, sa=0)),
    ], col_w=COL_W, bg=BGOLD, border=GOLD)
    items.append(rec_box)

    # Threshold sensitivity figure
    items.append(sp(0.12))
    for fi in poster_image(
            'data/results/threshold_sensitivity.png',
            max_w=COL_W, max_h=4.0 * cm,
            caption='F1/FPR sweep across threshold percentiles (70th–99th)'):
        items.append(fi)

    return items


def build_col3():
    """Right column: Zero-Day Capability, Conclusions, References, QR placeholder."""
    items = []

    # -- Zero-Day Detection
    items.append(sec_heading('Zero-Day Detection Capability'))
    items.append(sp(0.08))
    items.append(Paragraph(
        'Leave-one-class-out experiment: each attack class held out from threshold '
        'calibration; scored purely on reconstruction error.', BODYJ))
    items.append(sp(0.06))

    W_a = COL_W * 0.22
    W_b = COL_W * 0.23
    W_c = COL_W * 0.22
    W_d = COL_W * 0.33

    def zd_val(v, is_bad=False):
        clr = RED if is_bad else BLUE
        bold = True
        return Paragraph(
            f'<font name="Helvetica-Bold" size="7" color="{clr.hexval()}">{v}</font>',
            ps('zv', al=TA_CENTER, lead=9))

    zd_rows = [
        [tc('Class', bold=True), tc('Recall', bold=True),
         tc('Sep. Ratio', bold=True), tc('Notes', bold=True)],
        [tc('DoS'), zd_val('91.1%'),
         tc('~22×'), tc('High-volume → large error', al=TA_LEFT)],
        [tc('Probe'), zd_val('88.2%'),
         tc('~27.8×'), tc('Unusual ports → highest sep.', al=TA_LEFT)],
        [tc('U2R'), zd_val('68.7%'),
         tc('~24.1×'), tc('Privilege escalation signal', al=TA_LEFT)],
        [tc('R2L'), zd_val('28.7%', is_bad=True),
         Paragraph('<font name="Helvetica-Bold" size="7" color="#C62828">~3.7×</font>',
                   ps('rs', al=TA_CENTER, lead=9)),
         tc('Resembles normal sessions ⚠', al=TA_LEFT)],
    ]
    zd_tbl = Table(zd_rows, colWidths=[W_a, W_b, W_c, W_d])
    zd_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  BLUE),
        ('TEXTCOLOR',     (0, 0), (-1, 0),  W),
        ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, -1), 7),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [BGREY, W, BGREY, W]),
        ('GRID',          (0, 0), (-1, -1), 0.25, LG),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('LEFTPADDING',   (0, 0), (-1, -1), 3),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 3),
        # Red row for R2L
        ('BACKGROUND',    (0, 4), (-1, 4),  colors.HexColor('#FFF0F0')),
    ]))
    items.append(zd_tbl)
    items.append(Paragraph(
        '<i>R2L (remote-to-local) connections share byte counts, duration, and service '
        'patterns with normal sessions — low reconstruction error → documented weakness.</i>',
        CAPTN))
    items.append(sp(0.15))

    # -- Conclusions
    items.append(sec_heading('Conclusions'))
    items.append(sp(0.06))
    for t in [
        '<b>Best accuracy (0.844) and F1 (0.848)</b> of all four systems.',
        '<b>Only system with zero-day detection</b> — self-supervised, no attack '
        'labels needed.',
        '<b>~9× faster inference</b> than CNN-GRU (0.066 ms vs 0.589 ms/sample) '
        '— suitable for real-time deployment.',
        '<b>Honest limitation:</b> R2L recall 28.7% — those connections resemble '
        'normal traffic statistically.',
        '<b>Self-supervised anomaly detection</b> is a viable, practical complement '
        'to supervised classifiers in ZTA.',
    ]:
        items.append(b(t))
    items.append(sp(0.15))

    # -- References
    items.append(sec_heading('References'))
    items.append(sp(0.06))
    items.append(Paragraph(
        '[1] Gambo &amp; Almulhem (2026). Zero Trust Architecture: A Systematic '
        'Literature Review. <i>J. Network and Systems Mgmt.</i>, 34(1).',
        ps('ref1', fs=7, lead=9.5, al=TA_JUSTIFY, sa=2)))
    items.append(Paragraph(
        '[2] Bakhshi &amp; Ghita (2021). Anomaly Detection in Encrypted Internet '
        'Traffic Using Hybrid Deep Learning. <i>Security and Comm. Networks.</i>',
        ps('ref2', fs=7, lead=9.5, al=TA_JUSTIFY, sa=2)))
    items.append(Paragraph(
        '[3] Abdelhady et al. (2026). Hybrid ML Anomaly Detection and Lightweight '
        'ZTA for LoRaWAN. <i>IEEE Access</i>, 14, 18387–18407.',
        ps('ref3', fs=7, lead=9.5, al=TA_JUSTIFY, sa=2)))
    items.append(sp(0.15))

    # -- QR Code placeholder
    qr_inner = Table([[
        Paragraph(
            '<font name="Helvetica-Bold" size="8" color="#C8A84B">&#9633;</font>',
            ps('qi1', al=TA_CENTER, lead=14)),
    ]], [COL_W - 2 * cm])
    qr_inner.setStyle(TableStyle([
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))

    qr_box = Table([[
        Paragraph(
            '<font name="Helvetica-Bold" size="8" color="#555555">'
            'Scan for GitHub repo</font>',
            ps('qr1', al=TA_CENTER, lead=11)),
        Paragraph(
            '<font name="Helvetica-Bold" size="8.5" color="#C8A84B">'
            '&#9633;&#9633;&#9633;<br/>&#9633; QR &#9633;<br/>&#9633;&#9633;&#9633;</font>',
            ps('qrimg', al=TA_CENTER, lead=11)),
        Paragraph(
            '<font size="7.5" color="#555555">'
            'github.com/asdcaaron/<br/>zta-ml-framework</font>',
            ps('qr2', fn='Helvetica-Oblique', al=TA_CENTER, lead=10)),
    ]], [COL_W * 0.38, COL_W * 0.22, COL_W * 0.40])
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

    # Comparison bar figure
    items.append(sp(0.12))
    for fi in poster_image(
            'data/results/comparison_bar.png',
            max_w=COL_W, max_h=3.8 * cm,
            caption='4-way system comparison: Accuracy, F1, and FPR'):
        items.append(fi)

    return items


# ────────────────────────────────────────────────────────────────────────────
#  FULL-WIDTH HEADER
# ────────────────────────────────────────────────────────────────────────────
def build_header():
    header_tbl = Table([
        [Paragraph(
            'Uganda Christian University  |  BSc Computer Science',
            ps('hu', fn='Helvetica', fs=8.5, tc=W, al=TA_CENTER, lead=11))],
        [Paragraph(
            'Risk-Adaptive Zero Trust for Securing Hybrid Workforces<br/>'
            'Using Self-Supervised Anomaly Detection',
            ps('ht', fn='Helvetica-Bold', fs=18, tc=W, al=TA_CENTER, lead=22))],
        [Paragraph(
            'Okado Aaron Obbo  |  Reg No: S24B23/015  |  Student No: B29782',
            ps('ha', fn='Helvetica', fs=9, tc=W, al=TA_CENTER, lead=12))],
    ], [CW])
    header_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), BLUE),
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LINEBELOW',     (0, -1), (-1, -1), 2.0, GOLD),
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
        # Each item becomes a row in a single-column table
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

    c1 = col_table(col1_items, COL_W)
    c2 = col_table(col2_items, COL_W)
    c3 = col_table(col3_items, COL_W)

    body = Table([[c1, c2, c3]],
                 colWidths=[COL_W, COL_W, COL_W],
                 rowHeights=None)
    body.setStyle(TableStyle([
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING',    (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('LEFTPADDING',   (0, 0), (-1, -1), 0),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
        # Thin vertical dividers between columns
        ('LINEAFTER',  (0, 0), (1, -1), 0.5, LG),
        ('LEFTPADDING',  (1, 0), (1, -1), int(GAP * 28.35 / 2)),
        ('RIGHTPADDING', (0, 0), (0, -1), int(GAP * 28.35 / 2)),
        ('LEFTPADDING',  (2, 0), (2, -1), int(GAP * 28.35 / 2)),
        ('RIGHTPADDING', (1, 0), (1, -1), int(GAP * 28.35 / 2)),
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
