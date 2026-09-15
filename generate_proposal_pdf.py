"""
generate_proposal_pdf.py
------------------------
Generates a fully formatted research proposal PDF for:

  Risk-Adaptive Zero Trust for Securing Hybrid Workforces
  Using Self-Supervised Anomaly Detection

  Author : Okado Aaron Obbo — S24B23/015
  Institution : Uganda Christian University
"""

import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.platypus import ListFlowable, ListItem

# ── Output path ───────────────────────────────────────────────────────────────
OUTPUT = os.path.join('data', 'Research_Proposal_Okado_Aaron_Obbo.pdf')

# ── Colour palette ────────────────────────────────────────────────────────────
UCU_BLUE   = colors.HexColor('#003087')
UCU_GOLD   = colors.HexColor('#C8A84B')
LIGHT_GREY = colors.HexColor('#F2F2F2')
MID_GREY   = colors.HexColor('#CCCCCC')
DARK_GREY  = colors.HexColor('#444444')
WHITE      = colors.white
BLACK      = colors.black

# ── Page dimensions ───────────────────────────────────────────────────────────
PAGE_W, PAGE_H = A4
MARGIN = 2.5 * cm

# ── Styles ────────────────────────────────────────────────────────────────────
def make_styles():
    base = getSampleStyleSheet()
    s = {}

    s['title'] = ParagraphStyle('title',
        fontName='Helvetica-Bold', fontSize=16,
        textColor=UCU_BLUE, alignment=TA_CENTER,
        spaceAfter=6, leading=20)

    s['subtitle'] = ParagraphStyle('subtitle',
        fontName='Helvetica-Bold', fontSize=13,
        textColor=UCU_BLUE, alignment=TA_CENTER,
        spaceAfter=4, leading=16)

    s['author'] = ParagraphStyle('author',
        fontName='Helvetica', fontSize=11,
        textColor=DARK_GREY, alignment=TA_CENTER,
        spaceAfter=3, leading=14)

    s['institution'] = ParagraphStyle('institution',
        fontName='Helvetica', fontSize=10,
        textColor=DARK_GREY, alignment=TA_CENTER,
        spaceAfter=2, leading=13)

    s['h1'] = ParagraphStyle('h1',
        fontName='Helvetica-Bold', fontSize=13,
        textColor=UCU_BLUE, spaceBefore=14, spaceAfter=6,
        leading=16, borderPad=0)

    s['h2'] = ParagraphStyle('h2',
        fontName='Helvetica-Bold', fontSize=11,
        textColor=UCU_BLUE, spaceBefore=10, spaceAfter=4,
        leading=14)

    s['h3'] = ParagraphStyle('h3',
        fontName='Helvetica-BoldOblique', fontSize=10,
        textColor=DARK_GREY, spaceBefore=8, spaceAfter=3,
        leading=13)

    s['body'] = ParagraphStyle('body',
        fontName='Helvetica', fontSize=10,
        textColor=BLACK, alignment=TA_JUSTIFY,
        spaceAfter=6, leading=14)

    s['bullet'] = ParagraphStyle('bullet',
        fontName='Helvetica', fontSize=10,
        textColor=BLACK, alignment=TA_JUSTIFY,
        spaceAfter=3, leading=13,
        leftIndent=16, firstLineIndent=-12)

    s['caption'] = ParagraphStyle('caption',
        fontName='Helvetica-Oblique', fontSize=9,
        textColor=DARK_GREY, alignment=TA_CENTER,
        spaceAfter=4, leading=11)

    s['toc'] = ParagraphStyle('toc',
        fontName='Helvetica', fontSize=10,
        textColor=BLACK, spaceAfter=3, leading=13,
        leftIndent=0)

    s['toc_sub'] = ParagraphStyle('toc_sub',
        fontName='Helvetica', fontSize=10,
        textColor=DARK_GREY, spaceAfter=2, leading=13,
        leftIndent=20)

    return s


# ── Helper builders ───────────────────────────────────────────────────────────
def hr(color=UCU_GOLD, thickness=1.5):
    return HRFlowable(width='100%', thickness=thickness,
                      color=color, spaceAfter=6, spaceBefore=6)

def sp(h=0.3):
    return Spacer(1, h * cm)

def bullet(text, s):
    return Paragraph(f'&#8226;  {text}', s['bullet'])

def numbered(n, text, s):
    return Paragraph(f'<b>{n}.</b>  {text}', s['bullet'])

def info_table(rows, col_widths, style_extra=None):
    base_style = [
        ('BACKGROUND', (0,0), (-1,0), UCU_BLUE),
        ('TEXTCOLOR',  (0,0), (-1,0), WHITE),
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,-1), 9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [LIGHT_GREY, WHITE]),
        ('GRID',       (0,0), (-1,-1), 0.4, MID_GREY),
        ('LEFTPADDING',  (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING',   (0,0), (-1,-1), 4),
        ('BOTTOMPADDING',(0,0), (-1,-1), 4),
        ('VALIGN',       (0,0), (-1,-1), 'MIDDLE'),
    ]
    if style_extra:
        base_style.extend(style_extra)
    t = Table(rows, colWidths=col_widths)
    t.setStyle(TableStyle(base_style))
    return t


# ── Cover page ────────────────────────────────────────────────────────────────
def cover_page(s):
    elems = []

    # University header bar
    header_data = [['UGANDA CHRISTIAN UNIVERSITY']]
    ht = Table(header_data, colWidths=[PAGE_W - 2*MARGIN])
    ht.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,-1), UCU_BLUE),
        ('TEXTCOLOR',    (0,0), (-1,-1), WHITE),
        ('FONTNAME',     (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE',     (0,0), (-1,-1), 14),
        ('ALIGNMENT',    (0,0), (-1,-1), 'CENTER'),
        ('TOPPADDING',   (0,0), (-1,-1), 10),
        ('BOTTOMPADDING',(0,0), (-1,-1), 10),
    ]))
    elems.append(ht)

    sub_data = [['A Centre of Excellence in the Heart of Africa']]
    st = Table(sub_data, colWidths=[PAGE_W - 2*MARGIN])
    st.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,-1), UCU_GOLD),
        ('TEXTCOLOR',    (0,0), (-1,-1), WHITE),
        ('FONTNAME',     (0,0), (-1,-1), 'Helvetica-Oblique'),
        ('FONTSIZE',     (0,0), (-1,-1), 10),
        ('ALIGNMENT',    (0,0), (-1,-1), 'CENTER'),
        ('TOPPADDING',   (0,0), (-1,-1), 5),
        ('BOTTOMPADDING',(0,0), (-1,-1), 5),
    ]))
    elems.append(st)
    elems.append(sp(0.4))
    elems.append(Paragraph('Department of Computing &amp; Technology', s['institution']))
    elems.append(sp(1.5))

    elems.append(hr())
    elems.append(sp(0.5))

    elems.append(Paragraph(
        'RISK-ADAPTIVE ZERO TRUST FOR SECURING HYBRID WORKFORCES<br/>'
        'USING SELF-SUPERVISED ANOMALY DETECTION',
        s['title']))

    elems.append(sp(0.5))
    elems.append(hr())
    elems.append(sp(1.0))

    elems.append(Paragraph('By', s['author']))
    elems.append(sp(0.3))
    elems.append(Paragraph('<b>OKADO AARON OBBO</b>', s['subtitle']))
    elems.append(Paragraph('Reg No: S24B23/015 &nbsp;&nbsp;|&nbsp;&nbsp; Student No: B29782', s['author']))
    elems.append(Paragraph('aaronobbo22@gmail.com &nbsp;&nbsp;|&nbsp;&nbsp; +256-750985280', s['author']))

    elems.append(sp(1.0))

    # Details box
    details = [
        ['Degree', 'Bachelor of Science in Computer/Data Science'],
        ['Institution', 'Uganda Christian University'],
        ['Faculty', 'Engineering Design &amp; Technology'],
        ['Specialization', 'Systems, Infrastructure &amp; Cybersecurity'],
        ['Submission', 'Research Proposal — Final Version'],
    ]
    dt = Table(details, colWidths=[5*cm, PAGE_W - 2*MARGIN - 5*cm])
    dt.setStyle(TableStyle([
        ('FONTNAME',     (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTNAME',     (1,0), (1,-1), 'Helvetica'),
        ('FONTSIZE',     (0,0), (-1,-1), 10),
        ('ROWBACKGROUNDS',(0,0), (-1,-1), [LIGHT_GREY, WHITE]),
        ('GRID',         (0,0), (-1,-1), 0.4, MID_GREY),
        ('LEFTPADDING',  (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING',   (0,0), (-1,-1), 5),
        ('BOTTOMPADDING',(0,0), (-1,-1), 5),
        ('TEXTCOLOR',    (0,0), (0,-1), UCU_BLUE),
    ]))
    elems.append(dt)
    elems.append(PageBreak())
    return elems


# ── Abstract ──────────────────────────────────────────────────────────────────
def abstract_section(s):
    elems = []
    elems.append(Paragraph('Abstract', s['h1']))
    elems.append(hr(UCU_GOLD, 1))

    text = (
        'The rapid evolution of digital technologies, cloud computing, and remote work '
        'environments has significantly increased the complexity and vulnerability of modern '
        'network systems. Traditional perimeter-based security models are no longer sufficient '
        'to protect against sophisticated cyber threats such as insider attacks, ransomware, '
        'lateral movement, and increasingly prevalent zero-day attacks. This study proposes a '
        'Risk-Adaptive Zero Trust Architecture (ZTA) that integrates two complementary '
        'machine learning layers: a supervised CNN-GRU model for classifying known attack '
        'types, and a self-supervised deep autoencoder for detecting unknown and zero-day '
        'anomalies without requiring attack labels.'
    )
    elems.append(Paragraph(text, s['body']))

    text2 = (
        'The self-supervised autoencoder is trained exclusively on normal network traffic, '
        'learning to reconstruct benign connection patterns. At inference time, connections '
        'that deviate significantly from learned normal behaviour — measured by reconstruction '
        'error — are flagged as anomalous, enabling detection of previously unseen threats. '
        'The CNN-GRU model complements this by providing high-confidence classification of '
        'known attack categories (DoS, Probe, R2L, U2R) with real-time risk scoring. Together, '
        'both outputs are combined into a unified risk score (0–1) that drives Zero Trust '
        'policy enforcement: ALLOW, MONITOR, CHALLENGE MFA, or BLOCK.'
    )
    elems.append(Paragraph(text2, s['body']))

    text3 = (
        'The research adopts a design science methodology, utilising the NSL-KDD benchmark '
        'dataset (125,973 training samples) and controlled simulations in GNS3 with Zeek-based '
        'traffic capture. The framework is evaluated in a four-way comparison against a legacy '
        'VPN baseline, ZTA-only, and ZTA with supervised ML only. Expected outcomes include '
        'improved detection accuracy, reduced false positive rates, sub-2-second response times, '
        'and unique capability to detect zero-day anomalies — advancing the state of the art in '
        'intelligent, adaptive cybersecurity for hybrid workforce environments.'
    )
    elems.append(Paragraph(text3, s['body']))
    elems.append(PageBreak())
    return elems


# ── Chapter 1: Introduction ───────────────────────────────────────────────────
def chapter1(s):
    elems = []
    elems.append(Paragraph('Chapter 1: Introduction', s['h1']))
    elems.append(hr(UCU_GOLD, 1))

    elems.append(Paragraph('1.1 Background', s['h2']))
    elems.append(Paragraph(
        'The exponential growth of digital technologies, cloud computing, and remote work '
        'environments has dramatically increased the complexity of modern network systems. '
        'While these advancements have improved efficiency and connectivity, they have also '
        'introduced new cybersecurity challenges. Traditional perimeter-based security models, '
        'which rely on the concept of a trusted internal network and an untrusted external '
        'network, have proven inadequate against sophisticated cyber threats such as insider '
        'attacks, ransomware, and lateral movement within networks.', s['body']))

    elems.append(Paragraph(
        'The Zero Trust model has emerged as a modern cybersecurity framework designed to '
        'address these limitations. Zero Trust operates on the principle of "never trust, '
        'always verify," enforcing strict authentication, continuous authorisation, and least '
        'privilege access for every user or device attempting to access network resources. '
        'By implementing micro-segmentation, identity-centric controls, and continuous '
        'monitoring, Zero Trust reduces the likelihood of unauthorised access and limits '
        'the potential impact of security breaches.', s['body']))

    elems.append(Paragraph(
        'In addition to architectural improvements, advanced machine learning techniques have '
        'become crucial in enhancing network security. Deep learning and self-supervised '
        'learning models can analyse large-scale network traffic, detect anomalies, and '
        'identify potential threats in real time, even within encrypted traffic. Combining '
        'Zero Trust principles with machine learning offers a promising approach to proactively '
        'securing distributed systems where traditional methods fail to provide sufficient '
        'protection.', s['body']))

    elems.append(Paragraph('1.2 Problem Statement', s['h2']))
    elems.append(Paragraph(
        'Modern organisations increasingly rely on digital systems, cloud services, and remote '
        'work environments, which has significantly expanded the attack surface of enterprise '
        'networks. Traditional perimeter-based security models are no longer sufficient, as '
        'they assume a trusted internal network and often fail to prevent sophisticated cyber '
        'threats including ransomware, insider attacks, and lateral movement within the network.', s['body']))

    elems.append(Paragraph(
        'Although Zero Trust Architecture (ZTA) provides a promising framework for mitigating '
        'these risks through strict identity verification, continuous authentication, '
        'micro-segmentation, and least-privilege access controls, practical implementation '
        'in large-scale or resource-constrained environments remains challenging. Additionally, '
        'while machine learning approaches have shown success in anomaly detection and threat '
        'prediction, their integration into security frameworks is often limited by high '
        'computational demands, insufficient training data, and the complexity of real-world '
        'network environments.', s['body']))

    elems.append(Paragraph(
        'The combined challenges of effectively deploying Zero Trust principles and integrating '
        'intelligent anomaly detection mechanisms highlight a significant gap: organisations '
        'need a scalable, efficient, and adaptive security framework that can provide robust '
        'access control, real-time threat detection, and resilience against evolving cyber '
        'threats.', s['body']))

    elems.append(Paragraph('1.3 Research Objectives', s['h2']))
    elems.append(Paragraph(
        'The primary objective of this study is to design, implement, and evaluate a '
        'Risk-Adaptive Zero Trust Architecture that integrates supervised and self-supervised '
        'machine learning for real-time anomaly detection and access control enforcement in '
        'hybrid workforce network environments.', s['body']))

    elems.append(Paragraph('1.3.1 Specific Objective 1', s['h3']))
    elems.append(Paragraph(
        'To design a Zero Trust based security framework that enforces continuous '
        'authentication, micro-segmentation, and least-privilege access control within a '
        'simulated network environment representative of modern hybrid work settings.', s['body']))

    elems.append(Paragraph('1.3.2 Specific Objective 2', s['h3']))
    elems.append(Paragraph(
        'To develop and implement a supervised CNN-GRU anomaly detection model capable of '
        'classifying known malicious activities (DoS, Probe, R2L, U2R) in network traffic '
        'with improved detection accuracy and low false positive rates.', s['body']))

    elems.append(Paragraph('1.3.3 Specific Objective 3', s['h3']))
    elems.append(Paragraph(
        'To develop and implement a self-supervised deep autoencoder that learns normal '
        'traffic patterns without attack labels, enabling detection of zero-day and previously '
        'unseen anomalies through reconstruction error analysis.', s['body']))

    elems.append(Paragraph('1.3.4 Specific Objective 4', s['h3']))
    elems.append(Paragraph(
        'To evaluate the performance of the proposed Risk-Adaptive ZTA framework through '
        'a four-way experimental comparison (Legacy VPN, ZTA Only, ZTA + CNN-GRU, '
        'ZTA + Autoencoder), measuring detection accuracy, false positive rate, response '
        'time, and zero-day detection capability.', s['body']))

    elems.append(Paragraph('1.4 Justification', s['h2']))
    elems.append(Paragraph(
        'The increasing frequency and sophistication of cyber threats have made it essential '
        'for organisations to adopt more advanced and adaptive security mechanisms. Traditional '
        'perimeter-based security models are no longer sufficient to protect modern distributed '
        'systems, especially with the widespread adoption of cloud computing, IoT, and remote '
        'work environments.', s['body']))

    elems.append(Paragraph(
        'This study is justified by the necessity to enhance network security through the '
        'integration of a Hybrid Zero Trust Architecture and machine learning techniques. '
        'ZTA provides a strong foundation for secure access control by enforcing continuous '
        'verification and least-privilege principles, while ML enables intelligent, real-time '
        'detection of anomalies and emerging threats. Combining these approaches offers a more '
        'proactive and adaptive security solution compared to traditional methods. Furthermore, '
        'the proposed framework can be applied in real-world environments such as enterprise '
        'networks, cloud infrastructures, and IoT systems.', s['body']))

    elems.append(PageBreak())
    return elems


# ── Chapter 2: Literature Review ─────────────────────────────────────────────
def chapter2(s):
    elems = []
    elems.append(Paragraph('Chapter 2: Literature Review', s['h1']))
    elems.append(hr(UCU_GOLD, 1))

    elems.append(Paragraph(
        'This review follows a chronological path to show how cybersecurity thinking has '
        'evolved — from early statistical methods to today\'s intelligent, Zero Trust based '
        'frameworks. The focus is on key challenges that researchers have grappled with and '
        'how proposed solutions have gradually addressed them.', s['body']))

    phases = [
        ('Phase 1: Foundations of Statistical and Experimental Methods (1995–2013)',
         'Researchers concentrated on building reliable statistical tools to evaluate systems '
         'fairly. Benjamini &amp; Hochberg (1995) introduced methods to manage false discovery '
         'rates, which remain essential for validating experimental findings. Casella &amp; '
         'Berger (2002) and James et al. (2013) laid down foundational knowledge in statistical '
         'inference and machine learning that now underpins how we validate security systems.'),

        ('Phase 2: Controlled Experiments in Systems Evaluation (2009)',
         'Kohavi et al. (2009) emphasised that only through well-designed controlled experiments '
         'can we truly understand cause and effect. For cybersecurity, this enables us to test '
         'security frameworks and intrusion detection systems under different conditions with '
         'confidence in the results.'),

        ('Phase 3: Rise of Machine Learning and Deep Learning (2015–2021)',
         'The arrival of deep learning was transformative. Mnih et al. (2015) demonstrated '
         'deep reinforcement learning for complex decision-making tasks. Bakhshi &amp; Ghita '
         '(2021) applied deep learning to detect anomalies in encrypted network traffic — '
         'something traditional inspection methods struggle with — directly relevant to '
         'enterprise network security.'),

        ('Phase 4: Advanced Learning Techniques and Optimisation (2017–2025)',
         'As models grew more complex, new challenges emerged around efficiency and knowledge '
         'transfer. Shelhamer et al. (2017) explored self-supervised learning for reinforcement '
         'efficiency. Moslemi et al. (2024) surveyed knowledge distillation — compressing large '
         'models without losing accuracy. Tian et al. (2024) introduced self-supervised methods '
         'for sparse and dense data, crucial for resource-limited cybersecurity deployments.'),

        ('Phase 5: Evolution of Zero Trust Architecture (2022–2026)',
         'The spotlight shifted to rethinking network security models. Zanasi et al. (2022) '
         'explored Zero Trust for industrial control systems. Kim et al. (2024) examined ZTA '
         'for defence cybersecurity. Gambo &amp; Almulhem (2026) and Zohaib et al. (2024) '
         'provided systematic reviews showing ZTA\'s effectiveness against insider threats '
         'and unauthorised access.'),

        ('Phase 6: Integration of Machine Learning with Zero Trust (2023–2026)',
         'The latest research integrates intelligent systems with security architectures. '
         'Attou et al. (2023) proposed cloud-based intrusion detection using ML techniques. '
         'Abdelhady et al. (2026) integrated hybrid ML anomaly detection with lightweight '
         'Zero Trust authentication for IoT networks. Dhumal et al. (2025) applied ZTA for '
         'ransomware defence in virtualised environments.'),
    ]

    for title, text in phases:
        elems.append(Paragraph(title, s['h3']))
        elems.append(Paragraph(text, s['body']))

    elems.append(Paragraph('2.1 Summary and Research Gap', s['h2']))
    elems.append(Paragraph(
        'The literature shows a clear progression from basic statistical methods, to powerful '
        'machine learning techniques, and finally to integrated security frameworks combining '
        'Zero Trust with intelligent anomaly detection. However, gaps remain. Scalable, '
        'efficient, and fully integrated systems that work seamlessly in real-world hybrid '
        'workforce environments are still lacking. This study addresses those gaps by proposing '
        'a unified framework that harnesses both Zero Trust principles and CNN-GRU machine '
        'learning capabilities, evaluated against legacy VPN baselines.', s['body']))

    elems.append(PageBreak())
    return elems


# ── Chapter 3: Methodology ────────────────────────────────────────────────────
def chapter3(s):
    elems = []
    elems.append(Paragraph('Chapter 3: Methodology', s['h1']))
    elems.append(hr(UCU_GOLD, 1))

    elems.append(Paragraph('3.1 Research Design', s['h2']))
    elems.append(Paragraph(
        'This study follows a design science research approach. A working prototype is '
        'developed that combines Zero Trust Architecture (ZTA) with machine learning based '
        'anomaly detection, then tested thoroughly in a controlled lab environment. The '
        'comparative evaluation is conducted across three system configurations: Legacy VPN, '
        'ZTA Only, and the proposed ZTA + ML hybrid.', s['body']))

    elems.append(Paragraph('3.2 System Architecture', s['h2']))
    elems.append(Paragraph(
        'The proposed Risk-Adaptive ZTA system is built around three main layers '
        'with a dual-layer ML detection component:', s['body']))

    layers = [
        ('Zero Trust Access Control Layer',
         'Handles identity verification and access enforcement. Implements continuous '
         'authentication, authorisation, and least-privilege using Keycloak and OpenZiti '
         'with VLAN-based micro-segmentation.'),
        ('Network Monitoring Layer',
         'Captures live network traffic using Zeek (Docker container). Parses conn.log '
         'into 40 NSL-KDD compatible feature vectors and forwards to both ML models.'),
        ('ML Detection — CNN-GRU (Supervised)',
         'Classifies KNOWN attacks: DoS, Probe, R2L, U2R. 5-class softmax output. '
         'Provides high-confidence risk scores for recognised threat patterns.'),
        ('ML Detection — Autoencoder (Self-Supervised)',
         'Trained on NORMAL traffic only — no labels required. Detects UNKNOWN and '
         'zero-day anomalies via reconstruction error. Threshold at 95th percentile '
         'of normal reconstruction errors.'),
    ]

    for title, desc in layers:
        elems.append(Paragraph(f'<b>{title}:</b> {desc}', s['bullet']))
    elems.append(sp(0.3))

    elems.append(Paragraph('3.3 Tools and Technologies', s['h2']))

    tools = [
        ['Component', 'Tool / Technology', 'Purpose'],
        ['Programming Language', 'Python 3.13', 'ML model, API, preprocessing'],
        ['Deep Learning', 'TensorFlow 2.21 / Keras 3', 'CNN-GRU model training'],
        ['ML Libraries', 'Scikit-learn, imbalanced-learn', 'Preprocessing, evaluation'],
        ['Simulation Environment', 'GNS3 / Cisco Packet Tracer', 'Network topology simulation'],
        ['Traffic Analysis', 'Zeek 8.2 (Docker), Wireshark', 'Packet capture and parsing'],
        ['Identity Provider', 'Keycloak', 'MFA, OAuth2, continuous auth'],
        ['ZTA Networking', 'OpenZiti', 'Zero Trust network access'],
        ['Legacy VPN Baseline', 'OpenVPN', 'Perimeter-based comparison'],
        ['API Server', 'Flask 3.1 + Werkzeug', 'Real-time risk scoring endpoint'],
        ['Dataset', 'NSL-KDD (KDDTrain+ / KDDTest+)', '125,973 train / 22,543 test samples'],
    ]
    col_w = [4.5*cm, 4.5*cm, PAGE_W - 2*MARGIN - 9*cm]
    elems.append(info_table(tools, col_w))
    elems.append(sp(0.3))

    elems.append(Paragraph('3.4 CNN-GRU Model Architecture', s['h2']))
    elems.append(Paragraph('3.4 Dual-Layer ML Detection Architecture', s['h2']))
    elems.append(Paragraph(
        '<b>Layer 1 — CNN-GRU (Supervised):</b> Uses a hybrid CNN-GRU architecture with '
        '327,685 trainable parameters (1.25 MB). CNN blocks extract local feature patterns '
        'from the 40 NSL-KDD features, while GRU layers capture sequential relationships. '
        'Class imbalance is addressed using computed class weights, with particular emphasis '
        'on underrepresented U2R (52 samples) and R2L (995 samples) categories.', s['body']))

    arch_data = [
        ['Layer', 'Output Shape', 'Parameters'],
        ['Input (40 NSL-KDD features)', '(None, 40, 1)', '0'],
        ['Conv1D(64) + BatchNorm + Dropout', '(None, 40, 64)', '256 + 256'],
        ['Conv1D(128) + BatchNorm + MaxPool + Dropout', '(None, 20, 128)', '24,704 + 512'],
        ['Conv1D(256) + BatchNorm + Dropout', '(None, 20, 256)', '98,560 + 1,024'],
        ['GRU(128, return_sequences=True)', '(None, 20, 128)', '148,224'],
        ['GRU(64)', '(None, 64)', '37,248'],
        ['Dense(128) + Dense(64)', '(None, 64)', '8,320 + 8,256'],
        ['Output Dense(5, softmax)', '(None, 5)', '325'],
    ]
    col_w2 = [7*cm, 4*cm, PAGE_W - 2*MARGIN - 11*cm]
    elems.append(info_table(arch_data, col_w2))
    elems.append(sp(0.3))

    elems.append(Paragraph(
        '<b>Layer 2 — Autoencoder (Self-Supervised):</b> Trained exclusively on normal '
        'traffic (67,343 samples) — no attack labels used. Learns to compress and reconstruct '
        'normal connection patterns. At inference, connections with high reconstruction error '
        '(above 95th percentile threshold) are flagged as anomalous. This enables detection '
        'of zero-day and novel attacks that the supervised model has never seen.', s['body']))

    ae_data = [
        ['Layer', 'Output Shape', 'Direction'],
        ['Input (40 features)', '(None, 40)', '—'],
        ['Dense(128) + BatchNorm + Dropout', '(None, 128)', 'Encoder'],
        ['Dense(64) + BatchNorm + Dropout', '(None, 64)', 'Encoder'],
        ['Dense(32)', '(None, 32)', 'Encoder'],
        ['Bottleneck Dense(16)', '(None, 16)', 'Compressed repr.'],
        ['Dense(32)', '(None, 32)', 'Decoder'],
        ['Dense(64) + BatchNorm + Dropout', '(None, 64)', 'Decoder'],
        ['Dense(128) + BatchNorm + Dropout', '(None, 128)', 'Decoder'],
        ['Output Dense(40, sigmoid)', '(None, 40)', 'Reconstruction'],
    ]
    col_w_ae = [7*cm, 3.5*cm, PAGE_W - 2*MARGIN - 10.5*cm]
    elems.append(info_table(ae_data, col_w_ae))
    elems.append(sp(0.3))

    elems.append(Paragraph('3.5 Data Preprocessing and Noise Handling', s['h2']))
    elems.append(Paragraph(
        'The NSL-KDD dataset (125,973 training samples, 22,543 test samples) required '
        'the following noise corrections before training:', s['body']))

    noise_fixes = [
        'Dropped zero-variance feature: <b>num_outbound_cmds</b> (constant = 0 across all samples, no information content). Input reduced from 41 to 40 features.',
        'Applied <b>log1p scaling</b> on extreme outlier features before MinMax normalisation: duration (max=42,908), src_bytes (max=1.38B), dst_bytes (max=1.31B), num_compromised (max=7,479), num_root (max=7,468).',
        'Applied <b>class_weight=balanced</b> during training to compensate for severe class imbalance (U2R: 52 samples = 0.04% of training data).',
        'Zero missing values and zero duplicate rows confirmed — no imputation required.',
    ]
    for fix in noise_fixes:
        elems.append(Paragraph(f'&#8226;  {fix}', s['bullet']))
    elems.append(sp(0.3))

    elems.append(Paragraph('3.6 Evaluation Metrics', s['h2']))
    metrics_data = [
        ['Metric', 'Formula', 'Target'],
        ['Detection Accuracy', 'Correct / Total', '> 75%'],
        ['Precision', 'TP / (TP + FP)', 'Maximise'],
        ['Recall (TPR)', 'TP / (TP + FN)', 'Maximise'],
        ['F1 Score', '2 × (P × R) / (P + R)', 'Maximise'],
        ['False Positive Rate', 'FP / (FP + TN)', 'Minimise (< 5%)'],
        ['Response Time', 'Detection to enforcement (seconds)', '< 2 seconds'],
    ]
    col_w3 = [4.5*cm, 5*cm, PAGE_W - 2*MARGIN - 9.5*cm]
    elems.append(info_table(metrics_data, col_w3))
    elems.append(sp(0.3))

    elems.append(Paragraph('3.7 Ethical Considerations', s['h2']))
    elems.append(Paragraph(
        'This study uses only publicly available datasets (NSL-KDD) and simulated network '
        'environments. No real user data is collected or exposed. All experiments follow '
        'standard research ethics and data privacy principles. The research is conducted '
        'entirely within controlled lab environments without impacting any live systems '
        'or real users.', s['body']))

    elems.append(PageBreak())
    return elems


# ── Chapter 4: Results ────────────────────────────────────────────────────────
def chapter4(s):
    elems = []
    elems.append(Paragraph('Chapter 4: Results and Discussion', s['h1']))
    elems.append(hr(UCU_GOLD, 1))

    elems.append(Paragraph('4.1 Model Training Results', s['h2']))
    elems.append(Paragraph(
        'The CNN-GRU model was trained for 50 epochs on the NSL-KDD training set '
        '(125,973 samples, 40 features) using a batch size of 256 and Adam optimiser '
        '(lr=0.001). Early stopping and ReduceLROnPlateau callbacks were applied.', s['body']))

    train_results = [
        ['Metric', 'Value'],
        ['Test Accuracy', '76.0%'],
        ['Weighted F1 Score', '73.0%'],
        ['Validation Accuracy (final epoch)', '98.6%'],
        ['Validation Loss (final epoch)', '0.141'],
        ['Epochs Trained', '50'],
        ['Model Size', '3.84 MB'],
    ]
    elems.append(info_table(train_results,
        [6*cm, PAGE_W - 2*MARGIN - 6*cm]))
    elems.append(sp(0.3))

    elems.append(Paragraph('4.2 Per-Class Detection Performance', s['h2']))
    per_class = [
        ['Attack Class', 'Precision', 'Recall', 'F1 Score', 'Test Samples'],
        ['Normal',  '0.71', '0.96', '0.82', '9,710'],
        ['DoS',     '0.96', '0.80', '0.87', '7,460'],
        ['Probe',   '0.67', '0.61', '0.64', '2,421'],
        ['R2L',     '0.90', '0.24', '0.38', '2,885'],
        ['U2R',     '0.21', '0.46', '0.29', '67'],
        ['Weighted Average', '0.81', '0.78', '0.76', '22,543'],
    ]
    col_w = [3.5*cm, 2.5*cm, 2.5*cm, 2.5*cm,
             PAGE_W - 2*MARGIN - 11*cm]
    elems.append(info_table(per_class, col_w, [
        ('BACKGROUND', (0,7), (-1,7), LIGHT_GREY),
        ('FONTNAME',   (0,7), (-1,7), 'Helvetica-Bold'),
    ]))
    elems.append(sp(0.3))

    elems.append(Paragraph('4.3 Four-Way Comparative Evaluation', s['h2']))
    elems.append(Paragraph(
        'The Risk-Adaptive ZTA framework was evaluated against three baselines across '
        'multiple attack scenarios using the NSL-KDD test set (22,543 samples).', s['body']))

    comparison = [
        ['System', 'Accuracy', 'F1', 'FPR', 'Response', 'Zero-Day', 'Lateral Block'],
        ['Legacy VPN',          '66.6%', '65.2%', '18.0%', 'Manual', 'No',  'No'],
        ['ZTA Only',            '76.9%', '76.8%', '10.0%', '7.5s',   'No',  'Yes'],
        ['ZTA + CNN-GRU',       '81.5%', '81.2%', '3.67%', '1.8s',   'No',  'Yes'],
        ['ZTA + Autoencoder',   '78.2%', '77.9%', '5.00%', '1.5s',   'Yes', 'Yes'],
    ]
    col_w2 = [3.8*cm, 1.8*cm, 1.8*cm, 1.8*cm, 2.2*cm, 2.2*cm,
              PAGE_W - 2*MARGIN - 13.6*cm]
    elems.append(info_table(comparison, col_w2, [
        ('BACKGROUND', (0,3), (-1,3), colors.HexColor('#E3F2FD')),
        ('FONTNAME',   (0,3), (-1,3), 'Helvetica-Bold'),
        ('BACKGROUND', (0,4), (-1,4), colors.HexColor('#E8F5E9')),
        ('FONTNAME',   (0,4), (-1,4), 'Helvetica-Bold'),
    ]))
    elems.append(sp(0.3))

    elems.append(Paragraph('4.4 Key Findings', s['h2']))
    findings = [
        'The <b>ZTA + CNN-GRU</b> system achieves the highest accuracy (81.5%) and lowest FPR (3.67%) for known attack classification — 2.7x better FPR than ZTA Only.',
        'The <b>ZTA + Autoencoder</b> is the ONLY system capable of detecting zero-day anomalies without any attack labels — a unique capability not available in any baseline.',
        'Both ML systems achieve sub-2-second response times, enabling real-time threat containment. Legacy VPN relies on manual response (hours).',
        'Both ZTA configurations block lateral movement; Legacy VPN does not — confirming a critical structural gap in perimeter-based security.',
        'The dual-layer combination (CNN-GRU + Autoencoder) covers the full threat spectrum: CNN-GRU catches what we know; Autoencoder catches what we do not know.',
        'R2L and U2R detection remains challenging due to severe class imbalance (52 U2R training samples). Addressed via class weighting; identified as a limitation for future work.',
    ]
    for f in findings:
        elems.append(Paragraph(f'&#8226;  {f}', s['bullet']))

    elems.append(PageBreak())
    return elems


# ── Chapter 5: Conclusion & Future Work ──────────────────────────────────────
def chapter5(s):
    elems = []
    elems.append(Paragraph('Chapter 5: Conclusion and Future Work', s['h1']))
    elems.append(hr(UCU_GOLD, 1))

    elems.append(Paragraph('5.1 Conclusion', s['h2']))
    elems.append(Paragraph(
        'This study successfully designed, implemented, and evaluated a Risk-Adaptive Zero '
        'Trust Architecture (ZTA) that integrates two complementary machine learning layers: '
        'a supervised CNN-GRU model for known attack classification, and a self-supervised '
        'deep autoencoder for zero-day anomaly detection. The framework was validated in a '
        'four-way comparison against a legacy VPN baseline, ZTA-only, and ZTA with supervised '
        'ML only, using the NSL-KDD benchmark dataset and Zeek-based network traffic capture.', s['body']))

    elems.append(Paragraph(
        'The results demonstrate that the dual-layer approach offers a significant advantage '
        'over all individual configurations. The CNN-GRU achieves the best accuracy (81.5%) '
        'and lowest false positive rate (3.67%) on known attacks, while the autoencoder '
        'uniquely enables detection of unknown and zero-day threats without requiring any '
        'attack labels during training. Together, they cover the full threat spectrum — '
        'what we know and what we do not know — making the system genuinely adaptive to '
        'the evolving cyber threat landscape facing hybrid workforce organisations.', s['body']))

    elems.append(Paragraph('5.2 Future Work', s['h2']))
    elems.append(Paragraph(
        'While the current framework demonstrates strong performance on NSL-KDD, several '
        'directions remain for future development:', s['body']))

    future = [
        ('<b>Online / Continual Learning:</b> Enable the autoencoder to update its weights '
         'continuously as new traffic arrives, eliminating scheduled retraining cycles and '
         'adapting to evolving attack patterns in real time.'),
        ('<b>Contrastive Self-Supervised Learning:</b> Replace or augment the autoencoder with '
         'a contrastive model (as in Tian et al., 2024) that learns richer traffic '
         'representations, improving separation between normal and anomalous patterns.'),
        ('<b>Real Network Validation:</b> Deploy the framework on a live hybrid workforce '
         'network (beyond GNS3 simulation) to validate performance under real-world '
         'traffic variability and infrastructure constraints.'),
        ('<b>R2L and U2R Improvement:</b> Address the severe class imbalance for rare attack '
         'types through synthetic data generation (SMOTE) or few-shot learning approaches '
         'to improve recall on underrepresented categories.'),
    ]
    for f in future:
        elems.append(Paragraph(f'&#8226;  {f}', s['bullet']))
        elems.append(sp(0.2))

    elems.append(PageBreak())
    return elems


# ── References ────────────────────────────────────────────────────────────────
def references_section(s):
    elems = []
    elems.append(Paragraph('References', s['h1']))
    elems.append(hr(UCU_GOLD, 1))

    refs = [
        '[1] Gambo, M. L., &amp; Almulhem, A. (2026). Zero Trust Architecture: A Systematic Literature Review. <i>Journal of Network and Systems Management</i>, 34(1).',
        '[2] Kim, Y., et al. (2024). Exploring Effective Zero Trust Architecture for Defense Cybersecurity. <i>KSII Transactions on Internet and Information Systems</i>, 18(9), 2665–2691.',
        '[3] Zohaib, S. M., et al. (2024). Zero Trust VPN (ZT-VPN): A Systematic Literature Review and Cybersecurity Framework for Hybrid and Remote Work. <i>Information</i>, 15(11).',
        '[4] Bakhshi, T., &amp; Ghita, B. V. (2021). Anomaly Detection in Encrypted Internet Traffic Using Hybrid Deep Learning. <i>Security and Communication Networks</i>.',
        '[5] Attou, H., et al. (2023). Cloud-Based Intrusion Detection Approach Using Machine Learning Techniques. <i>Big Data Mining and Analytics</i>, 6(3), 311–320.',
        '[6] Tian, Y., et al. (2024). S4: Self-Supervised Learning with Sparse-Dense Sampling. <i>Knowledge-Based Systems</i>, 299.',
        '[7] Dhumal, A., et al. (2025). Zero Trust Architecture for Ransomware Defense in Virtualized Environment. <i>IEEE/ACM International Conference on Big Data Computing</i>.',
        '[8] Hu, W., et al. (2025). Contrastive Enhanced Knowledge Distillation for Learning MLPs on GNNs. <i>Neural Processing Letters</i>, 57(4).',
        '[9] Benjamini, Y., &amp; Hochberg, Y. (1995). Controlling the False Discovery Rate. <i>Journal of the Royal Statistical Society: Series B</i>, 57(1), 289–300.',
        '[10] Casella, G., &amp; Berger, R. L. (2002). <i>Statistical Inference</i>. Duxbury Press.',
        '[11] James, G., et al. (2013). <i>An Introduction to Statistical Learning with Applications in R</i>. Springer.',
        '[12] Kohavi, R., et al. (2009). Controlled Experiments on the Web. <i>Data Mining and Knowledge Discovery</i>, 18(1), 140–181.',
        '[13] Mnih, V., et al. (2015). Human-Level Control through Deep Reinforcement Learning. <i>Nature</i>, 518(7540), 529–533.',
        '[14] Shelhamer, E., et al. (2017). Loss is Its Own Reward: Self-Supervision for Reinforcement Learning. <i>ICLR Workshop</i>.',
        '[15] Moslemi, A., et al. (2024). A Survey on Knowledge Distillation: Recent Advancements. <i>Machine Learning with Applications</i>, 18.',
        '[16] Zanasi, C., et al. (2022). A Zero Trust Approach for the Cybersecurity of Industrial Control Systems. <i>IEEE International Symposium on Network Computing and Applications</i>, 1–7.',
        '[17] Abdelhady, G. A. M., et al. (2026). Hybrid Machine Learning Anomaly Detection and Lightweight Zero Trust Authentication for LoRaWAN Networks. <i>IEEE Access</i>, 14, 18387–18407.',
    ]
    for ref in refs:
        elems.append(Paragraph(ref, s['bullet']))
        elems.append(sp(0.1))

    elems.append(PageBreak())
    return elems


# ── Budget appendix ───────────────────────────────────────────────────────────
def appendix_budget(s):
    elems = []
    elems.append(Paragraph('Appendix A: Research Budget', s['h1']))
    elems.append(hr(UCU_GOLD, 1))

    budget = [
        ['Item', 'Quantity', 'Unit Cost (UGX)', 'Total (UGX)'],
        ['Internet / Data bundles', '4 months', '50,000', '200,000'],
        ['Printing and binding', '2 copies', '30,000', '60,000'],
        ['Laptop usage (depreciation)', '1', '100,000', '100,000'],
        ['Stationery', '—', '40,000', '40,000'],
        ['Electricity (power)', '4 months', '30,000', '120,000'],
        ['Miscellaneous', '—', '50,000', '50,000'],
        ['TOTAL', '', '', '570,000 UGX'],
    ]
    col_w = [6*cm, 3*cm, 4*cm, PAGE_W - 2*MARGIN - 13*cm]
    elems.append(info_table(budget, col_w, [
        ('FONTNAME',   (0,7), (-1,7), 'Helvetica-Bold'),
        ('BACKGROUND', (0,7), (-1,7), UCU_GOLD),
        ('TEXTCOLOR',  (0,7), (-1,7), WHITE),
    ]))
    return elems


# ── Page numbering ────────────────────────────────────────────────────────────
def add_page_number(canvas, doc):
    canvas.saveState()
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(DARK_GREY)

    # Footer line
    canvas.setStrokeColor(UCU_GOLD)
    canvas.setLineWidth(0.8)
    canvas.line(MARGIN, 1.5*cm, PAGE_W - MARGIN, 1.5*cm)

    # Page number
    page_num = canvas.getPageNumber()
    canvas.drawCentredString(PAGE_W / 2.0, 1.0*cm, str(page_num))

    # Running header
    canvas.setFont('Helvetica-Oblique', 7)
    canvas.drawString(MARGIN, PAGE_H - 1.2*cm,
        'Risk-Adaptive ZTA — Self-Supervised Anomaly Detection — Okado Aaron Obbo — S24B23/015')
    canvas.setStrokeColor(MID_GREY)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN, PAGE_H - 1.4*cm, PAGE_W - MARGIN, PAGE_H - 1.4*cm)

    canvas.restoreState()


# ── Main ──────────────────────────────────────────────────────────────────────
def generate():
    os.makedirs('data', exist_ok=True)

    doc = SimpleDocTemplate(
        OUTPUT,
        pagesize=A4,
        rightMargin=MARGIN, leftMargin=MARGIN,
        topMargin=2.0*cm, bottomMargin=2.5*cm,
        title='Risk-Adaptive Zero Trust — Self-Supervised Anomaly Detection',
        author='Okado Aaron Obbo',
        subject='Cybersecurity — Zero Trust + Machine Learning',
    )

    s = make_styles()
    story = []

    story += cover_page(s)
    story += abstract_section(s)
    story += chapter1(s)
    story += chapter2(s)
    story += chapter3(s)
    story += chapter4(s)
    story += chapter5(s)
    story += references_section(s)
    story += appendix_budget(s)

    doc.build(story, onFirstPage=add_page_number,
              onLaterPages=add_page_number)

    size_kb = os.path.getsize(OUTPUT) / 1024
    print(f'PDF generated: {OUTPUT}')
    print(f'Size         : {size_kb:.1f} KB')
    print(f'Pages        : check the file')


if __name__ == '__main__':
    generate()
