# =============================================================================
# demo.ps1  —  Live Pipeline Demo for Mid-Semester Presentation
# Risk-Adaptive Zero Trust  |  Okado Aaron Obbo  |  S24B23/015
#
# HOW TO USE ON PRESENTATION DAY:
#   1. Open PowerShell in the project folder
#   2. Run:  .\demo.ps1
#   3. Walk the panelist through each section
# =============================================================================

$PROJECT = "c:\Users\AARON\Desktop\New folder\zta-ml-framework"
Set-Location $PROJECT

# ── Colours ───────────────────────────────────────────────────────────────────
function title($t)  { Write-Host "`n$t" -ForegroundColor Cyan }
function ok($t)     { Write-Host "  $t" -ForegroundColor Green }
function warn($t)   { Write-Host "  $t" -ForegroundColor Yellow }
function danger($t) { Write-Host "  $t" -ForegroundColor Red }
function info($t)   { Write-Host "  $t" -ForegroundColor White }

Clear-Host
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  RISK-ADAPTIVE ZERO TRUST — LIVE PIPELINE DEMO" -ForegroundColor Cyan
Write-Host "  Okado Aaron Obbo  |  S24B23/015  |  BSc Computer Science" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# =============================================================================
# STEP 1 — Show the project files exist
# =============================================================================
title "STEP 1: Project Evidence"
info "Source code files:"
Get-ChildItem src\ | ForEach-Object { info "  src\$($_.Name)" }
info ""
info "Trained models:"
Get-ChildItem data\*.keras, data\*.h5 -ErrorAction SilentlyContinue |
    Select-Object Name, @{N='Size_MB';E={[math]::Round($_.Length/1MB,2)}} |
    ForEach-Object { info "  $($_.Name)  ($($_.Size_MB) MB)" }
info ""
info "Training results:"
Get-Content data\training_results.json

Read-Host "`n  [Press Enter to continue to Step 2]"

# =============================================================================
# STEP 2 — Check API is running, open browser
# =============================================================================
title "STEP 2: Risk-Scoring API"
info "Checking if API is running on port 5000..."

try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:5000/health" -TimeoutSec 3
    ok "API is UP  |  Model loaded: $($health.model_loaded)  |  Time: $($health.timestamp)"
    info ""
    info "Opening browser dashboard..."
    Start-Process "http://127.0.0.1:5000"
} catch {
    warn "API not running. Starting it now..."
    Start-Process powershell -ArgumentList "-NoExit -Command `"Set-Location '$PROJECT'; python src/api.py`""
    info "Waiting for API to start (15 seconds)..."
    Start-Sleep 15
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:5000/health" -TimeoutSec 5
    ok "API is now UP  |  Model loaded: $($health.model_loaded)"
    Start-Process "http://127.0.0.1:5000"
}

Read-Host "`n  [Press Enter to continue to Step 3 - Live Predictions]"

# =============================================================================
# STEP 3 — Live predictions on three scenarios
# =============================================================================
title "STEP 3: Live Risk Scoring — Three Scenarios"
info "Sending real connection features to the CNN-GRU model via the API..."
info ""

# ── Scenario A: Normal Traffic ─────────────────────────────────────────────
info "--- Scenario A: Normal HTTP connection (employee browsing) ---"
$body = '{"features":{"duration":0,"protocol_type":"tcp","service":"http","flag":"SF","src_bytes":232,"dst_bytes":8153,"count":8,"srv_count":8,"same_srv_rate":1.0,"serror_rate":0.0,"rerror_rate":0.0}}'
$r = Invoke-RestMethod -Uri "http://127.0.0.1:5000/predict" -Method POST -Body $body -ContentType "application/json"
ok "  Risk Score    : $($r.risk_score)   (LOW)"
ok "  Classification: $($r.classification)"
ok "  ZTA Action    : $($r.action)  <-- employee gets through"
info "  Confidence    : $($r.confidence)   |   Latency: $($r.latency_ms) ms"
info ""

# ── Scenario B: DoS Attack ─────────────────────────────────────────────────
info "--- Scenario B: DoS Attack (SYN flood — 511 failed connections) ---"
$body = '{"features":{"duration":0,"protocol_type":"tcp","service":"private","flag":"S0","src_bytes":0,"dst_bytes":0,"count":511,"srv_count":511,"serror_rate":1.0,"srv_serror_rate":1.0,"same_srv_rate":1.0,"diff_srv_rate":0.0,"rerror_rate":0.0}}'
$r = Invoke-RestMethod -Uri "http://127.0.0.1:5000/predict" -Method POST -Body $body -ContentType "application/json"
if ($r.action -eq "BLOCK") { danger "  Risk Score    : $($r.risk_score)   (HIGH)" }
else                        { warn   "  Risk Score    : $($r.risk_score)" }
if ($r.action -eq "BLOCK")          { danger "  ZTA Action    : $($r.action)  <-- attacker is blocked" }
elseif ($r.action -eq "CHALLENGE_MFA") { warn "  ZTA Action    : $($r.action)  <-- MFA challenge triggered" }
else                                { info "  ZTA Action    : $($r.action)" }
info "  Classification: $($r.classification)   |   Confidence: $($r.confidence)"
info "  Latency       : $($r.latency_ms) ms"
info ""

# ── Scenario C: Port Scan / Probe ──────────────────────────────────────────
info "--- Scenario C: Network Probe (port scan — high reject rate) ---"
$body = '{"features":{"duration":0,"protocol_type":"tcp","service":"private","flag":"REJ","src_bytes":0,"dst_bytes":0,"count":229,"srv_count":20,"rerror_rate":1.0,"srv_rerror_rate":1.0,"diff_srv_rate":0.06,"same_srv_rate":0.09,"serror_rate":0.0}}'
$r = Invoke-RestMethod -Uri "http://127.0.0.1:5000/predict" -Method POST -Body $body -ContentType "application/json"
if ($r.risk_score -gt 0.5) {
    warn "  Risk Score    : $($r.risk_score)   (MEDIUM-HIGH)"
    warn "  ZTA Action    : $($r.action)"
} else {
    info "  Risk Score    : $($r.risk_score)"
    info "  ZTA Action    : $($r.action)"
}
info "  Classification: $($r.classification)   |   Confidence: $($r.confidence)"
info "  Latency       : $($r.latency_ms) ms"

Read-Host "`n  [Press Enter to continue to Step 4 - Audit Trail]"

# =============================================================================
# STEP 4 — Show the audit trail
# =============================================================================
title "STEP 4: Audit Trail (every decision is logged)"
info "Last 5 entries in data\audit.jsonl:"
Get-Content data\audit.jsonl | Select-Object -Last 5 | ForEach-Object {
    $entry = $_ | ConvertFrom-Json
    $colour = if ($entry.action -eq "BLOCK") { "Red" }
              elseif ($entry.action -eq "CHALLENGE_MFA") { "Yellow" }
              elseif ($entry.action -eq "MONITOR") { "DarkYellow" }
              else { "Green" }
    Write-Host "  [$($entry.timestamp.Substring(0,19))]  " -NoNewline
    Write-Host "$($entry.action)" -ForegroundColor $colour -NoNewline
    Write-Host "  risk=$($entry.risk_score)  class=$($entry.classification)  confidence=$($entry.confidence)"
}

Read-Host "`n  [Press Enter to continue to Step 5 - Code Evidence]"

# =============================================================================
# STEP 5 — Show key code files
# =============================================================================
title "STEP 5: Key Source Files (open in editor if requested)"
info "The panelist can ask to see any of these:"
info ""
info "  src/autoencoder.py   -- self-supervised autoencoder (trains on normal only)"
info "  src/model.py         -- CNN-GRU architecture"
info "  src/train.py         -- trains both models"
info "  src/evaluate.py      -- 4-way comparison"
info "  src/api.py           -- Flask risk-scoring API"
info "  src/preprocess.py    -- noise removal + 40-feature pipeline"
info ""
info "GitHub repository:"
info "  https://github.com/asdcaaron/zta-ml-framework"
info "  Branch: Aaron  |  7 commits"

Read-Host "`n  [Press Enter to see GitHub commit history]"
Set-Location $PROJECT
git log --oneline 2>&1 | ForEach-Object { info "  $_" }

# =============================================================================
# DONE
# =============================================================================
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  DEMO COMPLETE" -ForegroundColor Cyan
Write-Host "  Total pipeline: Zeek -> preprocess -> CNN-GRU -> risk score" -ForegroundColor Cyan
Write-Host "  -> ZTA action -> audit log" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
