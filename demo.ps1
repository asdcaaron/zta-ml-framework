# =============================================================================
# demo.ps1  --  Live Dashboard Demo Startup
# Risk-Adaptive Zero Trust  |  Okado Aaron Obbo  |  S24B23/015  |  UCU
#
# HOW TO USE:
#   1. Open PowerShell (anywhere)
#   2. Run:  .\demo.ps1
#   3. It starts the Flask API, waits for the models to load, then opens the
#      dashboard in your browser. Present from the browser.
#
# The API runs in its own window -- leave it open. Close it (Ctrl+C) when done.
# =============================================================================

$PROJECT = "c:\Users\AARON\Desktop\Final Year Project Prototype\zta-ml-framework"
Set-Location $PROJECT

# -- Colours -------------------------------------------------------------------
function title($t)  { Write-Host "`n$t" -ForegroundColor Cyan }
function ok($t)     { Write-Host "  $t" -ForegroundColor Green }
function warn($t)   { Write-Host "  $t" -ForegroundColor Yellow }
function danger($t) { Write-Host "  $t" -ForegroundColor Red }
function info($t)   { Write-Host "  $t" -ForegroundColor White }

Clear-Host
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  RISK-ADAPTIVE ZERO TRUST -- LIVE DASHBOARD DEMO" -ForegroundColor Cyan
Write-Host "  Okado Aaron Obbo  |  S24B23/015  |  Uganda Christian University" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# -- Step 1: Confirm project location + zero-day variant model ----------------
if (-not (Test-Path "src\api.py")) {
    danger "Project not found at '$PROJECT'."
    danger "Update `$PROJECT at the top of demo.ps1 to your project folder."
    exit 1
}
$branch = git branch --show-current 2>$null
info "Project : $PROJECT"
info "Branch  : $branch"

if (Test-Path "data\cnn_gru_model_no_u2r.keras") {
    ok "Zero-day variant model found -- the U2R scenario will use it."
} else {
    warn "Zero-day variant model NOT found (data\cnn_gru_model_no_u2r.keras)."
    warn "The U2R scenario will fall back to the standard model."
    warn "Get the variant with:  git checkout feat/zero-day-variant"
}

# -- Step 2: Start the API (only if not already running) -----------------------
title "Starting the Flask API..."
$portResponds = $false
try {
    Invoke-RestMethod -Uri "http://127.0.0.1:5000/health" -TimeoutSec 2 | Out-Null
    $portResponds = $true
} catch {}

if ($portResponds) {
    ok "API already running on port 5000 -- not starting a second instance."
} else {
    info "Launching the API in a new window..."
    Start-Process powershell -ArgumentList "-NoExit -Command `"Set-Location '$PROJECT'; python src/api.py`""
    info "Waiting for the models to load (can take ~15s)..."
}

# Poll /health until BOTH models report loaded (max ~60s)
$ready = $false
$h = $null
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 2
    try {
        $h = Invoke-RestMethod -Uri "http://127.0.0.1:5000/health" -TimeoutSec 2
        if ($h.model_loaded -and $h.ae_model_loaded) { $ready = $true; break }
    } catch {}
}

if (-not $ready) {
    danger "API did not become ready in time. Check the API window for errors"
    danger "(e.g. missing dependencies or model files)."
    exit 1
}

ok "CNN-GRU loaded : $($h.model_loaded)"
ok "Autoencoder    : $($h.ae_model_loaded)"
if ($h.zeek) {
    info "Zeek pipeline : mode=$($h.zeek.mode), conn.log present=$($h.zeek.conn_log_present)"
}

# -- Step 3: Open the dashboard ------------------------------------------------
title "Opening the dashboard..."
Start-Process "http://localhost:5000/dashboard"
ok "Dashboard opened at http://localhost:5000/dashboard"
info "(If it doesn't open automatically, browse there.)"

# -- Step 4: Click guide for the presenter -------------------------------------
title "Demo guide -- click the scenario buttons in the dashboard"
info "  Normal Access     ->  ALLOW   (low risk)"
info "  DoS Attack         ->  BLOCK   (often the CNN misreads it as Normal,"
info "                                  but the autoencoder catches it)"
info "  Probe / Anomaly    ->  BLOCK"
info "  R2L Access         ->  CHALLENGE_MFA / BLOCK"
info "  U2R Attack         ->  ZERO-DAY: the CNN (trained without U2R) says"
info "                          Normal, but the autoencoder flags it, so the"
info "                          combined risk drives a BLOCK."
info ""
info "  Watch in the dashboard:"
info "    - Detection Results : CNN class + autoencoder anomaly flag"
info "    - Risk Assessment   : CNN / AE / combined risk bars"
info "    - ZTA Policy Decision badge"
info "    - Audit Log (right) + Network Activity bars (left)"
info ""
info "  The API window must stay open. Close it (Ctrl+C) when the demo ends."

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  DASHBOARD IS LIVE -- present from the browser" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
