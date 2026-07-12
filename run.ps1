# Prahari one-command demo start (Windows PowerShell).
#   .\run.ps1           start everything (seeds DB on first run)
#   .\run.ps1 -Reset    wipe + reseed the DB first (clean demo state)
param([switch]$Reset)

Set-Location $PSScriptRoot

if (-not (Test-Path .venv)) {
    Write-Host "[prahari] creating venv..."
    python -m venv .venv
}
$py = ".\.venv\Scripts\python.exe"

& $py -c "import fastapi" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[prahari] installing dependencies..."
    & $py -m pip install -q -r requirements.txt
}

if ($Reset -or -not (Test-Path prahari.db)) {
    Write-Host "[prahari] seeding 14 days of baseline history..."
    & $py -m app.simulator.seed --fresh --days 14
}

if (-not (Test-Path frontend\dist)) {
    Write-Host "[prahari] building frontend..."
    Push-Location frontend
    npm install --no-fund --no-audit
    npm run build
    Pop-Location
}

# Bind to 0.0.0.0 so a second computer on the same Wi-Fi/LAN can connect
# (SOC console on one machine, employee portal on another).
$lan = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $_.PrefixOrigin -ne 'WellKnown' } |
        Select-Object -First 1 -ExpandProperty IPAddress)
Write-Host ""
Write-Host "[prahari] ===================================================="
Write-Host "[prahari]  This computer  : http://localhost:8000"
if ($lan) { Write-Host "[prahari]  Other computers: http://$($lan):8000   (same Wi-Fi/LAN)" }
Write-Host "[prahari]  (if the 2nd computer can't connect, allow port 8000 in Windows Firewall)"
Write-Host "[prahari] ===================================================="
Write-Host ""
& $py -m uvicorn app.main:app --host 0.0.0.0 --port 8000
