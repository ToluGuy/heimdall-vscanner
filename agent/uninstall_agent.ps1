# uninstall_agent.ps1 — Heimdall V-Scanner agent uninstaller (Windows)
# Run as Administrator in PowerShell.
# Usage: .\uninstall_agent.ps1 [-Yes]

param([switch]$Yes)

$ErrorActionPreference = "Continue"

function Write-Ok($msg)   { Write-Host "  [OK]  $msg" -ForegroundColor Green  }
function Write-Warn($msg) { Write-Host "  [!!]  $msg" -ForegroundColor Yellow }
function Write-Info($msg) { Write-Host "  [->]  $msg" -ForegroundColor Cyan   }

function Confirm-Action($prompt) {
    if ($Yes) { return $true }
    $ans = Read-Host "  $prompt [y/N]"
    return $ans -match '^[Yy]'
}

Write-Host ""
Write-Host "  Heimdall V-Scanner — Agent Uninstaller (Windows)" -ForegroundColor Red
Write-Host "  ──────────────────────────────────────────────────"
Write-Host ""

$AgentDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallDir = "$env:USERPROFILE\vapt-agent"

# ── Stop and remove NSSM service if present ───────────────────────────────────
$NssmPath = (Get-Command nssm -ErrorAction SilentlyContinue)?.Source
$ServiceName = "HeimdallAgent"

if ($NssmPath) {
    $svcStatus = & sc.exe query $ServiceName 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Info "Stopping and removing NSSM service '$ServiceName'..."
        & $NssmPath stop    $ServiceName confirm 2>$null
        & $NssmPath remove  $ServiceName confirm 2>$null
        Write-Ok "NSSM service removed"
    } else {
        Write-Warn "NSSM service '$ServiceName' not found"
    }
} else {
    Write-Warn "NSSM not found — checking for running agent.py processes..."
}

# ── Kill any running agent.py processes ───────────────────────────────────────
$agentProcs = Get-Process -Name python -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*agent.py*" }
if ($agentProcs) {
    if (Confirm-Action "Kill running agent.py processes?") {
        $agentProcs | Stop-Process -Force
        Write-Ok "Processes killed"
    }
}

# ── Remove Desktop shortcuts ──────────────────────────────────────────────────
$shortcuts = @(
    "$env:USERPROFILE\Desktop\VAPT Agent.lnk",
    "$env:USERPROFILE\Desktop\VAPT Local Scanner.lnk"
)
foreach ($s in $shortcuts) {
    if (Test-Path $s) {
        Remove-Item $s -Force
        Write-Ok "Removed shortcut: $(Split-Path -Leaf $s)"
    }
}

# ── Remove key files ──────────────────────────────────────────────────────────
$keyFiles = @(
    Get-ChildItem -Path $AgentDir    -Filter "*_key.txt" -ErrorAction SilentlyContinue
    Get-ChildItem -Path $InstallDir  -Filter "*_key.txt" -ErrorAction SilentlyContinue
)
foreach ($f in $keyFiles) {
    Remove-Item $f.FullName -Force
    Write-Ok "Removed key file: $($f.Name)"
}

# ── Remove venv / install directory ───────────────────────────────────────────
if (Test-Path $InstallDir) {
    if (Confirm-Action "Remove install directory '$InstallDir'?") {
        Remove-Item $InstallDir -Recurse -Force
        Write-Ok "Removed $InstallDir"
    } else {
        Write-Warn "Install directory kept at $InstallDir"
    }
}

Write-Host ""
Write-Ok "Agent uninstall complete."
Write-Host "  Agent script files remain at $AgentDir — remove them manually if needed."
Write-Host ""
