# setup_agent.ps1
# VAPT Scanner — Windows Workstation Setup
# Sets up the agent (background polling) and local scanner (on-demand UI)
#
# Run in PowerShell as Administrator:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\setup_agent.ps1

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# ── colours ───────────────────────────────────────────────────────────────────

function Write-Step  { param($msg) Write-Host "  [→] $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "  [✓] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "  [✗] $msg" -ForegroundColor Red }

function Write-Banner {
    Write-Host ""
    Write-Host "  ██╗   ██╗ █████╗ ██████╗ ████████╗" -ForegroundColor Green
    Write-Host "  ██║   ██║██╔══██╗██╔══██╗╚══██╔══╝" -ForegroundColor Green
    Write-Host "  ██║   ██║███████║██████╔╝   ██║   " -ForegroundColor Green
    Write-Host "  ╚██╗ ██╔╝██╔══██║██╔═══╝    ██║   " -ForegroundColor Green
    Write-Host "   ╚████╔╝ ██║  ██║██║        ██║   " -ForegroundColor Green
    Write-Host "    ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝   " -ForegroundColor Green
    Write-Host "  Windows Workstation Setup" -ForegroundColor White
    Write-Host ""
}

# ── config ────────────────────────────────────────────────────────────────────

$InstallDir = "$env:USERPROFILE\vapt-agent"
$PythonDir  = "$InstallDir\python"
$VenvDir    = "$InstallDir\venv"
$NmapDir    = "C:\Program Files (x86)\Nmap"

# ── helper: run a command and throw on failure ─────────────────────────────────

function Invoke-Cmd {
    param([string]$Desc, [scriptblock]$Block)
    Write-Step $Desc
    try {
        & $Block
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            throw "Exit code $LASTEXITCODE"
        }
        Write-Ok $Desc
    } catch {
        Write-Fail "$Desc — $_"
        throw
    }
}

# ── check winget ──────────────────────────────────────────────────────────────

function Test-Winget {
    try { winget --version | Out-Null; return $true }
    catch { return $false }
}

# ── install Python ────────────────────────────────────────────────────────────

function Install-Python {
    $pythonExe = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonExe) {
        $ver = & python --version 2>&1
        Write-Ok "Python already installed — $ver"
        return
    }

    if (Test-Winget) {
        Write-Step "Installing Python 3.12 via winget..."
        winget install --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
        # refresh PATH
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH", "User")
        Write-Ok "Python installed"
    } else {
        # Fall back to direct download
        Write-Step "Downloading Python 3.12 installer..."
        $installer = "$env:TEMP\python-installer.exe"
        $url = "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe"
        Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing
        Write-Step "Running Python installer (silent)..."
        Start-Process -FilePath $installer -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1" -Wait
        Remove-Item $installer -Force
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH", "User")
        Write-Ok "Python installed"
    }
}

# ── install Nmap ──────────────────────────────────────────────────────────────

function Install-Nmap {
    if (Test-Path "$NmapDir\nmap.exe") {
        Write-Ok "Nmap already installed"
        return
    }

    if (Test-Winget) {
        Write-Step "Installing Nmap via winget..."
        winget install --id Insecure.Nmap --silent --accept-package-agreements --accept-source-agreements
    } else {
        Write-Step "Downloading Nmap installer..."
        $installer = "$env:TEMP\nmap-installer.exe"
        $url = "https://nmap.org/dist/nmap-7.95-setup.exe"
        Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing
        Write-Step "Running Nmap installer (silent)..."
        Start-Process -FilePath $installer -ArgumentList "/S" -Wait
        Remove-Item $installer -Force
    }

    # add to PATH for this session
    if (-not ($env:PATH -like "*Nmap*")) {
        $env:PATH += ";$NmapDir"
    }

    Write-Ok "Nmap installed"
}

# ── create install directory ──────────────────────────────────────────────────

function New-InstallDir {
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir | Out-Null
        Write-Ok "Created $InstallDir"
    } else {
        Write-Ok "Install directory already exists"
    }
}

# ── virtual environment ───────────────────────────────────────────────────────

function New-Venv {
    if (Test-Path "$VenvDir\Scripts\python.exe") {
        Write-Ok "Virtual environment already exists"
        return
    }
    Write-Step "Creating Python virtual environment..."
    python -m venv $VenvDir
    Write-Ok "Virtual environment created"
}

function Install-PythonDeps {
    Write-Step "Installing Python dependencies..."
    & "$VenvDir\Scripts\pip.exe" install --quiet --upgrade pip
    & "$VenvDir\Scripts\pip.exe" install --quiet requests python-dotenv
    Write-Ok "Dependencies installed"
}

# ── copy scripts ──────────────────────────────────────────────────────────────

function Copy-Scripts {
    $scriptDir = Split-Path -Parent $MyInvocation.ScriptName

    # agent.py
    $agentSrc = Join-Path $scriptDir "agent.py"
    if (Test-Path $agentSrc) {
        Copy-Item $agentSrc "$InstallDir\agent.py" -Force
        Write-Ok "agent.py copied"
    } else {
        Write-Warn "agent.py not found next to setup script — copy it manually to $InstallDir"
    }

    # local_scanner.py
    $scannerSrc = Join-Path $scriptDir "local_scanner.py"
    if (Test-Path $scannerSrc) {
        Copy-Item $scannerSrc "$InstallDir\local_scanner.py" -Force
        Write-Ok "local_scanner.py copied"
    } else {
        Write-Warn "local_scanner.py not found next to setup script — copy it manually to $InstallDir"
    }
}

# ── .env file ─────────────────────────────────────────────────────────────────

function New-EnvFile {
    $envFile = "$InstallDir\.env"

    if (Test-Path $envFile) {
        Write-Warn ".env already exists — keeping existing configuration"
        return
    }

    Write-Host ""
    Write-Host "  Agent Configuration" -ForegroundColor White
    Write-Host "  Press Enter to accept defaults where shown." -ForegroundColor Gray
    Write-Host ""

    $agentName = Read-Host "  Agent name [$(hostname)]"
    if ([string]::IsNullOrWhiteSpace($agentName)) { $agentName = hostname }

    $serverUrl = Read-Host "  Server URL [http://192.168.1.200:8000]"
    if ([string]::IsNullOrWhiteSpace($serverUrl)) { $serverUrl = "http://192.168.1.200:8000" }

    # Windows agents skip nikto_scan — Nikto requires Perl on Windows
    $capabilities = "nmap_scan,nse_scan"

    @"
VAPT_AGENT_NAME=$agentName
VAPT_SERVER_URL=$serverUrl
VAPT_CAPABILITIES=$capabilities
"@ | Out-File -FilePath $envFile -Encoding utf8 -Force

    Write-Ok ".env written"
    Write-Host "  Agent name : $agentName" -ForegroundColor Gray
    Write-Host "  Server URL : $serverUrl" -ForegroundColor Gray
    Write-Host "  Capabilities: $capabilities (nikto excluded — requires Perl on Windows)" -ForegroundColor Gray
}

# ── shortcuts ─────────────────────────────────────────────────────────────────

function New-Shortcut {
    param(
        [string]$Name,
        [string]$Target,
        [string]$Args,
        [string]$Description,
        [string]$WorkDir
    )
    $desktop = [System.Environment]::GetFolderPath("Desktop")
    $lnkPath = "$desktop\$Name.lnk"
    $wsh     = New-Object -ComObject WScript.Shell
    $sc      = $wsh.CreateShortcut($lnkPath)
    $sc.TargetPath       = $Target
    $sc.Arguments        = $Args
    $sc.Description      = $Description
    $sc.WorkingDirectory = $WorkDir
    $sc.Save()
    Write-Ok "Shortcut created: $Name (Desktop)"
}

function New-Shortcuts {
    $python = "$VenvDir\Scripts\python.exe"

    # Local Scanner shortcut — opens browser UI
    New-Shortcut `
        -Name        "VAPT Local Scanner" `
        -Target      $python `
        -Args        "`"$InstallDir\local_scanner.py`"" `
        -Description "Run VAPT Local Scanner (browser UI)" `
        -WorkDir     $InstallDir

    # Agent shortcut — runs background agent
    New-Shortcut `
        -Name        "VAPT Agent" `
        -Target      $python `
        -Args        "`"$InstallDir\agent.py`"" `
        -Description "Run VAPT Agent (connects to central server)" `
        -WorkDir     $InstallDir
}

# ── optional: Windows service for agent ───────────────────────────────────────

function Install-AgentService {
    Write-Host ""
    $answer = Read-Host "  Install VAPT Agent as a Windows service (runs at startup)? [y/N]"
    if ($answer -notmatch "^[Yy]$") {
        Write-Step "Skipping service installation"
        return
    }

    # Check if NSSM is available (Non-Sucking Service Manager)
    $nssm = Get-Command nssm -ErrorAction SilentlyContinue
    if (-not $nssm) {
        # Try to get it via winget
        if (Test-Winget) {
            Write-Step "Installing NSSM (service wrapper) via winget..."
            winget install --id NSSM.NSSM --silent --accept-package-agreements --accept-source-agreements 2>$null
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                        [System.Environment]::GetEnvironmentVariable("PATH", "User")
            $nssm = Get-Command nssm -ErrorAction SilentlyContinue
        }
    }

    if (-not $nssm) {
        Write-Warn "NSSM not available — agent will not run as a service."
        Write-Warn "Use the Desktop shortcut to start it manually, or install NSSM from https://nssm.cc"
        return
    }

    $svcName = "VAPTAgent"

    # Remove existing service if present
    $existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Step "Removing existing VAPT Agent service..."
        Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
        nssm remove $svcName confirm | Out-Null
    }

    Write-Step "Installing VAPT Agent as Windows service..."
    nssm install $svcName "$VenvDir\Scripts\python.exe" | Out-Null
    nssm set $svcName AppParameters "`"$InstallDir\agent.py`"" | Out-Null
    nssm set $svcName AppDirectory $InstallDir | Out-Null
    nssm set $svcName DisplayName "VAPT Agent" | Out-Null
    nssm set $svcName Description "VAPT Scanner workstation agent — polls central server for scan jobs" | Out-Null
    nssm set $svcName Start SERVICE_AUTO_START | Out-Null
    nssm set $svcName AppStdout "$InstallDir\logs\agent.log" | Out-Null
    nssm set $svcName AppStderr "$InstallDir\logs\agent.log" | Out-Null
    nssm set $svcName AppRotateFiles 1 | Out-Null
    nssm set $svcName AppRotateBytes 10485760 | Out-Null  # 10 MB

    New-Item -ItemType Directory -Path "$InstallDir\logs" -Force | Out-Null

    Start-Service -Name $svcName
    $status = (Get-Service -Name $svcName).Status
    Write-Ok "VAPT Agent service installed and started (status: $status)"
}

# ── summary ───────────────────────────────────────────────────────────────────

function Write-Summary {
    $envFile = "$InstallDir\.env"
    $serverUrl = "http://192.168.1.200:8000"
    if (Test-Path $envFile) {
        $line = Select-String -Path $envFile -Pattern "VAPT_SERVER_URL" | Select-Object -First 1
        if ($line) { $serverUrl = $line.Line.Split("=",2)[1].Trim() }
    }

    Write-Host ""
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Setup complete" -ForegroundColor Green
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Install directory : $InstallDir" -ForegroundColor Gray
    Write-Host "  Central server    : $serverUrl" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Desktop shortcuts created:" -ForegroundColor White
    Write-Host "    VAPT Local Scanner  — on-demand scans in your browser" -ForegroundColor Gray
    Write-Host "    VAPT Agent          — connects to central dashboard" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  To edit agent config:" -ForegroundColor White
    Write-Host "    notepad $InstallDir\.env" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  To run the local scanner from PowerShell:" -ForegroundColor White
    Write-Host "    $VenvDir\Scripts\python.exe $InstallDir\local_scanner.py" -ForegroundColor Gray
    Write-Host ""
}

# ── entry point ───────────────────────────────────────────────────────────────

Write-Banner

Write-Host "  Installation directory: $InstallDir" -ForegroundColor Gray
Write-Host ""

try {
    Install-Python
    Install-Nmap
    New-InstallDir
    New-Venv
    Install-PythonDeps
    Copy-Scripts
    New-EnvFile
    New-Shortcuts
    Install-AgentService
    Write-Summary
} catch {
    Write-Host ""
    Write-Fail "Setup failed: $_"
    Write-Host "  Check the error above and re-run the script." -ForegroundColor Yellow
    exit 1
}
