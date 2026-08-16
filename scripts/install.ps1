<#
  IAMAI installer for Windows.

  One command, no prior knowledge required:

    irm https://raw.githubusercontent.com/ZephyrPretendstoKnowTech/IAMAI/master/scripts/install.ps1 | iex

  It finds (or installs) Python, installs IAMAI into its own isolated place so it
  never clutters anything, adds the `iamai` command to your PATH, and starts the
  guided setup. Nothing here needs Administrator; it installs for the current
  user only. IAMAI is read-only: it can never change a tenant.
#>

$ErrorActionPreference = 'Stop'
$RepoUrl = 'https://github.com/ZephyrPretendstoKnowTech/IAMAI.git'

function Say($msg)  { Write-Host "  $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "  $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "  $msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "IAMAI installer" -ForegroundColor White
Write-Host "Read-only Microsoft Entra identity posture. Installs for you only." -ForegroundColor DarkGray
Write-Host ""

# --- 1. Find a Python 3.12+ interpreter, installing one if needed -------------
function Find-Python {
    foreach ($cmd in @('py -3.12', 'py -3', 'python', 'python3')) {
        $parts = $cmd.Split(' ')
        $exe = Get-Command $parts[0] -ErrorAction SilentlyContinue
        if (-not $exe) { continue }
        try {
            $v = & $parts[0] $parts[1..$parts.Length] -c "import sys;print('%d.%d'%sys.version_info[:2])" 2>$null
        } catch { continue }
        if ($v -and [version]$v -ge [version]'3.12') { return ,@($parts) }
    }
    return $null
}

$py = Find-Python
if (-not $py) {
    Warn "Python 3.12 or newer was not found."
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        Say "Installing Python 3.12 (current user)..."
        winget install -e --id Python.Python.3.12 --scope user --silent --accept-source-agreements --accept-package-agreements
        $env:PATH = "$env:LOCALAPPDATA\Programs\Python\Python312;$env:LOCALAPPDATA\Programs\Python\Python312\Scripts;$env:PATH"
        $py = Find-Python
    }
    if (-not $py) {
        Warn "Please install Python 3.12 from https://www.python.org/downloads/ (tick 'Add to PATH'),"
        Warn "then run this installer again."
        return
    }
}
Ok "Python found: $($py -join ' ')"

# --- 2. Install pipx (isolated app installer), quietly ------------------------
Say "Preparing the installer..."
& $py[0] $py[1..$py.Length] -m pip install --user --quiet --upgrade pip pipx
& $py[0] $py[1..$py.Length] -m pipx ensurepath | Out-Null

# Put pipx's app directory on PATH for THIS session so `iamai` is callable now,
# not just after a restart.
$pipxBin = & $py[0] $py[1..$py.Length] -m pipx environment --value PIPX_BIN_DIR 2>$null
if ($pipxBin) { $env:PATH = "$pipxBin;$env:PATH" }

# --- 3. Install IAMAI from GitHub into its own isolated environment -----------
Say "Installing IAMAI..."
& $py[0] $py[1..$py.Length] -m pipx install --force "git+$RepoUrl"

if (-not (Get-Command iamai -ErrorAction SilentlyContinue)) {
    Ok "IAMAI is installed."
    Warn "Close and reopen PowerShell, then run:  iamai setup"
    return
}

# --- 4. Start the guided setup -----------------------------------------------
Ok "IAMAI is installed."
Write-Host ""
Say "Starting setup. It will walk you through connecting a tenant."
Write-Host ""
iamai setup
