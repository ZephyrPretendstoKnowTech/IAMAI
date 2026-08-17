<#
  IAMAI installer for Windows.

  One command, no prior knowledge required:

    irm https://raw.githubusercontent.com/ZephyrPretendstoKnowTech/IAMAI/master/scripts/install.ps1 | iex

  It checks the machine first and says what it is about to do, finds (or
  installs) Python, installs IAMAI into its own isolated place so it never
  clutters anything, adds the `iamai` command to your PATH, verifies the
  install actually worked, and starts the guided setup. Nothing here needs
  Administrator; it installs for the current user only. IAMAI is read-only:
  it can never change a tenant.

  Written for Windows PowerShell 5.1 (the one every Windows machine ships
  with); it also runs on PowerShell 7. Every external command is checked, and
  the success message at the end is printed only after the installed command
  has been run and answered. If anything fails, the script stops there and
  says what failed and what to try.
#>

# Captured Python and pipx output falls back to the legacy cp1252 codepage,
# which cannot encode the emoji pipx prints and crashes with "'charmap' codec
# can't encode character". The console handles UTF-8 fine; it is the capture
# that needs telling.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'

# Stock Windows PowerShell 5.1 can still offer TLS 1.0 first, which GitHub
# rejects; without this the very first web request fails with a message that
# looks like a network problem.
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# Not 'Stop': under Windows PowerShell 5.1, Stop turns a native command's
# redirected stderr (pip and pipx write progress there) into a terminating
# error mid-install. Every external command below is checked explicitly via
# $LASTEXITCODE instead, and the web requests pass -ErrorAction Stop so their
# failures still reach the try/catch around them.
$ErrorActionPreference = 'Continue'

$Repo      = 'ZephyrPretendstoKnowTech/IAMAI'
$ApiLatest = "https://api.github.com/repos/$Repo/releases/latest"
$MasterZip = "https://github.com/$Repo/archive/refs/heads/master.zip"

function Say($msg)  { Write-Host "  $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "  $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "  $msg" -ForegroundColor Yellow }
function Detail($msg) { Write-Host "    $msg" -ForegroundColor DarkGray }

# Every failure path funnels through here: it names what failed, what to try,
# and stops. Nothing after a failure can print a success message.
function Fail([string]$What, [string[]]$Hints) {
    Write-Host ""
    Write-Host "  INSTALL FAILED: $What" -ForegroundColor Red
    foreach ($h in $Hints) { Warn $h }
    Write-Host ""
    throw "IAMAI-INSTALL-FAILED"
}

function Invoke-Python {
    # Runs the chosen Python with the given arguments and returns the output;
    # the caller checks $LASTEXITCODE. $script:Py holds e.g. @('py','-3.12').
    param([string[]]$PyArgs)
    $exe = $script:Py[0]
    $lead = @()
    if ($script:Py.Length -gt 1) { $lead = $script:Py[1..($script:Py.Length - 1)] }
    & $exe ($lead + $PyArgs) 2>&1
}

function Find-Python {
    foreach ($cmd in @('py -3.12', 'py -3', 'python', 'python3')) {
        $parts = $cmd.Split(' ')
        $exe = Get-Command $parts[0] -ErrorAction SilentlyContinue
        if (-not $exe) { continue }
        try {
            if ($parts.Length -gt 1) {
                $v = & $parts[0] $parts[1..($parts.Length - 1)] -c "import sys;print('%d.%d'%sys.version_info[:2])" 2>$null
            } else {
                $v = & $parts[0] -c "import sys;print('%d.%d'%sys.version_info[:2])" 2>$null
            }
        } catch { continue }
        if ($LASTEXITCODE -ne 0) { continue }
        if ($v -and [version]$v -ge [version]'3.12') { return ,@($parts) }
    }
    return $null
}

function Test-Endpoint([string]$Url) {
    try {
        Invoke-WebRequest -Uri $Url -Method Head -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop | Out-Null
        return $true
    } catch {
        # Some hosts refuse HEAD but serve GET; a refused method still proves
        # the host is reachable.
        if ($_.Exception.Response) { return $true }
        return $false
    }
}

function Get-InstallSource {
    # Preferred order: the pinned wheel attached to the latest release, then
    # the latest release's source archive (still pinned), then the master
    # archive as the fallback. All three are plain zip or wheel downloads, so
    # no git is ever needed.
    try {
        $release = Invoke-RestMethod -Uri $ApiLatest -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
        foreach ($asset in @($release.assets)) {
            if ($asset.name -like 'iamai-*.whl') {
                return @{ Spec = $asset.browser_download_url; Label = "release $($release.tag_name) (pinned wheel)" }
            }
        }
        if ($release.tag_name) {
            $zip = "https://github.com/$Repo/archive/refs/tags/$($release.tag_name).zip"
            return @{ Spec = $zip; Label = "release $($release.tag_name) (source archive)" }
        }
    } catch {
        Warn "Could not look up the latest release (GitHub API unreachable); using the development version instead."
    }
    return @{ Spec = $MasterZip; Label = 'the latest development version (master archive)' }
}

function Install-IAMAI {
    Write-Host ""
    Write-Host "IAMAI installer" -ForegroundColor White
    Write-Host "Read-only Microsoft Entra identity posture. Installs for you only." -ForegroundColor DarkGray
    Write-Host ""

    # --- Preflight: check the machine and say what is about to happen ---------
    Say "Checking this machine..."
    $psv = $PSVersionTable.PSVersion
    Detail "PowerShell $psv ($($PSVersionTable.PSEdition)); $env:PROCESSOR_ARCHITECTURE"

    $script:Py = Find-Python
    if ($script:Py) {
        $pyPath = (Get-Command $script:Py[0]).Source
        # Inner single quotes on purpose: Windows PowerShell 5.1 strips
        # embedded double quotes when passing arguments to a native command.
        $pyVer = Invoke-Python @('-c', "import sys;print('%d.%d.%d'%sys.version_info[:3])")
        Detail "Python $pyVer found at $pyPath"
    } else {
        Detail "Python 3.12+: not found (it will be installed for this user)"
    }

    $havePipx = $false
    if ($script:Py) {
        Invoke-Python @('-m', 'pipx', '--version') | Out-Null
        if ($LASTEXITCODE -eq 0) { $havePipx = $true }
    }
    if ($havePipx) { Detail "pipx: present" } else { Detail "pipx: not found (it will be installed for this user)" }

    $existing = Get-Command iamai -ErrorAction SilentlyContinue
    if ($existing) {
        Detail "IAMAI: already installed at $($existing.Source); it will be upgraded in place"
    } else {
        Detail "IAMAI: not installed yet"
    }

    if (-not (Test-Endpoint 'https://github.com')) {
        Fail "github.com is not reachable from this machine." @(
            "The installer downloads IAMAI from GitHub, so it needs to reach github.com.",
            "If this machine uses a proxy, set it for PowerShell first, then run the installer again."
        )
    }
    if (-not (Test-Endpoint 'https://pypi.org')) {
        Fail "pypi.org is not reachable from this machine." @(
            "IAMAI's Python dependencies come from pypi.org, so the install needs to reach it.",
            "If this machine uses a proxy, set it for PowerShell first, then run the installer again."
        )
    }
    Detail "Network: github.com and pypi.org are reachable"

    $source = Get-InstallSource

    Write-Host ""
    Say "This installer will:"
    if (-not $script:Py) { Detail "1. Install Python 3.12 for the current user (via winget)" }
    else { Detail "1. Use the Python already on this machine" }
    Detail "2. Install pipx, a tool that keeps IAMAI in its own isolated environment"
    Detail "3. Install IAMAI from $($source.Label)"
    Detail "4. Put the 'iamai' command on your PATH and verify it answers"
    Detail "Nothing needs Administrator. Nothing is changed outside your user profile."
    Write-Host ""

    # --- Step 1 of 4: Python ---------------------------------------------------
    if (-not $script:Py) {
        Say "Step 1 of 4: installing Python 3.12 (current user)..."
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $winget) {
            Fail "Python 3.12+ is not installed and winget is not available to install it." @(
                "Install Python 3.12 from https://www.python.org/downloads/ (tick 'Add python.exe to PATH'),",
                "then run this installer again."
            )
        }
        # --source winget pins the source so the msstore agreement prompt can
        # never appear, and --disable-interactivity means a piped install can
        # never sit waiting for a keypress it will never get.
        winget install -e --id Python.Python.3.12 --scope user --silent --source winget `
            --accept-source-agreements --accept-package-agreements --disable-interactivity
        if ($LASTEXITCODE -ne 0) {
            Fail "winget could not install Python 3.12 (exit code $LASTEXITCODE)." @(
                "Install Python 3.12 yourself from https://www.python.org/downloads/ (tick 'Add python.exe to PATH'),",
                "then run this installer again."
            )
        }
        $env:PATH = "$env:LOCALAPPDATA\Programs\Python\Python312;$env:LOCALAPPDATA\Programs\Python\Python312\Scripts;$env:PATH"
        $script:Py = Find-Python
        if (-not $script:Py) {
            Fail "Python was installed but cannot be found on PATH yet." @(
                "Close this window, open a new PowerShell window, and run the installer again;",
                "the new PATH entry takes effect in new windows."
            )
        }
        Ok "Step 1 of 4: Python installed."
    } else {
        Ok "Step 1 of 4: Python is ready ($($script:Py -join ' '))."
    }

    # --- Step 2 of 4: pipx -----------------------------------------------------
    Say "Step 2 of 4: preparing the isolated installer (pipx)..."
    $out = Invoke-Python @('-m', 'pip', 'install', '--user', '--quiet', '--upgrade', 'pipx')
    if ($LASTEXITCODE -ne 0) {
        $out | Select-Object -Last 10 | ForEach-Object { Detail $_ }
        Fail "pip could not install pipx (exit code $LASTEXITCODE)." @(
            "The last lines above are pip's own report of what went wrong.",
            "If it mentions a network or proxy problem, fix that and run the installer again."
        )
    }
    $out = Invoke-Python @('-m', 'pipx', 'ensurepath')
    if ($LASTEXITCODE -ne 0) {
        $out | Select-Object -Last 5 | ForEach-Object { Detail $_ }
        Fail "pipx could not add its app directory to your PATH (exit code $LASTEXITCODE)." @(
            "You can add it yourself: run  pipx environment --value PIPX_BIN_DIR  to see the directory,",
            "add it to your PATH, then run this installer again."
        )
    }
    # Put pipx's app directory on PATH for THIS session so `iamai` is callable
    # now, not just after a restart.
    $pipxBin = (Invoke-Python @('-m', 'pipx', 'environment', '--value', 'PIPX_BIN_DIR') | Select-Object -First 1)
    if ($LASTEXITCODE -eq 0 -and $pipxBin) { $env:PATH = "$pipxBin;$env:PATH" }
    Ok "Step 2 of 4: pipx is ready."

    # --- Step 3 of 4: IAMAI ----------------------------------------------------
    # Installed from a plain archive or wheel URL, never from git+https: stock
    # Windows has no git and this tool must not require installing one.
    Say "Step 3 of 4: installing IAMAI from $($source.Label)..."
    # Plain positional spec: modern pipx (1.16 was checked) has no --spec flag
    # on install. A source archive makes pipx build once extra to learn the
    # package name; a release wheel carries its name in the filename, which is
    # why the wheel is the preferred source above.
    $out = Invoke-Python @('-m', 'pipx', 'install', '--force', $source.Spec)
    $code = $LASTEXITCODE
    # pipx tidies its shared libraries on the way through and prints a warning
    # about setuptools not being installed; that is pipx housekeeping, not a
    # problem with this install, and it only confuses a first run.
    $out | Where-Object { $_ -notmatch 'Skipping (setuptools|wheel) as it is not installed' } |
        ForEach-Object { Detail $_ }
    if ($code -ne 0) {
        Fail "pipx could not install IAMAI (exit code $code)." @(
            "The lines above are the installer's own report of what went wrong.",
            "If it mentions a network or proxy problem, fix that and run this installer again.",
            "If it looks like a Python or pipx problem, please copy this output into an issue:",
            "  https://github.com/$Repo/issues"
        )
    }

    # --- Step 4 of 4: verify before claiming anything --------------------------
    Say "Step 4 of 4: verifying the install..."
    $cmd = Get-Command iamai -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Fail "The install finished but the 'iamai' command cannot be found on PATH." @(
            "Close this window, open a new PowerShell window, and run:  iamai --version",
            "If that also fails, run this installer again and copy its output into an issue:",
            "  https://github.com/$Repo/issues"
        )
    }
    $version = & iamai --version 2>$null
    if ($LASTEXITCODE -ne 0) {
        # Releases before 1.3.0 have no --version; --help proves the command
        # runs either way.
        & iamai --help | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Fail "The 'iamai' command was installed but does not run." @(
                "Run  iamai --help  yourself to see its error, and copy it into an issue:",
                "  https://github.com/$Repo/issues"
            )
        }
        $version = 'installed'
    }
    Ok "Step 4 of 4: verified. iamai answers ($version)."

    Write-Host ""
    Ok "IAMAI is installed."
    Detail "Installed from: $($source.Label)"
    Detail "Command: $($cmd.Source)"
    Detail "If a new window ever says 'iamai is not recognized', close and reopen PowerShell once."
    Write-Host ""
    Say "Starting setup. It will walk you through connecting a tenant."
    Write-Host ""
    iamai setup
}

# When PowerShell was launched to run a command or script (CI, automation),
# a failure must surface as a non-zero process exit code. In a hand-opened
# interactive window, `exit` would close the window and take the error text
# with it, so there the failure text stays on screen and $LASTEXITCODE is set
# instead.
function Test-ScriptedHost {
    foreach ($a in [Environment]::GetCommandLineArgs()) {
        if ($a -match '^-(Command|EncodedCommand|File|NonInteractive)') { return $true }
    }
    return $false
}

try {
    Install-IAMAI
} catch {
    if ($_.FullyQualifiedErrorId -notmatch 'IAMAI-INSTALL-FAILED') {
        Write-Host ""
        Write-Host "  INSTALL FAILED: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  This was not an expected failure; please copy this output into an issue:" -ForegroundColor Yellow
        Write-Host "  https://github.com/ZephyrPretendstoKnowTech/IAMAI/issues" -ForegroundColor Yellow
        Write-Host ""
    }
    cmd /c exit 1 | Out-Null   # sets $LASTEXITCODE for callers that check it
    if (Test-ScriptedHost) { exit 1 }
}
