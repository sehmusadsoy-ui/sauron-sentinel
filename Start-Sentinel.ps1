[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8765,
    [ValidateRange(5, 3600)]
    [int]$Interval = 15,
    [ValidateRange(1, 168)]
    [int]$LookbackHours = 24,
    [switch]$Reinstall,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$RepoRoot = $PSScriptRoot
$PythonExe = Join-Path $RepoRoot '.venv\Scripts\python.exe'

function Invoke-Checked {
    param([string]$FilePath, [string[]]$Arguments)
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE."
    }
}

try {
    Set-Location -LiteralPath $RepoRoot
    if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) {
        Write-Host 'Preparing the local Python environment...'
        $Bootstrap = Get-Command py -ErrorAction SilentlyContinue
        if ($Bootstrap) {
            Invoke-Checked -FilePath $Bootstrap.Source -Arguments @('-3', '-m', 'venv', (Join-Path $RepoRoot '.venv'))
        }
        else {
            $Bootstrap = Get-Command python -ErrorAction SilentlyContinue
            if (-not $Bootstrap) {
                throw 'Python 3.11 or newer is required. Install Python, then open this launcher again.'
            }
            Invoke-Checked -FilePath $Bootstrap.Source -Arguments @('-m', 'venv', (Join-Path $RepoRoot '.venv'))
        }
    }

    Invoke-Checked -FilePath $PythonExe -Arguments @('-c', "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 'Python 3.11 or newer is required.')")
    $VersionLine = Select-String -LiteralPath (Join-Path $RepoRoot 'pyproject.toml') -Pattern '^version = "([^"]+)"$'
    if (-not $VersionLine) {
        throw 'Cannot read the package version from pyproject.toml.'
    }
    $ExpectedVersion = $VersionLine.Matches[0].Groups[1].Value
    $InstalledVersion = & $PythonExe -c "import importlib.metadata as m; print(next((d.version for d in m.distributions() if d.metadata['Name'] == 'sauron-sentinel'), ''))"
    if ($LASTEXITCODE -ne 0) {
        throw 'Cannot inspect the local Python environment.'
    }
    $InstalledVersion = [string]$InstalledVersion

    if ($Reinstall -or $InstalledVersion.Trim() -ne $ExpectedVersion) {
        Write-Host 'Installing Sauron Sentinel locally. Initial setup may download build tools.'
        Invoke-Checked -FilePath $PythonExe -Arguments @('-m', 'pip', 'install', '--disable-pip-version-check', '--no-deps', '-e', $RepoRoot)
    }

    Write-Host "Starting the local dashboard at http://127.0.0.1:$Port/"
    Write-Host 'Keep this window open. Press Ctrl+C to stop monitoring.'
    $LaunchArguments = @('-m', 'sauron_sentinel', 'serve', '--port', "$Port", '--data-dir', (Join-Path $RepoRoot 'sentinel-data'), '--interval', "$Interval", '--lookback-hours', "$LookbackHours")
    if (-not $NoBrowser) {
        $LaunchArguments += '--open-browser'
    }
    & $PythonExe @LaunchArguments
    exit $LASTEXITCODE
}
catch {
    Write-Host "Sauron Sentinel could not start: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
