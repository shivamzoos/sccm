$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$sourceFile = Join-Path $scriptDir "conf.yaml"

$destDir  = "C:\ProgramData\Datadog\conf.d\windows_service.d"
$destFile = Join-Path $destDir "conf.yaml"
$agentSvc = "datadogagent"

try {
    # Require Administrator
    if (-not ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script as Administrator."
    }

    # Validate source file exists (same directory as script)
    if (-not (Test-Path $sourceFile)) {
        throw "conf.yaml not found in script directory: $scriptDir"
    }

    # Ensure destination directory exists
    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }

    # Backup existing config
    if (Test-Path $destFile) {
        $backup = "$destFile.bak_$(Get-Date -Format 'yyyyMMddHHmmss')"
        Copy-Item $destFile $backup -Force
    }

    # Copy conf.yaml
    Copy-Item -Path $sourceFile -Destination $destFile -Force

    # Restart Datadog Agent safely
    $svc = Get-Service -Name $agentSvc -ErrorAction Stop
    if ($svc.Status -eq "Running") {
        Restart-Service -Name $agentSvc -Force -ErrorAction Stop
    } else {
        Start-Service -Name $agentSvc -ErrorAction Stop
    }

    Write-Host "conf.yaml deployed and Datadog Agent restarted successfully." -ForegroundColor Green
}
catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
    exit 1
}
