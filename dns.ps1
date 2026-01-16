# Enable Datadog Microsoft DNS Integration (Audit Events)
# Run as Administrator
# Datadog Agent >= 7.66.0 required
# NO DNS Service Restart Required

Write-Host "Enabling Datadog Microsoft DNS Integration..." -ForegroundColor Green

$agentBin = "$env:ProgramFiles\Datadog\Datadog Agent\bin\agent.exe"
$datadogYaml = "C:\ProgramData\Datadog\datadog.yaml"
$configDir = "C:\ProgramData\Datadog\conf.d\microsoft_dns.d"
$configFile = "$configDir\conf.yaml"
$dnsAuditChannel = "Microsoft-Windows-DNSServer/Audit"
$hostname = $env:COMPUTERNAME

# ------------------------------------------------------------
# Step 0: Validate Datadog Agent
# ------------------------------------------------------------
Write-Host ""
Write-Host "Step 0: Validating Datadog Agent..." -ForegroundColor Yellow

if (-not (Test-Path $agentBin)) {
    Write-Host "ERROR: Datadog Agent not found. Install the Agent first." -ForegroundColor Red
    exit 1
}

$agentVersion = & $agentBin version
Write-Host "Datadog Agent detected: $agentVersion" -ForegroundColor Green

# ------------------------------------------------------------
# Step 1: Ensure DNS Audit Channel Exists
# ------------------------------------------------------------
Write-Host ""
Write-Host "Step 1: Checking DNS Audit Event channel..." -ForegroundColor Yellow

$channelExists = wevtutil el | Select-String $dnsAuditChannel

if (-not $channelExists) {
    Write-Host "ERROR: DNS Audit channel not found." -ForegroundColor Red
    Write-Host "Enable it with the following command:" -ForegroundColor Yellow
    Write-Host "dnscmd /config /EnableDnsAuditLogging 1" -ForegroundColor Cyan
    exit 1
}

Write-Host "DNS Audit channel is available" -ForegroundColor Green

# ------------------------------------------------------------
# Step 2: Enable logs in datadog.yaml
# ------------------------------------------------------------
Write-Host ""
Write-Host "Step 2: Enabling Datadog log collection..." -ForegroundColor Yellow

if (-not (Test-Path $datadogYaml)) {
    Write-Host "ERROR: datadog.yaml not found." -ForegroundColor Red
    exit 1
}

$content = Get-Content $datadogYaml

if ($content -match '^\s*logs_enabled:\s*true') {
    Write-Host "logs_enabled is already set to true" -ForegroundColor Green
}
elseif ($content -match '^\s*logs_enabled:') {
    (Get-Content $datadogYaml) `
        -replace '^\s*logs_enabled:.*', 'logs_enabled: true' |
        Set-Content $datadogYaml
    Write-Host "Updated logs_enabled to true" -ForegroundColor Green
}
else {
    Add-Content -Path $datadogYaml -Value "`nlogs_enabled: true"
    Write-Host "Added logs_enabled: true" -ForegroundColor Green
}

# ------------------------------------------------------------
# Step 3: Create Microsoft DNS integration config
# ------------------------------------------------------------
Write-Host ""
Write-Host "Step 3: Creating Microsoft DNS config..." -ForegroundColor Yellow

if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
}

$dnsConfig = @"
logs:
  - type: windows_event
    channel_path: "$dnsAuditChannel"
    source: microsoft-dns
    service: microsoft-dns
    sourcecategory: windowsevent
    tags:
      - "hostname:$hostname"
"@

Set-Content -Path $configFile -Value $dnsConfig -Force
Write-Host "Config written to $configFile" -ForegroundColor Green

# ------------------------------------------------------------
# Step 4: Restart Datadog Agent
# ------------------------------------------------------------
Write-Host ""
Write-Host "Step 4: Restarting Datadog Agent..." -ForegroundColor Yellow

Restart-Service datadogagent -Force -ErrorAction Stop
Write-Host "Datadog Agent restarted successfully" -ForegroundColor Green

# ------------------------------------------------------------
# Step 5: Verification
# ------------------------------------------------------------
Write-Host ""
Write-Host "Step 5: Verifying integration..." -ForegroundColor Yellow

& $agentBin status | Select-String -Pattern "microsoft_dns|Logs Agent" -Context 2,2

Write-Host ""
Write-Host "SUCCESS: Microsoft DNS Audit Log collection enabled!" -ForegroundColor Green

Write-Host ""
Write-Host "Next steps in Datadog UI:" -ForegroundColor Cyan
Write-Host "- Logs: search source:microsoft-dns"
Write-Host "- Security: Cloud SIEM - enable DNS-related rules"
Write-Host "- Create dashboards for DNS audit activity"
