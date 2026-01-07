# ============================================================================
# Datadog Configuration Deployment Script for EXL Infrastructure
# ============================================================================
# Description: Deploys Datadog YAML configs (Universal + Role-Specific only)
#              Custom scripts deployment will be done separately
# Version: 2.0 - Core Integrations Only
# ============================================================================


[CmdletBinding()]
param(
    [string]$DatadogConfPath = "C:\ProgramData\Datadog\conf.d",
    [string]$PackageSourcePath = $PSScriptRoot,
    [switch]$DryRun = $false,
    [string]$LogPath = "C:\Windows\Temp\DatadogDeployment.log"
)


# ============================================================================
# LOGGING FUNCTION
# ============================================================================
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Output $logMessage
    Add-Content -Path $LogPath -Value $logMessage -ErrorAction SilentlyContinue
}


# ============================================================================
# INITIALIZATION
# ============================================================================
Write-Log "===== Datadog Core Configuration Deployment Started ====="
Write-Log "Computer Name: $env:COMPUTERNAME"
Write-Log "Package Source: $PackageSourcePath"
Write-Log "Datadog Config Path: $DatadogConfPath"
Write-Log "Dry Run Mode: $DryRun"


$deployedRoles = @()
$deploymentErrors = @()


# ============================================================================
# STEP 1: DEPLOY UNIVERSAL CONFIGURATIONS (ALL SERVERS)
# ============================================================================
Write-Log "STEP 1: Deploying Universal Configurations" "INFO"


$universalConfigs = @(
    @{
        Source = "$PackageSourcePath\Universal-Configs\windows_service.yaml"
        Destination = "$DatadogConfPath\windows_service.d\conf.yaml"
        Description = "Windows Core Services (13 services)"
    },
    @{
        Source = "$PackageSourcePath\Universal-Configs\wmi_check.yaml"
        Destination = "$DatadogConfPath\wmi_check.d\conf.yaml"
        Description = "WMI Check (Memory Pages/Sec)"
    }
)


foreach ($config in $universalConfigs) {
    try {
        if (Test-Path $config.Source) {
            $destDir = Split-Path $config.Destination -Parent
            if (-not (Test-Path $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
                Write-Log "Created directory: $destDir" "INFO"
            }


            if (-not $DryRun) {
                Copy-Item -Path $config.Source -Destination $config.Destination -Force
                Write-Log "Deployed: $($config.Description)" "SUCCESS"
            } else {
                Write-Log "[DRY RUN] Would deploy: $($config.Description)" "INFO"
            }
        } else {
            Write-Log "Source file not found: $($config.Source)" "WARNING"
        }
    } catch {
        Write-Log "Failed to deploy $($config.Description): $($_.Exception.Message)" "ERROR"
        $deploymentErrors += "Universal Config: $($config.Description)"
    }
}


# ============================================================================
# STEP 2: DETECT AND DEPLOY ROLE-SPECIFIC INTEGRATIONS
# ============================================================================
Write-Log "STEP 2: Detecting Installed Roles and Deploying Integrations" "INFO"


# ============================================================================
# 2.1 ACTIVE DIRECTORY
# ============================================================================
Write-Log "Checking for Active Directory..." "INFO"
$ntdsService = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
if ($ntdsService) {
    Write-Log "Active Directory detected" "INFO"
    $deployedRoles += "ActiveDirectory"


    try {
        $sourceFile = "$PackageSourcePath\Role-Specific-Configs\active_directory.yaml"
        $destDir = "$DatadogConfPath\active_directory.d"
        $destFile = "$destDir\conf.yaml"


        if (Test-Path $sourceFile) {
            if (-not (Test-Path $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            }


            if (-not $DryRun) {
                Copy-Item -Path $sourceFile -Destination $destFile -Force
                Write-Log "Deployed: Active Directory integration" "SUCCESS"
            } else {
                Write-Log "[DRY RUN] Would deploy: Active Directory" "INFO"
            }
        }
    } catch {
        Write-Log "Failed to deploy Active Directory: $($_.Exception.Message)" "ERROR"
        $deploymentErrors += "Active Directory"
    }
}


# ============================================================================
# 2.2 DNS SERVER
# ============================================================================
Write-Log "Checking for DNS Server..." "INFO"
$dnsService = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
if ($dnsService) {
    Write-Log "DNS Server detected" "INFO"
    $deployedRoles += "DNS"


    try {
        # Enable DNS Audit Logging
        Write-Log "Enabling DNS audit logging..." "INFO"
        try {
            Set-DnsServerDiagnostics -EventLogLevel 7 -ErrorAction SilentlyContinue
            Write-Log "DNS audit logging enabled" "SUCCESS"
        } catch {
            Write-Log "Could not enable DNS audit logging (run manually)" "WARNING"
        }

        $sourceFile = "$PackageSourcePath\Role-Specific-Configs\microsoft_dns.yaml"
        $destDir = "$DatadogConfPath\microsoft_dns.d"
        $destFile = "$destDir\conf.yaml"


        if (Test-Path $sourceFile) {
            if (-not (Test-Path $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            }


            if (-not $DryRun) {
                Copy-Item -Path $sourceFile -Destination $destFile -Force
                Write-Log "Deployed: DNS Server integration" "SUCCESS"
            } else {
                Write-Log "[DRY RUN] Would deploy: DNS Server" "INFO"
            }
        }
    } catch {
        Write-Log "Failed to deploy DNS Server: $($_.Exception.Message)" "ERROR"
        $deploymentErrors += "DNS Server"
    }
}


# ============================================================================
# 2.3 IIS WEB SERVER
# ============================================================================
Write-Log "Checking for IIS Web Server..." "INFO"
$iisService = Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue
if ($iisService) {
    Write-Log "IIS Web Server detected" "INFO"
    $deployedRoles += "IIS"


    try {
        $sourceFile = "$PackageSourcePath\Role-Specific-Configs\iis.yaml"
        $destDir = "$DatadogConfPath\iis.d"
        $destFile = "$destDir\conf.yaml"


        if (Test-Path $sourceFile) {
            if (-not (Test-Path $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            }


            if (-not $DryRun) {
                Copy-Item -Path $sourceFile -Destination $destFile -Force
                Write-Log "Deployed: IIS Web Server integration" "SUCCESS"
            } else {
                Write-Log "[DRY RUN] Would deploy: IIS" "INFO"
            }
        }
    } catch {
        Write-Log "Failed to deploy IIS: $($_.Exception.Message)" "ERROR"
        $deploymentErrors += "IIS Server"
    }
}


# ============================================================================
# 2.4 SQL SERVER
# ============================================================================
Write-Log "Checking for SQL Server..." "INFO"
$sqlServices = Get-Service -Name "MSSQLSERVER","MSSQL$*" -ErrorAction SilentlyContinue
if ($sqlServices) {
    Write-Log "SQL Server detected - $(($sqlServices | Measure-Object).Count) instance(s)" "INFO"
    $deployedRoles += "SQLServer"


    try {
        $sourceFile = "$PackageSourcePath\Role-Specific-Configs\sqlserver.yaml"
        $destDir = "$DatadogConfPath\sqlserver.d"
        $destFile = "$destDir\conf.yaml"


        if (Test-Path $sourceFile) {
            if (-not (Test-Path $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            }


            if (-not $DryRun) {
                Copy-Item -Path $sourceFile -Destination $destFile -Force
                Write-Log "Deployed: SQL Server integration" "SUCCESS"
            } else {
                Write-Log "[DRY RUN] Would deploy: SQL Server" "INFO"
            }
        }
    } catch {
        Write-Log "Failed to deploy SQL Server: $($_.Exception.Message)" "ERROR"
        $deploymentErrors += "SQL Server"
    }
}


# ============================================================================
# 2.5 EXCHANGE SERVER
# ============================================================================
Write-Log "Checking for Exchange Server..." "INFO"
$exchangeService = Get-Service -Name "MSExchangeServiceHost" -ErrorAction SilentlyContinue
if ($exchangeService) {
    Write-Log "Exchange Server detected" "INFO"
    $deployedRoles += "Exchange"


    try {
        $sourceFile = "$PackageSourcePath\Role-Specific-Configs\exchange_server.yaml"
        $destDir = "$DatadogConfPath\exchange_server.d"
        $destFile = "$destDir\conf.yaml"


        if (Test-Path $sourceFile) {
            if (-not (Test-Path $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            }


            if (-not $DryRun) {
                Copy-Item -Path $sourceFile -Destination $destFile -Force
                Write-Log "Deployed: Exchange Server integration" "SUCCESS"
            } else {
                Write-Log "[DRY RUN] Would deploy: Exchange Server" "INFO"
            }
        }
    } catch {
        Write-Log "Failed to deploy Exchange Server: $($_.Exception.Message)" "ERROR"
        $deploymentErrors += "Exchange Server"
    }
}


# ============================================================================
# 2.6 CERTIFICATE AUTHORITY
# ============================================================================
Write-Log "Checking for Certificate Authority..." "INFO"
$caService = Get-Service -Name "CertSvc" -ErrorAction SilentlyContinue
if ($caService) {
    Write-Log "Certificate Authority detected" "INFO"
    $deployedRoles += "CertificateAuthority"


    try {
        $sourceFile = "$PackageSourcePath\Role-Specific-Configs\tls.yaml"
        $destDir = "$DatadogConfPath\tls.d"
        $destFile = "$destDir\conf.yaml"


        if (Test-Path $sourceFile) {
            if (-not (Test-Path $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            }


            if (-not $DryRun) {
                Copy-Item -Path $sourceFile -Destination $destFile -Force
                Write-Log "Deployed: TLS/Certificate integration" "SUCCESS"
            } else {
                Write-Log "[DRY RUN] Would deploy: TLS" "INFO"
            }
        }
    } catch {
        Write-Log "Failed to deploy Certificate Authority: $($_.Exception.Message)" "ERROR"
        $deploymentErrors += "Certificate Authority"
    }
}


# ============================================================================
# STEP 3: RESTART DATADOG AGENT
# ============================================================================
Write-Log "STEP 3: Restarting Datadog Agent" "INFO"


if (-not $DryRun) {
    try {
        $datadogService = Get-Service -Name "datadogagent" -ErrorAction Stop
        if ($datadogService.Status -eq "Running") {
            Write-Log "Stopping Datadog Agent..." "INFO"
            Stop-Service -Name "datadogagent" -Force -ErrorAction Stop
            Start-Sleep -Seconds 5
        }


        Write-Log "Starting Datadog Agent..." "INFO"
        Start-Service -Name "datadogagent" -ErrorAction Stop
        Start-Sleep -Seconds 10


        $datadogService = Get-Service -Name "datadogagent" -ErrorAction Stop
        if ($datadogService.Status -eq "Running") {
            Write-Log "Datadog Agent restarted successfully" "SUCCESS"
        } else {
            Write-Log "Datadog Agent failed to start - Status: $($datadogService.Status)" "ERROR"
            $deploymentErrors += "Agent Restart"
        }
    } catch {
        Write-Log "Failed to restart Datadog Agent: $($_.Exception.Message)" "ERROR"
        $deploymentErrors += "Agent Restart"
    }
} else {
    Write-Log "[DRY RUN] Would restart Datadog Agent" "INFO"
}


# ============================================================================
# STEP 4: DEPLOYMENT SUMMARY
# ============================================================================
Write-Log "===== DEPLOYMENT SUMMARY =====" "INFO"
Write-Log "Computer: $env:COMPUTERNAME" "INFO"
Write-Log "Universal Configs: 2 (Windows Services + WMI Check)" "INFO"
Write-Log "Role-Specific Integrations Detected: $(($deployedRoles | Measure-Object).Count)" "INFO"


if ($deployedRoles.Count -gt 0) {
    Write-Log "Deployed Integrations:" "INFO"
    foreach ($role in $deployedRoles) {
        Write-Log "  - $role" "INFO"
    }
} else {
    Write-Log "No role-specific integrations detected" "INFO"
}


if ($deploymentErrors.Count -gt 0) {
    Write-Log "Errors encountered:" "ERROR"
    foreach ($error in $deploymentErrors) {
        Write-Log "  - $error" "ERROR"
    }
    Write-Log "===== DEPLOYMENT COMPLETED WITH ERRORS =====" "ERROR"
    exit 1
} else {
    Write-Log "===== DEPLOYMENT COMPLETED SUCCESSFULLY =====" "SUCCESS"
    Write-Log "NOTE: Custom scripts (DHCP, ADFS, WSFC) will be deployed separately" "INFO"
    exit 0
}
