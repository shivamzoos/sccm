# ============================================================================
# Datadog Configuration Deployment Script for EXL Infrastructure
# ============================================================================
# Description: Automatically deploys Datadog YAML configs based on detected
#              Windows roles and services across 3000+ servers via SCCM
# Version: 1.0
# ============================================================================

[CmdletBinding()]
param(
    [string]$DatadogConfPath = "C:\ProgramData\Datadog\conf.d",
    [string]$DatadogChecksPath = "C:\ProgramData\Datadog\checks.d",
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
Write-Log "===== Datadog Configuration Deployment Started ====="
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
        Description = "Windows Core Services Monitoring (13 services)"
    },
    @{
        Source = "$PackageSourcePath\Universal-Configs\wmi_check.yaml"
        Destination = "$DatadogConfPath\wmi_check.d\conf.yaml"
        Description = "WMI Performance Counters (Paging Memory)"
    },
    @{
        Source = "$PackageSourcePath\Universal-Configs\http_check.yaml"
        Destination = "$DatadogConfPath\http_check.d\conf.yaml"
        Description = "HTTP Web Application Availability"
    },
    @{
        Source = "$PackageSourcePath\Universal-Configs\tcp_check.yaml"
        Destination = "$DatadogConfPath\tcp_check.d\conf.yaml"
        Description = "TCP Port and Client Device Monitoring"
    },
    @{
        Source = "$PackageSourcePath\Universal-Configs\win32_event_log.yaml"
        Destination = "$DatadogConfPath\win32_event_log.d\conf.yaml"
        Description = "Windows Event Log (Service Account Lockouts)"
    },
    @{
        Source = "$PackageSourcePath\Universal-Configs\logs_config.yaml"
        Destination = "$DatadogConfPath\conf.yaml"
        Description = "Custom Log File Monitoring"
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
# STEP 2: DETECT INSTALLED ROLES AND SERVICES
# ============================================================================
Write-Log "STEP 2: Detecting Installed Roles and Services" "INFO"

# ============================================================================
# 2.1 ACTIVE DIRECTORY SERVER
# ============================================================================
Write-Log "Checking for Active Directory Domain Services..." "INFO"
$ntdsService = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
if ($ntdsService) {
    Write-Log "Active Directory detected - NTDS service found" "INFO"
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
                Write-Log "[DRY RUN] Would deploy: Active Directory integration" "INFO"
            }
        }
    } catch {
        Write-Log "Failed to deploy Active Directory config: $($_.Exception.Message)" "ERROR"
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
        $sourceFile = "$PackageSourcePath\Role-Specific-Configs\microsoft_dns.yaml"
        $destDir = "$DatadogConfPath\microsoft_dns.d"
        $destFile = "$destDir\conf.yaml"

        if (Test-Path $sourceFile) {
            if (-not (Test-Path $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            }

            if (-not $DryRun) {
                Copy-Item -Path $sourceFile -Destination $destFile -Force
                Write-Log "Deployed: DNS Server integration (microsoft-dns)" "SUCCESS"
            } else {
                Write-Log "[DRY RUN] Would deploy: DNS Server integration" "INFO"
            }
        }
    } catch {
        Write-Log "Failed to deploy DNS config: $($_.Exception.Message)" "ERROR"
        $deploymentErrors += "DNS Server"
    }
}

# ============================================================================
# 2.3 IIS WEB SERVER
# ============================================================================
Write-Log "Checking for IIS Web Server..." "INFO"
$iisService = Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue
if ($iisService) {
    Write-Log "IIS Web Server detected - W3SVC service found" "INFO"
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
                Write-Log "[DRY RUN] Would deploy: IIS integration" "INFO"
            }
        }
    } catch {
        Write-Log "Failed to deploy IIS config: $($_.Exception.Message)" "ERROR"
        $deploymentErrors += "IIS Server"
    }
}

# ============================================================================
# 2.4 SQL SERVER
# ============================================================================
Write-Log "Checking for SQL Server..." "INFO"
$sqlServices = Get-Service -Name "MSSQLSERVER","MSSQL$*" -ErrorAction SilentlyContinue
if ($sqlServices) {
    Write-Log "SQL Server detected - $(($sqlServices | Measure-Object).Count) instance(s) found" "INFO"
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
                Write-Log "Deployed: SQL Server integration (with AlwaysOn support)" "SUCCESS"
            } else {
                Write-Log "[DRY RUN] Would deploy: SQL Server integration" "INFO"
            }
        }
    } catch {
        Write-Log "Failed to deploy SQL Server config: $($_.Exception.Message)" "ERROR"
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
                Write-Log "[DRY RUN] Would deploy: Exchange Server integration" "INFO"
            }
        }
    } catch {
        Write-Log "Failed to deploy Exchange config: $($_.Exception.Message)" "ERROR"
        $deploymentErrors += "Exchange Server"
    }
}

# ============================================================================
# 2.6 CERTIFICATE AUTHORITY (CA)
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
                Write-Log "Deployed: TLS/Certificate monitoring integration" "SUCCESS"
            } else {
                Write-Log "[DRY RUN] Would deploy: TLS integration" "INFO"
            }
        }
    } catch {
        Write-Log "Failed to deploy CA/TLS config: $($_.Exception.Message)" "ERROR"
        $deploymentErrors += "Certificate Authority"
    }
}

# ============================================================================
# STEP 3: DEPLOY CUSTOM MONITORING SCRIPTS
# ============================================================================
Write-Log "STEP 3: Deploying Custom Monitoring Scripts" "INFO"

# ============================================================================
# 3.1 DHCP SERVER MONITORING
# ============================================================================
Write-Log "Checking for DHCP Server..." "INFO"
$dhcpService = Get-Service -Name "DHCPServer" -ErrorAction SilentlyContinue
if ($dhcpService) {
    Write-Log "DHCP Server detected - deploying custom monitoring script" "INFO"
    $deployedRoles += "DHCP"

    try {
        $sourceScript = "$PackageSourcePath\Custom-Scripts\dhcp_monitoring.ps1"
        $destScript = "$DatadogChecksPath\dhcp_monitoring.ps1"
        $yamlSource = "$PackageSourcePath\Custom-Scripts\dhcp_check.yaml"
        $yamlDest = "$DatadogConfPath\dhcp_check.d\conf.yaml"

        if (Test-Path $sourceScript) {
            if (-not (Test-Path $DatadogChecksPath)) {
                New-Item -Path $DatadogChecksPath -ItemType Directory -Force | Out-Null
            }

            if (-not $DryRun) {
                Copy-Item -Path $sourceScript -Destination $destScript -Force
                Write-Log "Deployed: DHCP custom monitoring script" "SUCCESS"

                # Deploy YAML config for custom check
                if (Test-Path $yamlSource) {
                    $yamlDestDir = Split-Path $yamlDest -Parent
                    if (-not (Test-Path $yamlDestDir)) {
                        New-Item -Path $yamlDestDir -ItemType Directory -Force | Out-Null
                    }
                    Copy-Item -Path $yamlSource -Destination $yamlDest -Force
                    Write-Log "Deployed: DHCP check YAML configuration" "SUCCESS"
                }
            } else {
                Write-Log "[DRY RUN] Would deploy: DHCP monitoring script" "INFO"
            }
        }
    } catch {
        Write-Log "Failed to deploy DHCP script: $($_.Exception.Message)" "ERROR"
        $deploymentErrors += "DHCP Monitoring"
    }
}

# ============================================================================
# 3.2 AD FS MONITORING
# ============================================================================
Write-Log "Checking for AD FS Server..." "INFO"
$adfsService = Get-Service -Name "adfssrv" -ErrorAction SilentlyContinue
if ($adfsService) {
    Write-Log "AD FS Server detected - deploying custom event log monitoring" "INFO"
    $deployedRoles += "ADFS"

    try {
        $sourceScript = "$PackageSourcePath\Custom-Scripts\adfs_monitoring.ps1"
        $destScript = "$DatadogChecksPath\adfs_monitoring.ps1"
        $yamlSource = "$PackageSourcePath\Custom-Scripts\adfs_eventlog.yaml"
        $yamlDest = "$DatadogConfPath\win32_event_log.d\adfs.yaml"

        if (Test-Path $sourceScript) {
            if (-not $DryRun) {
                Copy-Item -Path $sourceScript -Destination $destScript -Force
                Write-Log "Deployed: AD FS custom monitoring script" "SUCCESS"

                # Deploy event log config
                if (Test-Path $yamlSource) {
                    Copy-Item -Path $yamlSource -Destination $yamlDest -Force
                    Write-Log "Deployed: AD FS event log configuration" "SUCCESS"
                }
            } else {
                Write-Log "[DRY RUN] Would deploy: AD FS monitoring script" "INFO"
            }
        }
    } catch {
        Write-Log "Failed to deploy AD FS script: $($_.Exception.Message)" "ERROR"
        $deploymentErrors += "AD FS Monitoring"
    }
}

# ============================================================================
# 3.3 WINDOWS FAILOVER CLUSTER MONITORING
# ============================================================================
Write-Log "Checking for Windows Failover Cluster..." "INFO"
try {
    $clusterService = Get-Service -Name "ClusSvc" -ErrorAction SilentlyContinue
    if ($clusterService) {
        Write-Log "Windows Failover Cluster detected - deploying WSFC monitoring script" "INFO"
        $deployedRoles += "FailoverCluster"

        $sourceScript = "$PackageSourcePath\Custom-Scripts\wsfc_monitoring.ps1"
        $destScript = "$DatadogChecksPath\wsfc_monitoring.ps1"
        $yamlSource = "$PackageSourcePath\Custom-Scripts\wsfc_check.yaml"
        $yamlDest = "$DatadogConfPath\wsfc_check.d\conf.yaml"

        if (Test-Path $sourceScript) {
            if (-not $DryRun) {
                Copy-Item -Path $sourceScript -Destination $destScript -Force
                Write-Log "Deployed: WSFC custom monitoring script" "SUCCESS"

                # Deploy YAML config
                if (Test-Path $yamlSource) {
                    $yamlDestDir = Split-Path $yamlDest -Parent
                    if (-not (Test-Path $yamlDestDir)) {
                        New-Item -Path $yamlDestDir -ItemType Directory -Force | Out-Null
                    }
                    Copy-Item -Path $yamlSource -Destination $yamlDest -Force
                    Write-Log "Deployed: WSFC check YAML configuration" "SUCCESS"
                }
            } else {
                Write-Log "[DRY RUN] Would deploy: WSFC monitoring script" "INFO"
            }
        }
    }
} catch {
    Write-Log "Failed to check/deploy WSFC monitoring: $($_.Exception.Message)" "ERROR"
}

# ============================================================================
# STEP 4: RESTART DATADOG AGENT
# ============================================================================
Write-Log "STEP 4: Restarting Datadog Agent" "INFO"

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
# STEP 5: DEPLOYMENT SUMMARY
# ============================================================================
Write-Log "===== DEPLOYMENT SUMMARY =====" "INFO"
Write-Log "Computer: $env:COMPUTERNAME" "INFO"
Write-Log "Total Roles Detected: $(($deployedRoles | Measure-Object).Count)" "INFO"

if ($deployedRoles.Count -gt 0) {
    Write-Log "Deployed Configurations for Roles:" "INFO"
    foreach ($role in $deployedRoles) {
        Write-Log "  - $role" "INFO"
    }
} else {
    Write-Log "No additional roles detected - Universal configs only" "INFO"
}

if ($deploymentErrors.Count -gt 0) {
    Write-Log "Errors encountered during deployment:" "ERROR"
    foreach ($error in $deploymentErrors) {
        Write-Log "  - $error" "ERROR"
    }
    Write-Log "===== DEPLOYMENT COMPLETED WITH ERRORS =====" "ERROR"
    exit 1
} else {
    Write-Log "===== DEPLOYMENT COMPLETED SUCCESSFULLY =====" "SUCCESS"
    exit 0
}
