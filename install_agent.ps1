<#
.SYNOPSIS
    Automated installation and registration script for Wazuh Windows Agent v4.14.9.
.DESCRIPTION
    Downloads the official Wazuh Windows Agent MSI, installs it silently,
    registers it with the local Wazuh Manager (127.0.0.1), and verifies service status.
    Designed for SOC lab telemetry collection.
.PARAMETER ManagerAddress
    IP or hostname of the Wazuh Manager (default: 127.0.0.1)
.PARAMETER AgentName
    Friendly identifier for this endpoint (default: Lenovo-LOQ-Host)
.PARAMETER Uninstall
    If specified, silently removes the Wazuh Agent from the host.
#>
[CmdletBinding()]
param(
    [string]$ManagerAddress = "127.0.0.1",
    [string]$AgentName = "Lenovo-LOQ-Host",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$agentVersion = "4.14.9-1"
$msiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$agentVersion.msi"
$agentDir = Join-Path $PSScriptRoot "agent"
$msiPath = Join-Path $agentDir "wazuh-agent-$agentVersion.msi"
$installPath = "C:\Program Files (x86)\ossec-agent"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  WAZUH WINDOWS AGENT DEPLOYMENT" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Handle Uninstallation
if ($Uninstall) {
    Write-Host "[*] Uninstall flag specified. Checking existing installation..." -ForegroundColor Yellow
    if (Test-Path $installPath) {
        Write-Host "[*] Stopping Wazuh service..." -ForegroundColor Yellow
        Stop-Service -Name "wazuh" -ErrorAction SilentlyContinue
        Write-Host "[*] Uninstalling Wazuh Agent..." -ForegroundColor Yellow
        if (Test-Path $msiPath) {
            Start-Process msiexec.exe -ArgumentList "/x `"$msiPath`" /qn /norestart" -Wait
        } else {
            # Find Uninstall string from registry
            $app = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -like "*Wazuh Agent*" }
            if ($app) {
                Start-Process msiexec.exe -ArgumentList "/x $($app.PSChildName) /qn /norestart" -Wait
            }
        }
        Write-Host "[+] Wazuh Agent successfully uninstalled." -ForegroundColor Green
    } else {
        Write-Host "[+] Wazuh Agent is not installed on this system." -ForegroundColor Green
    }
    exit 0
}

# 2. Check Administrator Privilege
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Administrator privileges are required to install Windows Services." -ForegroundColor Red
    Write-Host "    Please run PowerShell as Administrator, or re-run this script with elevated privileges:" -ForegroundColor Yellow
    Write-Host "    powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -ForegroundColor Cyan
    exit 1
}

# 3. Create Agent Staging Directory and Download MSI
if (-not (Test-Path $agentDir)) {
    New-Item -ItemType Directory -Path $agentDir -Force | Out-Null
}

if (-not (Test-Path $msiPath)) {
    Write-Host "[*] Downloading official Wazuh Agent v$agentVersion (~6 MB)..." -ForegroundColor Yellow
    Write-Host "    Source: $msiUrl" -ForegroundColor Gray
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
    Write-Host "[+] Download complete: $msiPath" -ForegroundColor Green
} else {
    Write-Host "[+] Cached MSI installer found: $msiPath" -ForegroundColor Green
}

# 4. Check if already installed
$existingService = Get-Service -Name "wazuh" -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "[*] Existing Wazuh service found (Status: $($existingService.Status))." -ForegroundColor Yellow
} else {
    Write-Host "[*] Installing Wazuh Agent silently (Manager: $ManagerAddress, Agent: $AgentName)..." -ForegroundColor Yellow
    $msiArgs = "/i `"$msiPath`" /q WAZUH_MANAGER=`"$ManagerAddress`" WAZUH_REGISTRATION_SERVER=`"$ManagerAddress`" WAZUH_AGENT_NAME=`"$AgentName`""
    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Write-Host "[!] MSI installation failed with exit code $($proc.ExitCode)." -ForegroundColor Red
        exit $proc.ExitCode
    }
    Write-Host "[+] Wazuh Agent installation succeeded." -ForegroundColor Green
}

# 5. Start / Restart Agent Service
Write-Host "[*] Starting Wazuh Agent service..." -ForegroundColor Yellow
try {
    Start-Service -Name "wazuh"
    Write-Host "[+] Wazuh Agent service is RUNNING." -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to start Wazuh service: $_" -ForegroundColor Red
}

# 6. Verify Agent Configuration & Connectivity
$ossecConf = Join-Path $installPath "ossec.conf"
if (Test-Path $ossecConf) {
    Write-Host "[+] Agent configuration verified: $ossecConf" -ForegroundColor Green
}

$ossecLog = Join-Path $installPath "ossec.log"
if (Test-Path $ossecLog) {
    Write-Host "`nRecent Agent log entries ($ossecLog):" -ForegroundColor Cyan
    Get-Content $ossecLog -Tail 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
}

Write-Host "`n[+] Agent setup complete! Run .\check_health.ps1 to verify manager and agent status." -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
