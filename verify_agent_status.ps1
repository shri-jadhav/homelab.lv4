<#
.SYNOPSIS
    Verification script for Wazuh Windows Agent connectivity and manager enrollment.
.DESCRIPTION
    Validates Windows Service state, client keys, connection logs,
    manager registration, and connection persistence across service restart.
#>
[CmdletBinding()]
param(
    [string]$AgentServiceName = "wazuh",
    [string]$ContainerName = "wazuh-soc-lab-wazuh.manager-1"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  WAZUH WINDOWS AGENT STATUS & ENROLLMENT VERIFICATION" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check Windows Service Status
$svc = Get-Service -Name $AgentServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host "[-] Service '$AgentServiceName' is NOT installed on this host." -ForegroundColor Red
    Write-Host "    Run install_agent.ps1 in an Administrator PowerShell window first." -ForegroundColor Yellow
    exit 1
}

Write-Host "[+] Windows Service Status:" -ForegroundColor Green
Write-Host "    Name         : $($svc.Name)" -ForegroundColor Cyan
Write-Host "    Display Name : $($svc.DisplayName)" -ForegroundColor Cyan
$statusColor = if ($svc.Status -eq "Running") { "Green" } else { "Yellow" }
Write-Host "    Status       : $($svc.Status)" -ForegroundColor $statusColor

# 2. Check Installed Binary & Version
$agentExe = "C:\Program Files (x86)\ossec-agent\wazuh-agent.exe"
if (-not (Test-Path $agentExe)) {
    $agentExe = "C:\Program Files (x86)\ossec-agent\ossec-agent.exe"
}
if (Test-Path $agentExe) {
    $verInfo = (Get-Item $agentExe).VersionInfo
    Write-Host "[+] Agent Binary Verified:" -ForegroundColor Green
    Write-Host "    Path         : $agentExe" -ForegroundColor Cyan
    Write-Host "    FileVersion  : $($verInfo.FileVersion)" -ForegroundColor Cyan
    Write-Host "    ProductVer   : $($verInfo.ProductVersion)" -ForegroundColor Cyan
}

# 3. Check Agent Configuration & Manager Binding
$ossecConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
if (Test-Path $ossecConf) {
    [xml]$xml = Get-Content $ossecConf
    $mgrServer = $xml.ossec_config.client.server.address
    Write-Host "[+] Configured Manager Address: $mgrServer" -ForegroundColor Green
}

# 4. Check Client Keys (Enrollment)
$clientKeys = "C:\Program Files (x86)\ossec-agent\client.keys"
if (Test-Path $clientKeys) {
    $keyData = Get-Content $clientKeys | Where-Object { $_ -and -not $_.StartsWith("#") }
    if ($keyData) {
        $parts = $keyData -split "\s+"
        Write-Host "[+] Agent Enrollment Key Detected:" -ForegroundColor Green
        Write-Host "    Agent ID     : $($parts[0])" -ForegroundColor Cyan
        Write-Host "    Agent Name   : $($parts[1])" -ForegroundColor Cyan
        Write-Host "    IP Binding   : $($parts[2])" -ForegroundColor Cyan
    } else {
        Write-Host "[!] client.keys file is empty. Agent may still be negotiating registration." -ForegroundColor Yellow
    }
}

# 5. Query Wazuh Manager for Active Agents
Write-Host "`n[*] Querying Wazuh Manager for enrolled agents..." -ForegroundColor Yellow
$mgrOutput = docker exec $ContainerName /var/ossec/bin/agent_control -l 2>$null
if ($mgrOutput) {
    $mgrOutput | ForEach-Object { Write-Host "    $_" -ForegroundColor Cyan }
} else {
    Write-Host "[-] Could not retrieve agent status from manager container." -ForegroundColor Yellow
}

# 6. Check Service Restart Persistence
Write-Host "`n[*] Testing connection persistence across service restart..." -ForegroundColor Yellow
try {
    Restart-Service -Name $AgentServiceName -Force -ErrorAction Stop
    Start-Sleep -Seconds 5
    $restartedSvc = Get-Service -Name $AgentServiceName
    Write-Host "[+] Service restarted successfully. Current status: $($restartedSvc.Status)" -ForegroundColor Green

    # Wait for re-connection
    Start-Sleep -Seconds 5
    $reconnectedOutput = docker exec $ContainerName /var/ossec/bin/agent_control -l 2>$null
    Write-Host "[+] Post-restart Manager Status:" -ForegroundColor Green
    $reconnectedOutput | ForEach-Object { Write-Host "    $_" -ForegroundColor Cyan }
} catch {
    Write-Host "[!] Service restart requires Administrator privileges: $_" -ForegroundColor Gray
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
