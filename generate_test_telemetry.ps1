<#
.SYNOPSIS
    Controlled Security Telemetry Generator and Wazuh Integration Validator.
.DESCRIPTION
    Safely triggers authorized test activity (failed authentication - Windows Event ID 4625),
    verifies genuine Windows event logging, checks Wazuh SIEM detection,
    and feeds exported alerts into the custom SOC Detection Engineering Lab.
#>
[CmdletBinding()]
param(
    [string]$TargetHost = "127.0.0.1",
    [string]$SyntheticUser = "soc_test_attacker",
    [int]$Attempts = 5
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  CONTROLLED SOC TELEMETRY GENERATOR & SIEM VALIDATOR" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Safety Verification: Ensure test user is synthetic and never the active account
$currentAccount = [Environment]::UserName
if ($SyntheticUser -eq $currentAccount -or $SyntheticUser -in @("Admin", "Administrator")) {
    Write-Host "[!] SAFETY INTERLOCK TRIGGERED: Target user '$SyntheticUser' matches a real/administrative account." -ForegroundColor Red
    Write-Host "    To prevent account lockout, the test user MUST be a non-existent synthetic identifier." -ForegroundColor Red
    exit 1
}

# 1. Generate Controlled Authentication Failures
Write-Host "[*] Triggering $Attempts safe, controlled authentication failures (Event ID 4625)..." -ForegroundColor Yellow
Write-Host "    Target User : $SyntheticUser (Synthetic, Non-Existent)" -ForegroundColor Cyan
Write-Host "    Target Host : $TargetHost" -ForegroundColor Cyan
Write-Host "    Active Host User : $currentAccount (PROTECTED - NOT TARGETED)" -ForegroundColor Green

for ($i = 1; $i -le $Attempts; $i++) {
    Write-Host "  -> Attempt $i/$Attempts : Sending invalid credential challenge..." -NoNewline
    # Use net use to trigger standard Windows NTLM authentication failure without lockout of valid accounts
    $null = & net.exe use "\\$TargetHost\IPC$" /u:"$SyntheticUser" "InvalidP@ssw0rd!$i" 2>&1
    Write-Host " [Logged]" -ForegroundColor Green
    Start-Sleep -Milliseconds 400
}

# 2. Inspect Windows Event Log (if permissions allow)
Write-Host "`n[*] Inspecting local Windows Security Event Log..." -ForegroundColor Yellow
try {
    $winEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents $Attempts -ErrorAction Stop
    Write-Host "[+] Confirmed $($winEvents.Count) genuine Windows Event ID 4625 record(s):" -ForegroundColor Green
    foreach ($evt in $winEvents) {
        Write-Host "    Timestamp: $($evt.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ssZ')) | Provider: $($evt.ProviderName) | Machine: $($evt.MachineName)" -ForegroundColor Cyan
    }
} catch {
    Write-Host "    Note: Reading Windows Security Log requires Administrator privilege." -ForegroundColor Gray
    Write-Host "    (The Wazuh Agent runs as LocalSystem and collects these records directly)." -ForegroundColor Gray
}

# 3. Query Wazuh Manager Container for Alerts
Write-Host "`n[*] Waiting for Wazuh Manager to analyze agent telemetry (~10 seconds)..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

$containerName = "wazuh-soc-lab-wazuh.manager-1"
$alertsJson = if (Get-Command docker -ErrorAction SilentlyContinue) {
    docker exec $containerName tail -n 50 /var/ossec/logs/alerts/alerts.json 2>$null
} else {
    wsl.exe -d Ubuntu -u root -- docker exec $containerName tail -n 50 /var/ossec/logs/alerts/alerts.json 2>$null
}

$outDir = Join-Path $PSScriptRoot "data"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$alertsExportPath = Join-Path $outDir "wazuh_alerts.json"

if ($alertsJson) {
    $alertsJson | Out-File -FilePath $alertsExportPath -Encoding utf8
    $alertCount = ($alertsJson | Measure-Object).Count
    Write-Host "[+] Exported $alertCount raw Wazuh alert record(s) to: $alertsExportPath" -ForegroundColor Green
} else {
    Write-Host "[!] No recent alerts returned by Wazuh manager yet. Check agent connection status." -ForegroundColor Yellow
}

# 4. Feed into Custom Detection Engineering Lab
$detectLabDir = $PSScriptRoot
$detectCli = Join-Path $detectLabDir "src\detectlab\cli.py"

if ((Test-Path $alertsExportPath) -and (Test-Path $detectCli)) {
    Write-Host "`n[*] Feeding genuine Wazuh SIEM alerts into SOC Detection Engineering Lab..." -ForegroundColor Yellow
    $labOut = Join-Path $PSScriptRoot "artifacts_wazuh"
    
    Push-Location $detectLabDir
    try {
        $env:PYTHONPATH = "src"
        python -m detectlab.cli --wazuh-alerts "$alertsExportPath" --out "$labOut"
        Write-Host "`n[+] Detection Engineering Lab correlated genuine Wazuh SIEM telemetry successfully!" -ForegroundColor Green
        Write-Host "    HTML Dashboard: $(Join-Path $labOut 'report.html')" -ForegroundColor Cyan
        Write-Host "    Incidents JSON: $(Join-Path $labOut 'incidents.json')" -ForegroundColor Cyan
    } finally {
        Pop-Location
    }
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
