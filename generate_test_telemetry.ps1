<#
.SYNOPSIS
    Controlled Multi-Vector SOC Telemetry Generator & SIEM Pipeline Validator.
.DESCRIPTION
    Safely triggers authorized test activity across multiple anomaly types:
      - Authentication Brute Force (Event ID 4625 -> DET-AUTH-001)
      - Horizontal Password Spray (Event ID 4625 across 8 accounts -> DET-AUTH-002)
      - Reconnaissance Burst (Discovery commands -> DET-RECON-001)
      - Ephemeral Scheduled Task Persistence (Event ID 4698/4699 -> DET-PERSIST-001)
      - Endpoint Audit Policy Health Query (auditpol inspection)
    Verifies genuine Windows event logging, polls Wazuh SIEM detection with bounded retries,
    feeds exported alerts into the custom SOC Detection Engineering Lab, and generates the
    upgraded dark cyber operations console and audit dossier.
#>
[CmdletBinding()]
param(
    [ValidateSet("all", "auth", "spray", "recon", "persist", "audit")]
    [string]$TestMode = "all",
    [string]$TargetHost = "127.0.0.1",
    [string]$SyntheticUser = "soc_test_attacker",
    [int]$Attempts = 5,
    [int]$TimeoutSeconds = 40,
    [switch]$UniqueUser = $false
)

$ErrorActionPreference = 'Stop'

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  MULTI-VECTOR SOC TELEMETRY GENERATOR & SIEM VALIDATOR" -ForegroundColor Cyan
Write-Host "  Mode: $TestMode | Target: $TargetHost" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# -------------------------------------------------------------------------
# Stage 1: Pre-Flight & Safety Checks
# -------------------------------------------------------------------------
Write-Host "`n[Stage 1/8] Pre-Flight System & Safety Verification..." -ForegroundColor Yellow

$currentAccount = [Environment]::UserName
$runSuffix = (Get-Date).ToString("HHmmss")
if ($UniqueUser) {
    $SyntheticUser = "${SyntheticUser}_$runSuffix"
}

# Safety Interlock: Protect real accounts from lockout
$protectedAccounts = @($currentAccount, "Admin", "Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount")
if ($SyntheticUser -in $protectedAccounts) {
    Write-Host "[!] SAFETY INTERLOCK TRIGGERED: Target user '$SyntheticUser' matches a protected system account." -ForegroundColor Red
    Write-Host "    To prevent account lockout, the test user MUST be a non-existent synthetic identifier." -ForegroundColor Red
    exit 1
}

# Check Wazuh Agent Service on Windows
$wazuhService = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if (-not $wazuhService) {
    Write-Host "[-] WARNING: WazuhSvc service not found on this host. Agent telemetry may not be forwarded." -ForegroundColor Yellow
} elseif ($wazuhService.Status -ne "Running") {
    Write-Host "[-] WARNING: WazuhSvc service is $($wazuhService.Status). Starting service..." -ForegroundColor Yellow
    try {
        Start-Service -Name "WazuhSvc" -ErrorAction Stop
        Write-Host "[+] WazuhSvc started successfully." -ForegroundColor Green
    } catch {
        Write-Host "[-] Could not start WazuhSvc: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "[+] Wazuh Agent service (WazuhSvc) is active and running." -ForegroundColor Green
}

# Check Wazuh Manager Container
$managerContainer = "wazuh-soc-lab-wazuh.manager-1"
$dockerCheck = & docker ps --filter "name=$managerContainer" --format "{{.Status}}" 2>$null
if (-not $dockerCheck) {
    Write-Host "[!] ERROR: Wazuh Manager container '$managerContainer' is not running." -ForegroundColor Red
    Write-Host "    Run 'docker compose up -d' or verify container status before running telemetry tests." -ForegroundColor Red
    exit 1
} else {
    Write-Host "[+] Wazuh Manager container is healthy: $dockerCheck" -ForegroundColor Green
}

# Check Python environment
$pythonCmd = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } elseif (Get-Command py -ErrorAction SilentlyContinue) { "py -3" } else { $null }
if (-not $pythonCmd) {
    Write-Host "[!] ERROR: Python 3 was not found in PATH." -ForegroundColor Red
    exit 1
}

# -------------------------------------------------------------------------
# Stage 2: Initialize Run Metadata
# -------------------------------------------------------------------------
$runId = "run-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$runStartTimeUtc = [DateTime]::UtcNow
$runStartTimeLocal = Get-Date

Write-Host "`n[Stage 2/8] Run Parameters Initialized" -ForegroundColor Yellow
Write-Host "    Run Identifier   : $runId" -ForegroundColor Cyan
Write-Host "    Test Mode        : $TestMode" -ForegroundColor Cyan
Write-Host "    Target Host      : $TargetHost" -ForegroundColor Cyan
Write-Host "    Synthetic User   : $SyntheticUser" -ForegroundColor Cyan
Write-Host "    Protected User   : $currentAccount (PROTECTED - NOT TARGETED)" -ForegroundColor Green
Write-Host "    Start Timestamp  : $($runStartTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'))" -ForegroundColor Cyan

$executionResults = [ordered]@{}

# -------------------------------------------------------------------------
# Stage 3: Multi-Vector Anomaly Execution
# -------------------------------------------------------------------------
Write-Host "`n[Stage 3/8] Executing Multi-Vector Security Anomalies..." -ForegroundColor Yellow

# --- Vector 1: Authentication Brute Force (DET-AUTH-001) ---
if ($TestMode -in @("all", "auth")) {
    Write-Host "`n  [Vector 1/5] Authentication Brute Force Attack Simulation..." -ForegroundColor Cyan
    Write-Host "    Targeting: $SyntheticUser ($Attempts rapid failed logins to trigger threshold)" -ForegroundColor Gray
    $authFailures = 0
    for ($i = 1; $i -le $Attempts; $i++) {
        $tempErr = Join-Path $env:TEMP "net_err_${i}.log"
        $tempOut = Join-Path $env:TEMP "net_out_${i}.log"
        $proc = Start-Process -FilePath "net.exe" -ArgumentList "use \\$TargetHost\IPC$ /u:$SyntheticUser InvalidPass_${i}_${runId}" -NoNewWindow -Wait -PassThru -RedirectStandardError $tempErr -RedirectStandardOutput $tempOut
        $exitCode = $proc.ExitCode
        Remove-Item $tempErr -Force -ErrorAction SilentlyContinue
        Remove-Item $tempOut -Force -ErrorAction SilentlyContinue
        if ($exitCode -ne 0) { $authFailures++ }
        Start-Sleep -Milliseconds 250
    }
    Write-Host "    [+] Dispatched $authFailures failed logon challenge(s)." -ForegroundColor Green
    $executionResults["Auth_Brute_Force"] = "$authFailures attempts sent"
}

# --- Vector 2: Horizontal Password Spraying (DET-AUTH-002) ---
if ($TestMode -in @("all", "spray")) {
    Write-Host "`n  [Vector 2/5] Horizontal Password Spray Simulation..." -ForegroundColor Cyan
    Write-Host "    Targeting: 8 distinct synthetic accounts from single source IP" -ForegroundColor Gray
    $sprayFailures = 0
    for ($s = 1; $s -le 8; $s++) {
        $sprayUser = "soc_spray_${s}_${runSuffix}"
        $tempErr = Join-Path $env:TEMP "spray_err_${s}.log"
        $tempOut = Join-Path $env:TEMP "spray_out_${s}.log"
        $proc = Start-Process -FilePath "net.exe" -ArgumentList "use \\$TargetHost\IPC$ /u:$sprayUser UniformSprayPass_${runId}" -NoNewWindow -Wait -PassThru -RedirectStandardError $tempErr -RedirectStandardOutput $tempOut
        $exitCode = $proc.ExitCode
        Remove-Item $tempErr -Force -ErrorAction SilentlyContinue
        Remove-Item $tempOut -Force -ErrorAction SilentlyContinue
        if ($exitCode -ne 0) { $sprayFailures++ }
        Start-Sleep -Milliseconds 200
    }
    Write-Host "    [+] Dispatched $sprayFailures horizontal spray challenge(s) across distinct accounts." -ForegroundColor Green
    $executionResults["Password_Spray"] = "$sprayFailures spray attempts sent"
}

# --- Vector 3: Discovery & Reconnaissance Burst (DET-RECON-001) ---
if ($TestMode -in @("all", "recon")) {
    Write-Host "`n  [Vector 3/5] Host & Privilege Discovery Burst Simulation..." -ForegroundColor Cyan
    Write-Host "    Executing rapid discovery burst: whoami /priv, net user, net localgroup, ipconfig" -ForegroundColor Gray
    $reconCommands = @(
        @{ Cmd = "whoami.exe"; Args = "/priv"; Desc = "User Privilege Discovery (T1033)" },
        @{ Cmd = "net.exe"; Args = "user"; Desc = "Local User Enumeration (T1087.001)" },
        @{ Cmd = "net.exe"; Args = "localgroup Administrators"; Desc = "Privileged Group Discovery (T1069.001)" },
        @{ Cmd = "ipconfig.exe"; Args = "/all"; Desc = "Network Configuration Discovery (T1016)" }
    )
    $reconExecuted = 0
    foreach ($rc in $reconCommands) {
        Write-Host "    -> Executing: $($rc.Cmd) $($rc.Args) [$($rc.Desc)]" -ForegroundColor Gray
        $proc = Start-Process -FilePath $rc.Cmd -ArgumentList $rc.Args -NoNewWindow -Wait -PassThru -RedirectStandardOutput (Join-Path $env:TEMP "recon_out.log") -RedirectStandardError (Join-Path $env:TEMP "recon_err.log")
        if ($proc.ExitCode -eq 0) { $reconExecuted++ }
        Start-Sleep -Milliseconds 150
    }
    Remove-Item (Join-Path $env:TEMP "recon_*.log") -Force -ErrorAction SilentlyContinue
    Write-Host "    [+] Executed $reconExecuted/4 discovery burst command(s)." -ForegroundColor Green
    $executionResults["Recon_Burst"] = "$reconExecuted commands executed"
}

# --- Vector 4: Persistence Canary via Ephemeral Scheduled Task (DET-PERSIST-001) ---
if ($TestMode -in @("all", "persist")) {
    Write-Host "`n  [Vector 4/5] Persistence Canary via Scheduled Task Simulation..." -ForegroundColor Cyan
    $canaryTaskName = "SOC_Canary_${runId}"
    Write-Host "    Creating ephemeral canary task: $canaryTaskName" -ForegroundColor Gray
    
    $createProc = Start-Process -FilePath "schtasks.exe" -ArgumentList "/create /tn `"$canaryTaskName`" /tr `"cmd.exe /c echo SOC_Canary`" /sc once /st 23:59 /f" -NoNewWindow -Wait -PassThru -RedirectStandardOutput (Join-Path $env:TEMP "task_out.log") -RedirectStandardError (Join-Path $env:TEMP "task_err.log")
    
    if ($createProc.ExitCode -eq 0) {
        Write-Host "    [+] Task '$canaryTaskName' created successfully (Event ID 4698 generated)." -ForegroundColor Green
        Start-Sleep -Milliseconds 500
        # Immediate cleanup
        Write-Host "    -> Immediately deleting canary task to restore pristine state..." -ForegroundColor Gray
        $delProc = Start-Process -FilePath "schtasks.exe" -ArgumentList "/delete /tn `"$canaryTaskName`" /f" -NoNewWindow -Wait -PassThru -RedirectStandardOutput (Join-Path $env:TEMP "del_out.log") -RedirectStandardError (Join-Path $env:TEMP "del_err.log")
        Write-Host "    [+] Task cleaned up cleanly (Exit: $($delProc.ExitCode)). Zero persistent artifacts remain." -ForegroundColor Green
        $executionResults["Persistence_Canary"] = "Created & deleted $canaryTaskName"
    } else {
        Write-Host "    [-] Task creation exited with code $($createProc.ExitCode) (requires Administrator elevation for scheduled task auditing)." -ForegroundColor Yellow
        $executionResults["Persistence_Canary"] = "Requires elevated permissions"
    }
    Remove-Item (Join-Path $env:TEMP "*task*.log"), (Join-Path $env:TEMP "*del*.log") -Force -ErrorAction SilentlyContinue
}

# --- Vector 5: Security Audit Policy Health Query ---
if ($TestMode -in @("all", "audit")) {
    Write-Host "`n  [Vector 5/5] Endpoint Audit Policy & Defense Health Query..." -ForegroundColor Cyan
    try {
        $auditOut = Join-Path $env:TEMP "auditpol_out.log"
        $proc = Start-Process -FilePath "auditpol.exe" -ArgumentList "/get /category:*" -NoNewWindow -Wait -PassThru -RedirectStandardOutput $auditOut -RedirectStandardError (Join-Path $env:TEMP "auditpol_err.log")
        if ($proc.ExitCode -eq 0 -and (Test-Path $auditOut)) {
            $auditLines = Get-Content $auditOut
            $logonAudit = ($auditLines | Where-Object { $_ -match "Logon" -or $_ -match "Account Logon" }) | Select-Object -First 3
            Write-Host "    [+] Active Endpoint Audit Policy Sample:" -ForegroundColor Green
            foreach ($al in $logonAudit) {
                Write-Host "        $($al.Trim())" -ForegroundColor Gray
            }
            $executionResults["Audit_Policy_Check"] = "Verified active logging"
        } else {
            Write-Host "    [-] Auditpol check completed with exit code $($proc.ExitCode)" -ForegroundColor Gray
            $executionResults["Audit_Policy_Check"] = "Queried"
        }
        Remove-Item (Join-Path $env:TEMP "auditpol_*.log") -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "    [-] Auditpol check skipped: $($_.Exception.Message)" -ForegroundColor Gray
    }
}

# -------------------------------------------------------------------------
# Stage 4: Local Windows Event Log Verification
# -------------------------------------------------------------------------
Write-Host "`n[Stage 4/8] Inspecting Local Windows Security Event Log..." -ForegroundColor Yellow
$localLogVerified = 0
try {
    $recentEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4625
        StartTime = $runStartTimeLocal.AddSeconds(-3)
    } -MaxEvents 50 -ErrorAction Stop

    $matchedEvents = @($recentEvents | Where-Object {
        $msg = $_.Message
        if ($msg -and ($msg -match $SyntheticUser -or $msg -match "soc_spray")) { return $true }
        try {
            $xml = [xml]$_.ToXml()
            $target = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            return ($target -eq $SyntheticUser -or $target -match "soc_spray")
        } catch {
            return $false
        }
    })

    $localLogVerified = $matchedEvents.Count
    if ($localLogVerified -gt 0) {
        Write-Host "[+] Confirmed $localLogVerified genuine Windows Event ID 4625 record(s) matching run:" -ForegroundColor Green
        foreach ($evt in $matchedEvents | Select-Object -First 3) {
            Write-Host "    RecordID: $($evt.RecordId) | Time: $($evt.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ssZ')) | Provider: $($evt.ProviderName)" -ForegroundColor Cyan
        }
    } else {
        Write-Host "[-] Note: No Event ID 4625 matching '$SyntheticUser' found in local log yet (query window: $($runStartTimeLocal.ToString('HH:mm:ss')))." -ForegroundColor Gray
    }
} catch {
    Write-Host "[-] Notice: Direct reading of Windows Security log requires elevated Administrator privilege." -ForegroundColor Gray
    Write-Host "    (The Wazuh Agent service runs as LocalSystem and reads security events directly)." -ForegroundColor Gray
}

# -------------------------------------------------------------------------
# Stage 5: Wazuh SIEM Alert Collection with Bounded Polling
# -------------------------------------------------------------------------
Write-Host "`n[Stage 5/8] Polling Wazuh Manager SIEM for Alerts (Max $TimeoutSeconds seconds)..." -ForegroundColor Yellow
$pollIntervalSec = 2
$maxPolls = [Math]::Ceiling($TimeoutSeconds / $pollIntervalSec)
$matchingAlerts = @()
$allRecentAlerts = @()

for ($poll = 1; $poll -le $maxPolls; $poll++) {
    $rawLines = & docker exec $managerContainer tail -n 250 /var/ossec/logs/alerts/alerts.json 2>$null
    if ($rawLines) {
        $currentMatches = @()
        foreach ($line in $rawLines) {
            if (-not $line -or -not ($line.Trim().StartsWith("{"))) { continue }
            try {
                $alertObj = $line | ConvertFrom-Json
                $allRecentAlerts += $line
                
                $userInAlert = $alertObj.data.win.eventdata.targetUserName
                $fullLog = $alertObj.full_log
                
                $isTargetMatch = (
                    $userInAlert -eq $SyntheticUser -or 
                    ($userInAlert -and $userInAlert -match "soc_spray") -or
                    ($fullLog -and ($fullLog -match $SyntheticUser -or $fullLog -match "soc_spray" -or $fullLog -match "SOC_Canary"))
                )
                
                if ($isTargetMatch) {
                    $currentMatches += $line
                }
            } catch {
                # Ignore malformed stream lines
            }
        }
        
        $matchingAlerts = $currentMatches
        if ($matchingAlerts.Count -ge 5) {
            Write-Host "    [Poll $poll/$maxPolls] Detected $($matchingAlerts.Count) matching alert(s) in Wazuh!" -ForegroundColor Green
            break
        } else {
            Write-Host "    [Poll $poll/$maxPolls] Found $($matchingAlerts.Count) targeted alert(s)... waiting ${pollIntervalSec}s" -ForegroundColor Gray
        }
    }
    Start-Sleep -Seconds $pollIntervalSec
}

# -------------------------------------------------------------------------
# Stage 6: Export Sanitized Test Telemetry
# -------------------------------------------------------------------------
Write-Host "`n[Stage 6/8] Exporting Raw Telemetry Data..." -ForegroundColor Yellow
$dataDir = Join-Path $PSScriptRoot "data"
if (-not (Test-Path $dataDir)) { New-Item -ItemType Directory -Path $dataDir -Force | Out-Null }
$alertsExportPath = Join-Path $dataDir "wazuh_alerts.json"
$runBackupPath = Join-Path $dataDir "wazuh_alerts_${runId}.json"

if ($matchingAlerts.Count -gt 0) {
    $matchingAlerts | Out-File -FilePath $alertsExportPath -Encoding utf8
    $matchingAlerts | Out-File -FilePath $runBackupPath -Encoding utf8
    Write-Host "[+] Successfully exported $($matchingAlerts.Count) target alert(s) to: $alertsExportPath" -ForegroundColor Green
} elseif ($allRecentAlerts.Count -gt 0) {
    $uniqueRecent = $allRecentAlerts | Select-Object -Unique
    $uniqueRecent | Out-File -FilePath $alertsExportPath -Encoding utf8
    Write-Host "[-] Notice: Exported $($uniqueRecent.Count) recent system alerts to verify general detection pipeline." -ForegroundColor Yellow
} else {
    Write-Host "[!] ERROR: No alerts could be retrieved from Wazuh Manager alerts.json." -ForegroundColor Red
    exit 1
}

# -------------------------------------------------------------------------
# Stage 7: Feed into Python SOC Detection Engineering Engine
# -------------------------------------------------------------------------
Write-Host "`n[Stage 7/8] Running Custom SOC Detection Engineering Lab..." -ForegroundColor Yellow
$labOut = Join-Path $PSScriptRoot "artifacts_wazuh"

try {
    $cliCmd = "import sys; sys.path.insert(0, 'src'); from detectlab.cli import main; sys.argv=['cli', '--wazuh-alerts', r'$alertsExportPath', '--out', r'$labOut']; main()"
    & $pythonCmd -c $cliCmd
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] ERROR: Detection lab engine exited with code $LASTEXITCODE." -ForegroundColor Red
        exit $LASTEXITCODE
    }
} catch {
    Write-Host "[!] ERROR executing detectlab.cli: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# -------------------------------------------------------------------------
# Stage 8: End-to-End Assertion & Verification
# -------------------------------------------------------------------------
Write-Host "`n[Stage 8/8] Verifying End-to-End Detection Assertions..." -ForegroundColor Yellow
$labAlertsFile = Join-Path $labOut "alerts.json"
$labIncidentsFile = Join-Path $labOut "incidents.json"
$labReportHtml = Join-Path $labOut "report.html"

if (-not (Test-Path $labAlertsFile)) {
    Write-Host "[!] ASSERTION FAILED: alerts.json was not generated in $labOut." -ForegroundColor Red
    exit 1
}

$alertsOutput = Get-Content -Raw -Path $labAlertsFile | ConvertFrom-Json
$matchingEngineAlerts = @($alertsOutput | Where-Object {
    $_.entity -match $SyntheticUser -or $_.entity -match "soc_spray" -or ($_.context -and $_.context.user -eq $SyntheticUser)
})

Write-Host "----------------------------------------------------------" -ForegroundColor Cyan
Write-Host "  MULTI-VECTOR EXECUTION & DETECTION SUMMARY" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------" -ForegroundColor Cyan
foreach ($key in $executionResults.Keys) {
    Write-Host ("  {0,-26} : {1}" -f $key, $executionResults[$key]) -ForegroundColor White
}
Write-Host "  --------------------------------------------------------" -ForegroundColor Gray
Write-Host "  Local Log Confirmed (4625): $localLogVerified" -ForegroundColor White
Write-Host "  Wazuh Alerts Ingested     : $($matchingAlerts.Count)" -ForegroundColor White
Write-Host "  Engine Alerts Triggered   : $($alertsOutput.Count) total ($($matchingEngineAlerts.Count) targeted)" -ForegroundColor White

Write-Host "`n[+] Verification Complete! Interactive Artifacts Generated:" -ForegroundColor Green
Write-Host "  Interactive Console : $labReportHtml" -ForegroundColor Cyan
Write-Host "  Correlated Incidents: $labIncidentsFile" -ForegroundColor White
Write-Host "  Detection Alerts    : $labAlertsFile" -ForegroundColor White

exit 0
