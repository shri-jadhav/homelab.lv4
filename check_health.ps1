# Health check script for Wazuh Single-Node SIEM Lab
[CmdletBinding()]
param(
    [string]$BindHost = "127.0.0.1"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  WAZUH SINGLE-NODE SIEM LAB - HEALTH CHECK" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$hasFailed = $false

# 1. Determine Docker Execution Engine (Host CLI or Ubuntu WSL2)
$dockerCli = Get-Command docker -ErrorAction SilentlyContinue
function Invoke-LabDocker {
    param([string[]]$DockerArgs)
    if ($dockerCli) {
        & docker @DockerArgs
    } else {
        & wsl.exe -d Ubuntu -u root -- docker @DockerArgs
    }
}

try {
    $dockerVersion = Invoke-LabDocker @("version", "--format", "{{.Server.Version}}") 2>&1
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($dockerVersion)) {
        Write-Host "[!] Docker daemon is not responding via host or WSL2." -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Docker daemon is running (Engine: $dockerVersion)." -ForegroundColor Green
} catch {
    Write-Host "[!] Unable to communicate with Docker: $_" -ForegroundColor Red
    exit 1
}

# 2. Check Container States
Write-Host "`nChecking Wazuh container states..." -ForegroundColor Yellow
$targetServices = @("wazuh.manager", "wazuh.indexer", "wazuh.dashboard")

foreach ($svc in $targetServices) {
    $containerName = "wazuh-soc-lab-$svc-1"
    $status = Invoke-LabDocker @("inspect", "-f", "{{.State.Status}}", $containerName) 2>$null
    if ($status -eq "running") {
        Write-Host "  [+] $svc : RUNNING ($containerName)" -ForegroundColor Green
    } elseif ($status) {
        Write-Host "  [!] $svc : NOT RUNNING ($status)" -ForegroundColor Yellow
        $hasFailed = $true
    } else {
        Write-Host "  [-] $svc : CONTAINER NOT FOUND" -ForegroundColor Red
        $hasFailed = $true
    }
}

# 3. Test Network Endpoints
Write-Host "`nTesting local TLS endpoints and services..." -ForegroundColor Yellow


# Dashboard Web UI (443)
$dashboardUri = "https://$($BindHost):443"
$dashCode = & curl.exe -k -s -o /dev/null -w "%{http_code}" -m 5 $dashboardUri 2>$null
if ($dashCode -eq "200" -or $dashCode -eq "302") {
    Write-Host "  [+] Wazuh Dashboard ($dashboardUri) is responding (HTTP $dashCode)." -ForegroundColor Green
} else {
    Write-Host "  [-] Wazuh Dashboard ($dashboardUri) failed (Status: '$dashCode')." -ForegroundColor Red
    $hasFailed = $true
}

# Wazuh Manager API (55000)
$managerApiUri = "https://$($BindHost):55000"
$mgrCode = & curl.exe -k -s -o /dev/null -w "%{http_code}" -m 5 $managerApiUri 2>$null
if ($mgrCode -eq "200" -or $mgrCode -eq "401") {
    Write-Host "  [+] Wazuh Manager API ($managerApiUri) is responding (HTTP $mgrCode)." -ForegroundColor Green
} else {
    Write-Host "  [-] Wazuh Manager API ($managerApiUri) failed (Status: '$mgrCode')." -ForegroundColor Red
    $hasFailed = $true
}

# Wazuh Agent Ports (1514, 1515)
foreach ($port in @(1514, 1515)) {
    $tcp = Test-NetConnection -ComputerName $BindHost -Port $port -WarningAction SilentlyContinue
    if ($tcp.TcpTestSucceeded) {
        Write-Host "  [+] Wazuh Agent Port $port ($($BindHost):$port) is listening." -ForegroundColor Green
    } else {
        Write-Host "  [-] Wazuh Agent Port $port ($($BindHost):$port) is not listening." -ForegroundColor Red
        $hasFailed = $true
    }
}

# 4. Check Windows Agent Service Status
Write-Host "`nChecking host Windows Wazuh Agent service..." -ForegroundColor Yellow
$agentSvc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
if ($agentSvc -and $agentSvc.Status -eq "Running") {
    Write-Host "  [+] Windows Agent Service ($($agentSvc.Name)) : RUNNING" -ForegroundColor Green
} elseif ($agentSvc) {
    Write-Host "  [!] Windows Agent Service ($($agentSvc.Name)) : $($agentSvc.Status)" -ForegroundColor Yellow
    $hasFailed = $true
} else {
    Write-Host "  [-] Windows Agent Service (WazuhSvc) is not installed." -ForegroundColor Red
    $hasFailed = $true
}

# 5. Check Agent Enrollment State in Manager
$agentList = Invoke-LabDocker @("exec", "wazuh-soc-lab-wazuh.manager-1", "/var/ossec/bin/agent_control", "-l") 2>$null
if ($agentList -match "ID: 001.*Active") {
    Write-Host "  [+] Windows Host Agent (ID 001) : ACTIVE in Wazuh Manager" -ForegroundColor Green
} else {
    Write-Host "  [!] Windows Host Agent (ID 001) : NOT ACTIVE in Manager" -ForegroundColor Yellow
    $hasFailed = $true
}

Write-Host "==========================================================" -ForegroundColor Cyan
if ($hasFailed) {
    Write-Host "[!] Health check completed with errors." -ForegroundColor Red
    exit 1
} else {
    Write-Host "[+] All Wazuh SOC Lab components healthy." -ForegroundColor Green
    exit 0
}
