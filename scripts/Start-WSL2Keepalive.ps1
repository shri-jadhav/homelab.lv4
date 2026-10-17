<#
.SYNOPSIS
    Keeps the Ubuntu WSL2 distribution alive by running a persistent background process.

.DESCRIPTION
    WSL2 shuts down its Linux kernel when all active sessions exit — even with vmIdleTimeout=-1
    configured — because the timer only covers idle periods between *sessions*, not session
    termination itself.  This script launches a persistent `sleep infinity` process inside
    the Ubuntu distribution, preventing the kernel from shutting down and stopping the
    Wazuh Docker containers that depend on it.

    Designed to be registered as a Windows Task Scheduler task that fires at user logon
    (see Register-WSL2KeepaliveTask.ps1).

.NOTES
    - The process is non-interactive and runs hidden.
    - It is safe to run this script multiple times; duplicate sessions do not harm WSL2.
    - After a Windows reboot, the Task Scheduler will re-launch this automatically.
    - To verify: run `wsl.exe -d Ubuntu -u root -- pgrep sleep` in PowerShell.
#>

param()

$distro = "Ubuntu"
$logDir = "$env:LOCALAPPDATA\Wazuh-WSL2"

if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

$logFile = "$logDir\keepalive-$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$Message)
    $ts = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    "$ts  $Message" | Tee-Object -FilePath $logFile -Append | Write-Verbose
}

Write-Log "=== Wazuh WSL2 Keepalive starting ==="

# Check WSL2 availability
$wslExe = Get-Command wsl.exe -ErrorAction SilentlyContinue
if (-not $wslExe) {
    Write-Log "ERROR: wsl.exe not found. Exiting."
    exit 1
}

# Verify the distro exists
$distros = wsl.exe --list --quiet 2>&1
if ($LASTEXITCODE -ne 0 -or ($distros -notmatch $distro)) {
    Write-Log "ERROR: WSL2 distribution '$distro' not found. Exiting."
    exit 1
}

Write-Log "Launching persistent 'sleep infinity' in $distro (as root)..."

# Start hidden PowerShell job that runs sleep infinity in WSL2
$proc = Start-Process -FilePath "wsl.exe" `
    -ArgumentList "-d", $distro, "-u", "root", "--", "sleep", "infinity" `
    -WindowStyle Hidden `
    -PassThru `
    -ErrorAction Stop

Write-Log "Keepalive process started. PID: $($proc.Id)"
Write-Log "WSL2 distribution '$distro' will remain active."
Write-Log "To stop: kill PID $($proc.Id) or run 'wsl --shutdown'."
