<#
.SYNOPSIS
    Registers a Windows Task Scheduler task or Startup link to keep WSL2 alive at user logon.

.DESCRIPTION
    Creates (or updates) a scheduled task named "WazuhWSL2Keepalive" that runs
    Start-WSL2Keepalive.ps1 at logon. Also places a resilient fallback shortcut in the user's
    Windows Startup folder so it works with or without elevated privileges.
#>

$taskName    = "WazuhWSL2Keepalive"
$scriptPath  = Join-Path $PSScriptRoot "Start-WSL2Keepalive.ps1"
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

if (-not (Test-Path $scriptPath)) {
    Write-Error "Start-WSL2Keepalive.ps1 not found at: $scriptPath"
    exit 1
}

Write-Host "Registering WSL2 Keepalive for $currentUser..." -ForegroundColor Cyan

# 1. Attempt Task Scheduler Registration
try {
    $action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 0) -MultipleInstances IgnoreNew -StartWhenAvailable

    # Idempotent remove if present
    $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }

    $task = Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description "Keeps Ubuntu WSL2 kernel alive for Wazuh containers." -Force -ErrorAction Stop
    Write-Host "[+] Task Scheduler: '$taskName' registered successfully." -ForegroundColor Green
} catch {
    Write-Warning "Task Scheduler registration failed or requires elevation: $_"
}

# 2. Add Windows Startup Folder VBS/Shortcut (Always works for current user without admin)
$startupFolder = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Startup)
$vbsWrapper = Join-Path $startupFolder "WazuhWSL2Keepalive.vbs"

$vbsContent = @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & "$scriptPath" & """", 0, False
"@

try {
    [System.IO.File]::WriteAllText($vbsWrapper, $vbsContent)
    Write-Host "[+] Windows Startup: Created silent launcher at $vbsWrapper" -ForegroundColor Green
} catch {
    Write-Warning "Failed to write to Startup folder: $_"
}

Write-Host "`n[+] WSL2 Keepalive persistence configured successfully!" -ForegroundColor Green
