# Safe Teardown Script for Wazuh Single-Node SIEM Lab
# Stops containers without deleting persistent volumes or index data.
[CmdletBinding()]
param(
    [switch]$RemoveVolumes = $false
)

Write-Host "Stopping Wazuh containers..." -ForegroundColor Yellow
if ($RemoveVolumes) {
    Write-Warning "CAUTION: -RemoveVolumes requested. This will delete all Wazuh index data and configurations."
    $confirm = Read-Host "Are you sure you want to delete all volumes? (y/N)"
    if ($confirm -eq 'y' -or $confirm -eq 'Y') {
        docker compose down -v
        Write-Host "Containers and volumes removed." -ForegroundColor Green
    } else {
        Write-Host "Teardown aborted." -ForegroundColor Gray
    }
} else {
    docker compose down
    Write-Host "Containers stopped safely. Persistent volumes are preserved." -ForegroundColor Green
}
