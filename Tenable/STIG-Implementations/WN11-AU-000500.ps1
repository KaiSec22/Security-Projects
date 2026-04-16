<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Kai Gallette
    LinkedIn        : linkedin.com/in/kai-gallette/
    GitHub          : github.com/KaiSec22
    Date Created    : 2026-04-16
    Last Modified   : 2026-04-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AU-000500/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE

> Run the following command

    Example syntax:
    PS C:\> .\WN11-AU-000500.ps1 
#>

# Ensures the Application event log maximum size is set to 32768 KB
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$valueName = "MaxSize"
$valueData = 32768

# Create the registry path if it does not exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Create or update the MaxSize value
New-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -PropertyType DWord -Force | Out-Null

Write-Host "STIG remediation applied: $registryPath\$valueName set to $valueData"