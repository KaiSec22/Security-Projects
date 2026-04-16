<#
.SYNOPSIS
    This PowerShell script configures the default AutoRun behavior to prevent autorun commands and displays the resulting registry value for validation.

.NOTES
    Author          : Kai Gallette
    LinkedIn        : linkedin.com/in/kai-gallette/
    GitHub          : github.com/KaiSec22
    Date Created    : 2026-04-16
    Last Modified   : 2026-04-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000185
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000185/

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Example syntax:
    PS C:\> .\WN11-CC-000185.ps1
#>

# Prevent AutoRun commands from executing
$registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$valueName = "NoAutorun"
$valueData = 1

# Create the registry path if it does not exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Create or update the policy value
New-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -PropertyType DWord -Force | Out-Null

# Validate the current setting
Write-Host "Current AutoRun policy value:"
Get-ItemProperty -Path $registryPath -Name $valueName
