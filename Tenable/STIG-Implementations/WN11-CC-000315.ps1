<#
.SYNOPSIS
    This PowerShell script disables the Windows Installer feature "Always install with elevated privileges" and displays the resulting registry value for validation.

.NOTES
    Author          : Kai Gallette
    LinkedIn        : linkedin.com/in/kai-gallette/
    GitHub          : github.com/KaiSec22
    Date Created    : 2026-04-16
    Last Modified   : 2026-04-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000315
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000315/

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Example syntax:
    PS C:\> .\WN11-CC-000315.ps1
#>

# Disable Always Install with Elevated Privileges
$registryPath = "HKLM:\Software\Policies\Microsoft\Windows\Installer"
$valueName = "AlwaysInstallElevated"
$valueData = 0

# Create the registry path if it does not exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Create or update the policy value
New-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -PropertyType DWord -Force | Out-Null

# Validate the current setting
Write-Host "Current AlwaysInstallElevated policy value:"
Get-ItemProperty -Path $registryPath -Name $valueName
