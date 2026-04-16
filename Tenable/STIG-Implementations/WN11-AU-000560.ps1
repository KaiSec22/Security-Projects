<#
.SYNOPSIS
    This PowerShell script enables Success auditing for the "Other Logon/Logoff Events" audit subcategory and displays the resulting audit policy settings for validation.

.NOTES
    Author          : Kai Gallette
    LinkedIn        : linkedin.com/in/kai-gallette/
    GitHub          : github.com/KaiSec22
    Date Created    : 2026-04-16
    Last Modified   : 2026-04-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000560
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AU-000560/

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
  Example syntax:
  PS C:\> .\WN11-AU-000560.ps1
#>

# Enable Success auditing for Other Logon/Logoff Events
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable

# Validate the current audit policy setting
Write-Host "Current audit policy settings for Other Logon/Logoff Events:"
auditpol /get /subcategory:"Other Logon/Logoff Events"
