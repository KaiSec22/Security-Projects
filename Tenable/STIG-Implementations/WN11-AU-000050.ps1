<#
.SYNOPSIS
    This PowerShell script enables Success auditing for the "Process Creation" audit subcategory and displays the resulting audit policy settings for validation.

.NOTES
    Author          : Kai Gallette
    LinkedIn        : linkedin.com/in/kai-gallette/
    GitHub          : github.com/KaiSec22
    Date Created    : 2026-04-16
    Last Modified   : 2026-04-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000050
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AU-000050/

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
      Example syntax:
      PS C:\> .\WN11-AU-000050.ps1
#>

# Enable Success auditing for Process Creation
auditpol /set /subcategory:"Process Creation" /success:enable

# Validate the current audit policy setting
Write-Host "Current audit policy settings for Process Creation:"
auditpol /get /subcategory:"Process Creation"
