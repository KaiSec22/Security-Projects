<#
.SYNOPSIS
    This PowerShell script configures the local account lockout duration to 15 minutes and displays the resulting account policy settings for validation.

.NOTES
    Author          : Kai Gallette
    LinkedIn        : linkedin.com/in/kai-gallette/
    GitHub          : github.com/KaiSec22
    Date Created    : 2026-04-16
    Last Modified   : 2026-04-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AC-000005
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AC-000005/

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Example syntax:
    PS C:\> .\WN11-AC-000005.ps1
#>

# Configure account lockout duration to 15 minutes
net accounts /lockoutduration:15

# Validate current account policy settings
Write-Host "Current account policy settings:"
net accounts
