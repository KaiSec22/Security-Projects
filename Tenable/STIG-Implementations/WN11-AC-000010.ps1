<#
.SYNOPSIS
    This PowerShell script configures the local account lockout threshold to 3 invalid logon attempts and displays the resulting account policy settings for validation.

.NOTES
    Author          : Kai Gallette
    LinkedIn        : linkedin.com/in/kai-gallette/
    GitHub          : github.com/KaiSec22
    Date Created    : 2026-04-16
    Last Modified   : 2026-04-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AC-000010
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AC-000010/

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE

        Example syntax:
        PS C:\> .\WN11-AC-000010.ps1
#>

# Configure account lockout threshold to 3 invalid logon attempts
net accounts /lockoutthreshold:3

# Validate current account policy settings
Write-Host "Current account policy settings:"
net accounts
