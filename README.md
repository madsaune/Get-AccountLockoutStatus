PSAccountLockoutStatus
-----------------------------

A powershell script for querying domain controllers about a users account lockout status

# Examples

    C:\PS> .\Get-AccountLockoutStatus.ps1 <samaccountname> | ogv

    C:\PS> .\Get-AccountLockoutStatus.ps1 <samaccountname> | ft -autosize

    C:\PS> .\Get-AccountLockoutStatus.ps1 -Identity <samaccountname>