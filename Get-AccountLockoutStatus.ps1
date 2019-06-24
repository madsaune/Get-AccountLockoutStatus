<#

.SYNOPSIS
Gets relevant information about a user who might be locked out.

.DESCRIPTION
Adds a file name extension to a supplied name.
Takes any strings for the file name or extension.

.PARAMETER Identity
SamAccountName, UserPrincipalName

.EXAMPLE
C:\PS> .\Get-AccountLockoutStatus.ps1 <samaccountname> | ogv

.EXAMPLE
C:\PS> .\Get-AccountLockoutStatus.ps1 <samaccountname> | ft -autosize

.EXAMPLE
C:\PS> .\Get-AccountLockoutStatus.ps1 -Identity <samaccountname>

#>

[CmdletBinding()]
param(
    [parameter(Mandatory=$true,
    Position=0)]
    [string] $Identity
)

Begin {

    Try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } Catch {
        Write-Error $_
        Break
    }

} Process {

    Write-Verbose "Fetching all Domain Controllers."
    $DomainControllers = Get-ADDomainController -Filter *

    $PDCEmulator = $DomainControllers | Where-Object { $_.OperationMasterRoles -contains "PDCEmulator" }

    If ($null -eq $PDCEmulator) {
        Write-Warning "Could not find PDCEmulator for fetching Eventlogs."
    } Else {
        Write-Verbose "Querying EventLog on $($PDCEmulator.HostName) for lockout security events."
        Try {
            $AllLockoutEvents = Get-WinEvent -ComputerName $PDCEmulator.HostName -FilterHashtable @{LogName='Security';Id=4740;} -ErrorAction Continue
        } Catch {
            Write-Verbose "Could not find any events."
        }
    }

    ForEach ($DC in $DomainControllers) {

        Try {
            $User = Get-ADUser -Identity $Identity -Server $DC.HostName -Properties LockedOut,badPwdCount,LastBadPasswordAttempt,PasswordLastSet,PasswordExpired,PasswordNeverExpires,Enabled,samAccountName,AccountLockoutTime
        } Catch {
            Write-Error $_
            Break
        }

        $LockoutDC = "N/A";

        If ($null -ne $AllLockoutEvents) {
            Foreach ($Event in $AllLockoutEvents) {
                If ($Event.Properties[2].Value -match $UserInfo.SID.Value) {
                    $LockoutDC = $Event.MachineName;
                }
            }
        }

        [pscustomobject]@{
            DC = $DC.Name;
            SiteName = $DC.Site;

            IsLockedOut = $User.LockedOut;
            
            BadPasswordCount = $User.badPwdCount;
            LastBadPasswordAttempt = ($User.LastBadPasswordAttempt).ToLocalTime();
            AccountLockoutTime = If ($null -eq $User.AccountLockoutTime) { "N/A" } else { $User.AccountLockoutTime };
            OriginalLock = $LockoutDC;
            
            PasswordLastSet = $User.PasswordLastSet;
            PasswordHasExpired = $User.PasswordExpired;
            PasswordNeverExpires = $User.PasswordNeverExpires;
            Enabled = $User.Enabled;
            SamAccountName = $User.samAccountName;
        }
    } # End Foreach

} # End Process