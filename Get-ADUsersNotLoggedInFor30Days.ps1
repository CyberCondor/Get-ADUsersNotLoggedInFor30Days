<#
.SYNOPSIS
If an enabled user's AD last login date is > 30 days, the user is included in end results.
.DESCRIPTION
Get Enabled AD Users Not Logged In For 30 Days
.EXAMPLE
PS C:\> Get-ADUsersNotLoggedInFor30Days.ps1 -Server CyberCondor.local
## Input
ADUsers
- Contains list of all users and their properties of interest
## Output
.\EnabledADAccountsWhereLastLoginGT30Days-$($Server)_$($CurrentDate).csv
#>

param(
    [Parameter(mandatory=$True, Position=0, ValueFromPipeline=$false)]
    [system.String]$Server
)
Write-Host "`n`t`tAttempting to query Active Directory.'n" -BackgroundColor Black -ForegroundColor Yellow
try{Get-ADUser -server $Server -filter 'Title -like "*Admin*"' > $null -ErrorAction stop
}
catch{$errMsg = $_.Exception.message
    if($errMsg.Contains("is not recognized as the name of a cmdlet")){
        Write-Warning "`t $_.Exception"
        Write-Output "Ensure 'RSAT Active Directory DS-LDS Tools' are installed through 'Windows Features' & ActiveDirectory PS Module is installed"
    }
    elseif($errMsg.Contains("Unable to contact the server")){
        Write-Warning "`t $_.Exception"
        Write-Output "Check server name and that server is reachable, then try again."
    }
    else{Write-Warning "`t $_.Exception"}
    break
}

function Get-ExistingUsers_AD($Properties_AD){
    try{$ExistingUsers = Get-ADUser -Server $Server -Filter * -Properties $Properties_AD | where{$_.Enabled -eq $true} | Select $Properties_AD -ErrorAction Stop
        return $ExistingUsers
    }
    catch{$errMsg = $_.Exception.message
        Write-Warning "`t $_.Exception"
        return $null
    }
}
function Get-UserRunningThisProgram($ExistingUsers_AD){
    foreach($ExistingUser in $ExistingUsers_AD){
        if($ExistingUser.SamAccountName -eq $env:UserName){return $ExistingUser}
    }
    Write-Warning "User Running this program not found."
    return $null
}
function SanitizeManagerPropertyFormat($ExistingUsers_AD){
    foreach($ExistingUser in $ExistingUsers_AD){
        [string]$UnsanitizedName = $ExistingUser.Manager
        $NameSanitized = $false
        if(($UnsanitizedName -ne $null) -and ($UnsanitizedName -ne "") -and ($UnsanitizedName -ne "`n") -and ($UnsanitizedName -match '[a-zA-Z]') -and ($UnsanitizedName.Length -ne 1)){
            $index = 0
            while($NameSanitized -eq $false){
                $SanitizedName = $ExistingUser.Manager.Substring(3,$index++)
                if($ExistingUser.Manager[$index] -eq ','){
                    $ExistingUser.Manager = $SanitizedName.Substring(0,$SanitizedName.Length - 2)
                    $NameSanitized = $true
                }
            }
        }
        else{$ExistingUser.Manager = "NULL"}
    }
}

$Properties_AD = @("Name",
                   "Office",
                   "Title",
                   "Department",
                   "Manager",
                   "UserPrincipalName",
                   "SamAccountName",
                   "Enabled",
                   "whenCreated",
                   "whenChanged",
                   "PasswordLastSet",
                   "PasswordExpired",
                   "AccountExpirationDate",
                   "logonCount",
                   "LastLogonDate",
                   "LastBadPasswordAttempt",
                   "Description")

$CurrentDate = get-date -format MM-dd-yyy
$ExistingUsers = Get-ExistingUsers_AD $Properties_AD
if($ExistingUsers -eq $null){break}
Get-UserRunningThisProgram $ExistingUsers

SanitizeManagerPropertyFormat $ExistingUsers

$ExportedFileName = "EnabledADAccountsWhereLastLoginGT30Days-$($Server)_$($CurrentDate).csv"

$ExistingUsers | 
    where{$_.LastLogonDate -lt [datetime]::Now.AddDays(-30)}  | 
    select $Properties_AD |
    sort PasswordExpired,AccountExpirationDate,Office,Title,Department,Manager,Description,LastLogonDate |
    Export-Csv $ExportedFileName -NoTypeInformation

Write-Host "`nSummary of AD Accounts Where Last Login Date > 30 Days is available @ '$($ExportedFileName)'"