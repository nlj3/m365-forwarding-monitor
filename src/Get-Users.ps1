# M365 Forwarding Monitor is metadata-only. This script lists users and does not
# read email bodies, subjects, previews, attachments, or message content.

function Get-M365MonitorUsers {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = "./output"
    )

    $users = Invoke-M365CallWithRetry -OperationName "Graph users list" -OutputPath $OutputPath -ScriptBlock {
        Write-Host "Listing users with Microsoft Graph metadata only..."
        $allUsers = New-Object System.Collections.Generic.List[object]
        $uri = 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,mail,accountEnabled,userType&$top=999'

        while ($uri) {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            foreach ($graphUser in @($response.value)) {
                if ($graphUser.accountEnabled -eq $true -and $graphUser.userType -ne "Guest") {
                    $allUsers.Add([pscustomobject]@{
                        Id                = $graphUser.id
                        DisplayName       = $graphUser.displayName
                        UserPrincipalName = $graphUser.userPrincipalName
                        Mail              = $graphUser.mail
                        AccountEnabled    = $graphUser.accountEnabled
                        UserType          = $graphUser.userType
                    })
                }
            }

            $uri = $response.'@odata.nextLink'
        }

        return @($allUsers)
    }

    if ($null -eq $users) {
        return @()
    }

    return @($users)
}
