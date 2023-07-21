function Get-AzureToken {

    <#
    .DESCRIPTION
        Generate a device code to be used at https://www.microsoft.com/devicelogin. Once a user has successfully authenticated, you will be presented with a JSON Web Token JWT in the variable $response.
    .EXAMPLE
        Get-AzureToken -Client Substrate
    #>
    [cmdletbinding()]
    Param(
        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'SharePoint'
        )]
        [string]$SharePointTenantName,
        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'SharePoint')]
        [switch]$UseAdmin,
        [Parameter(
            Mandatory = $True,
            ParameterSetName = 'Default'
        )]
        [ValidateSet("Outlook", "MSTeams", "Graph", "AzureCoreManagement", "AzureManagement", "MSGraph", "DODMSGraph", "Custom", "Substrate")]
        [String[]]$Client,
        [Parameter(
            Mandatory = $False,
            ParameterSetName = 'Default'
        )]
        [String]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(
            Mandatory = $False,
            ParameterSetName = 'Default'
        )]
        [String]$Scope = "https://graph.microsoft.com/.default offline_access openid",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )
    if ($Device) {
        if ($Browser) {
            $UserAgent = Forge-UserAgent -Device $Device -Browser $Browser
        } else {
            $UserAgent = Forge-UserAgent -Device $Device
        }
    } else {
        if ($Browser) {
            $UserAgent = Forge-UserAgent -Browser $Browser
        } else {
            $UserAgent = Forge-UserAgent
        }
    }
    $Headers = @{}
    $Headers["User-Agent"] = $UserAgent
    if ($Client -eq "Outlook") {

        $body = @{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "scope"     = "https://outlook.office365.com/.default offline_access openid"
        }
    } elseif ($Client -eq "Substrate") {

        $body = @{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "scope"     = "https://substrate.office.com/.default offline_access openid"
        }
    } elseif ($Client -eq "Custom") {

        $body = @{
            "client_id" = $ClientID
            "scope"     = $Scope
        }
    } elseif ($Client -eq "MSTeams") {

        $body = @{
            "client_id" = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
            "scope"     = "https://api.spaces.skype.com/.default offline_access openid"
        }
    } elseif ($Client -eq "Graph") {

        $body = @{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "scope"     = "https://graph.windows.net/.default offline_access openid"
        }
    } elseif ($Client -eq "MSGraph") {

        $body = @{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "scope"     = "https://graph.microsoft.com/.default offline_access openid"
        }
    } elseif ($Client -eq "DODMSGraph") {

        $body = @{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "scope"     = "https://dod-graph.microsoft.us/.default offline_access openid"
        }
    } elseif ($Client -eq "AzureCoreManagement") {

        $body = @{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "scope"     = "https://management.core.windows.net/.default offline_access openid"
        }
    } elseif ($Client -eq "AzureManagement") {

        $body = @{
            "client_id" = "84070985-06ea-473d-82fe-eb82b4011c9d"
            "scope"     = "https://management.azure.com/.default offline_access openid"
        }
    } elseif ($Client -eq "OneDrive") {
        $body = @{
            "client_id" = "ab9b8c07-8f02-4f72-87fa-80105867a763"
            "scope"     = "https://officeapps.live.com/.default offline_access openid"
        }
    }

    if ($UseAdmin) {
        $AdminSuffix = "-admin"
    } else {
        $AdminSuffix = ""
    }

    if ($PSBoundParameters.ContainsKey('SharePointTenantName')) {
        $body = @{
            "client_id" = "9bc3ab49-b65d-410a-85ad-de819febfddc"
            "scope"     = "https://$SharePointTenantName$AdminSuffix.sharepoint.com/Sites.FullControl.All offline_access openid"
        }
    }

    if ($client -match "DOD") {
        $BaseUrl = "login.microsoftonline.us"
    } else {
        $BaseUrl = "login.microsoftonline.com"
    }

    # Login Process
    Write-Verbose ( $body | ConvertTo-Json )
    try {
        $authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://$BaseUrl/common/oauth2/v2.0/devicecode" -Headers $Headers -Body $body -ErrorAction SilentlyContinue
    } catch {
        Write-Verbose ( $_.Exception.Message )
        throw $_.Exception.Message
    }
    Write-Output $authResponse
    $continue = $true
    $interval = $authResponse.interval
    $expires = $authResponse.expires_in
    $body = @{
        "client_id"   = $body['client_id']
        "grant_type"  = "urn:ietf:params:oauth:grant-type:device_code"
        "device_code" = $authResponse.device_code
    }
    Write-Verbose ($body | ConvertTo-Json)
    if ($UseCAE) {
        # Add 'cp1' as client claim to get a access token valid for 24 hours
        $Claims = ( @{"access_token" = @{ "xms_cc" = @{ "values" = @("cp1") } } } | ConvertTo-Json -Compress -Depth 99 )
        $body.Add("claims", $Claims)
        Write-Verbose ( $body | ConvertTo-Json )
    }
    while ($continue) {
        Start-Sleep -Seconds $interval
        $total += $interval

        if ($total -gt $expires) {
            Write-Error "Timeout occurred"
            return
        }
        # Remove response if it exists
        Remove-Variable -Name response -Scope global -ErrorAction SilentlyContinue
        # Try to get the response. Will give 40x while pending so we need to try&catch
        try {
            $global:response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://$BaseUrl/common/oauth2/v2.0/token" -Headers $Headers -Body $body -ErrorAction SilentlyContinue
        } catch {
            # This is normal flow, always returns 40x unless successful
            $details = $_.ErrorDetails.Message | ConvertFrom-Json
            $continue = $details.error -eq "authorization_pending"
            Write-Output $details.error

            if (!$continue) {
                # Not pending so this is a real error
                Write-Error $details.error_description
                return
            }
        }

        # If we got response, all okay!
        if ($response) {
            Write-Output $response
            $jwt = $response.access_token

            $output = Parse-JWTtoken -token $jwt
            $global:upn = $output.upn
            Write-Output $upn
            break
        }
    }
}

# Refresh Token Functions
function RefreshTo-SubstrateToken {
    <#
    .DESCRIPTION
        Generate a Substrate token from a refresh token.
    .EXAMPLE
        RefreshTo-SubstrateToken -domain myclient.org -refreshToken ey....
        $SubstrateToken.access_token
    #>

    [cmdletbinding()]
    Param([Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    $Parameters = @{
        Domain       = $Domain
        refreshToken = $refreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        Scope        = "https://substrate.office.com/.default offline_access openid"
    }

    $global:SubstrateToken = Invoke-RefreshToToken @Parameters
    Write-Verbose "Token acquired and saved as `$SubstrateToken"
    $SubstrateToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
}

function RefreshTo-MSManageToken {
    <#
    .DESCRIPTION
        Generate a manage token from a refresh token.
    .EXAMPLE
        RefreshTo-MSManage -domain myclient.org -refreshToken ey....
        $MSManageToken.access_token
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    $Parameters = @{
        Domain       = $Domain
        refreshToken = $refreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        Scope        = "https://enrollment.manage.microsoft.com/.default offline_access openid"
    }

    $global:MSManageToken = Invoke-RefreshToToken @Parameters
    Write-Verbose "Token acquired and saved as `$MSManageToken"
    $MSManageToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
}

function RefreshTo-MSTeamsToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Teams token from a refresh token.
    .EXAMPLE
        RefreshTo-MSTeamsToken -domain myclient.org -refreshToken ey....
        $MSTeamsToken.access_token
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    $Parameters = @{
        Domain       = $Domain
        refreshToken = $refreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        Scope        = "https://api.spaces.skype.com/.default offline_access openid"
    }

    $global:MSTeamsToken = Invoke-RefreshToToken @Parameters
    Write-Verbose "Token acquired and saved as `$MSTeamsToken"
    $MSTeamsToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
}

function RefreshTo-OfficeManagementToken {
    <#
    .DESCRIPTION
        Generate a Office Manage token from a refresh token.
    .EXAMPLE
        RefreshTo-OfficeManagementToken -domain myclient.org -refreshToken ey....
        $OfficeManagement.access_token
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "00b41c95-dab0-4487-9791-b9d2c32c80f2",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    $Parameters = @{
        Domain       = $Domain
        refreshToken = $refreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        Scope        = "https://manage.office.com/.default offline_access openid"
    }

    $global:OfficeManagementToken = Invoke-RefreshToToken @Parameters
    Write-Verbose "Token acquired and saved as `$OfficeManagementToken"
    $OfficeManagementToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
}

function RefreshTo-OutlookToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Outlook token from a refresh token.
    .EXAMPLE
        RefreshTo-OutlookToken -domain myclient.org -refreshToken ey....
        $OutlookToken.access_token
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    $Parameters = @{
        Domain       = $Domain
        refreshToken = $refreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        Scope        = "https://outlook.office365.com/.default offline_access openid"
    }

    $global:OutlookToken = Invoke-RefreshToToken @Parameters
    Write-Verbose "Token acquired and saved as `$OutlookToken"
    $OutlookToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
}

function RefreshTo-MSGraphToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Graph token from a refresh token.
    .EXAMPLE
        RefreshTo-MSGraphToken -domain myclient.org -refreshToken ey....
        $MSGraphToken.access_token
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    $Parameters = @{
        Domain       = $Domain
        refreshToken = $refreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        Scope        = "https://graph.microsoft.com/.default offline_access openid"
    }

    $global:MSGraphToken = Invoke-RefreshToToken @Parameters
    Write-Verbose "Token acquired and saved as `$MSGraphToken"
    $MSGraphToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
}

function RefreshTo-GraphToken {
    <#
    .DESCRIPTION
        Generate a windows graph token from a refresh token.
    .EXAMPLE
        RefreshTo-GraphToken -domain myclient.org -refreshToken ey....
        $GraphToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    $Parameters = @{
        Domain       = $Domain
        refreshToken = $refreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        Scope        = "https://graph.windows.net/.default offline_access openid"
    }

    $global:GraphToken = Invoke-RefreshToToken @Parameters
    Write-Verbose "Token acquired and saved as `$GraphToken"
    $GraphToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
}

function RefreshTo-OfficeAppsToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Office Apps token from a refresh token.
    .EXAMPLE
        RefreshTo-OfficeAppsToken -domain myclient.org -refreshToken ey....
        $OfficeAppsToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID = "ab9b8c07-8f02-4f72-87fa-80105867a763",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    $Parameters = @{
        Domain       = $Domain
        refreshToken = $refreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        Scope        = "https://officeapps.live.com/.default offline_access openid"
    }

    $global:OfficeAppsToken = Invoke-RefreshToToken @Parameters
    Write-Verbose "Token acquired and saved as `$OfficeAppsToken"
    $OfficeAppsToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
}

function RefreshTo-AzureCoreManagementToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Core Mangement token from a refresh token.
    .EXAMPLE
        RefreshTo-AzureCoreManagementToken -domain myclient.org -refreshToken ey....
        $AzureCoreManagementToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    $Parameters = @{
        Domain       = $Domain
        refreshToken = $refreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        Scope        = "https://management.core.windows.net/.default offline_access openid"
    }

    $global:AzureCoreManagementToken = Invoke-RefreshToToken @Parameters
    Write-Verbose "Token acquired and saved as `$AzureCoreManagementToken"
    $AzureCoreManagementToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
}

function RefreshTo-AzureManagementToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Mangement token from a refresh token.
    .EXAMPLE
        RefreshTo-AzureManagementToken -domain myclient.org -refreshToken ey....
        $AzureManagementToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    $Parameters = @{
        Domain       = $Domain
        refreshToken = $refreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        Scope        = "https://management.azure.com/.default offline_access openid"
    }

    $global:AzureManagementToken = Invoke-RefreshToToken @Parameters
    Write-Verbose "Token acquired and saved as `$AzureManagementToken"
    $AzureManagementToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
}

function RefreshTo-MAMToken {
    <#
    .DESCRIPTION
        Generate a Microsoft intune mam token from a refresh token.
    .EXAMPLE
        RefreshTo-MAMToken -domain myclient.org -refreshToken ey....
        $MAMToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "6c7e8096-f593-4d72-807f-a5f86dcc9c77",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    $Parameters = @{
        Domain       = $Domain
        refreshToken = $refreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        Scope        = "https://intunemam.microsoftonline.com/.default offline_access openid"
    }

    $global:MAMToken = Invoke-RefreshToToken @Parameters
    Write-Verbose "Token acquired and saved as `$MamToken"
    $MamToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
}

function RefreshTo-DODMSGraphToken {
    <#
    .DESCRIPTION
        Generate a Microsoft DOD Graph token from a refresh token.
    .EXAMPLE
        RefreshTo-DODMSGraphToken -domain myclient.org -refreshToken ey....
        $DODMSGraphToken.access_token
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    $Parameters = @{
        Domain       = $Domain
        refreshToken = $refreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        UseDoD       = $true
        Scope        = "https://dod-graph.microsoft.us/.default offline_access openid"
    }

    $global:DODMSGraphToken = Invoke-RefreshToToken @Parameters
    Write-Verbose "Token acquired and saved as `$DODMSGraphToken"
    $DODMSGraphToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
}


function RefreshTo-SharePointToken {
    <#
    .DESCRIPTION
        Generate a Microsoft SharePoint token from a refresh token.
    .EXAMPLE
        RefreshTo-SharePointToken -domain myclient.org -refreshToken ey....
        $SharePointToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $true)]
        [string]$SharePointTenantName,
        [Parameter(Mandatory = $false)]
        [switch]$UseAdmin,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID = "9bc3ab49-b65d-410a-85ad-de819febfddc",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    if ($UseAdmin) {
        $AdminSuffix = "-admin"
    } else {
        $AdminSuffix = ""
    }

    $Parameters = @{
        Domain       = $Domain
        refreshToken = $refreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        Scope        = "https://$SharePointTenantName$AdminSuffix.sharepoint.com/Sites.FullControl.All offline_access openid"
    }

    $global:SharePointToken = Invoke-RefreshToToken @Parameters
    Write-Verbose "Token acquired and saved as `$SharePointToken"
    $SharePointToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
}

function RefreshTo-OneDriveToken {
    <#
    .DESCRIPTION
        Generate a OneDrive token from a refresh token.
    .EXAMPLE
        RefreshTo-OneDriveToken -domain myclient.org -refreshToken ey....
        $OneDriveToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID = "ab9b8c07-8f02-4f72-87fa-80105867a763",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    $Parameters = @{
        Domain       = $Domain
        refreshToken = $refreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        Scope        = "https://officeapps.live.com/.default offline_access openid"
    }

    $global:OneDriveToken = Invoke-RefreshToToken @Parameters
    Write-Verbose "Token acquired and saved as `$OneDriveToken"
    $OneDriveToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
}

function Invoke-RefreshToToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $true)]
        [string]$refreshToken,
        [Parameter(Mandatory = $true)]
        [string]$ClientID,
        [Parameter(Mandatory = $true)]
        [string]$Scope,
        [Parameter(Mandatory = $False)]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE,
        [Parameter(Mandatory = $False)]
        [Switch]$UseDoD
    )

    if ($Device) {
        if ($Browser) {
            $UserAgent = Forge-UserAgent -Device $Device -Browser $Browser
        } else {
            $UserAgent = Forge-UserAgent -Device $Device
        }
    } else {
        if ($Browser) {
            $UserAgent = Forge-UserAgent -Browser $Browser
        } else {
            $UserAgent = Forge-UserAgent
        }
    }

    Write-Verbose "UserAgent: $UserAgent"

    $Headers = @{}
    $Headers["User-Agent"] = $UserAgent

    $TenantId = Get-TenantID -domain $domain
    if ($UseDoD) {
        $authUrl = "https://login.microsoftonline.us/$($TenantId)"
    } else {
        $authUrl = "https://login.microsoftonline.com/$($TenantId)"
    }


    Write-Verbose $refreshToken

    $body = @{
        "scope"         = $Scope
        "client_id"     = $ClientId
        "grant_type"    = "refresh_token"
        "refresh_token" = $refreshToken
    }

    if ($UseCAE) {
        # Add 'cp1' as client claim to get a access token valid for 24 hours
        $Claims = ( @{"access_token" = @{ "xms_cc" = @{ "values" = @("cp1") } } } | ConvertTo-Json -Compress -Depth 99 )
        $body.Add("claims", $Claims)
    }

    Write-Verbose ( $body | ConvertTo-Json )

    $Token = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/v2.0/token" -Headers $Headers -Body $body
    Return $Token
}

function Clear-Token {
    <#
    .DESCRIPTION
        Clear your saved tokens
    .EXAMPLE
        Clear-Token -Token All
        Clear-Token -Token Substrate
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory = $true)]
        [ValidateSet("All", "Response", "Outlook", "MSTeams", "Graph", "AzureCoreManagement", "OfficeManagement", "MSGraph", "DODMSGraph", "Custom", "Substrate", "SharePoint", "OneDrive")]
        [string]$Token
    )
    if ($Token -eq "All") {
        # Remove variables from the global scope
        Remove-Variable -Scope Global -Name response -ErrorAction 0
        Remove-Variable -Scope Global -Name OutlookToken -ErrorAction 0
        Remove-Variable -Scope Global -Name MSTeamsToken -ErrorAction 0
        Remove-Variable -Scope Global -Name GraphToken -ErrorAction 0
        Remove-Variable -Scope Global -Name AzureCoreManagementToken -ErrorAction 0
        Remove-Variable -Scope Global -Name OfficeManagementToken -ErrorAction 0
        Remove-Variable -Scope Global -Name MSGraphToken -ErrorAction 0
        Remove-Variable -Scope Global -Name DODMSGraphToken -ErrorAction 0
        Remove-Variable -Scope Global -Name CustomToken -ErrorAction 0
        Remove-Variable -Scope Global -Name SubstrateToken -ErrorAction 0
        Remove-Variable -Scope Global -Name CustomToken -ErrorAction 0
        Remove-Variable -Scope Global -Name SharePointToken -ErrorAction 0
    } elseif ($Token -eq "Response") {
        Remove-Variable -Scope Global -Name response -ErrorAction 0
    } elseif ($Token -eq "Outlook") {
        Remove-Variable -Scope Global -Name OutlookToken -ErrorAction 0
    } elseif ($Token -eq "MSTeams") {
        Remove-Variable -Scope Global -Name MSTeamsToken -ErrorAction 0
    } elseif ($Token -eq "Graph") {
        Remove-Variable -Scope Global -Name GraphToken -ErrorAction 0
    } elseif ($Token -eq "AzureCoreManagement") {
        Remove-Variable -Scope Global -Name AzureCoreManagementToken -ErrorAction 0
    } elseif ($Token -eq "OfficeManagement") {
        Remove-Variable -Scope Global -Name OfficeManagementToken -ErrorAction 0
    } elseif ($Token -eq "MSGraph") {
        Remove-Variable -Scope Global -Name MSGraphToken -ErrorAction 0
    } elseif ($Token -eq "DODMSGraph") {
        Remove-Variable -Scope Global -Name DODMSGraphToken -ErrorAction 0
    } elseif ($Token -eq "Custom") {
        Remove-Variable -Scope Global -Name CustomToken -ErrorAction 0
    } elseif ($Token -eq "Substrate") {
        Remove-Variable -Scope Global -Name SubstrateToken -ErrorAction 0
    } elseif ( $Token -eq "SharePoint") {
        Remove-Variable -Scope Global -Name SharePointToken -ErrorAction 0
    } elseif ( $Token -eq "OneDrive") {
        Remove-Variable -Scope Global -Name OneDriveToken -ErrorAction 0
    } else {
        Write-Error "Token $Token not found"
    }
}
