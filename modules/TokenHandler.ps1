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
        [ValidateSet("Yammer", "Outlook", "MSTeams", "Graph", "AzureCoreManagement", "AzureManagement", "MSGraph", "DODMSGraph", "Custom", "Substrate")]
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
            $UserAgent = Get-ForgedUserAgent -Device $Device -Browser $Browser
        } else {
            $UserAgent = Get-ForgedUserAgent -Device $Device
        }
    } else {
        if ($Browser) {
            $UserAgent = Get-ForgedUserAgent -Browser $Browser
        } else {
            $UserAgent = Get-ForgedUserAgent
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
    } elseif ($Client -eq "Yammer") {

        $body = @{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "resource"  = "https://www.yammer.com/.default offline_access openid"
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

            $output = ConvertFrom-JWTtoken -token $jwt
            $global:TokenDomain = $output.upn -split '@' | Select-Object -Last 1
            $global:TokenUpn = $output.upn
            break
        }
    }
}

function Get-AzureTokenFromESTSCookie {

    <#
    .DESCRIPTION
        Authenticate to an application (default graph.microsoft.com) using Authorization Code flow.
        Authenticates to MSGraph as Teams FOCI client by default.
        https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow

    .EXAMPLE
        Get-AzureTokenFromESTSCookie -Client MSTeams -ESTSAuthCookie "0.AbcAp.."

    .AUTHOR
        Adapted for PowerShell by https://github.com/rotarydrone from ROADtools by https://github.com/dirkjanm
        https://github.com/rvrsh3ll/TokenTactics/pull/9
        https://github.com/dirkjanm/ROADtools/wiki/ROADtools-Token-eXchange-(roadtx)#selenium-based-authentication
    #>

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String[]]
        $ESTSAuthCookie,
        [Parameter(Mandatory = $False)]
        [String[]]
        [ValidateSet("MSTeams", "MSEdge", "AzurePowershell")]
        $Client = "MSTeams",
        [Parameter(Mandatory = $False)]
        [String]
        $Resource = "https://graph.microsoft.com/",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'AndroidMobile', 'iPhone')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser
    )

    if ($Device) {
        if ($Browser) {
            $UserAgent = Get-ForgedUserAgent -Device $Device -Browser $Browser
        } else {
            $UserAgent = Get-ForgedUserAgent -Device $Device
        }
    } else {
        if ($Browser) {
            $UserAgent = Get-ForgedUserAgent -Browser $Browser
        } else {
            $UserAgent = Get-ForgedUserAgent
        }
    }


    if ($Client -eq "MSTeams") {
        $client_id = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
    } elseif ($Client -eq "MSEdge") {
        $client_id = "ecd6b820-32c2-49b6-98a6-444530e5a77a"
    } elseif ($Client -eq "AzurePowershell") {
        $client_id = "1950a258-227b-4e31-a9cf-717495945fc2"
    }

    $Headers = @{}
    $Headers["User-Agent"] = $UserAgent

    $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    $cookie = [System.Net.Cookie]::new("ESTSAuthPERSISTENT", "$($ESTSAuthCookie)")
    $session.Cookies.Add('https://login.microsoftonline.com/', $cookie)

    $state = [System.Guid]::NewGuid().ToString()
    $redirect_uri = ([System.Uri]::EscapeDataString("https://login.microsoftonline.com/common/oauth2/nativeclient"))

    # Get the authorization code from the STS
    if ($PSVersionTable.PSEdition -ne "Core") {
        $sts_response = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=$($client_id)&resource=$($Resource)&redirect_uri=$($redirect_uri)&state=$($state)" -Headers $Headers
    } else {
        $sts_response = Invoke-WebRequest -UseBasicParsing -SkipHttpErrorCheck -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=$($client_id)&resource=$($Resource)&redirect_uri=$($redirect_uri)&state=$($state)" -Headers $Headers
    }

    if ($sts_response.StatusCode -eq 302) {

        if ($PSVersionTable.PSEdition -ne "Core") {
            $uri = [System.Uri]$sts_response.Headers.Location
        } else {
            $uri = [System.Uri]$sts_response.Headers.Location[0]
        }

        # Get the parameters from the redirect URI and build a hashtable containing the different parameters
        $query = $uri.Query.TrimStart('?')
        $queryParams = @{}
        $paramPairs = $query.Split('&')

        foreach ($pair in $paramPairs) {
            $parts = $pair.Split('=')
            $key = $parts[0]
            $value = $parts[1]
            $queryParams[$key] = $value
        }
        # When code is present, we have a valid refresh token and can use it to request a new token
        if ($queryParams.ContainsKey('code')) {
            $refreshToken = $queryParams['code']
        } else {
            Write-Host "[-] Code not found in redirected URL path"
            Write-Host "    Requested URL: https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=$($client_id)&resource=$($Resource)&redirect_uri=$($redirect_uri)&state=$($state)"
            Write-Host "    Response Code: $($sts_response.StatusCode)"
            Write-Host "    Response URI:  $($sts_response.Headers.Location)"
            return
        }
    } else {
        Write-Host "[-] Expected 302 redirect but received other status"
        Write-Host "    Requested URL: https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=$($client_id)&resource=$($Resource)&redirect_uri=$($redirect_uri)&state=$($state)"
        Write-Host "    Response Code: $($sts_response.StatusCode)"
        Write-Host "[-] The request may require user interation to complete, or the provided cookie is invalid"
        return
    }

    if ($refreshToken) {

        $body = @{
            "resource"     = $Resource
            "client_id"    = $client_id
            "grant_type"   = "authorization_code"
            "redirect_uri" = "https://login.microsoftonline.com/common/oauth2/nativeclient"
            "code"         = $refreshToken
            "scope"        = "openid"
        }

        $global:response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/token" -Headers $Headers -Body $body
        $output = ConvertFrom-JWTtoken -token $response.access_token
        $global:TokenDomain = $output.upn -split '@' | Select-Object -Last 1
        $global:TokenUpn = $output.upn
    }
}

# Refresh Token Functions
function Invoke-RefreshToSubstrateToken {
    <#
    .DESCRIPTION
        Generate a Substrate token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToSubstrateToken -domain myclient.org -refreshToken ey....
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

function Invoke-RefreshToMSManageToken {
    <#
    .DESCRIPTION
        Generate a manage token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToMSManage -domain myclient.org -refreshToken ey....
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

function Invoke-RefreshToMSTeamsToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Teams token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToMSTeamsToken -domain myclient.org -refreshToken ey....
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

function Invoke-RefreshToOfficeManagementToken {
    <#
    .DESCRIPTION
        Generate a Office Manage token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToOfficeManagementToken -domain myclient.org -refreshToken ey....
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

function Invoke-RefreshToOutlookToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Outlook token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToOutlookToken -domain myclient.org -refreshToken ey....
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

function Invoke-RefreshToMSGraphToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Graph token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToMSGraphToken -domain myclient.org -refreshToken ey....
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

function Invoke-RefreshToGraphToken {
    <#
    .DESCRIPTION
        Generate a windows graph token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToGraphToken -domain myclient.org -refreshToken ey....
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

function Invoke-RefreshToOfficeAppsToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Office Apps token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToOfficeAppsToken -domain myclient.org -refreshToken ey....
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

function Invoke-RefreshToAzureCoreManagementToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Core Mangement token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToAzureCoreManagementToken -domain myclient.org -refreshToken ey....
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

function Invoke-RefreshToAzureStorageToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Storage token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToAzureStorageToken -domain myclient.org -refreshToken ey....
        $AzureStorageToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
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
        Scope        = "https://storage.azure.com/.default offline_access openid"
    }

    $global:AzureStorageToken = Invoke-RefreshToToken @Parameters
    Write-Verbose "Token acquired and saved as `$AzureStorageToken"
    $AzureStorageToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
}

function Invoke-RefreshToAzureKeyVaultToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Key Vault token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToAzureKeyVaultToken -domain myclient.org -refreshToken ey....
        $AzureKeyVaultToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
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
        refreshToken = $RefreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        Scope        = "https://vault.azure.net/.default offline_access openid"
    }

    $global:AzureKeyVaultToken = Invoke-RefreshToToken @Parameters
    Write-Verbose "Token acquired and saved as `$AzureKeyVaultToken"
    $AzureKeyVaultToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
}

function Invoke-RefreshToAzureManagementToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Mangement token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToAzureManagementToken -domain myclient.org -refreshToken ey....
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

function Invoke-RefreshToMAMToken {
    <#
    .DESCRIPTION
        Generate a Microsoft intune mam token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToMAMToken -domain myclient.org -refreshToken ey....
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

function Invoke-RefreshToDODMSGraphToken {
    <#
    .DESCRIPTION
        Generate a Microsoft DOD Graph token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToDODMSGraphToken -domain myclient.org -refreshToken ey....
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


function Invoke-RefreshToSharePointToken {
    <#
    .DESCRIPTION
        Generate a Microsoft SharePoint token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToSharePointToken -domain myclient.org -refreshToken ey....
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

function Invoke-RefreshToOneDriveToken {
    <#
    .DESCRIPTION
        Generate a OneDrive token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToOneDriveToken -domain myclient.org -refreshToken ey....
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

function Invoke-RefreshToYammerToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Teams token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToYammerToken -domain myclient.org -refreshToken ey....
        $YammerToken.access_token
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
        Scope        = "https://api.spaces.skype.com/.default offline_access openid"
    }

    $global:YammerToken = Invoke-RefreshToToken @Parameters
    Write-Verbose "Token acquired and saved as `$YammerToken"
    $YammerToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
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
            $UserAgent = Get-ForgedUserAgent -Device $Device -Browser $Browser
        } else {
            $UserAgent = Get-ForgedUserAgent -Device $Device
        }
    } else {
        if ($Browser) {
            $UserAgent = Get-ForgedUserAgent -Browser $Browser
        } else {
            $UserAgent = Get-ForgedUserAgent
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
        [ValidateSet("All", "Response", "Outlook", "MSTeams", "Graph", "AzureCoreManagement", "OfficeManagement", "MSGraph", "DODMSGraph", "Custom", "Substrate", "SharePoint", "OneDrive", "Yammer")]
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
        Remove-Variable -Scope Global -Name YammerToken -ErrorAction 0
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
    } elseif ( $Token -eq "Yammer") {
        Remove-Variable -Scope Global -Name YammerToken -ErrorAction 0
    } else {
        Write-Error "Token $Token not found"
    }
}
