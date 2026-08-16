function Invoke-TTNativeRedirectWebRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [System.Collections.IDictionary]$Headers,
        [string]$Proxy
    )

    # Invoke-WebRequest validates the Location scheme even with
    # MaximumRedirection=0. Use the .NET request directly for registered
    # native/URN redirects so the 302 can be inspected without following it.
    $request = [System.Net.HttpWebRequest]::Create($Uri)
    $request.AllowAutoRedirect = $false
    $request.CookieContainer = $WebSession.Cookies
    $request.UserAgent = $WebSession.UserAgent
    if ($Proxy) {
        $request.Proxy = [System.Net.WebProxy]::new($Proxy)
    }
    foreach ($header in @($Headers.GetEnumerator())) {
        if ($header.Key -ieq 'User-Agent') {
            $request.UserAgent = [string]$header.Value
        } else {
            $request.Headers[$header.Key] = [string]$header.Value
        }
    }

    $response = $null
    try {
        $response = $request.GetResponse()
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            $response = $_.Exception.Response
        } else {
            throw
        }
    }

    try {
        $rawContent = ''
        $responseStream = $response.GetResponseStream()
        if ($responseStream) {
            $reader = [System.IO.StreamReader]::new($responseStream)
            try {
                $rawContent = $reader.ReadToEnd()
            } finally {
                $reader.Dispose()
            }
        }

        $responseHeaders = $response.Headers
        $location = $responseHeaders['Location']
        if ($location) {
            Add-Member -InputObject $responseHeaders -MemberType NoteProperty -Name Location -Value $location -Force
        }

        return [PSCustomObject]@{
            StatusCode = [int]$response.StatusCode
            RawContent = $rawContent
            Content    = $rawContent
            Headers    = $responseHeaders
        }
    } finally {
        $response.Dispose()
    }
}

function Get-EntraIDTokenFromCookie {

    <#
    .DESCRIPTION
        Authenticate to an application (default graph.microsoft.com) using Authorization Code flow and a cookie
        Authenticates to MSGraph as Teams FOCI client by default.
        https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow

    .EXAMPLE
        Get-EntraIDTokenFromCookie -CookieType ESTSAUTHPERSISTENT -CookieValue "0.AbcAp.."

    .AUTHOR
        Adapted for PowerShell by https://github.com/rotarydrone from ROADtools by https://github.com/dirkjanm
        https://github.com/rvrsh3ll/TokenTactics/pull/9
        https://github.com/dirkjanm/ROADtools/wiki/ROADtools-Token-eXchange-(roadtx)#selenium-based-authentication

        Extended to support appverify endpoint, multiple cookie formats and full error handling by Fabian Bader
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]$CookieType,
        [Parameter(Mandatory = $True)]
        [string]$CookieValue,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'AndroidMobile', 'iPhone')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$Resource = "https://graph.microsoft.com",
        [Parameter(Mandatory = $true)]
        [string]$Scope = "openid offline_access",
        [Parameter(Mandatory = $false)]
        [string]$RedirectUrl,
        [Parameter(Mandatory = $false)]
        [switch]$UseCodeVerifier,
        [Parameter(Mandatory = $false)]
        [string]$CodeVerifier,
        [Parameter(Mandatory = $false)]
        [switch]$UseV1Endpoint,
        [Parameter(Mandatory = $false)]
        [switch]$UseCAE,
        [Parameter(Mandatory = $false)]
        [string]$Proxy
    )

    if ([string]::IsNullOrWhiteSpace($ClientID)) {
        $ClientID = (Resolve-TTEntraOAuthClient -Client MSTeams).ClientID
    }
    if ([string]::IsNullOrWhiteSpace($RedirectUrl)) {
        $RedirectUrl = $script:TTClientRedirectUris[$ClientID]
    }
    if ([string]::IsNullOrWhiteSpace($RedirectUrl)) {
        throw "No redirect URI is known for client ID '$ClientID'. Provide -RedirectUrl."
    }

    # Configure Default Parameters
    $PSDefaultParameterValues = @{}
    $PSDefaultParameterValues.Add('Invoke-WebRequest:Verbose', $false)

    if ($Proxy) {
        Write-Verbose "$([char]0x2718) Setting proxy to $Proxy"
        $PSDefaultParameterValues.Add('Invoke-WebRequest:Proxy', $Proxy)
    }

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
        if ([string]::IsNullOrWhiteSpace($CodeVerifier)) {
            $CodeVerifier = Get-TTCodeVerifier
        }
        $CodeChallenge = Get-TTCodeChallenge -CodeVerifier $CodeVerifier
        $Uri += "&code_challenge=$CodeChallenge&code_challenge_method=S256"
    }
    if ($UseCAE -and ( $UseV1Endpoint -eq $false )) {
        # Add 'cp1' as client claim to get a access token valid for 24 hours
        $Uri += "&claims=" + ( @{"access_token" = @{ "xms_cc" = @{ "values" = @("cp1") } } } | ConvertTo-Json -Compress -Depth 99 )
    }
    Write-Verbose "Requesting URL: $Uri"
    Write-Output "$([char]0x2718)  Calling authorization endpoint with $CookieType cookie"
    $redirectScheme = ([System.Uri]$RedirectUrl).Scheme
    if ($redirectScheme -notin @('http', 'https')) {
        $sts_response = Invoke-TTNativeRedirectWebRequest -Uri $Uri -WebSession $session -Headers $Headers -Proxy $Proxy
    } elseif ($PSVersionTable.PSEdition -ne "Core") {
        $sts_response = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri $Uri -Headers $Headers
    } else {
        $sts_response = Invoke-WebRequest -UseBasicParsing -SkipHttpErrorCheck -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri $Uri -Headers $Headers
    }

    Write-Verbose "Status code: $($sts_response.StatusCode)"
    if ( $sts_response.StatusCode -eq 200 -and $sts_response.RawContent -match "\`$Config=(.*);") {
        Write-Verbose "AppConfig found in initial response"
        $AppConfig = $Matches[1] | ConvertFrom-Json
        Write-Debug "AppConfig: $($AppConfig | ConvertTo-Json -Depth 99)"

        # Handle ConvergedSignIn flow
        if ($AppConfig.pgid -eq "ConvergedSignIn") {
            Write-Output "$([char]0x2718)  ConvergedSignIn - Attempting to continue sign-in flow"
            $Uri = $AppConfig.urlLogin + "&sessionid=$($AppConfig.arrSessions[0].id)"
            if ($PSVersionTable.PSEdition -ne "Core") {
                $sts_response = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri $Uri -Headers $Headers
            } else {
                $sts_response = Invoke-WebRequest -UseBasicParsing -SkipHttpErrorCheck -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri $Uri -Headers $Headers
            }
            Remove-Variable -Name AppConfig -ErrorAction SilentlyContinue
        }

        if ($sts_response.RawContent -match "\`$Config=(.*);") {
            Write-Verbose "AppConfig found in initial response"
            $AppConfig = $Matches[1] | ConvertFrom-Json
            Write-Debug "AppConfig: $($AppConfig | ConvertTo-Json -Depth 99)"
        }

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
    if ($sts_response.StatusCode -eq 302) {
        # Header adapters return either a string or a string array across
        # PowerShell editions. Normalize both forms before parsing the code.
        $RequestURL = [string](@($sts_response.Headers.Location)[0])
        try {
            $queryParams = ConvertTo-URLParameters -RequestURL $RequestURL
        } catch {
            $queryParams = @{}
        }

        #region Manual sign-in required
        if (-not $queryParams.ContainsKey('code')) {
            # Native and URN redirects are OAuth callback targets, not URLs
            # that Invoke-WebRequest can request. Report the failed flow
            # without sending an unsupported scheme to PowerShell.
            $locationUri = $null
            $isAbsoluteLocation = [System.Uri]::TryCreate(
                $RequestURL,
                [System.UriKind]::Absolute,
                [ref]$locationUri
            )
            if ($isAbsoluteLocation -and $locationUri.Scheme -notin @('http', 'https')) {
                Write-Verbose "$([char]0x2718)  Single sign-on failed; received a native redirect ($($locationUri.Scheme)) without an authorization code"
                Write-Output "$([char]0x2718)  Could not find an authorization code in the native redirect"
                Write-Output "    Redirect scheme: $($locationUri.Scheme)"
                return
            }

            Write-Verbose "$([char]0x2718)  Single sign-on failed; received an HTTP redirect without an authorization code"

            $sts_response = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri $RequestURL -Headers $Headers
            if ( $sts_response.RawContent -match "\`$Config=(.*);") {
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

        # When code is present, we have a valid refresh token and can use it to request a new token
        $AuthorizationCode = $queryParams['code']
        Write-Verbose "Authorization Code: $($AuthorizationCode[0..10] -join '' )..."
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
            Write-Error "Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
        }
    }
}

function Get-EntraIDTokenFromESTSCookie {

    <#
    .DESCRIPTION
        Authenticate to an application (default graph.microsoft.com) using Authorization Code flow using an ESTS cookie for authentication.

    .EXAMPLE
        Get-EntraIDTokenFromESTSCookie -Client MSTeams -ESTSAuthCookie "0.AbcAp.."

    .AUTHOR
        Fabian Bader
    #>

    [CmdletBinding()]
    param(
        [Alias("ESTSAuthCookie")]
        [Parameter(Mandatory = $True)]
        [string]$CookieValue,
        [ValidateSet("ESTSAUTHPERSISTENT", "ESTSAUTH")]
        $ESTSCookieType = "ESTSAUTHPERSISTENT",
        [Parameter(Mandatory = $False)]
        [ValidateSet("MSTeams", "MSEdge", "AzurePowershell", "AzureManagement", "DeviceComplianceBypass", "Custom")]
        [string]$Client = "MSTeams",
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'AndroidMobile', 'iPhone')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$Resource = "https://graph.microsoft.com",
        [Parameter(Mandatory = $False)]
        [string]$Scope = "openid offline_access",
        [Parameter(Mandatory = $False)]
        [string]$RedirectUrl,
        [Parameter(Mandatory = $false)]
        [switch]$UseCodeVerifier,
        [Parameter(Mandatory = $false)]
        [string]$CodeVerifier,
        [Parameter(Mandatory = $false)]
        [switch]$UseV1Endpoint,
        [Parameter(Mandatory = $false)]
        [switch]$UseCAE,
        [Parameter(Mandatory = $false)]
        [string]$Proxy
    )

    $legacyClient = Resolve-TTLegacyOAuthClient -Client $Client -ClientID $ClientID -RedirectUrl $RedirectUrl

    $Parameters = @{
        "CookieType"  = $ESTSCookieType
        "CookieValue" = $CookieValue
        "ClientID"    = $legacyClient.ClientID
        "Scope"       = $Scope
        "RedirectUrl" = $legacyClient.RedirectUrl
        "Verbose"     = $VerbosePreference
        "UseCodeVerifier" = $UseCodeVerifier
        "CodeVerifier" = $CodeVerifier
        "UseV1Endpoint" = $UseV1Endpoint
        "UseCAE" = $UseCAE
    }
    if ($Proxy) {
        $Parameters.Add("Proxy", $Proxy)
    }
    if ($CustomUserAgent) {
        $Parameters.Add("CustomUserAgent", $CustomUserAgent)
    } elseif ($Device) {
        if ($Browser) {
            $Parameters.Add("CustomUserAgent", (Get-ForgedUserAgent -Device $Device -Browser $Browser))
        } else {
            $Parameters.Add("CustomUserAgent", (Get-ForgedUserAgent -Device $Device))
        }
    } elseif ($Browser) {
        $Parameters.Add("CustomUserAgent", (Get-ForgedUserAgent -Browser $Browser))
    } else {
        $Parameters.Add("CustomUserAgent", (Get-ForgedUserAgent))
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
    Get-EntraIDTokenFromCookie @Parameters
}

function Get-EntraIDTokenFromRefreshTokenCredentialCookie {
    <#
    .DESCRIPTION
        Authenticate to an application (default graph.microsoft.com) using Authorization Code flow using an x-ms-RefreshTokenCredential cookie for authentication.

    .EXAMPLE
        Get-EntraIDTokenFromRefreshTokenCredentialCookie -Client MSTeams -RefreshTokenCredential "eyJhbGciOiJ..."

    .AUTHOR
        Fabian Bader
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]$RefreshTokenCredential,
        [Parameter(Mandatory = $False)]
        [ValidateSet("MSTeams", "MSEdge", "AzurePowershell", "AzureManagement", "DeviceComplianceBypass", "Custom")]
        [string]$Client = "MSTeams",
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'AndroidMobile', 'iPhone')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$Resource = "https://graph.microsoft.com",
        [Parameter(Mandatory = $False)]
        [string]$Scope = "openid offline_access",
        [Parameter(Mandatory = $False)]
        [string]$RedirectUrl,
        [Parameter(Mandatory = $false)]
        [string]$Proxy
    )

    $legacyClient = Resolve-TTLegacyOAuthClient -Client $Client -ClientID $ClientID -RedirectUrl $RedirectUrl
    $Parameters = @{
        "CookieType"  = "x-ms-RefreshTokenCredential"
        "CookieValue" = $RefreshTokenCredential
        "ClientID"    = $legacyClient.ClientID
        "Scope"       = $Scope
        "RedirectUrl" = $legacyClient.RedirectUrl
        "Verbose"     = $VerbosePreference
    }
    if ($Proxy) {
        $Parameters.Add("Proxy", $Proxy)
    }
    if ($CustomUserAgent) {
        $Parameters.Add("CustomUserAgent", $CustomUserAgent)
    } elseif ($Device) {
        if ($Browser) {
            $Parameters.Add("CustomUserAgent", (Get-ForgedUserAgent -Device $Device -Browser $Browser))
        } else {
            $Parameters.Add("CustomUserAgent", (Get-ForgedUserAgent -Device $Device))
        }
    } elseif ($Browser) {
        $Parameters.Add("CustomUserAgent", (Get-ForgedUserAgent -Browser $Browser))
    } else {
        $Parameters.Add("CustomUserAgent", (Get-ForgedUserAgent))
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
    Get-EntraIDTokenFromCookie @Parameters
}
