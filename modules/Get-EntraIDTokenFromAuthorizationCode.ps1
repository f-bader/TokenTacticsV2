function Get-EntraIDTokenFromAuthorizationCode {
    <#
    .DESCRIPTION
        Authenticate to an application (default graph.microsoft.com) using Authorization Code flow.
        Authenticates to MSGraph as Teams FOCI client by default.
        https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow

    .EXAMPLE
        Get-EntraIDTokenFromAuthorizationCode -Client MSGraph -AuthorizationCode "1.AXkAT2xo4yev..."

    .AUTHOR
        Adapted for TokenTactics from the original code by
        @gladstomych https://github.com/JumpsecLabs/TokenSmith and
        @zh54321 https://github.com/zh54321/PoCEntraDeviceComplianceBypass/blob/main/poc_entra_compliance_bypass.ps1

        First published by @_dirkjan: https://bsky.app/profile/dirkjanm.io/post/3ld4nbbhqd222
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("MSGraph", "Graph", "DeviceRegistration", "Custom")]
        [string]$Client = "MSGraph",
        [Parameter(Mandatory = $True, ParameterSetName = 'Default')]
        [string]$AuthorizationCode,
        [Parameter(ParameterSetName = 'Default')]
        [string]$RedirectUrl = "ms-appx-web://Microsoft.AAD.BrokerPlugin/S-1-15-2-2666988183-1750391847-2906264630-3525785777-2857982319-3063633125-1907478113",
        [Parameter(Mandatory = $True, ParameterSetName = 'RequestURL')]
        [string]$RequestURL,
        [Parameter(Mandatory = $False)]
        [string]$ClientID = "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",
        [Parameter(Mandatory = $False)]
        [string]$Scope,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'AndroidMobile', 'iPhone')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [switch]$UseCAE,
        [Parameter(Mandatory = $False)]
        [string]$CodeVerifier,
        [Parameter(Mandatory = $False)]
        [switch]$UseV1Endpoint,
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
        Write-Error "Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
    #endregion
}

function Get-EntraIDAuthorizationCode {
    <#
    .DESCRIPTION


    .EXAMPLE
        # Use Windows based Redirect URL
        Get-EntraIDAuthorizationCode -RedirectUrl "ms-appx-web://Microsoft.AAD.BrokerPlugin/S-1-15-2-2666988183-1750391847-2906264630-3525785777-2857982319-3063633125-1907478113"

        # Use Android based Redirect URL
        Get-EntraIDAuthorizationCode -RedirectUrl "msauth://com.microsoft.windowsintune.companyportal/1L4Z9FJCgn5c0VLhyAxC5O9LdlE="

    .AUTHOR
        Adapted for TokenTactics from the original code by
        @gladstomych https://github.com/JumpsecLabs/TokenSmith and
        @zh54321 https://github.com/zh54321/PoCEntraDeviceComplianceBypass/blob/main/poc_entra_compliance_bypass.ps1
    #>

    [CmdletBinding()]
    param(
        [ValidateSet("MSGraph", "Graph", "Custom")]
        [string]$Client = "MSGraph",
        [Parameter(Mandatory = $False)]
        [string]$ClientID = "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",
        [Parameter(Mandatory = $false)]
        [string]$RedirectUrl = "msauth://com.microsoft.windowsintune.companyportal/1L4Z9FJCgn5c0VLhyAxC5O9LdlE=",
        [Parameter(Mandatory = $False)]
        [string]$AuthorizationCodeState = "9gaPNizkzgtisKqA",
        [Parameter(Mandatory = $False)]
        [string]$Scope,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE,
        [Parameter(Mandatory = $False)]
        [switch]$UseCodeVerifier,
        [Parameter(Mandatory = $False)]
        [switch]$UseV1Endpoint,
        [Parameter(Mandatory = $False)]
        [string]$Resource,
        [Parameter(Mandatory = $False)]
        [string]$Username,
        [Parameter(Mandatory = $False)]
        [switch]$CopyToClipboard,
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
    if ($Username) {
        $BaseUrl += "&login_hint=$Username"
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
        $V1EndpointString = "-Resource `"$Resource`" -UseV1Endpoint"
    }
    if ($Client -eq "Custom") {
        Write-Output "   Get-EntraIDTokenFromAuthorizationCode -Client Custom -RedirectUrl `"$RedirectUrl`" -ClientID `"$ClientID`" -Scope `"$Scope`" -AuthorizationCode `$AuthCode $CodeVerifierString $V1EndpointString"
    } else {
        Write-Output "   Get-EntraIDTokenFromAuthorizationCode -Client $Client -RedirectUrl `"$RedirectUrl`" -AuthorizationCode `$AuthCode $CodeVerifierString $V1EndpointString"
    }

    if ($CopyToClipboard) {
        $BaseUrl | Set-Clipboard
        Write-Output "   The URL has been copied to your clipboard"
    }
}
