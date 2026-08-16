function Get-EntraIDTokenFromAuthorizationCode {
    <#
    .DESCRIPTION
        Exchange an authorization code for a token.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Substrate', 'MSManage', 'MSTeams', 'OfficeManagement', 'Outlook', 'MSGraph', 'Graph', 'OfficeApps', 'AzureCoreManagement', 'AzureStorage', 'AzureKeyVault', 'AzureManagement', 'AzurePowerShell', 'AzureCLI', 'MAM', 'DODMSGraph', 'SharePoint', 'OneDrive', 'Yammer', 'DeviceRegistration', 'Custom')]
        [string]$Client = 'MSGraph',
        [Parameter(Mandatory = $True, ParameterSetName = 'Default')]
        [string]$AuthorizationCode,
        [Parameter(Mandatory = $True, ParameterSetName = 'RequestURL')]
        [string]$RequestURL,
        [Parameter(ParameterSetName = 'Default')]
        [string]$RedirectUrl,
        [Parameter(Mandatory = $False)]
        [string]$ClientID,
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
    $Headers = @{ 'User-Agent' = $UserAgent }

    $profile = if ($Client -eq 'MSGraph') { Get-TTEntraOAuthProfile -Name AuthorizationCode } else { $null }
    if ([string]::IsNullOrWhiteSpace($ClientID) -and $profile) { $ClientID = $profile.ClientID }
    if ($RequestURL) {
        $queryParams = ConvertTo-URLParameters -RequestURL $RequestURL
        if ($queryParams.ContainsKey('code')) {
            $AuthorizationCode = $queryParams['code']
            Write-Verbose "Code: $($AuthorizationCode[0..10])..."
            Write-Debug "Code: $AuthorizationCode"
        } else {
            Write-Warning 'Code not found in redirected URL path. Aborting...'
            return
        }
        $uri = [System.Uri]::new($RequestURL)
        $RedirectUrl = $uri.GetLeftPart([System.UriPartial]::Path)
        if ([string]::IsNullOrWhiteSpace($RedirectUrl)) {
            Write-Warning 'Redirect URL not found in redirected URL path. Aborting...'
            return
        }
        Write-Verbose "Redirect URL: $RedirectUrl"
    } elseif ([string]::IsNullOrWhiteSpace($RedirectUrl) -and $profile) {
        $RedirectUrl = $profile.RedirectUrl
    }

    if ($Client -ne 'Custom' -and -not [string]::IsNullOrWhiteSpace($Scope)) {
        Write-Warning 'Custom scope is set but client is not set to Custom. Ignoring scope.'
        $Scope = $null
    }
    $resolved = Resolve-TTEntraOAuthClient `
        -Client $Client `
        -ClientID $ClientID `
        -Scope $Scope `
        -Resource $Resource `
        -RedirectUrl $RedirectUrl `
        -UseV1Endpoint:$UseV1Endpoint
    if ([string]::IsNullOrWhiteSpace($RedirectUrl)) { $RedirectUrl = $resolved.RedirectUrl }
    if ([string]::IsNullOrWhiteSpace($RedirectUrl)) {
        throw "No redirect URI is known for client ID '$($resolved.ClientID)'. Provide -RedirectUrl."
    }

    $body = @{
        grant_type = 'authorization_code'
        redirect_uri = $RedirectUrl
        code = $AuthorizationCode
        client_id = $resolved.ClientID
    }
    $body.scope = $resolved.Scope
    if ($resolved.UseV1Endpoint) { $body.resource = $resolved.Resource }
    if ($UseCAE -and -not $resolved.UseV1Endpoint) {
        $body.claims = (@{ access_token = @{ xms_cc = @{ values = @('cp1') } } } | ConvertTo-Json -Compress -Depth 99)
    }
    if ($CodeVerifier) { $body.code_verifier = $CodeVerifier }

    Write-Verbose 'Calling token endpoint with Authorization Code'
    Write-Verbose ($body | ConvertTo-Json -Depth 99)
    try {
        $authority = if ($resolved.Authority) { $resolved.Authority } else { 'login.microsoftonline.com' }
        $endpoint = if ($resolved.UseV1Endpoint) { 'oauth2/token' } else { 'oauth2/v2.0/token' }
        $global:response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://$authority/common/$endpoint" -Headers $Headers -Body $body
        $output = ConvertFrom-JWTtoken -token $response.access_token
        $global:TokenDomain = $output.upn -split '@' | Select-Object -Last 1
        $global:TokenUpn = $output.upn
        Write-Output "$([char]0x2713)  Token acquired and saved as `$response"
    } catch {
        Write-Error "Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Get-EntraIDAuthorizationCode {
    <#
    .DESCRIPTION
        Build an authorization-code URL.

    .EXAMPLE
        Get-EntraIDAuthorizationCode -RedirectUrl 'ms-appx-web://Microsoft.AAD.BrokerPlugin/S-1-15-2-2666988183-1750391847-2906264630-3525785777-2857982319-3063633125-1907478113'
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Substrate', 'MSManage', 'MSTeams', 'OfficeManagement', 'Outlook', 'MSGraph', 'Graph', 'OfficeApps', 'AzureCoreManagement', 'AzureStorage', 'AzureKeyVault', 'AzureManagement', 'AzurePowerShell', 'AzureCLI', 'MAM', 'DODMSGraph', 'SharePoint', 'OneDrive', 'Yammer', 'DeviceRegistration', 'Custom')]
        [string]$Client = 'MSGraph',
        [Parameter(Mandatory = $False)]
        [string]$ClientID,
        [Parameter(Mandatory = $false)]
        [string]$RedirectUrl,
        [Parameter(Mandatory = $False)]
        [string]$AuthorizationCodeState = '9gaPNizkzgtisKqA',
        [Parameter(Mandatory = $False)]
        [string]$Scope,
        [Parameter(Mandatory = $False)]
        [switch]$UseCAE,
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

    $profile = if ($Client -eq 'MSGraph') { Get-TTEntraOAuthProfile -Name AuthorizationCodeMobile } else { $null }
    if ([string]::IsNullOrWhiteSpace($ClientID) -and $profile) { $ClientID = $profile.ClientID }
    if ([string]::IsNullOrWhiteSpace($RedirectUrl) -and $profile) { $RedirectUrl = $profile.RedirectUrl }

    if ($Client -ne 'Custom' -and -not [string]::IsNullOrWhiteSpace($Scope)) {
        Write-Warning 'Custom scope is set but client is not set to Custom. Ignoring scope.'
        $Scope = $null
    }
    $resolved = Resolve-TTEntraOAuthClient `
        -Client $Client `
        -ClientID $ClientID `
        -Scope $Scope `
        -Resource $Resource `
        -RedirectUrl $RedirectUrl `
        -UseV1Endpoint:$UseV1Endpoint
    if ([string]::IsNullOrWhiteSpace($RedirectUrl)) { $RedirectUrl = $resolved.RedirectUrl }
    if ([string]::IsNullOrWhiteSpace($RedirectUrl)) {
        throw "No redirect URI is known for client ID '$($resolved.ClientID)'. Provide -RedirectUrl."
    }

    $authority = if ($resolved.Authority) { $resolved.Authority } else { 'login.microsoftonline.com' }
    $endpoint = if ($resolved.UseV1Endpoint) { 'oauth2/authorize' } else { 'oauth2/v2.0/authorize' }
    $BaseUrl = "https://$authority/organizations/${endpoint}?response_type=code"
    $BaseUrl += "&redirect_uri=$RedirectUrl"
    $BaseUrl += "&state=$AuthorizationCodeState"
    if ($resolved.UseV1Endpoint -and $resolved.Resource) { $BaseUrl += "&resource=$($resolved.Resource)" }
    if ($UseCodeVerifier) {
        $CodeVerifier = Get-TTCodeVerifier
        $CodeChallenge = Get-TTCodeChallenge -CodeVerifier $CodeVerifier
        $BaseUrl += "&code_challenge=$CodeChallenge"
        $BaseUrl += '&code_challenge_method=S256'
    }
    if ($Username) { $BaseUrl += "&login_hint=$Username" }
    if ($resolved.Scope) { $BaseUrl += "&scope=$($resolved.Scope)" }
    $BaseUrl += "&client_id=$($resolved.ClientID)"
    if ($UseCAE -and -not $resolved.UseV1Endpoint) {
        $BaseUrl += '&claims=' + (@{ access_token = @{ xms_cc = @{ values = @('cp1') } } } | ConvertTo-Json -Compress -Depth 99)
    }

    Write-Output $([uri]::EscapeUriString($BaseUrl))
    if ($OpenInBrowser) {
        Start-Process $BaseUrl
        Write-Output '1. The URL has been opened in your default browser'
    } else {
        Write-Output '1. Copy and paste the URL into a browser'
    }
    Write-Output '2. Enable the developer tools and switch to the network tab'
    Write-Output '3. Authenticate using your credentials'
    Write-Output '4. Copy either the Request URL from the header tab or the code value from the payload tab'
    Write-Output '5. Use the code value (-AuthorizationCode) or complete Request URL (-RequestURL) to get a token:'
    Write-Output ''
    Write-Output '   `$AuthCode = Get-Clipboard'
    if ($UseCodeVerifier) { $CodeVerifierString = "-CodeVerifier `"$CodeVerifier`"" }
    if ($resolved.UseV1Endpoint) { $V1EndpointString = "-Resource `"$($resolved.Resource)`" -UseV1Endpoint" }
    if ($Client -eq 'Custom') {
        Write-Output "   Get-EntraIDTokenFromAuthorizationCode -Client Custom -RedirectUrl `"$RedirectUrl`" -ClientID `"$($resolved.ClientID)`" -Scope `"$($resolved.Scope)`" -AuthorizationCode `$AuthCode $CodeVerifierString $V1EndpointString"
    } else {
        Write-Output "   Get-EntraIDTokenFromAuthorizationCode -Client $Client -RedirectUrl `"$RedirectUrl`" -AuthorizationCode `$AuthCode $CodeVerifierString $V1EndpointString"
    }
    if ($CopyToClipboard) {
        $BaseUrl | Set-Clipboard
        Write-Output '   The URL has been copied to your clipboard'
    }
}
