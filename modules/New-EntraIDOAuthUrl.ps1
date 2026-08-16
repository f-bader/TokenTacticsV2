function Add-TTUriQueryParameter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    $builder = [System.UriBuilder]$Uri
    $query = [System.Web.HttpUtility]::ParseQueryString($builder.Query)
    $query.Set($Name, $Value)
    $builder.Query = $query.ToString()
    return $builder.Uri.AbsoluteUri
}

function Resolve-TTEntraPostbackUri {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PostbackUrl,
        [string]$Authority = 'login.microsoftonline.com'
    )

    if ([string]::IsNullOrWhiteSpace($PostbackUrl)) {
        throw 'The FIDO flow did not provide a postback URL (urlPost).'
    }

    $absoluteUri = $null
    if ([Uri]::TryCreate($PostbackUrl, [UriKind]::Absolute, [ref]$absoluteUri) -and
        $absoluteUri.Scheme -in @('http', 'https')) {
        if ($absoluteUri.Host -notmatch '(^|\.)login\.microsoft\.com$' -and
            $absoluteUri.Host -notmatch '(^|\.)login\.microsoftonline\.(com|us)$') {
            throw "The FIDO postback URL must target a Microsoft login host, not '$($absoluteUri.Host)'."
        }
        return $absoluteUri.AbsoluteUri
    }

    $baseUri = [Uri]::new("https://$Authority")
    try {
        return [Uri]::new($baseUri, $PostbackUrl).AbsoluteUri
    } catch {
        throw "Invalid FIDO postback URL '$PostbackUrl'. $($_.Exception.Message)"
    }
}

function New-TTEntraAuthorizationUrl {
    [CmdletBinding()]
    param(
        [ValidateSet('Substrate','MSManage','MSTeams','OfficeManagement','Outlook','MSGraph','Graph','OfficeApps','AzureCoreManagement','AzureStorage','AzureKeyVault','AzureManagement','AzurePowerShell','AzureCLI','MAM','DODMSGraph','SharePoint','OneDrive','Yammer','DeviceRegistration','Custom')]
        [string]$Client = 'MSGraph',
        [string]$ClientID,
        [string]$Tenant = 'organizations',
        [string]$Authority = 'login.microsoftonline.com',
        [string]$RedirectUrl,
        [string]$Scope,
        [string]$Resource,
        [string]$SharePointTenantName,
        [switch]$SharePointUseAdmin,
        [switch]$UseV1Endpoint,
        [switch]$UseCAE,
        [switch]$UseCodeVerifier,
        [string]$CodeVerifier,
        [string]$AuthorizationCodeState,
        [string]$Username,
        [string]$AuthUrl
    )

    $resolved = Resolve-TTEntraOAuthClient `
        -Client $Client `
        -ClientID $ClientID `
        -Scope $Scope `
        -Resource $Resource `
        -RedirectUrl $RedirectUrl `
        -SharePointTenantName $SharePointTenantName `
        -SharePointUseAdmin:$SharePointUseAdmin `
        -UseV1Endpoint:$UseV1Endpoint
    if ($resolved.Authority -and $Authority -eq 'login.microsoftonline.com') {
        $Authority = $resolved.Authority
    }
    if ([string]::IsNullOrWhiteSpace($AuthorizationCodeState)) {
        $AuthorizationCodeState = [Guid]::NewGuid().ToString()
    }
    if ($UseCodeVerifier -and [string]::IsNullOrWhiteSpace($CodeVerifier)) {
        $CodeVerifier = Get-TTCodeVerifier
    }

    if ($AuthUrl) {
        try {
            $builder = [System.UriBuilder]$AuthUrl
            $query = [System.Web.HttpUtility]::ParseQueryString($builder.Query)
        } catch {
            throw "Invalid auth URL format. $($_.Exception.Message)"
        }
        if ($builder.Scheme -ne 'https' -or $builder.Host -notmatch '(^|\.)login\.microsoftonline\.(com|us)$') {
            throw "Auth URL must start with 'https://login.microsoftonline.com/' or use the login.microsoftonline.us authority."
        }
    } else {
        $selectedRedirect = if ([string]::IsNullOrWhiteSpace($RedirectUrl)) {
            $resolved.RedirectUrl
        } else {
            $RedirectUrl
        }
        if ([string]::IsNullOrWhiteSpace($selectedRedirect)) {
            throw "No redirect URI is known for client ID '$($resolved.ClientID)'. Provide -RedirectUrl for this app registration."
        }
        $endpoint = if ($resolved.UseV1Endpoint) { 'oauth2/authorize' } else { 'oauth2/v2.0/authorize' }
        $builder = [System.UriBuilder]::new('https', $Authority, 443, "$Tenant/$endpoint")
        $query = [System.Web.HttpUtility]::ParseQueryString('')
        $query.Set('response_type', 'code')
        $query.Set('redirect_uri', $selectedRedirect)
        $query.Set('state', $AuthorizationCodeState)
        if ($resolved.UseV1Endpoint -and $resolved.Resource) {
            $query.Set('resource', $resolved.Resource)
        }
        if ($resolved.Scope) {
            $query.Set('scope', $resolved.Scope)
        }
        $query.Set('client_id', $resolved.ClientID)
    }

    if (-not $query.Get('response_type')) { $query.Set('response_type', 'code') }
    if (-not $query.Get('state')) { $query.Set('state', $AuthorizationCodeState) }
    if (-not $query.Get('client_id')) { $query.Set('client_id', $resolved.ClientID) }
    if (-not $query.Get('redirect_uri')) {
        $selectedRedirect = if ([string]::IsNullOrWhiteSpace($RedirectUrl)) { $resolved.RedirectUrl } else { $RedirectUrl }
        if (-not [string]::IsNullOrWhiteSpace($selectedRedirect)) {
            $query.Set('redirect_uri', $selectedRedirect)
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($RedirectUrl)) {
        # An explicit redirect override must stay consistent throughout the flow.
        $query.Set('redirect_uri', $RedirectUrl)
    }
    foreach ($requiredParameter in @('client_id', 'response_type', 'redirect_uri')) {
        if ([string]::IsNullOrWhiteSpace($query.Get($requiredParameter))) {
            throw "Missing required parameter '$requiredParameter' in auth URL."
        }
    }
    if (-not $query.Get('sso_reload')) { $query.Set('sso_reload', 'true') }
    if ($Username -and -not $query.Get('login_hint')) { $query.Set('login_hint', $Username) }
    if ($UseCodeVerifier) {
        $query.Set('code_challenge', (Get-TTCodeChallenge -CodeVerifier $CodeVerifier))
        $query.Set('code_challenge_method', 'S256')
    }
    if ($UseCAE -and -not $resolved.UseV1Endpoint) {
        $claims = @{ access_token = @{ xms_cc = @{ values = @('cp1') } } } | ConvertTo-Json -Compress -Depth 10
        $query.Set('claims', $claims)
    }

    $builder.Query = $query.ToString()
    $actualRedirect = $query.Get('redirect_uri')
    $actualClientId = $query.Get('client_id')
    $actualScope = $query.Get('scope')
    $actualResource = $query.Get('resource')

    [PSCustomObject]@{
        Url                    = $builder.Uri.AbsoluteUri
        Client                 = $resolved.Client
        ClientID               = $actualClientId
        Tenant                 = $Tenant
        Authority              = $Authority
        RedirectUrl            = $actualRedirect
        Scope                  = $actualScope
        Resource               = $actualResource
        UseV1Endpoint          = [bool]$resolved.UseV1Endpoint
        UseCAE                 = $UseCAE.IsPresent
        UseCodeVerifier        = $UseCodeVerifier.IsPresent
        CodeVerifier           = $CodeVerifier
        AuthorizationCodeState = $query.Get('state')
    }
}
