<#
    Private OAuth helpers shared by the FIDO cmdlets.

    The client names intentionally mirror the public refresh-token cmdlets in
    Invoke-RefreshToToken.ps1.  These functions are dot-sourced by the module,
    but are not exported.
#>

$script:TTDefaultOAuthRedirectUri = 'https://login.microsoftonline.com/common/oauth2/nativeclient'

# Redirect URIs belong to the app registration, not to the requested resource
# or scope. These values are the preferred non-interactive redirect URIs from
# the ROADtools first-party client data.
$script:TTClientRedirectUris = @{
    '1b730954-1685-4b74-9bfd-dac224a7b894' = $script:TTDefaultOAuthRedirectUri # aadps
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = $script:TTDefaultOAuthRedirectUri # azcli
    '1fec8e78-bce4-4aaf-ab1b-5451cc387264' = $script:TTDefaultOAuthRedirectUri # teams
    '1950a258-227b-4e31-a9cf-717495945fc2' = $script:TTDefaultOAuthRedirectUri # azps
    'ecd6b820-32c2-49b6-98a6-444530e5a77a' = $script:TTDefaultOAuthRedirectUri # msedge
    '29d9ed98-a469-4536-ade2-f981bc1d605e' = 'ms-appx-web://Microsoft.AAD.BrokerPlugin/DRSFF' # msbroker
    '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223' = 'ms-appx-web://Microsoft.AAD.BrokerPlugin/9ba1a5c7-f17a-4de9-a1f1-6178c8d51223' # companyportal
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' = 'https://startups.portal.azure.com/auth/login/' # azureportal
    'd3590ed6-52b3-4102-aeff-aad2292ab01c' = 'ms-appx-web://Microsoft.AAD.BrokerPlugIn/S-1-15-2-1479478596-3248452454-924133441-2206841801-2812823084-3237817612-3652912309'
    '00b41c95-dab0-4487-9791-b9d2c32c80f2' = 'msauth://com.ms.office365admin/Ac5NobvxUHqRzkP59tdeFTg49D4='
    'ab9b8c07-8f02-4f72-87fa-80105867a763' = $script:TTDefaultOAuthRedirectUri
    '6c7e8096-f593-4d72-807f-a5f86dcc9c77' = 'urn:ietf:wg:oauth:2.0:oob'
    '9bc3ab49-b65d-410a-85ad-de819febfddc' = 'http://localhost'
}

$script:TTBuiltInOAuthClients = [ordered]@{
    Substrate = @{
        ClientID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
        Scope    = 'https://substrate.office.com/.default offline_access openid'
    }
    MSManage = @{
        ClientID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
        Scope    = 'https://enrollment.manage.microsoft.com/.default offline_access openid'
    }
    MSTeams = @{
        ClientID = '1fec8e78-bce4-4aaf-ab1b-5451cc387264'
        Scope    = 'https://api.spaces.skype.com/.default offline_access openid'
    }
    OfficeManagement = @{
        ClientID = '00b41c95-dab0-4487-9791-b9d2c32c80f2'
        Scope    = 'https://manage.office.com/.default offline_access openid'
    }
    Outlook = @{
        ClientID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
        Scope    = 'https://outlook.office365.com/.default offline_access openid'
    }
    MSGraph = @{
        ClientID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
        Scope    = 'https://graph.microsoft.com/.default offline_access openid'
    }
    Graph = @{
        ClientID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
        Scope    = 'https://graph.windows.net/.default offline_access openid'
    }
    OfficeApps = @{
        ClientID = 'ab9b8c07-8f02-4f72-87fa-80105867a763'
        Scope    = 'https://officeapps.live.com/.default offline_access openid'
    }
    AzureCoreManagement = @{
        ClientID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
        Scope    = 'https://management.core.windows.net/.default offline_access openid'
    }
    AzureStorage = @{
        ClientID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
        Scope    = 'https://storage.azure.com/.default offline_access openid'
    }
    AzureKeyVault = @{
        ClientID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
        Scope    = 'https://vault.azure.net/.default offline_access openid'
    }
    AzureManagement = @{
        ClientID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
        Scope    = 'https://management.azure.com/.default offline_access openid'
    }
    MAM = @{
        ClientID = '6c7e8096-f593-4d72-807f-a5f86dcc9c77'
        Scope    = 'https://intunemam.microsoftonline.com/.default offline_access openid'
    }
    DODMSGraph = @{
        ClientID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
        Scope    = 'https://dod-graph.microsoft.us/.default offline_access openid'
        Authority = 'login.microsoftonline.us'
    }
    SharePoint = @{
        ClientID = '9bc3ab49-b65d-410a-85ad-de819febfddc'
        ScopeTemplate = 'https://{0}{1}.sharepoint.com/Sites.FullControl.All offline_access openid'
    }
    OneDrive = @{
        ClientID = 'ab9b8c07-8f02-4f72-87fa-80105867a763'
        Scope    = 'https://officeapps.live.com/.default offline_access openid'
    }
    Yammer = @{
        ClientID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
        Scope    = 'https://www.yammer.com/.default offline_access openid'
    }
    DeviceRegistration = @{
        ClientID = '1b730954-1685-4b74-9bfd-dac224a7b894'
        Scope    = 'openid'
        Resource = '01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9'
        UseV1Endpoint = $true
    }
}

function Get-TTEntraOAuthClientNames {
    return @($script:TTBuiltInOAuthClients.Keys) + 'Custom'
}

function Resolve-TTEntraOAuthClient {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Client,
        [string]$ClientID,
        [string]$Scope,
        [string]$Resource,
        [string]$RedirectUrl,
        [string]$SharePointTenantName,
        [switch]$SharePointUseAdmin,
        [switch]$UseV1Endpoint
    )

    if ($Client -eq 'Custom') {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            throw 'ClientID must be provided for Custom client.'
        }
        if ([string]::IsNullOrWhiteSpace($Scope)) {
            throw 'Scope must be provided for Custom client.'
        }

        $resolvedRedirect = if ([string]::IsNullOrWhiteSpace($RedirectUrl)) {
            $script:TTClientRedirectUris[$ClientID]
        } else {
            $RedirectUrl
        }

        return [PSCustomObject]@{
            Client         = $Client
            ClientID       = $ClientID
            Scope          = $Scope
            Resource       = $Resource
            RedirectUrl     = $resolvedRedirect
            UseV1Endpoint  = $UseV1Endpoint.IsPresent
        }
    }

    if (-not $script:TTBuiltInOAuthClients.Contains($Client)) {
        throw "Unsupported OAuth client '$Client'. Supported clients: $((Get-TTEntraOAuthClientNames) -join ', ')."
    }

    $definition = $script:TTBuiltInOAuthClients[$Client]
    $resolvedScope = $Scope
    if ([string]::IsNullOrWhiteSpace($resolvedScope)) {
        if ($definition.ScopeTemplate) {
            if ([string]::IsNullOrWhiteSpace($SharePointTenantName)) {
                throw 'SharePointTenantName must be provided for the SharePoint client.'
            }
            $adminSuffix = if ($SharePointUseAdmin) { '-admin' } else { '' }
            $resolvedScope = [string]::Format($definition.ScopeTemplate, $SharePointTenantName, $adminSuffix)
        } else {
            $resolvedScope = $definition.Scope
        }
    }

    $resolvedResource = if ([string]::IsNullOrWhiteSpace($Resource)) { $definition.Resource } else { $Resource }
    $resolvedUseV1 = $UseV1Endpoint.IsPresent -or [bool]$definition.UseV1Endpoint
    $resolvedClientId = if ([string]::IsNullOrWhiteSpace($ClientID)) { $definition.ClientID } else { $ClientID }
    $resolvedRedirect = if ([string]::IsNullOrWhiteSpace($RedirectUrl)) {
        $script:TTClientRedirectUris[$resolvedClientId]
    } else {
        $RedirectUrl
    }

    [PSCustomObject]@{
        Client         = $Client
        ClientID       = $resolvedClientId
        Scope          = $resolvedScope
        Resource       = $resolvedResource
        RedirectUrl     = $resolvedRedirect
        UseV1Endpoint  = $resolvedUseV1
        Authority      = $definition.Authority
    }
}

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
        [ValidateSet('Substrate','MSManage','MSTeams','OfficeManagement','Outlook','MSGraph','Graph','OfficeApps','AzureCoreManagement','AzureStorage','AzureKeyVault','AzureManagement','MAM','DODMSGraph','SharePoint','OneDrive','Yammer','DeviceRegistration','Custom')]
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
