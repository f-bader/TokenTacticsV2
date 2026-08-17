<#
    Private OAuth client registry shared by the authentication cmdlets.

    Keep client IDs, scopes, authorities, endpoint versions, and preferred
    redirect URIs here so individual flows do not grow separate defaults.
#>

$script:TTDefaultOAuthRedirectUri = 'https://login.microsoftonline.com/common/oauth2/nativeclient'

$script:TTClientRedirectUris = @{
    '1b730954-1685-4b74-9bfd-dac224a7b894' = $script:TTDefaultOAuthRedirectUri
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = $script:TTDefaultOAuthRedirectUri
    '1fec8e78-bce4-4aaf-ab1b-5451cc387264' = $script:TTDefaultOAuthRedirectUri
    '1950a258-227b-4e31-a9cf-717495945fc2' = $script:TTDefaultOAuthRedirectUri
    '84070985-06ea-473d-82fe-eb82b4011c9d' = $script:TTDefaultOAuthRedirectUri
    'ecd6b820-32c2-49b6-98a6-444530e5a77a' = $script:TTDefaultOAuthRedirectUri
    '29d9ed98-a469-4536-ade2-f981bc1d605e' = 'ms-appx-web://Microsoft.AAD.BrokerPlugin/DRSFF'
    '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223' = 'ms-appx-web://Microsoft.AAD.BrokerPlugin/9ba1a5c7-f17a-4de9-a1f1-6178c8d51223'
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' = 'https://startups.portal.azure.com/auth/login/'
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
        ClientID = '1950a258-227b-4e31-a9cf-717495945fc2'
        Scope    = 'https://management.azure.com/.default offline_access openid'
    }
    AzurePowerShell = @{
        ClientID = '1950a258-227b-4e31-a9cf-717495945fc2'
        Scope    = 'https://management.azure.com/.default offline_access openid'
    }
    AzureCLI = @{
        ClientID = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
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

$script:TTLegacyOAuthProfiles = @{
    AuthorizationCode = @{
        Client = 'MSGraph'
        ClientID = '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223'
        Scope = 'https://graph.microsoft.com/.default offline_access openid'
        RedirectUrl = 'ms-appx-web://Microsoft.AAD.BrokerPlugin/S-1-15-2-2666988183-1750391847-2906264630-3525785777-2857982319-3063633125-1907478113'
    }
    AuthorizationCodeMobile = @{
        Client = 'MSGraph'
        ClientID = '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223'
        Scope = 'https://graph.microsoft.com/.default offline_access openid'
        RedirectUrl = 'msauth://com.microsoft.windowsintune.companyportal/1L4Z9FJCgn5c0VLhyAxC5O9LdlE='
    }
    LegacyPasskey = @{
        Client = 'AzureCLI'
        ClientID = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
        Scope = 'https://graph.microsoft.com/.default'
        RedirectUrl = $script:TTDefaultOAuthRedirectUri
    }
}

$script:TTLegacyOAuthClients = @{
    MSTeams = @{ ClientID = '1fec8e78-bce4-4aaf-ab1b-5451cc387264' }
    MSEdge = @{ ClientID = 'ecd6b820-32c2-49b6-98a6-444530e5a77a' }
    AzurePowershell = @{ ClientID = '1950a258-227b-4e31-a9cf-717495945fc2' }
    DeviceComplianceBypass = @{
        ClientID = '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223'
        RedirectUrl = $script:TTLegacyOAuthProfiles.AuthorizationCodeMobile.RedirectUrl
    }
    AzureManagement = @{ ClientID = '84070985-06ea-473d-82fe-eb82b4011c9d' }
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
            Client = $Client
            ClientID = $ClientID
            Scope = $Scope
            Resource = $Resource
            RedirectUrl = $resolvedRedirect
            UseV1Endpoint = $UseV1Endpoint.IsPresent
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
        Client = $Client
        ClientID = $resolvedClientId
        Scope = $resolvedScope
        Resource = $resolvedResource
        RedirectUrl = $resolvedRedirect
        UseV1Endpoint = $resolvedUseV1
        Authority = $definition.Authority
    }
}

function Get-TTEntraOAuthProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('AuthorizationCode', 'AuthorizationCodeMobile', 'LegacyPasskey')]
        [string]$Name
    )

    return [PSCustomObject]$script:TTLegacyOAuthProfiles[$Name]
}

function Get-TTEntraOAuthDefaultScope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Client
    )

    $resolved = Resolve-TTEntraOAuthClient -Client $Client
    return @($resolved.Scope -split '\s+' | Where-Object { $_ -like '*.default' })[0]
}

function Resolve-TTLegacyOAuthClient {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('MSTeams', 'MSEdge', 'AzurePowershell', 'DeviceComplianceBypass', 'AzureManagement', 'Custom')]
        [string]$Client,
        [string]$ClientID,
        [string]$RedirectUrl
    )

    if ($Client -eq 'Custom') {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            throw 'ClientID must be provided for Custom client.'
        }
        return [PSCustomObject]@{
            Client = $Client
            ClientID = $ClientID
            RedirectUrl = $RedirectUrl
        }
    }

    $definition = $script:TTLegacyOAuthClients[$Client]
    $resolvedClientId = if ([string]::IsNullOrWhiteSpace($ClientID)) { $definition.ClientID } else { $ClientID }
    $resolvedRedirect = if ([string]::IsNullOrWhiteSpace($RedirectUrl)) {
        if ($definition.RedirectUrl) { $definition.RedirectUrl } else { $script:TTClientRedirectUris[$resolvedClientId] }
    } else {
        $RedirectUrl
    }

    [PSCustomObject]@{
        Client = $Client
        ClientID = $resolvedClientId
        RedirectUrl = $resolvedRedirect
    }
}
