function Get-EntraIDTokenFromNestedAppAuth {
    <#
    .DESCRIPTION
        Exchange a broker application's refresh token for a nested application's token using
        Nested App Authentication (NAA / BroCi).

        The default values target the Azure Portal broker and the ADIbizaUX nested client,
        but all broker and client settings can be overridden.

    .EXAMPLE
        Get-EntraIDTokenFromNestedAppAuth -TenantId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" -RefreshToken $response.refresh_token

    .AUTHOR
        Fabian Bader
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $False)]
        [string]$TenantId = "common",
        [Parameter(Mandatory = $False)]
        [string]$Domain,
        [Parameter(Mandatory = $False)]
        [string]$AuthorityHost = "login.microsoftonline.com",
        [Parameter(Mandatory = $False)]
        [ValidateSet('AzurePortal', 'Teams', 'Microsoft365', 'EntraAdminCenter', 'IntuneAdminCenter', 'Defender', 'Purview')]
        [string]$BrokerPreset,
        [Parameter(Mandatory = $False)]
        [string]$BrokerClientId = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
        [Parameter(Mandatory = $False)]
        [string]$BrokerRedirectUri = "https://portal.azure.com/auth/redirect/",
        [Parameter(Mandatory = $False)]
        [string]$ClientId = "74658136-14ec-4630-ad9b-26e160ff0fc6",
        [Parameter(Mandatory = $False)]
        [string]$Scope = "https://graph.microsoft.com/.default openid profile offline_access",
        [Parameter(Mandatory = $False)]
        [string]$RedirectUri,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'AndroidMobile', 'iPhone')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [string]$ClientRequestId = ([System.Guid]::NewGuid().ToString()),
        [Parameter(Mandatory = $False)]
        [string]$ClientInfo = "1",
        [Parameter(Mandatory = $False)]
        [string]$XClientSku = "msal.js.browser",
        [Parameter(Mandatory = $False)]
        [string]$XClientVer = "5.13.0",
        [Parameter(Mandatory = $False)]
        [string]$XMsLibCapability = "retry-after, h429",
        [Parameter(Mandatory = $False)]
        [string]$XClientCurrentTelemetry,
        [Parameter(Mandatory = $False)]
        [string]$XClientLastTelemetry,
        [Parameter(Mandatory = $False)]
        [switch]$IncludeClientIdInQuery,
        [Alias("XAnchorMailbox")]
        [Parameter(Mandatory = $False)]
        [string]$AnchorMailbox,
        [Parameter(Mandatory = $False)]
        [string]$Claims,
        [Parameter(Mandatory = $False)]
        [switch]$UseCAE
    )

    if ([string]::IsNullOrWhiteSpace($RefreshToken)) {
        Write-Error "RefreshToken must be provided or `$response.refresh_token must be populated"
        return
    }

    $BrokerPresets = @{
        "AzurePortal" = @{
            BrokerClientId    = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
            BrokerRedirectUri = "https://portal.azure.com/auth/redirect/"
        }
        "Teams" = @{
            BrokerClientId          = "5e3ce6c0-2b1f-4285-8d4b-75ee78787346"
            BrokerRedirectUri       = "https://teams.cloud.microsoft/v2/authv2"
            RedirectUri             = "brk-multihub://m365.cloud.microsoft"
            IncludeClientIdInQuery  = $true
            XClientVer              = "5.6.3"
            XClientCurrentTelemetry = "5|61,0,,,,|,"
            XClientLastTelemetry    = "5|0||||0,0"
        }
        "Microsoft365" = @{
            BrokerClientId    = "4765445b-32c6-49b0-83e6-1d93765276ca"
            BrokerRedirectUri = "https://www.microsoft365.com/spalanding"
        }
        "EntraAdminCenter" = @{
            BrokerClientId    = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
            BrokerRedirectUri = "https://entra.microsoft.com/auth/login/"
        }
        "IntuneAdminCenter" = @{
            BrokerClientId    = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
            BrokerRedirectUri = "https://intune.microsoft.com/auth/login/"
        }
        "Defender" = @{
            BrokerClientId    = "80ccca67-54bd-44ab-8625-4b79c4dc7775"
            BrokerRedirectUri = "https://security.microsoft.com/Blank"
        }
        "Purview" = @{
            BrokerClientId    = "80ccca67-54bd-44ab-8625-4b79c4dc7775"
            BrokerRedirectUri = "https://purview.microsoft.com/Blank"
        }
    }

    if ($PSBoundParameters.ContainsKey('BrokerPreset')) {
        $SelectedBrokerPreset = $BrokerPresets[$BrokerPreset]
        if (-not $PSBoundParameters.ContainsKey('BrokerClientId')) {
            $BrokerClientId = $SelectedBrokerPreset.BrokerClientId
        }
        if (-not $PSBoundParameters.ContainsKey('BrokerRedirectUri')) {
            $BrokerRedirectUri = $SelectedBrokerPreset.BrokerRedirectUri
        }
        if ($SelectedBrokerPreset.ContainsKey('RedirectUri') -and -not $PSBoundParameters.ContainsKey('RedirectUri')) {
            $RedirectUri = $SelectedBrokerPreset.RedirectUri
        }
        if ($SelectedBrokerPreset.ContainsKey('XClientVer') -and -not $PSBoundParameters.ContainsKey('XClientVer')) {
            $XClientVer = $SelectedBrokerPreset.XClientVer
        }
        if ($SelectedBrokerPreset.ContainsKey('XClientCurrentTelemetry') -and -not $PSBoundParameters.ContainsKey('XClientCurrentTelemetry')) {
            $XClientCurrentTelemetry = $SelectedBrokerPreset.XClientCurrentTelemetry
        }
        if ($SelectedBrokerPreset.ContainsKey('XClientLastTelemetry') -and -not $PSBoundParameters.ContainsKey('XClientLastTelemetry')) {
            $XClientLastTelemetry = $SelectedBrokerPreset.XClientLastTelemetry
        }
        Write-Verbose "Using broker preset $BrokerPreset"
    }

    $ShouldIncludeClientIdInQuery = $IncludeClientIdInQuery.IsPresent
    if ($PSBoundParameters.ContainsKey('BrokerPreset') -and $BrokerPreset -eq 'Teams') {
        $ShouldIncludeClientIdInQuery = $true
    }

    if ($PSBoundParameters.ContainsKey('Domain')) {
        $TenantId = Get-TenantID -domain $Domain
        Write-Verbose "Resolved tenant ID from domain $Domain`: $TenantId"
    }

    if ([string]::IsNullOrWhiteSpace($Claims) -and $UseCAE) {
        # Add 'cp1' as client claim to get a CAE-capable access token.
        $Claims = ( @{"access_token" = @{ "xms_cc" = @{ "values" = @("cp1") } } } | ConvertTo-Json -Compress -Depth 99 )
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

    if ([string]::IsNullOrWhiteSpace($RedirectUri)) {
        try {
            $BrokerRedirectUriObject = [System.Uri]$BrokerRedirectUri
        } catch {
            Write-Error "Invalid BrokerRedirectUri format. $($_.Exception.Message)"
            return
        }

        $BrokerAuthority = $BrokerRedirectUriObject.GetLeftPart([System.UriPartial]::Authority)
        if ([string]::IsNullOrWhiteSpace($BrokerAuthority)) {
            Write-Error "BrokerRedirectUri must contain a valid authority"
            return
        }
        $RedirectUri = "brk-${BrokerClientId}://$($BrokerAuthority -replace '^https?://', '')"
    }

    $Headers = @{}
    $Headers["User-Agent"] = $UserAgent

    $TokenEndpointQueryParameters = [System.Collections.Generic.List[string]]::new()
    if ($ShouldIncludeClientIdInQuery) {
        $TokenEndpointQueryParameters.Add("client_id=$([System.Uri]::EscapeDataString($ClientId))")
    }
    $TokenEndpointQueryParameters.Add("brk_client_id=$([System.Uri]::EscapeDataString($BrokerClientId))")
    $TokenEndpointQueryParameters.Add("brk_redirect_uri=$([System.Uri]::EscapeDataString($BrokerRedirectUri))")
    $TokenEndpointQueryParameters.Add("client-request-id=$([System.Uri]::EscapeDataString($ClientRequestId))")
    $TokenEndpointUri = "https://$AuthorityHost/$TenantId/oauth2/v2.0/token?" + ($TokenEndpointQueryParameters -join '&')

    $body = @{
        "client_id"           = $ClientId
        "redirect_uri"        = $RedirectUri
        "scope"               = $Scope
        "grant_type"          = "refresh_token"
        "client_info"         = $ClientInfo
        "x-client-SKU"        = $XClientSku
        "x-client-VER"        = $XClientVer
        "x-ms-lib-capability" = $XMsLibCapability
        "refresh_token"       = $RefreshToken
        "brk_client_id"       = $BrokerClientId
        "brk_redirect_uri"    = $BrokerRedirectUri
    }

    if (-not [string]::IsNullOrWhiteSpace($AnchorMailbox)) {
        $body.Add("X-AnchorMailbox", $AnchorMailbox)
    }
    if (-not [string]::IsNullOrWhiteSpace($Claims)) {
        $body.Add("claims", $Claims)
    }
    if (-not [string]::IsNullOrWhiteSpace($XClientCurrentTelemetry)) {
        $body.Add("x-client-current-telemetry", $XClientCurrentTelemetry)
    }
    if (-not [string]::IsNullOrWhiteSpace($XClientLastTelemetry)) {
        $body.Add("x-client-last-telemetry", $XClientLastTelemetry)
    }

    Write-Verbose "Calling brokered token endpoint"
    Write-Verbose "URI: $TokenEndpointUri"
    Write-Verbose ($body | ConvertTo-Json -Depth 99)

    try {
        $global:response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $TokenEndpointUri -Headers $Headers -Body $body
        $output = ConvertFrom-JWTtoken -token $response.access_token
        $global:TokenDomain = $output.upn -split '@' | Select-Object -Last 1
        $global:TokenUpn = $output.upn
        Write-Output "$([char]0x2713)  Token acquired and saved as `$response"
    } catch {
        Write-Error "Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}
