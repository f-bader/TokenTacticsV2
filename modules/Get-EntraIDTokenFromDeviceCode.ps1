function Get-EntraIDTokenFromDeviceCode {
    <#
    .DESCRIPTION
        Generate a device code to be used at https://www.microsoft.com/devicelogin.
        Once a user has successfully authenticated, the token is saved in
        $response.
    .EXAMPLE
        Get-EntraIDTokenFromDeviceCode -Client Substrate
    #>
    param(
        [Parameter(Mandatory = $False, ParameterSetName = 'CustomUserAgent,PredefinedUserAgent')]
        [ValidateSet('Substrate', 'MSManage', 'MSTeams', 'OfficeManagement', 'Outlook', 'MSGraph', 'Graph', 'OfficeApps', 'AzureCoreManagement', 'AzureStorage', 'AzureKeyVault', 'AzureManagement', 'AzurePowerShell', 'AzureCLI', 'MAM', 'DODMSGraph', 'SharePoint', 'OneDrive', 'Yammer', 'DeviceRegistration', 'Custom')]
        [string]$Client = 'MSGraph',
        [Parameter(Mandatory = $False, ParameterSetName = 'CustomUserAgent,PredefinedUserAgent')]
        [string]$ClientID,
        [Parameter(Mandatory = $False, ParameterSetName = 'CustomUserAgent,PredefinedUserAgent')]
        [string]$Scope,
        [Parameter(Mandatory = $False, ParameterSetName = 'CustomUserAgent')]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False, ParameterSetName = 'PredefinedUserAgent')]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False, ParameterSetName = 'PredefinedUserAgent')]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False, ParameterSetName = 'CustomUserAgent,PredefinedUserAgent')]
        [switch]$UseCAE,
        [Parameter(Mandatory = $false, ParameterSetName = 'CustomUserAgent,PredefinedUserAgent')]
        [string]$SharePointTenantName,
        [Alias('UseAdmin')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CustomUserAgent,PredefinedUserAgent')]
        [switch]$SharePointUseAdmin,
        [Alias('Domain')]
        [Parameter(Mandatory = $False, ParameterSetName = 'CustomUserAgent,PredefinedUserAgent')]
        [string]$ResourceTenant = 'common'
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
    $effectiveClient = if ($PSBoundParameters.ContainsKey('SharePointTenantName')) { 'SharePoint' } else { $Client }
    if ($effectiveClient -ne 'Custom' -and -not [string]::IsNullOrWhiteSpace($Scope)) {
        Write-Warning 'Custom scope is set but client is not set to Custom. Ignoring scope.'
        $Scope = $null
    }
    $resolved = Resolve-TTEntraOAuthClient `
        -Client $effectiveClient `
        -ClientID $ClientID `
        -Scope $Scope `
        -SharePointTenantName $SharePointTenantName `
        -SharePointUseAdmin:$SharePointUseAdmin

    $isV1 = [bool]$resolved.UseV1Endpoint
    $BaseUrl = if ($resolved.Authority) { $resolved.Authority } else { 'login.microsoftonline.com' }
    $endpointVersion = if ($isV1) { 'oauth2' } else { 'oauth2/v2.0' }
    $body = @{ client_id = $resolved.ClientID }
    if ($isV1) {
        if ([string]::IsNullOrWhiteSpace($resolved.Resource)) {
            throw "Resource must be provided for v1 client '$effectiveClient'."
        }
        $body.resource = $resolved.Resource
    } else {
        $body.scope = $resolved.Scope
    }

    Write-Verbose ($body | ConvertTo-Json -Depth 99)
    try {
        $authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://$BaseUrl/$ResourceTenant/$endpointVersion/devicecode" -Headers $Headers -Body $body -ErrorAction SilentlyContinue
    } catch {
        Write-Verbose $_.Exception.Message
        throw $_.Exception.Message
    }

    Write-Output $authResponse
    $interval = $authResponse.interval
    $expires = $authResponse.expires_in
    $total = 0
    $continue = $true
    $pollUri = "https://$BaseUrl/$ResourceTenant/$endpointVersion/token"
    $pollBody = @{
        client_id = $resolved.ClientID
        grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
    }
    if ($isV1) {
        # The v1 device authorization contract calls this value `code`.
        # The v2 contract uses `device_code` instead.
        $pollBody.code = $authResponse.device_code
        $pollBody.resource = $resolved.Resource
    } else {
        $pollBody.device_code = $authResponse.device_code
    }
    if ($UseCAE -and -not $isV1) {
        $pollBody.claims = (@{ access_token = @{ xms_cc = @{ values = @('cp1') } } } | ConvertTo-Json -Compress -Depth 99)
    }

    Write-Verbose ($pollBody | ConvertTo-Json -Depth 99)
    while ($continue) {
        Start-Sleep -Seconds $interval
        $total += $interval
        if ($total -gt $expires) {
            Write-Error 'Timeout occurred'
            return
        }

        Remove-Variable -Name response -Scope global -ErrorAction SilentlyContinue
        $details = $null
        try {
            $global:response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $pollUri -Headers $Headers -Body $pollBody -ErrorAction SilentlyContinue
        } catch {
            if ($_.ErrorDetails.Message) {
                try { $details = $_.ErrorDetails.Message | ConvertFrom-Json } catch { $details = $null }
            }
            if ($details) {
                Write-Verbose "Error: $($details.error)"
                $continue = $details.error -eq 'authorization_pending'
            } else {
                throw
            }
        }

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
