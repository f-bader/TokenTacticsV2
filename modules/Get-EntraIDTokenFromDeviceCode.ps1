function Get-EntraIDTokenFromDeviceCode {
    <#
    .DESCRIPTION
        Generate a device code to be used at https://www.microsoft.com/devicelogin. Once a user has successfully authenticated, you will be presented with a JSON Web Token JWT in the variable $response.
    .EXAMPLE
        Get-EntraIDTokenFromDeviceCode -Client Substrate
    #>
    param(
        [Parameter(Mandatory = $False, ParameterSetName = 'CustomUserAgent,PredefinedUserAgent')]
        [ValidateSet("Yammer", "Outlook", "MSTeams", "Graph", "AzureCoreManagement", "AzureManagement", "MSGraph", "DODMSGraph", "Custom", "Substrate", "SharePoint", "OneDrive")]
        [string]$Client = "MSGraph",
        [Parameter(Mandatory = $False, ParameterSetName = 'CustomUserAgent,PredefinedUserAgent')]
        [string]$ClientID,
        [Parameter(Mandatory = $False, ParameterSetName = 'CustomUserAgent,PredefinedUserAgent')]
        [string]$Scope,
        [Parameter(
            Mandatory = $False,
            ParameterSetName = 'CustomUserAgent'
        )]
        [string]$CustomUserAgent,
        [Parameter(
            Mandatory = $False,
            ParameterSetName = 'PredefinedUserAgent'
        )]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(
            Mandatory = $False,
            ParameterSetName = 'PredefinedUserAgent'
        )]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False, ParameterSetName = 'CustomUserAgent,PredefinedUserAgent')]
        [Switch]$UseCAE,
        [Parameter(Mandatory = $false, ParameterSetName = 'CustomUserAgent,PredefinedUserAgent')]
        [string]$SharePointTenantName,
        [Alias('UseAdmin')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CustomUserAgent,PredefinedUserAgent')]
        [switch]$SharePointUseAdmin,
        [Alias("Domain")]
        [Parameter(Mandatory = $False, ParameterSetName = 'CustomUserAgent,PredefinedUserAgent')]
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

    if ($SharePointUseAdmin) {
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
    if ($Client -eq 'SharePoint' -and -not $PSBoundParameters.ContainsKey('SharePointTenantName')) {
        Write-Error "SharePointTenantName must be provided for the SharePoint client"
        return
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
