function Get-TenantID {
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName = 'Domain', Mandatory = $True)]
        [string]$domain
    )
    Process {
        $openIdConfig = Invoke-RestMethod -Method Get -Uri "https://login.microsoftonline.com/$domain/.well-known/openid-configuration"
        if ([string]::IsNullOrWhiteSpace($openIdConfig.authorization_endpoint)) {
            throw 'The OpenID configuration did not contain an authorization endpoint.'
        }

        $authorizationEndpoint = [Uri]$openIdConfig.authorization_endpoint
        $tenantId = $authorizationEndpoint.Segments[1].Trim('/')
        $parsedTenantId = [Guid]::Empty
        if (-not [Guid]::TryParse($tenantId, [ref]$parsedTenantId)) {
            throw "The authorization endpoint did not contain a valid tenant ID: $($openIdConfig.authorization_endpoint)"
        }

        return $parsedTenantId.ToString()
    }
}
