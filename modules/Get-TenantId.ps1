function Get-TenantID {
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName = 'Domain', Mandatory = $True)]
        [string]$domain
    )
    Process {
        $openIdConfig = Invoke-RestMethod "https://login.microsoftonline.com/$domain/.well-known/openid-configuration"
        $TenantId = $OpenIdConfig.authorization_endpoint.Split("/")[3]
        return $TenantId
    }
}
