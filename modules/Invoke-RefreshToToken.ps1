function Invoke-TTRefreshToBuiltInClient {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Client,
        [Parameter(Mandatory)]
        [string]$Domain,
        [string]$RefreshToken,
        [string]$ClientID,
        [string]$CustomUserAgent,
        [string]$Device,
        [string]$Browser,
        [switch]$UseCAE,
        [string]$SharePointTenantName,
        [switch]$SharePointUseAdmin
    )

    $resolved = Resolve-TTEntraOAuthClient `
        -Client $Client `
        -ClientID $ClientID `
        -SharePointTenantName $SharePointTenantName `
        -SharePointUseAdmin:$SharePointUseAdmin

    $parameters = @{
        Domain          = $Domain
        refreshToken    = $RefreshToken
        ClientID        = $resolved.ClientID
        Scope           = $resolved.Scope
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
    }
    if ($resolved.Resource) { $parameters.Resource = $resolved.Resource }
    if ($resolved.UseV1Endpoint) { $parameters.UseV1Endpoint = $true }
    if ($resolved.Authority -eq 'login.microsoftonline.us') { $parameters.UseDoD = $true }

    return Invoke-RefreshToToken @parameters
}

function Invoke-RefreshToSubstrateToken {
    <#
    .DESCRIPTION
        Generate a Substrate token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToSubstrateToken -domain myclient.org -refreshToken ey....
        $SubstrateToken.access_token
    #>

    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [switch]$UseCAE
    )

    try {
        $global:SubstrateToken = Invoke-TTRefreshToBuiltInClient -Client Substrate -Domain $Domain -RefreshToken $refreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE
        Write-Output "$([char]0x2713)  Token acquired and saved as `$SubstrateToken"
        $SubstrateToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Invoke-RefreshToMSManageToken {
    <#
    .DESCRIPTION
        Generate a manage token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToMSManage -domain myclient.org -refreshToken ey....
        $MSManageToken.access_token
    #>
    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    try {
        $global:MSManageToken = Invoke-TTRefreshToBuiltInClient -Client MSManage -Domain $Domain -RefreshToken $refreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE
        Write-Output "$([char]0x2713)  Token acquired and saved as `$MSManageToken"
        $MSManageToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Invoke-RefreshToMSTeamsToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Teams token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToMSTeamsToken -domain myclient.org -refreshToken ey....
        $MSTeamsToken.access_token
    #>
    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    try {
        $global:MSTeamsToken = Invoke-TTRefreshToBuiltInClient -Client MSTeams -Domain $Domain -RefreshToken $refreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE
        Write-Output "$([char]0x2713)  Token acquired and saved as `$MSTeamsToken"
        $MSTeamsToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Invoke-RefreshToOfficeManagementToken {
    <#
    .DESCRIPTION
        Generate a Office Manage token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToOfficeManagementToken -domain myclient.org -refreshToken ey....
        $OfficeManagement.access_token
    #>
    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    try {
        $global:OfficeManagementToken = Invoke-TTRefreshToBuiltInClient -Client OfficeManagement -Domain $Domain -RefreshToken $refreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE
        Write-Output "$([char]0x2713)  Token acquired and saved as `$OfficeManagementToken"
        $OfficeManagementToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Invoke-RefreshToOutlookToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Outlook token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToOutlookToken -domain myclient.org -refreshToken ey....
        $OutlookToken.access_token
    #>
    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    try {
        $global:OutlookToken = Invoke-TTRefreshToBuiltInClient -Client Outlook -Domain $Domain -RefreshToken $refreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE
        Write-Output "$([char]0x2713)  Token acquired and saved as `$OutlookToken"
        $OutlookToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Invoke-RefreshToMSGraphToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Graph token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToMSGraphToken -domain myclient.org -refreshToken ey....
        $MSGraphToken.access_token
    #>
    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    try {
        $global:MSGraphToken = Invoke-TTRefreshToBuiltInClient -Client MSGraph -Domain $Domain -RefreshToken $refreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE
        Write-Output "$([char]0x2713)  Token acquired and saved as `$MSGraphToken"
        $MSGraphToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Invoke-RefreshToGraphToken {
    <#
    .DESCRIPTION
        Generate a windows graph token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToGraphToken -domain myclient.org -refreshToken ey....
        $GraphToken.access_token
    #>
    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    try {
        $global:GraphToken = Invoke-TTRefreshToBuiltInClient -Client Graph -Domain $Domain -RefreshToken $refreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE
        Write-Output "$([char]0x2713)  Token acquired and saved as `$GraphToken"
        $GraphToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Invoke-RefreshToOfficeAppsToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Office Apps token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToOfficeAppsToken -domain myclient.org -refreshToken ey....
        $OfficeAppsToken.access_token
    #>
    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    try {
        $global:OfficeAppsToken = Invoke-TTRefreshToBuiltInClient -Client OfficeApps -Domain $Domain -RefreshToken $refreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE
        Write-Output "$([char]0x2713)  Token acquired and saved as `$OfficeAppsToken"
        $OfficeAppsToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Invoke-RefreshToAzureCoreManagementToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Core Mangement token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToAzureCoreManagementToken -domain myclient.org -refreshToken ey....
        $AzureCoreManagementToken.access_token
    #>
    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    try {
        $global:AzureCoreManagementToken = Invoke-TTRefreshToBuiltInClient -Client AzureCoreManagement -Domain $Domain -RefreshToken $refreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE
        Write-Output "$([char]0x2713)  Token acquired and saved as `$AzureCoreManagementToken"
        $AzureCoreManagementToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Invoke-RefreshToAzureStorageToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Storage token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToAzureStorageToken -domain myclient.org -refreshToken ey....
        $AzureStorageToken.access_token
    #>
    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    try {
        $global:AzureStorageToken = Invoke-TTRefreshToBuiltInClient -Client AzureStorage -Domain $Domain -RefreshToken $RefreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE
        Write-Output "$([char]0x2713)  Token acquired and saved as `$AzureStorageToken"
        $AzureStorageToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Invoke-RefreshToAzureKeyVaultToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Key Vault token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToAzureKeyVaultToken -domain myclient.org -refreshToken ey....
        $AzureKeyVaultToken.access_token
    #>
    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    try {
        $global:AzureKeyVaultToken = Invoke-TTRefreshToBuiltInClient -Client AzureKeyVault -Domain $Domain -RefreshToken $RefreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE
        Write-Output "$([char]0x2713)  Token acquired and saved as `$AzureKeyVaultToken"
        $AzureKeyVaultToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Invoke-RefreshToAzureManagementToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Mangement token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToAzureManagementToken -domain myclient.org -refreshToken ey....
        $AzureManagementToken.access_token
    #>
    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    try {
        $global:AzureManagementToken = Invoke-TTRefreshToBuiltInClient -Client AzureManagement -Domain $Domain -RefreshToken $refreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE
        Write-Output "$([char]0x2713)  Token acquired and saved as `$AzureManagementToken"
        $AzureManagementToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Invoke-RefreshToMAMToken {
    <#
    .DESCRIPTION
        Generate a Microsoft intune mam token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToMAMToken -domain myclient.org -refreshToken ey....
        $MAMToken.access_token
    #>
    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    try {
        $global:MAMToken = Invoke-TTRefreshToBuiltInClient -Client MAM -Domain $Domain -RefreshToken $refreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE
        Write-Output "$([char]0x2713)  Token acquired and saved as `$MamToken"
        $MamToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Invoke-RefreshToDODMSGraphToken {
    <#
    .DESCRIPTION
        Generate a Microsoft DOD Graph token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToDODMSGraphToken -domain myclient.org -refreshToken ey....
        $DODMSGraphToken.access_token
    #>
    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    try {
        $global:DODMSGraphToken = Invoke-TTRefreshToBuiltInClient -Client DODMSGraph -Domain $Domain -RefreshToken $refreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE
        Write-Output "$([char]0x2713)  Token acquired and saved as `$DODMSGraphToken"
        $DODMSGraphToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Invoke-RefreshToSharePointToken {
    <#
    .DESCRIPTION
        Generate a Microsoft SharePoint token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToSharePointToken -domain myclient.org -refreshToken ey....
        $SharePointToken.access_token
    #>
    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $true)]
        [string]$SharePointTenantName,
        [Alias('UseAdmin')]
        [Parameter(Mandatory = $false)]
        [switch]$SharePointUseAdmin,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    try {
        $global:SharePointToken = Invoke-TTRefreshToBuiltInClient -Client SharePoint -Domain $Domain -RefreshToken $refreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE -SharePointTenantName $SharePointTenantName -SharePointUseAdmin:$SharePointUseAdmin
        Write-Output "$([char]0x2713)  Token acquired and saved as `$SharePointToken"
        $SharePointToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}
function Invoke-RefreshToOneDriveToken {
    <#
    .DESCRIPTION
        Generate a OneDrive token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToOneDriveToken -domain myclient.org -refreshToken ey....
        $OneDriveToken.access_token
    #>
    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    try {
        $global:OneDriveToken = Invoke-TTRefreshToBuiltInClient -Client OneDrive -Domain $Domain -RefreshToken $refreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE
        Write-Output "$([char]0x2713)  Token acquired and saved as `$OneDriveToken"
        $OneDriveToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Invoke-RefreshToYammerToken {
    <#
    .DESCRIPTION
        Generate a Yammer access token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToYammerToken -domain myclient.org -refreshToken ey....
        $YammerToken.access_token
    #>
    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    try {
        $global:YammerToken = Invoke-TTRefreshToBuiltInClient -Client Yammer -Domain $Domain -RefreshToken $refreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE
        Write-Output "$([char]0x2713)  Token acquired and saved as `$YammerToken"
        $YammerToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Invoke-RefreshToDeviceRegistrationToken {
    <#
    .DESCRIPTION
        GGenerate an access token for the device registration service from a refresh token.
    .EXAMPLE
        Invoke-RefreshToDeviceRegistrationToken -domain myclient.org -refreshToken ey....
        $DeviceRegistrationToken.access_token
    #>
    [CmdletBinding()]
    param(
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    try {
        $global:DeviceRegistrationToken = Invoke-TTRefreshToBuiltInClient -Client DeviceRegistration -Domain $Domain -RefreshToken $refreshToken -ClientID $ClientID -CustomUserAgent $CustomUserAgent -Device $Device -Browser $Browser -UseCAE:$UseCAE
        Write-Output "$([char]0x2713)  Token acquired and saved as `$DeviceRegistrationToken"
        $DeviceRegistrationToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    } catch {
        Write-Output "$([char]0x274C) Could not get tokens $(Get-EntraErrorDescription -ErrorRecord $_)"
    }
}

function Invoke-RefreshToToken {
    [CmdletBinding()]
    param (
        [Alias("ResourceTenant", "TenantId")]
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $true)]
        [string]$refreshToken,
        [Parameter(Mandatory = $true)]
        [string]$ClientID,
        [Parameter(Mandatory = $true)]
        [string]$Scope,
        [Parameter(Mandatory = $false)]
        [string]$Resource,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE,
        [Parameter(Mandatory = $False)]
        [Switch]$UseDoD,
        [Parameter(Mandatory = $False)]
        [Switch]$UseV1Endpoint

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

    Write-Verbose "UserAgent: $UserAgent"

    $Headers = @{}
    $Headers["User-Agent"] = $UserAgent

    $TenantId = Get-TenantID -domain $domain
    if ($UseDoD) {
        $authUrl = "https://login.microsoftonline.us/$($TenantId)"
    } else {
        $authUrl = "https://login.microsoftonline.com/$($TenantId)"
    }


    # Never write refresh-token material to verbose logs.
    Write-Verbose 'Refresh token supplied.'

    $body = @{
        "scope"         = $Scope
        "client_id"     = $ClientId
        "grant_type"    = "refresh_token"
        "refresh_token" = $refreshToken
    }

    if ($UseCAE -and -not $UseV1Endpoint) {
        # Add the cp1 client capability only to v2 token requests.
        $Claims = ( @{"access_token" = @{ "xms_cc" = @{ "values" = @("cp1") } } } | ConvertTo-Json -Compress -Depth 99 )
        $body.Add("claims", $Claims)
    } elseif ($UseCAE) {
        Write-Warning 'CAE claims are not supported by the v1 token endpoint. Ignoring -UseCAE.'
    }

    if ($Resource) {
        $body.Add("resource", $Resource)
    }

    Write-Verbose ( $body | ConvertTo-Json -Depth 99)

    if ($UseV1Endpoint) {
        $uri = "$($authUrl)/oauth2/token"
    } else {
        $uri = "$($authUrl)/oauth2/v2.0/token"
    }

    $Token = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $uri -Headers $Headers -Body $body
    return $Token
}
