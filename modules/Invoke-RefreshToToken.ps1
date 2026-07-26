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
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
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

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $refreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        Scope           = "https://substrate.office.com/.default offline_access openid"
    }

    try {
        $global:SubstrateToken = Invoke-RefreshToToken @Parameters
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
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
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

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $refreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        Scope           = "https://enrollment.manage.microsoft.com/.default offline_access openid"
    }

    try {
        $global:MSManageToken = Invoke-RefreshToToken @Parameters
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
        $ClientId = "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
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

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $refreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        Scope           = "https://api.spaces.skype.com/.default offline_access openid"
    }

    try {
        $global:MSTeamsToken = Invoke-RefreshToToken @Parameters
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
        $ClientId = "00b41c95-dab0-4487-9791-b9d2c32c80f2",
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

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $refreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        Scope           = "https://manage.office.com/.default offline_access openid"
    }

    try {
        $global:OfficeManagementToken = Invoke-RefreshToToken @Parameters
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
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
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

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $refreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        Scope           = "https://outlook.office365.com/.default offline_access openid"
    }

    try {
        $global:OutlookToken = Invoke-RefreshToToken @Parameters
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
        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
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

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $refreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        Scope           = "https://graph.microsoft.com/.default offline_access openid"
    }

    try {
        $global:MSGraphToken = Invoke-RefreshToToken @Parameters
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
        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
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

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $refreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        Scope           = "https://graph.windows.net/.default offline_access openid"
    }

    try {
        $global:GraphToken = Invoke-RefreshToToken @Parameters
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
        [string]$ClientID = "ab9b8c07-8f02-4f72-87fa-80105867a763",
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

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $refreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        Scope           = "https://officeapps.live.com/.default offline_access openid"
    }

    try {
        $global:OfficeAppsToken = Invoke-RefreshToToken @Parameters
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
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
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

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $refreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        Scope           = "https://management.core.windows.net/.default offline_access openid"
    }

    try {
        $global:AzureCoreManagementToken = Invoke-RefreshToToken @Parameters
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
        [string]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
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

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $refreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        Scope           = "https://storage.azure.com/.default offline_access openid"
    }

    try {
        $global:AzureStorageToken = Invoke-RefreshToToken @Parameters
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
        [string]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
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

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $RefreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        Scope           = "https://vault.azure.net/.default offline_access openid"
    }

    try {
        $global:AzureKeyVaultToken = Invoke-RefreshToToken @Parameters
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
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
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

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $refreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        Scope           = "https://management.azure.com/.default offline_access openid"
    }

    try {
        $global:AzureManagementToken = Invoke-RefreshToToken @Parameters
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
        $ClientId = "6c7e8096-f593-4d72-807f-a5f86dcc9c77",
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

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $refreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        Scope           = "https://intunemam.microsoftonline.com/.default offline_access openid"
    }

    try {
        $global:MAMToken = Invoke-RefreshToToken @Parameters
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
        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
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

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $refreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        UseDoD          = $true
        Scope           = "https://dod-graph.microsoft.us/.default offline_access openid"
    }

    try {
        $global:DODMSGraphToken = Invoke-RefreshToToken @Parameters
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
        [string]$ClientID = "9bc3ab49-b65d-410a-85ad-de819febfddc",
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

    if ($SharePointUseAdmin) {
        $AdminSuffix = "-admin"
    } else {
        $AdminSuffix = ""
    }

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $refreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        Scope           = "https://$SharePointTenantName$AdminSuffix.sharepoint.com/Sites.FullControl.All offline_access openid"
    }

    try {
        $global:SharePointToken = Invoke-RefreshToToken @Parameters
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
        [string]$ClientID = "ab9b8c07-8f02-4f72-87fa-80105867a763",
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

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $refreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        Scope           = "https://officeapps.live.com/.default offline_access openid"
    }

    try {
        $global:OneDriveToken = Invoke-RefreshToToken @Parameters
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
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
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

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $refreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        Scope           = "https://www.yammer.com/.default offline_access openid"
    }

    try {
        $global:YammerToken = Invoke-RefreshToToken @Parameters
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
        $ClientId = "1b730954-1685-4b74-9bfd-dac224a7b894",
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

    $Parameters = @{
        Domain          = $Domain
        refreshToken    = $refreshToken
        ClientID        = $ClientID
        CustomUserAgent = $CustomUserAgent
        Device          = $Device
        Browser         = $Browser
        UseCAE          = $UseCAE
        Scope           = "openid"
        Resource        = "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9"
        UseV1Endpoint   = $true
    }

    try {
        $global:DeviceRegistrationToken = Invoke-RefreshToToken @Parameters
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


    Write-Verbose $refreshToken

    $body = @{
        "scope"         = $Scope
        "client_id"     = $ClientId
        "grant_type"    = "refresh_token"
        "refresh_token" = $refreshToken
    }

    if ($UseCAE) {
        # Add 'cp1' as client claim to get a access token valid for 24 hours
        $Claims = ( @{"access_token" = @{ "xms_cc" = @{ "values" = @("cp1") } } } | ConvertTo-Json -Compress -Depth 99 )
        $body.Add("claims", $Claims)
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
