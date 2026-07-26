function Clear-Token {
    <#
    .DESCRIPTION
        Clear your saved tokens
    .EXAMPLE
        Clear-Token -Token All
        Clear-Token -Token Substrate
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("All", "Response", "Outlook", "MSTeams", "Graph", "AzureCoreManagement", "AzureManagement", "AzureStorage", "AzureKeyVault", "OfficeManagement", "OfficeApps", "MSGraph", "MSManage", "DODMSGraph", "MAM", "Custom", "Substrate", "SharePoint", "OneDrive", "Yammer", "DeviceRegistration")]
        [string]$Token
    )

    $tokenVariables = @{
        Response            = 'response'
        Outlook             = 'OutlookToken'
        MSTeams             = 'MSTeamsToken'
        Graph               = 'GraphToken'
        AzureCoreManagement = 'AzureCoreManagementToken'
        AzureManagement     = 'AzureManagementToken'
        AzureStorage        = 'AzureStorageToken'
        AzureKeyVault       = 'AzureKeyVaultToken'
        OfficeManagement    = 'OfficeManagementToken'
        OfficeApps          = 'OfficeAppsToken'
        MSGraph             = 'MSGraphToken'
        MSManage            = 'MSManageToken'
        DODMSGraph          = 'DODMSGraphToken'
        MAM                 = 'MAMToken'
        Custom              = 'CustomToken'
        Substrate           = 'SubstrateToken'
        SharePoint          = 'SharePointToken'
        OneDrive            = 'OneDriveToken'
        Yammer              = 'YammerToken'
        DeviceRegistration  = 'DeviceRegistrationToken'
    }

    $variablesToRemove = if ($Token -eq 'All') {
        $tokenVariables.Values
    } else {
        @($tokenVariables[$Token])
    }

    Remove-Variable -Scope Global -Name $variablesToRemove -ErrorAction SilentlyContinue
}
