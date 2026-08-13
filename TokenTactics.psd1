@{
    # Script module or binary module file associated with this manifest.
    RootModule        = 'TokenTactics.psm1'

    # Version number of this module.
    ModuleVersion     = '0.5.0'
    
    # ID used to uniquely identify this module
    GUID              = '6194f0f0-8b91-4c32-b1b1-bc46c9d7a95c'

    # Author of this module
    Author            = 'Stephan Borosh & Bobby Cooke & Fabian Bader'

    # Copyright statement for this module
    Copyright         = 'BSD 3-Clause'

    # Description of the functionality provided by this module
    Description       = 'Azure JSON Web Token ("JWT") Token Manipulation Toolset'

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        'Clear-Token'
        'ConvertFrom-JWTtoken'
        'ConvertTo-PEMPrivateKey'
        'Get-EntraIDAuthorizationCode'
        'Get-EntraIDFido2Challenge'
        'Get-EntraIDTokenFromCertificate'
        'Get-EntraIDTokenFromClientSecret'
        'Get-EntraIDTokenFromDeviceCode'
        'Get-EntraIDTokenFromFederatedCredential'
        'Get-EntraIDTokenFromGitHubActions'
        'Get-EntraIDTokenFromAzureArcManagedIdentity'
        'Get-EntraIDTokenOnBehalfOf'
        'Get-EntraIDTokenFromAuthorizationCode'
        'Get-EntraIDTokenFromCookie'
        'Get-EntraIDTokenFromESTSCookie'
        'Get-EntraIDTokenFromNestedAppAuth'
        'Get-EntraIDTokenFromRefreshTokenCredentialCookie'
        'Get-EntraIDTokenFromSCCAUTHCookie'
        'Get-ForgedUserAgent'
        'Get-TenantID'
        'Get-WindowsHelloFidoAssertion'
        'Invoke-EntraIDPasskeyAssertionLogin'
        'Invoke-EntraIDPasskeyLogin'
        'Invoke-RefreshToAzureCoreManagementToken'
        'Invoke-RefreshToAzureKeyVaultToken'
        'Invoke-RefreshToAzureManagementToken'
        'Invoke-RefreshToAzureStorageToken'
        'Invoke-RefreshToDeviceRegistrationToken'
        'Invoke-RefreshToDODMSGraphToken'
        'Invoke-RefreshToGraphToken'
        'Invoke-RefreshToMAMToken'
        'Invoke-RefreshToMSGraphToken'
        'Invoke-RefreshToMSManageToken'
        'Invoke-RefreshToMSTeamsToken'
        'Invoke-RefreshToOfficeAppsToken'
        'Invoke-RefreshToOfficeManagementToken'
        'Invoke-RefreshToOneDriveToken'
        'Invoke-RefreshToOutlookToken'
        'Invoke-RefreshToSharePointToken'
        'Invoke-RefreshToSubstrateToken'
        'Invoke-RefreshToYammerToken'
        'New-EntraIDUserHandle'
        'New-TPMCertificate'
        'New-EntraIDImplicitAuthorizationUrl'
        'ConvertFrom-EntraIDImplicitRedirect'
        'New-EntraIDFederatedSigningCertificate'
        'New-EntraIDFederatedIssuerMetadata'
        'New-EntraIDFederatedClientAssertion'
    )

    AliasesToExport = @(
        'Parse-JWTtoken'
        'Forge-UserAgent'
        'RefreshTo-SubstrateToken'
        'RefreshTo-MSManageToken'
        'RefreshTo-MSTeamsToken'
        'RefreshTo-OfficeManagementToken'
        'RefreshTo-OutlookToken'
        'RefreshTo-MSGraphToken'
        'RefreshTo-GraphToken'
        'RefreshTo-OfficeAppsToken'
        'RefreshTo-AzureCoreManagementToken'
        'RefreshTo-AzureManagementToken'
        'RefreshTo-MAMToken'
        'RefreshTo-DODMSGraphToken'
        'RefreshTo-SharePointToken'
        'RefreshTo-OneDriveToken'
        'RefreshTo-YammerToken'
        'RefreshTo-AzureStorageToken'
        'RefreshTo-AzureKeyVaultToken'
        'RefreshTo-DeviceRegistrationToken'
        'Get-EntraIDToken'
        'Get-AzureToken'
        'Get-AzureTokenFromESTSCookie'
        'Get-AzureTokenFromAuthorizationCode'
        'Get-AzureAuthorizationCode'
        'Get-AzureTokenFromCookie'
        'Get-AzureTokenFromRefreshTokenCredentialCookie'
    )

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData       = @{
        PSData = @{
            Tags       = @('security', 'pentesting', 'red team', 'offense', 'jwt', 'token', 'azure')
            LicenseUri = 'https://github.com/f-bader/TokenTacticsv2/blob/main/LICENSE'
            ProjectUri = 'https://github.com/f-bader/TokenTacticsv2'
        }
    }
}
