BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force

    $script:ExpectedFunctions = @(
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

    $script:ExpectedAliases = @{
        'Forge-UserAgent'                                = 'Get-ForgedUserAgent'
        'Get-EntraIDToken'                             = 'Get-EntraIDTokenFromDeviceCode'
        'Get-AzureAuthorizationCode'                    = 'Get-EntraIDAuthorizationCode'
        'Get-AzureToken'                                = 'Get-EntraIDTokenFromDeviceCode'
        'Get-AzureTokenFromAuthorizationCode'           = 'Get-EntraIDTokenFromAuthorizationCode'
        'Get-AzureTokenFromCookie'                      = 'Get-EntraIDTokenFromCookie'
        'Get-AzureTokenFromESTSCookie'                  = 'Get-EntraIDTokenFromESTSCookie'
        'Get-AzureTokenFromRefreshTokenCredentialCookie' = 'Get-EntraIDTokenFromRefreshTokenCredentialCookie'
        'Parse-JWTtoken'                                = 'ConvertFrom-JWTtoken'
        'RefreshTo-AzureCoreManagementToken'            = 'Invoke-RefreshToAzureCoreManagementToken'
        'RefreshTo-AzureKeyVaultToken'                  = 'Invoke-RefreshToAzureKeyVaultToken'
        'RefreshTo-AzureManagementToken'                = 'Invoke-RefreshToAzureManagementToken'
        'RefreshTo-AzureStorageToken'                   = 'Invoke-RefreshToAzureStorageToken'
        'RefreshTo-DeviceRegistrationToken'             = 'Invoke-RefreshToDeviceRegistrationToken'
        'RefreshTo-DODMSGraphToken'                     = 'Invoke-RefreshToDODMSGraphToken'
        'RefreshTo-GraphToken'                          = 'Invoke-RefreshToGraphToken'
        'RefreshTo-MAMToken'                            = 'Invoke-RefreshToMAMToken'
        'RefreshTo-MSGraphToken'                        = 'Invoke-RefreshToMSGraphToken'
        'RefreshTo-MSManageToken'                       = 'Invoke-RefreshToMSManageToken'
        'RefreshTo-MSTeamsToken'                        = 'Invoke-RefreshToMSTeamsToken'
        'RefreshTo-OfficeAppsToken'                     = 'Invoke-RefreshToOfficeAppsToken'
        'RefreshTo-OfficeManagementToken'               = 'Invoke-RefreshToOfficeManagementToken'
        'RefreshTo-OneDriveToken'                       = 'Invoke-RefreshToOneDriveToken'
        'RefreshTo-OutlookToken'                        = 'Invoke-RefreshToOutlookToken'
        'RefreshTo-SharePointToken'                     = 'Invoke-RefreshToSharePointToken'
        'RefreshTo-SubstrateToken'                      = 'Invoke-RefreshToSubstrateToken'
        'RefreshTo-YammerToken'                         = 'Invoke-RefreshToYammerToken'
    }
}

Describe 'TokenTactics module contract' {
    It 'exports exactly the supported functions' {
        $actual = @(Get-Command -Module TokenTactics -CommandType Function | Select-Object -ExpandProperty Name | Sort-Object)
        $actual | Should -Be ($script:ExpectedFunctions | Sort-Object)
    }

    It 'exports exactly the supported aliases with the correct targets' {
        $actual = @(Get-Command -Module TokenTactics -CommandType Alias)
        @($actual.Name | Sort-Object) | Should -Be @($script:ExpectedAliases.Keys | Sort-Object)

        foreach ($alias in $actual) {
            $alias.Definition | Should -Be $script:ExpectedAliases[$alias.Name]
        }
    }

    It 'keeps implementation helpers private' {
        Get-Command ConvertTo-URLParameters -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        Get-Command Invoke-RefreshToToken -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        Get-Command New-FidoSignature -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
}
