BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force

    # Build a fake token response object used across all tests
    $script:FakeTenantId = "aaaabbbb-cccc-dddd-eeee-ffffaaaabbbb"
    $script:FakeTokenResponse = [PSCustomObject]@{
        access_token  = $script:FakeAccessToken
        refresh_token = $script:FakeRefreshToken
        token_type    = "Bearer"
        expires_in    = 3600
        ext_expires_in = 3600
        scope         = "User.Read"
    }
    $script:FakeOpenIdConfig = [PSCustomObject]@{
        authorization_endpoint = "https://login.microsoftonline.com/$($script:FakeTenantId)/oauth2/authorize"
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToToken (internal)
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }

    It "Calls Get-TenantID with the supplied domain" {
        InModuleScope TokenTactics {
            Invoke-RefreshToToken -Domain "contoso.com" -refreshToken "rt1" -ClientID "client1" -Scope "https://graph.microsoft.com/.default"
        }
        Should -Invoke -ModuleName TokenTactics Get-TenantID -ParameterFilter { $domain -eq "contoso.com" } -Times 1
    }

    It "Calls the v2.0 token endpoint by default" {
        InModuleScope TokenTactics {
            Invoke-RefreshToToken -Domain "contoso.com" -refreshToken "rt1" -ClientID "client1" -Scope "https://graph.microsoft.com/.default"
        }
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Uri -match "oauth2/v2\.0/token"
        } -Times 1
    }

    It "Uses the v1 token endpoint when -UseV1Endpoint is set" {
        InModuleScope TokenTactics {
            Invoke-RefreshToToken -Domain "contoso.com" -refreshToken "rt1" -ClientID "client1" -Scope "openid" -UseV1Endpoint
        }
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Uri -match "oauth2/token" -and $Uri -notmatch "v2\.0"
        } -Times 1
    }

    It "Returns the token response from Invoke-RestMethod" {
        $result = InModuleScope TokenTactics {
            Invoke-RefreshToToken -Domain "contoso.com" -refreshToken "rt1" -ClientID "client1" -Scope "https://graph.microsoft.com/.default"
        }
        $result.token_type | Should -Be "Bearer"
    }

    It "Adds CAE claims to the body when -UseCAE is set" {
        InModuleScope TokenTactics {
            Invoke-RefreshToToken -Domain "contoso.com" -refreshToken "rt1" -ClientID "client1" -Scope "https://graph.microsoft.com/.default" -UseCAE
        }
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body.ContainsKey("claims") -and $Body["claims"] -match "cp1"
        } -Times 1
    }

    It "Uses the DoD login endpoint when -UseDoD is set" {
        InModuleScope TokenTactics {
            Invoke-RefreshToToken -Domain "contoso.com" -refreshToken "rt1" -ClientID "client1" -Scope "https://dod-graph.microsoft.us/.default" -UseDoD
        }
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Uri -match "microsoftonline\.us"
        } -Times 1
    }

    It "sends one exact refresh-token request" {
        InModuleScope TokenTactics {
            Invoke-RefreshToToken `
                -Domain 'contoso.com' `
                -refreshToken 'exact-refresh-token' `
                -ClientID 'exact-client-id' `
                -Scope 'api://exact/.default offline_access' `
                -CustomUserAgent 'Exact-Agent/1.0'
        }

        Should -Invoke -ModuleName TokenTactics Get-TenantID -Times 1 -Exactly -Scope It -ParameterFilter {
            $domain -eq 'contoso.com'
        }
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -Times 1 -Exactly -Scope It -ParameterFilter {
            $UseBasicParsing -and
            "$Method" -eq 'Post' -and
            $Uri -eq "https://login.microsoftonline.com/$script:FakeTenantId/oauth2/v2.0/token" -and
            $Headers.Count -eq 1 -and
            $Headers['User-Agent'] -eq 'Exact-Agent/1.0' -and
            $Body.Count -eq 4 -and
            $Body['scope'] -eq 'api://exact/.default offline_access' -and
            $Body['client_id'] -eq 'exact-client-id' -and
            $Body['grant_type'] -eq 'refresh_token' -and
            $Body['refresh_token'] -eq 'exact-refresh-token'
        }
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToMSGraphToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToMSGraphToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name MSGraphToken -ErrorAction SilentlyContinue
    }

    It "Sets `$global:MSGraphToken after a successful call" {
        Invoke-RefreshToMSGraphToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        $global:MSGraphToken | Should -Not -BeNullOrEmpty
    }

    It "Uses the MSGraph scope" {
        Invoke-RefreshToMSGraphToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["scope"] -match "graph\.microsoft\.com"
        } -Times 1
    }

    It "Outputs a success message" {
        $output = Invoke-RefreshToMSGraphToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        ($output | ForEach-Object { "$_" } | Where-Object { $_ -match "MSGraphToken" }).Count | Should -BeGreaterThan 0
    }

    It "Outputs an error message when Invoke-RestMethod throws" {
        Mock -ModuleName TokenTactics Invoke-RestMethod { throw "network error" } -Verifiable
        $output = @(Invoke-RefreshToMSGraphToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken 2>&1)
        ($output | ForEach-Object { "$_" } | Where-Object { $_ -match "Could not get tokens" }).Count | Should -BeGreaterThan 0
        ($output -join "`n") | Should -Match 'network error'
        @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToGraphToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToGraphToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name GraphToken -ErrorAction SilentlyContinue
    }

    It "Sets `$global:GraphToken after a successful call" {
        Invoke-RefreshToGraphToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        $global:GraphToken | Should -Not -BeNullOrEmpty
    }

    It "Uses the Windows Graph (graph.windows.net) scope" {
        Invoke-RefreshToGraphToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["scope"] -match "graph\.windows\.net"
        } -Times 1
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToMSTeamsToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToMSTeamsToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name MSTeamsToken -ErrorAction SilentlyContinue
    }

    It "Sets `$global:MSTeamsToken after a successful call" {
        Invoke-RefreshToMSTeamsToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        $global:MSTeamsToken | Should -Not -BeNullOrEmpty
    }

    It "Uses the Teams (api.spaces.skype.com) scope" {
        Invoke-RefreshToMSTeamsToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["scope"] -match "api\.spaces\.skype\.com"
        } -Times 1
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToOutlookToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToOutlookToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name OutlookToken -ErrorAction SilentlyContinue
    }

    It "Sets `$global:OutlookToken after a successful call" {
        Invoke-RefreshToOutlookToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        $global:OutlookToken | Should -Not -BeNullOrEmpty
    }

    It "Uses the Outlook (outlook.office365.com) scope" {
        Invoke-RefreshToOutlookToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["scope"] -match "outlook\.office365\.com"
        } -Times 1
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToSubstrateToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToSubstrateToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name SubstrateToken -ErrorAction SilentlyContinue
    }

    It "Sets `$global:SubstrateToken after a successful call" {
        Invoke-RefreshToSubstrateToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        $global:SubstrateToken | Should -Not -BeNullOrEmpty
    }

    It "Uses the Substrate (substrate.office.com) scope" {
        Invoke-RefreshToSubstrateToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["scope"] -match "substrate\.office\.com"
        } -Times 1
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToOfficeManagementToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToOfficeManagementToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name OfficeManagementToken -ErrorAction SilentlyContinue
    }

    It "Sets `$global:OfficeManagementToken after a successful call" {
        Invoke-RefreshToOfficeManagementToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        $global:OfficeManagementToken | Should -Not -BeNullOrEmpty
    }

    It "Uses the Office Management (manage.office.com) scope" {
        Invoke-RefreshToOfficeManagementToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["scope"] -match "manage\.office\.com"
        } -Times 1
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToOfficeAppsToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToOfficeAppsToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name OfficeAppsToken -ErrorAction SilentlyContinue
    }

    It "Sets `$global:OfficeAppsToken after a successful call" {
        Invoke-RefreshToOfficeAppsToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        $global:OfficeAppsToken | Should -Not -BeNullOrEmpty
    }

    It "Uses the OfficeApps (officeapps.live.com) scope" {
        Invoke-RefreshToOfficeAppsToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["scope"] -match "officeapps\.live\.com"
        } -Times 1
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToAzureCoreManagementToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToAzureCoreManagementToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name AzureCoreManagementToken -ErrorAction SilentlyContinue
    }

    It "Sets `$global:AzureCoreManagementToken after a successful call" {
        Invoke-RefreshToAzureCoreManagementToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        $global:AzureCoreManagementToken | Should -Not -BeNullOrEmpty
    }

    It "Uses the AzureCore (management.core.windows.net) scope" {
        Invoke-RefreshToAzureCoreManagementToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["scope"] -match "management\.core\.windows\.net"
        } -Times 1
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToAzureManagementToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToAzureManagementToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name AzureManagementToken -ErrorAction SilentlyContinue
    }

    It "Sets `$global:AzureManagementToken after a successful call" {
        Invoke-RefreshToAzureManagementToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        $global:AzureManagementToken | Should -Not -BeNullOrEmpty
    }

    It "Uses the AzureManagement (management.azure.com) scope" {
        Invoke-RefreshToAzureManagementToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["scope"] -match "management\.azure\.com"
        } -Times 1
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToAzureStorageToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToAzureStorageToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name AzureStorageToken -ErrorAction SilentlyContinue
    }

    It "Sets `$global:AzureStorageToken after a successful call" {
        Invoke-RefreshToAzureStorageToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        $global:AzureStorageToken | Should -Not -BeNullOrEmpty
    }

    It "Uses the AzureStorage (storage.azure.com) scope" {
        Invoke-RefreshToAzureStorageToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["scope"] -match "storage\.azure\.com"
        } -Times 1
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToAzureKeyVaultToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToAzureKeyVaultToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name AzureKeyVaultToken -ErrorAction SilentlyContinue
    }

    It "Sets `$global:AzureKeyVaultToken after a successful call" {
        Invoke-RefreshToAzureKeyVaultToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        $global:AzureKeyVaultToken | Should -Not -BeNullOrEmpty
    }

    It "Uses the AzureKeyVault (vault.azure.net) scope" {
        Invoke-RefreshToAzureKeyVaultToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["scope"] -match "vault\.azure\.net"
        } -Times 1
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToMAMToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToMAMToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name MAMToken -ErrorAction SilentlyContinue
    }

    It "Sets `$global:MAMToken after a successful call" {
        Invoke-RefreshToMAMToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        $global:MAMToken | Should -Not -BeNullOrEmpty
    }

    It "Uses the MAM (intunemam.microsoftonline.com) scope" {
        Invoke-RefreshToMAMToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["scope"] -match "intunemam\.microsoftonline\.com"
        } -Times 1
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToMSManageToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToMSManageToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name MSManageToken -ErrorAction SilentlyContinue
    }

    It "Sets `$global:MSManageToken after a successful call" {
        Invoke-RefreshToMSManageToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        $global:MSManageToken | Should -Not -BeNullOrEmpty
    }

    It "Uses the MSManage (enrollment.manage.microsoft.com) scope" {
        Invoke-RefreshToMSManageToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["scope"] -match "enrollment\.manage\.microsoft\.com"
        } -Times 1
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToDODMSGraphToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToDODMSGraphToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name DODMSGraphToken -ErrorAction SilentlyContinue
    }

    It "Sets `$global:DODMSGraphToken after a successful call" {
        Invoke-RefreshToDODMSGraphToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        $global:DODMSGraphToken | Should -Not -BeNullOrEmpty
    }

    It "Uses the DoD Graph (dod-graph.microsoft.us) scope" {
        Invoke-RefreshToDODMSGraphToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["scope"] -match "dod-graph\.microsoft\.us"
        } -Times 1
    }

    It "Calls the DoD login endpoint" {
        Invoke-RefreshToDODMSGraphToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Uri -match "microsoftonline\.us"
        } -Times 1
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToSharePointToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToSharePointToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name SharePointToken -ErrorAction SilentlyContinue
    }

    It "Sets `$global:SharePointToken after a successful call" {
        Invoke-RefreshToSharePointToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken -SharePointTenantName "contoso"
        $global:SharePointToken | Should -Not -BeNullOrEmpty
    }

    It "Builds the scope using the provided SharePointTenantName" {
        Invoke-RefreshToSharePointToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken -SharePointTenantName "contoso"
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["scope"] -match "contoso\.sharepoint\.com"
        } -Times 1
    }

    It "Appends -admin suffix when -SharePointUseAdmin is set" {
        Invoke-RefreshToSharePointToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken -SharePointTenantName "contoso" -SharePointUseAdmin
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["scope"] -match "contoso-admin\.sharepoint\.com"
        } -Times 1
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToOneDriveToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToOneDriveToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name OneDriveToken -ErrorAction SilentlyContinue
    }

    It "Sets `$global:OneDriveToken after a successful call" {
        Invoke-RefreshToOneDriveToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        $global:OneDriveToken | Should -Not -BeNullOrEmpty
    }

    It "Uses the OneDrive (officeapps.live.com) scope" {
        Invoke-RefreshToOneDriveToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["scope"] -match "officeapps\.live\.com"
        } -Times 1
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToYammerToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToYammerToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name YammerToken -ErrorAction SilentlyContinue
    }

    It "sets the Yammer token using the Yammer resource rather than the Teams resource" {
        Invoke-RefreshToYammerToken -Domain 'contoso.com' -RefreshToken $script:FakeRefreshToken

        $global:YammerToken | Should -Be $script:FakeTokenResponse
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -Times 1 -Exactly -Scope It -ParameterFilter {
            $Body['scope'] -eq 'https://www.yammer.com/.default offline_access openid' -and
            $Body['scope'] -notmatch 'api\.spaces\.skype\.com' -and
            $Body['grant_type'] -eq 'refresh_token' -and
            $Body['refresh_token'] -eq $script:FakeRefreshToken
        }
    }
}

# ---------------------------------------------------------------------------
# Invoke-RefreshToDeviceRegistrationToken
# ---------------------------------------------------------------------------
Describe "Invoke-RefreshToDeviceRegistrationToken" {
    BeforeAll {
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name DeviceRegistrationToken -ErrorAction SilentlyContinue
    }

    It "Sets `$global:DeviceRegistrationToken after a successful call" {
        Invoke-RefreshToDeviceRegistrationToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        $global:DeviceRegistrationToken | Should -Not -BeNullOrEmpty
    }

    It "Uses the v1 endpoint for device registration" {
        Invoke-RefreshToDeviceRegistrationToken -Domain "contoso.com" -RefreshToken $script:FakeRefreshToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Uri -match "oauth2/token" -and $Uri -notmatch "v2\.0"
        } -Times 1
    }
}

# ---------------------------------------------------------------------------
# Get-EntraIDTokenFromAuthorizationCode
# ---------------------------------------------------------------------------
Describe "Get-EntraIDTokenFromAuthorizationCode" {
    BeforeAll {
        Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeTokenResponse }
    }
    AfterEach {
        Remove-Variable -Scope Global -Name response -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name TokenDomain -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name TokenUpn -ErrorAction SilentlyContinue
    }

    It "Sets `$global:response after a successful call" {
        Get-EntraIDTokenFromAuthorizationCode -AuthorizationCode "auth-code-123"
        $global:response | Should -Not -BeNullOrEmpty
    }

    It "Calls the v2.0 token endpoint by default" {
        Get-EntraIDTokenFromAuthorizationCode -AuthorizationCode "auth-code-123"
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Uri -match "oauth2/v2\.0/token"
        } -Times 1
    }

    It "Sends grant_type=authorization_code" {
        Get-EntraIDTokenFromAuthorizationCode -AuthorizationCode "auth-code-123"
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["grant_type"] -eq "authorization_code"
        } -Times 1
    }

    It "Extracts authorization code from a RequestURL" {
        $requestUrl = "ms-appx-web://Microsoft.AAD.BrokerPlugin/S-1-15-2-123?code=extracted-code-456&state=abc"
        Get-EntraIDTokenFromAuthorizationCode -RequestURL $requestUrl
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Body -is [hashtable] -and $Body["code"] -eq "extracted-code-456"
        } -Times 1
    }

    It "Sets `$global:TokenDomain from the token's upn" {
        Get-EntraIDTokenFromAuthorizationCode -AuthorizationCode "auth-code-123"
        $global:TokenDomain | Should -Be "contoso.com"
    }

    It "Sets `$global:TokenUpn from the token" {
        Get-EntraIDTokenFromAuthorizationCode -AuthorizationCode "auth-code-123"
        $global:TokenUpn | Should -Be "test.user@contoso.com"
    }
}

# ---------------------------------------------------------------------------
# Get-EntraIDTokenFromNestedAppAuth
# ---------------------------------------------------------------------------
Describe "Get-EntraIDTokenFromNestedAppAuth" {
    $brokerPresetCases = @(
        @{
            BrokerPreset      = 'AzurePortal'
            BrokerClientId    = 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c'
            BrokerRedirectUri = 'https://portal.azure.com/auth/redirect/'
            RedirectUri       = 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com'
        }
        @{
            BrokerPreset      = 'Microsoft365'
            BrokerClientId    = '4765445b-32c6-49b0-83e6-1d93765276ca'
            BrokerRedirectUri = 'https://www.microsoft365.com/spalanding'
            RedirectUri       = 'brk-4765445b-32c6-49b0-83e6-1d93765276ca://www.microsoft365.com'
        }
        @{
            BrokerPreset      = 'EntraAdminCenter'
            BrokerClientId    = 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c'
            BrokerRedirectUri = 'https://entra.microsoft.com/auth/login/'
            RedirectUri       = 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://entra.microsoft.com'
        }
        @{
            BrokerPreset      = 'IntuneAdminCenter'
            BrokerClientId    = 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c'
            BrokerRedirectUri = 'https://intune.microsoft.com/auth/login/'
            RedirectUri       = 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://intune.microsoft.com'
        }
        @{
            BrokerPreset      = 'Defender'
            BrokerClientId    = '80ccca67-54bd-44ab-8625-4b79c4dc7775'
            BrokerRedirectUri = 'https://security.microsoft.com/Blank'
            RedirectUri       = 'brk-80ccca67-54bd-44ab-8625-4b79c4dc7775://security.microsoft.com'
        }
        @{
            BrokerPreset      = 'Purview'
            BrokerClientId    = '80ccca67-54bd-44ab-8625-4b79c4dc7775'
            BrokerRedirectUri = 'https://purview.microsoft.com/Blank'
            RedirectUri       = 'brk-80ccca67-54bd-44ab-8625-4b79c4dc7775://purview.microsoft.com'
        }
    )

    BeforeEach {
        foreach ($name in 'response', 'TokenDomain', 'TokenUpn') {
            Remove-Variable -Scope Global -Name $name -ErrorAction SilentlyContinue
        }

        Mock -ModuleName TokenTactics Invoke-RestMethod { throw "Unexpected REST request: $Method $Uri" }
        Mock -ModuleName TokenTactics Get-TenantID { return $script:FakeTenantId }
    }

    AfterEach {
        foreach ($name in 'response', 'TokenDomain', 'TokenUpn') {
            Remove-Variable -Scope Global -Name $name -ErrorAction SilentlyContinue
        }
    }

    It "sends the exact Azure Portal brokered token request with CAE claims" {
        $brokerClientId = 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c'
        $brokerRedirectUri = 'https://portal.azure.com/auth/redirect/'
        $clientRequestId = '11111111-2222-3333-4444-555555555555'
        $anchorMailbox = "Oid:3135fd4e-140c-43c0-ad02-718913648fb9@$($script:FakeTenantId)"
        $claims = '{"access_token":{"xms_cc":{"values":["cp1"]}}}'

        Mock -ModuleName TokenTactics Invoke-RestMethod { $script:FakeTokenResponse } -ParameterFilter {
            $parsedUri = [Uri]$Uri
            $query = [System.Web.HttpUtility]::ParseQueryString($parsedUri.Query)

            $UseBasicParsing -and
            "$Method" -eq 'Post' -and
            $parsedUri.Scheme -eq 'https' -and
            $parsedUri.Host -eq 'login.microsoftonline.com' -and
            $parsedUri.AbsolutePath -eq "/$script:FakeTenantId/oauth2/v2.0/token" -and
            $Headers -is [System.Collections.IDictionary] -and
            $Headers.Count -eq 1 -and
            $Headers['User-Agent'] -eq 'Nested-Agent/1.0' -and
            $query.Count -eq 3 -and
            $query['brk_client_id'] -eq $brokerClientId -and
            $query['brk_redirect_uri'] -eq $brokerRedirectUri -and
            $query['client-request-id'] -eq $clientRequestId -and
            $Body -is [System.Collections.IDictionary] -and
            $Body.Count -eq 13 -and
            $Body['client_id'] -eq '74658136-14ec-4630-ad9b-26e160ff0fc6' -and
            $Body['redirect_uri'] -eq 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com' -and
            $Body['scope'] -eq 'https://graph.microsoft.com/.default openid profile offline_access' -and
            $Body['grant_type'] -eq 'refresh_token' -and
            $Body['client_info'] -eq '1' -and
            $Body['x-client-SKU'] -eq 'msal.js.browser' -and
            $Body['x-client-VER'] -eq '5.13.0' -and
            $Body['x-ms-lib-capability'] -eq 'retry-after, h429' -and
            $Body['refresh_token'] -eq 'nested-app-refresh-token' -and
            $Body['brk_client_id'] -eq $brokerClientId -and
            $Body['brk_redirect_uri'] -eq $brokerRedirectUri -and
            $Body['X-AnchorMailbox'] -eq $anchorMailbox -and
            $Body['claims'] -eq $claims
        }

        Get-EntraIDTokenFromNestedAppAuth `
            -TenantId $script:FakeTenantId `
            -RefreshToken 'nested-app-refresh-token' `
            -CustomUserAgent 'Nested-Agent/1.0' `
            -ClientRequestId $clientRequestId `
            -AnchorMailbox $anchorMailbox `
            -UseCAE

        $global:response | Should -Be $script:FakeTokenResponse
        $global:TokenDomain | Should -Be 'contoso.com'
        $global:TokenUpn | Should -Be 'test.user@contoso.com'
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -Times 1 -Exactly -Scope It
    }

    It "matches the Teams Cloud brokered request shape for the provided example" {
        $brokerClientId = '5e3ce6c0-2b1f-4285-8d4b-75ee78787346'
        $brokerRedirectUri = 'https://teams.cloud.microsoft/v2/authv2'
        $clientRequestId = '019f9eab-d509-781d-8e67-1ca76d834633'
        $anchorMailbox = "Oid:e7417ac7-0485-4014-9100-33163bd6211f@$($script:FakeTenantId)"
        $clientId = '4765445b-32c6-49b0-83e6-1d93765276ca'
        $scope = '4765445b-32c6-49b0-83e6-1d93765276ca/.default openid profile offline_access'

        Mock -ModuleName TokenTactics Invoke-RestMethod { $script:FakeTokenResponse } -ParameterFilter {
            $parsedUri = [Uri]$Uri
            $query = [System.Web.HttpUtility]::ParseQueryString($parsedUri.Query)

            $UseBasicParsing -and
            "$Method" -eq 'Post' -and
            $parsedUri.Scheme -eq 'https' -and
            $parsedUri.Host -eq 'login.microsoftonline.com' -and
            $parsedUri.AbsolutePath -eq "/$script:FakeTenantId/oauth2/v2.0/token" -and
            $Headers -is [System.Collections.IDictionary] -and
            $Headers.Count -eq 1 -and
            $Headers['User-Agent'] -eq 'Nested-Agent/Teams' -and
            $query.Count -eq 4 -and
            $query['client_id'] -eq $clientId -and
            $query['brk_client_id'] -eq $brokerClientId -and
            $query['brk_redirect_uri'] -eq $brokerRedirectUri -and
            $query['client-request-id'] -eq $clientRequestId -and
            $Body -is [System.Collections.IDictionary] -and
            $Body.Count -eq 14 -and
            $Body['client_id'] -eq $clientId -and
            $Body['redirect_uri'] -eq 'brk-multihub://m365.cloud.microsoft' -and
            $Body['scope'] -eq $scope -and
            $Body['grant_type'] -eq 'refresh_token' -and
            $Body['client_info'] -eq '1' -and
            $Body['x-client-SKU'] -eq 'msal.js.browser' -and
            $Body['x-client-VER'] -eq '5.6.3' -and
            $Body['x-ms-lib-capability'] -eq 'retry-after, h429' -and
            $Body['x-client-current-telemetry'] -eq '5|61,0,,,,|,' -and
            $Body['x-client-last-telemetry'] -eq '5|0||||0,0' -and
            $Body['refresh_token'] -eq 'teams-refresh-token' -and
            $Body['X-AnchorMailbox'] -eq $anchorMailbox -and
            $Body['brk_client_id'] -eq $brokerClientId -and
            $Body['brk_redirect_uri'] -eq $brokerRedirectUri
        }

        Get-EntraIDTokenFromNestedAppAuth `
            -BrokerPreset Teams `
            -TenantId $script:FakeTenantId `
            -RefreshToken 'teams-refresh-token' `
            -ClientId $clientId `
            -Scope $scope `
            -ClientRequestId $clientRequestId `
            -AnchorMailbox $anchorMailbox `
            -CustomUserAgent 'Nested-Agent/Teams'

        $global:response | Should -Be $script:FakeTokenResponse
        $global:TokenDomain | Should -Be 'contoso.com'
        $global:TokenUpn | Should -Be 'test.user@contoso.com'
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -Times 1 -Exactly -Scope It
    }

    It "maps the <BrokerPreset> broker preset to the expected broker values" -ForEach $brokerPresetCases {
        Mock -ModuleName TokenTactics Invoke-RestMethod { $script:FakeTokenResponse } -ParameterFilter {
            $parsedUri = [Uri]$Uri
            $query = [System.Web.HttpUtility]::ParseQueryString($parsedUri.Query)

            $UseBasicParsing -and
            "$Method" -eq 'Post' -and
            $parsedUri.Scheme -eq 'https' -and
            $parsedUri.Host -eq 'login.microsoftonline.com' -and
            $parsedUri.AbsolutePath -eq "/$script:FakeTenantId/oauth2/v2.0/token" -and
            $Headers -is [System.Collections.IDictionary] -and
            $Headers.Count -eq 1 -and
            $Headers['User-Agent'] -eq 'Nested-Agent/Preset' -and
            $query['brk_client_id'] -eq $BrokerClientId -and
            $query['brk_redirect_uri'] -eq $BrokerRedirectUri -and
            $Body -is [System.Collections.IDictionary] -and
            $Body.Count -eq 11 -and
            $Body['client_id'] -eq 'nested-client-id' -and
            $Body['redirect_uri'] -eq $RedirectUri -and
            $Body['scope'] -eq 'api://nested/.default offline_access' -and
            $Body['grant_type'] -eq 'refresh_token' -and
            $Body['refresh_token'] -eq 'preset-refresh-token' -and
            $Body['brk_client_id'] -eq $BrokerClientId -and
            $Body['brk_redirect_uri'] -eq $BrokerRedirectUri
        }

        Get-EntraIDTokenFromNestedAppAuth `
            -BrokerPreset $BrokerPreset `
            -TenantId $script:FakeTenantId `
            -RefreshToken 'preset-refresh-token' `
            -ClientId 'nested-client-id' `
            -Scope 'api://nested/.default offline_access' `
            -CustomUserAgent 'Nested-Agent/Preset' `
            -ClientRequestId '99999999-8888-7777-6666-555555555555'

        $global:response | Should -Be $script:FakeTokenResponse
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -Times 1 -Exactly -Scope It
    }

    It "uses `$response.refresh_token as a fallback and lets explicit broker overrides win over the preset" {
        $global:response = [PSCustomObject]@{ refresh_token = 'fallback-refresh-token' }
        $brokerClientId = '11111111-2222-3333-4444-555555555555'
        $brokerRedirectUri = 'https://contoso.example/auth/callback/'
        $clientRequestId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

        Mock -ModuleName TokenTactics Invoke-RestMethod { $script:FakeTokenResponse } -ParameterFilter {
            $parsedUri = [Uri]$Uri
            $query = [System.Web.HttpUtility]::ParseQueryString($parsedUri.Query)

            $UseBasicParsing -and
            "$Method" -eq 'Post' -and
            $parsedUri.Scheme -eq 'https' -and
            $parsedUri.Host -eq 'login.microsoftonline.com' -and
            $parsedUri.AbsolutePath -eq "/$script:FakeTenantId/oauth2/v2.0/token" -and
            $Headers -is [System.Collections.IDictionary] -and
            $Headers.Count -eq 1 -and
            $Headers['User-Agent'] -eq 'Nested-Agent/2.0' -and
            $query.Count -eq 3 -and
            $query['brk_client_id'] -eq $brokerClientId -and
            $query['brk_redirect_uri'] -eq $brokerRedirectUri -and
            $query['client-request-id'] -eq $clientRequestId -and
            $Body -is [System.Collections.IDictionary] -and
            $Body.Count -eq 11 -and
            $Body['client_id'] -eq 'nested-client-id' -and
            $Body['redirect_uri'] -eq 'brk-11111111-2222-3333-4444-555555555555://contoso.example' -and
            $Body['scope'] -eq 'api://nested/.default offline_access' -and
            $Body['grant_type'] -eq 'refresh_token' -and
            $Body['client_info'] -eq '1' -and
            $Body['x-client-SKU'] -eq 'msal.js.browser' -and
            $Body['x-client-VER'] -eq '5.13.0' -and
            $Body['x-ms-lib-capability'] -eq 'retry-after, h429' -and
            $Body['refresh_token'] -eq 'fallback-refresh-token' -and
            $Body['brk_client_id'] -eq $brokerClientId -and
            $Body['brk_redirect_uri'] -eq $brokerRedirectUri
        }

        Get-EntraIDTokenFromNestedAppAuth `
            -BrokerPreset 'Defender' `
            -Domain 'contoso.com' `
            -BrokerClientId $brokerClientId `
            -BrokerRedirectUri $brokerRedirectUri `
            -ClientId 'nested-client-id' `
            -Scope 'api://nested/.default offline_access' `
            -CustomUserAgent 'Nested-Agent/2.0' `
            -ClientRequestId $clientRequestId

        $global:response | Should -Be $script:FakeTokenResponse
        Should -Invoke -ModuleName TokenTactics Get-TenantID -Times 1 -Exactly -Scope It -ParameterFilter {
            $domain -eq 'contoso.com'
        }
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -Times 1 -Exactly -Scope It
    }
}
