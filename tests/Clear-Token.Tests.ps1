$tokenCases = @(
    @{ Token = 'Response'; Variable = 'response' }
    @{ Token = 'Outlook'; Variable = 'OutlookToken' }
    @{ Token = 'MSTeams'; Variable = 'MSTeamsToken' }
    @{ Token = 'Graph'; Variable = 'GraphToken' }
    @{ Token = 'AzureCoreManagement'; Variable = 'AzureCoreManagementToken' }
    @{ Token = 'AzureManagement'; Variable = 'AzureManagementToken' }
    @{ Token = 'AzureStorage'; Variable = 'AzureStorageToken' }
    @{ Token = 'AzureKeyVault'; Variable = 'AzureKeyVaultToken' }
    @{ Token = 'OfficeManagement'; Variable = 'OfficeManagementToken' }
    @{ Token = 'OfficeApps'; Variable = 'OfficeAppsToken' }
    @{ Token = 'MSGraph'; Variable = 'MSGraphToken' }
    @{ Token = 'MSManage'; Variable = 'MSManageToken' }
    @{ Token = 'DODMSGraph'; Variable = 'DODMSGraphToken' }
    @{ Token = 'MAM'; Variable = 'MAMToken' }
    @{ Token = 'Custom'; Variable = 'CustomToken' }
    @{ Token = 'Substrate'; Variable = 'SubstrateToken' }
    @{ Token = 'SharePoint'; Variable = 'SharePointToken' }
    @{ Token = 'OneDrive'; Variable = 'OneDriveToken' }
    @{ Token = 'Yammer'; Variable = 'YammerToken' }
    @{ Token = 'DeviceRegistration'; Variable = 'DeviceRegistrationToken' }
)

BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force

    $script:TokenVariables = @(
        'response', 'OutlookToken', 'MSTeamsToken', 'GraphToken',
        'AzureCoreManagementToken', 'AzureManagementToken', 'AzureStorageToken',
        'AzureKeyVaultToken', 'OfficeManagementToken', 'OfficeAppsToken',
        'MSGraphToken', 'MSManageToken', 'DODMSGraphToken', 'MAMToken',
        'CustomToken', 'SubstrateToken', 'SharePointToken', 'OneDriveToken',
        'YammerToken', 'DeviceRegistrationToken'
    )
    $script:OriginalGlobals = @{}
    foreach ($name in $script:TokenVariables) {
        $existing = Get-Variable -Scope Global -Name $name -ErrorAction SilentlyContinue
        if ($existing) {
            $script:OriginalGlobals[$name] = $existing.Value
        }
    }
}

AfterAll {
    if ($script:TokenVariables) {
        Remove-Variable -Scope Global -Name $script:TokenVariables -ErrorAction SilentlyContinue
    }
    foreach ($entry in $script:OriginalGlobals.GetEnumerator()) {
        Set-Variable -Scope Global -Name $entry.Key -Value $entry.Value
    }
}

Describe 'Clear-Token' {
    BeforeEach {
        foreach ($name in $script:TokenVariables) {
            Set-Variable -Scope Global -Name $name -Value ([PSCustomObject]@{ access_token = $name })
        }
    }

    AfterEach {
        Remove-Variable -Scope Global -Name $script:TokenVariables -ErrorAction SilentlyContinue
    }

    It 'removes every token variable for -Token All' {
        Clear-Token -Token All

        foreach ($name in $script:TokenVariables) {
            Get-Variable -Scope Global -Name $name -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }
    }

    It 'removes <Variable> and no other variable for -Token <Token>' -ForEach $tokenCases {
        Clear-Token -Token $Token

        Get-Variable -Scope Global -Name $Variable -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        foreach ($otherName in $script:TokenVariables | Where-Object { $_ -ne $Variable }) {
            (Get-Variable -Scope Global -Name $otherName -ErrorAction Stop).Value.access_token | Should -Be $otherName
        }
    }

    It 'does not throw when the selected variable does not exist' {
        Remove-Variable -Scope Global -Name MSTeamsToken -ErrorAction SilentlyContinue
        { Clear-Token -Token MSTeams } | Should -Not -Throw
    }
}
