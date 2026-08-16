BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force
    $script:TokenResponse = [pscustomobject]@{
        access_token = $script:FakeAccessToken
        token_type = 'Bearer'
        expires_in = 3600
    }
}

Describe 'Entra OAuth client registry' {
    It 'contains every built-in client exposed by the central resolver' {
        $expected = @(
            'Substrate', 'MSManage', 'MSTeams', 'OfficeManagement', 'Outlook',
            'MSGraph', 'Graph', 'OfficeApps', 'AzureCoreManagement',
            'AzureStorage', 'AzureKeyVault', 'AzureManagement', 'AzurePowerShell',
            'AzureCLI', 'MAM', 'DODMSGraph', 'SharePoint', 'OneDrive', 'Yammer',
            'DeviceRegistration'
        )

        $names = InModuleScope TokenTactics { Get-TTEntraOAuthClientNames }
        foreach ($name in $expected) {
            $names | Should -Contain $name
        }
        $names | Should -Contain 'Custom'
    }

    It 'uses the selected Azure Management client and retains the legacy cookie client' {
        $values = InModuleScope TokenTactics {
            [pscustomobject]@{
                AzureManagement = (Resolve-TTEntraOAuthClient -Client AzureManagement).ClientID
                AzurePowerShell = (Resolve-TTEntraOAuthClient -Client AzurePowerShell).ClientID
                LegacyCookie = (Resolve-TTLegacyOAuthClient -Client AzureManagement).ClientID
            }
        }

        $values.AzureManagement | Should -Be '1950a258-227b-4e31-a9cf-717495945fc2'
        $values.AzurePowerShell | Should -Be '1950a258-227b-4e31-a9cf-717495945fc2'
        $values.LegacyCookie | Should -Be '84070985-06ea-473d-82fe-eb82b4011c9d'
    }

    It 'resolves legacy Company Portal and passkey profiles' {
        $profiles = InModuleScope TokenTactics {
            [pscustomobject]@{
                Windows = Get-TTEntraOAuthProfile -Name AuthorizationCode
                Mobile = Get-TTEntraOAuthProfile -Name AuthorizationCodeMobile
                Passkey = Get-TTEntraOAuthProfile -Name LegacyPasskey
            }
        }

        $profiles.Windows.ClientID | Should -Be '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223'
        $profiles.Windows.RedirectUrl | Should -Be 'ms-appx-web://Microsoft.AAD.BrokerPlugin/S-1-15-2-2666988183-1750391847-2906264630-3525785777-2857982319-3063633125-1907478113'
        $profiles.Mobile.RedirectUrl | Should -Be 'msauth://com.microsoft.windowsintune.companyportal/1L4Z9FJCgn5c0VLhyAxC5O9LdlE='
        $profiles.Passkey.ClientID | Should -Be '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
        $profiles.Passkey.RedirectUrl | Should -Be 'https://login.microsoftonline.com/common/oauth2/nativeclient'
    }

    It 'marks Device Registration as a v1 client with its resource' {
        $client = InModuleScope TokenTactics { Resolve-TTEntraOAuthClient -Client DeviceRegistration }

        $client.UseV1Endpoint | Should -BeTrue
        $client.Resource | Should -Be '01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9'
    }

    It 'uses the registry scope for workload defaults' {
        InModuleScope TokenTactics { Get-TTEntraOAuthDefaultScope -Client MSGraph } |
            Should -Be 'https://graph.microsoft.com/.default'
    }
}

Describe 'Get-EntraIDTokenFromDeviceCode registry integration' {
    BeforeEach {
        Remove-Variable -Scope Global -Name response, TokenDomain, TokenUpn -ErrorAction SilentlyContinue
        Mock -ModuleName TokenTactics Get-ForgedUserAgent { 'TokenTactics-Test/1.0' }
        Mock -ModuleName TokenTactics Start-Sleep {}
    }

    AfterEach {
        Remove-Variable -Scope Global -Name response, TokenDomain, TokenUpn -ErrorAction SilentlyContinue
    }

    It 'sends Yammer as a v2 scope instead of a resource' {
        $deviceResponse = [pscustomobject]@{ device_code = 'yammer-device-code'; interval = 1; expires_in = 900 }
        Mock -ModuleName TokenTactics Invoke-RestMethod { $deviceResponse } -ParameterFilter {
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode' -and
            $Body['client_id'] -eq 'd3590ed6-52b3-4102-aeff-aad2292ab01c' -and
            $Body['scope'] -eq 'https://www.yammer.com/.default offline_access openid' -and
            -not $Body.ContainsKey('resource')
        }
        Mock -ModuleName TokenTactics Invoke-RestMethod { $script:TokenResponse } -ParameterFilter {
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
        }

        Get-EntraIDTokenFromDeviceCode -Client Yammer | Out-Null

        Should -Invoke Invoke-RestMethod -ModuleName TokenTactics -Times 1 -Exactly -Scope It -ParameterFilter {
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode' -and
            $Body['scope'] -eq 'https://www.yammer.com/.default offline_access openid' -and
            -not $Body.ContainsKey('resource')
        }
    }

    It 'uses the registry v1 endpoint for Device Registration' {
        $deviceResponse = [pscustomobject]@{ device_code = 'drs-device-code'; interval = 1; expires_in = 900 }
        Mock -ModuleName TokenTactics Invoke-RestMethod { $deviceResponse } -ParameterFilter {
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/devicecode' -and
            $Body['client_id'] -eq '1b730954-1685-4b74-9bfd-dac224a7b894' -and
            $Body['resource'] -eq '01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9'
        }
        Mock -ModuleName TokenTactics Invoke-RestMethod { $script:TokenResponse } -ParameterFilter {
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/token' -and
            $Body['code'] -eq 'drs-device-code' -and
            -not $Body.ContainsKey('device_code') -and
            $Body['resource'] -eq '01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9'
        }

        Get-EntraIDTokenFromDeviceCode -Client DeviceRegistration | Out-Null

        Should -Invoke Invoke-RestMethod -ModuleName TokenTactics -Times 1 -Exactly -Scope It -ParameterFilter {
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/devicecode' -and
            $Body['resource'] -eq '01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9'
        }
    }
}
