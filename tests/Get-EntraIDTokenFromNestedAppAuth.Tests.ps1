BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force

    $script:FakeTenantId = "aaaabbbb-cccc-dddd-eeee-ffffaaaabbbb"
    $script:FakeTokenResponse = [PSCustomObject]@{
        access_token   = $script:FakeAccessToken
        refresh_token  = $script:FakeRefreshToken
        token_type     = "Bearer"
        expires_in     = 3600
        ext_expires_in = 3600
        scope          = "User.Read"
    }
}

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
