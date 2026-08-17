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

    It "validates an expected state before exchanging a RequestURL" {
        $requestUrl = "https://app.example/callback?code=state-code&state=ExactState"

        Get-EntraIDTokenFromAuthorizationCode -RequestURL $requestUrl -ExpectedState 'ExactState'

        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -Times 1
    }

    It "rejects a mismatched state without calling the token endpoint" {
        $requestUrl = "https://app.example/callback?code=state-code&state=ExactState"

        { Get-EntraIDTokenFromAuthorizationCode -RequestURL $requestUrl -ExpectedState 'exactstate' } |
            Should -Throw '*state value did not match*'

        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -Times 0
    }

    It "rejects a missing state without calling the token endpoint" {
        $requestUrl = "https://app.example/callback?code=state-code"

        { Get-EntraIDTokenFromAuthorizationCode -RequestURL $requestUrl -ExpectedState 'expected' } |
            Should -Throw '*does not contain a state value*'

        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -Times 0
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
