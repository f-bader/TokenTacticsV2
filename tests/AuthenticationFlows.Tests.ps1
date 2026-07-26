BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force

    $script:TestUserAgent = 'TokenTactics-Test/1.0'
    $script:TokenResponse = [PSCustomObject]@{
        access_token  = $script:FakeAccessToken
        refresh_token = $script:FakeRefreshToken
        token_type    = 'Bearer'
        expires_in    = 3600
    }
}

Describe 'Get-EntraIDTokenFromDeviceCode device-code flow' {
    BeforeEach {
        foreach ($name in 'response', 'TokenDomain', 'TokenUpn', 'AuthenticationFlowPollAttempt') {
            Remove-Variable -Scope Global -Name $name -ErrorAction SilentlyContinue
        }
        Mock -ModuleName TokenTactics Get-ForgedUserAgent { 'TokenTactics-Test/1.0' }
    }

    AfterEach {
        foreach ($name in 'response', 'TokenDomain', 'TokenUpn', 'AuthenticationFlowPollAttempt') {
            Remove-Variable -Scope Global -Name $name -ErrorAction SilentlyContinue
        }
    }

    It 'requests and exchanges a OneDrive device code using the exact contracts' {
        $deviceResponse = [PSCustomObject]@{
            device_code = 'one-drive-device-code'
            user_code   = 'ABCD-EFGH'
            interval    = 4
            expires_in  = 900
        }

        Mock -ModuleName TokenTactics Invoke-RestMethod { throw "Unexpected REST request: $Method $Uri" }
        Mock -ModuleName TokenTactics Invoke-RestMethod { $deviceResponse } -ParameterFilter {
            $UseBasicParsing -and
            "$Method" -eq 'Post' -and
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode' -and
            "$ErrorAction" -eq 'SilentlyContinue' -and
            $Headers -is [System.Collections.IDictionary] -and
            $Headers.Count -eq 1 -and
            $Headers['User-Agent'] -eq 'TokenTactics-Test/1.0' -and
            $Body -is [System.Collections.IDictionary] -and
            $Body.Count -eq 2 -and
            $Body['client_id'] -eq 'ab9b8c07-8f02-4f72-87fa-80105867a763' -and
            $Body['scope'] -eq 'https://officeapps.live.com/.default offline_access openid'
        }
        Mock -ModuleName TokenTactics Invoke-RestMethod { $script:TokenResponse } -ParameterFilter {
            $UseBasicParsing -and
            "$Method" -eq 'Post' -and
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/v2.0/token' -and
            "$ErrorAction" -eq 'SilentlyContinue' -and
            $Headers -is [System.Collections.IDictionary] -and
            $Headers.Count -eq 1 -and
            $Headers['User-Agent'] -eq 'TokenTactics-Test/1.0' -and
            $Body -is [System.Collections.IDictionary] -and
            $Body.Count -eq 3 -and
            $Body['client_id'] -eq 'ab9b8c07-8f02-4f72-87fa-80105867a763' -and
            $Body['grant_type'] -eq 'urn:ietf:params:oauth:grant-type:device_code' -and
            $Body['device_code'] -eq 'one-drive-device-code'
        }
        Mock -ModuleName TokenTactics Start-Sleep {} -ParameterFilter { $Seconds -eq 4 }

        Get-EntraIDTokenFromDeviceCode -Client OneDrive

        $global:response.access_token | Should -Be $script:FakeAccessToken
        $global:TokenDomain | Should -Be 'contoso.com'
        $global:TokenUpn | Should -Be 'test.user@contoso.com'
        Should -Invoke Invoke-RestMethod -ModuleName TokenTactics -Exactly -Scope It -Times 2
        Should -Invoke Invoke-RestMethod -ModuleName TokenTactics -Exactly -Scope It -Times 1 -ParameterFilter {
            $UseBasicParsing -and
            "$Method" -eq 'Post' -and
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode' -and
            "$ErrorAction" -eq 'SilentlyContinue' -and
            $Headers.Count -eq 1 -and
            $Headers['User-Agent'] -eq 'TokenTactics-Test/1.0' -and
            $Body.Count -eq 2 -and
            $Body['client_id'] -eq 'ab9b8c07-8f02-4f72-87fa-80105867a763' -and
            $Body['scope'] -eq 'https://officeapps.live.com/.default offline_access openid'
        }
        Should -Invoke Invoke-RestMethod -ModuleName TokenTactics -Exactly -Scope It -Times 1 -ParameterFilter {
            $UseBasicParsing -and
            "$Method" -eq 'Post' -and
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/v2.0/token' -and
            "$ErrorAction" -eq 'SilentlyContinue' -and
            $Headers.Count -eq 1 -and
            $Headers['User-Agent'] -eq 'TokenTactics-Test/1.0' -and
            $Body.Count -eq 3 -and
            $Body['client_id'] -eq 'ab9b8c07-8f02-4f72-87fa-80105867a763' -and
            $Body['grant_type'] -eq 'urn:ietf:params:oauth:grant-type:device_code' -and
            $Body['device_code'] -eq 'one-drive-device-code'
        }
        Should -Invoke Start-Sleep -ModuleName TokenTactics -Exactly -Scope It -Times 1 -ParameterFilter {
            $Seconds -eq 4
        }
    }

    It 'polls again after authorization_pending and then succeeds' {
        $global:AuthenticationFlowPollAttempt = 0
        $deviceResponse = [PSCustomObject]@{
            device_code = 'pending-device-code'
            user_code   = 'PEND-ING1'
            interval    = 2
            expires_in  = 900
        }

        Mock -ModuleName TokenTactics Invoke-RestMethod { throw "Unexpected REST request: $Method $Uri" }
        Mock -ModuleName TokenTactics Invoke-RestMethod { $deviceResponse } -ParameterFilter {
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode' -and
            "$Method" -eq 'Post' -and
            $Body['client_id'] -eq 'ab9b8c07-8f02-4f72-87fa-80105867a763' -and
            $Body['scope'] -eq 'https://officeapps.live.com/.default offline_access openid'
        }
        Mock -ModuleName TokenTactics Invoke-RestMethod {
            if ($global:AuthenticationFlowPollAttempt -eq 0) {
                $global:AuthenticationFlowPollAttempt++
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    [System.InvalidOperationException]::new('Authorization is pending'),
                    'authorization_pending',
                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                    $null
                )
                $errorRecord.ErrorDetails = [System.Management.Automation.ErrorDetails]::new(
                    '{"error":"authorization_pending","error_description":"Authorization is pending"}'
                )
                throw $errorRecord
            }

            $global:AuthenticationFlowPollAttempt++
            return $script:TokenResponse
        } -ParameterFilter {
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/v2.0/token' -and
            "$Method" -eq 'Post' -and
            $Body.Count -eq 3 -and
            $Body['client_id'] -eq 'ab9b8c07-8f02-4f72-87fa-80105867a763' -and
            $Body['grant_type'] -eq 'urn:ietf:params:oauth:grant-type:device_code' -and
            $Body['device_code'] -eq 'pending-device-code'
        }
        Mock -ModuleName TokenTactics Start-Sleep {} -ParameterFilter { $Seconds -eq 2 }

        Get-EntraIDTokenFromDeviceCode -Client OneDrive

        $global:response.access_token | Should -Be $script:FakeAccessToken
        $global:AuthenticationFlowPollAttempt | Should -Be 2
        Should -Invoke Invoke-RestMethod -ModuleName TokenTactics -Exactly -Scope It -Times 3
        Should -Invoke Invoke-RestMethod -ModuleName TokenTactics -Exactly -Scope It -Times 1 -ParameterFilter {
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode' -and
            "$Method" -eq 'Post' -and
            $Body.Count -eq 2 -and
            $Body['client_id'] -eq 'ab9b8c07-8f02-4f72-87fa-80105867a763' -and
            $Body['scope'] -eq 'https://officeapps.live.com/.default offline_access openid'
        }
        Should -Invoke Invoke-RestMethod -ModuleName TokenTactics -Exactly -Scope It -Times 2 -ParameterFilter {
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/v2.0/token' -and
            "$Method" -eq 'Post' -and
            $Body.Count -eq 3 -and
            $Body['client_id'] -eq 'ab9b8c07-8f02-4f72-87fa-80105867a763' -and
            $Body['grant_type'] -eq 'urn:ietf:params:oauth:grant-type:device_code' -and
            $Body['device_code'] -eq 'pending-device-code'
        }
        Should -Invoke Start-Sleep -ModuleName TokenTactics -Exactly -Scope It -Times 2 -ParameterFilter {
            $Seconds -eq 2
        }
    }

    It 'rejects SharePoint without a tenant name before making an HTTP request' {
        Mock -ModuleName TokenTactics Invoke-RestMethod { throw "Unexpected REST request: $Method $Uri" }

        { Get-EntraIDTokenFromDeviceCode -Client SharePoint -ErrorAction Stop } |
            Should -Throw '*SharePointTenantName must be provided*'

        Should -Invoke Invoke-RestMethod -ModuleName TokenTactics -Exactly -Scope It -Times 0
    }

    It 'keeps Get-EntraIDToken as a compatibility alias' {
        $deviceResponse = [PSCustomObject]@{
            device_code = 'alias-device-code'
            user_code   = 'ALIA-S123'
            interval    = 3
            expires_in  = 900
        }

        Mock -ModuleName TokenTactics Invoke-RestMethod { throw "Unexpected REST request: $Method $Uri" }
        Mock -ModuleName TokenTactics Invoke-RestMethod { $deviceResponse } -ParameterFilter {
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode' -and
            "$Method" -eq 'Post' -and
            $Body['client_id'] -eq 'ab9b8c07-8f02-4f72-87fa-80105867a763' -and
            $Body['scope'] -eq 'https://officeapps.live.com/.default offline_access openid'
        }
        Mock -ModuleName TokenTactics Invoke-RestMethod { $script:TokenResponse } -ParameterFilter {
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/v2.0/token' -and
            "$Method" -eq 'Post' -and
            $Body['client_id'] -eq 'ab9b8c07-8f02-4f72-87fa-80105867a763' -and
            $Body['grant_type'] -eq 'urn:ietf:params:oauth:grant-type:device_code' -and
            $Body['device_code'] -eq 'alias-device-code'
        }
        Mock -ModuleName TokenTactics Start-Sleep {} -ParameterFilter { $Seconds -eq 3 }

        Get-EntraIDToken -Client OneDrive

        $global:response.access_token | Should -Be $script:FakeAccessToken
        Should -Invoke Invoke-RestMethod -ModuleName TokenTactics -Exactly -Scope It -Times 2
    }
}

Describe 'Get-EntraIDTokenFromCookie authorization-code flow' {
    BeforeEach {
        foreach ($name in 'response', 'TokenDomain', 'TokenUpn') {
            Remove-Variable -Scope Global -Name $name -ErrorAction SilentlyContinue
        }
    }

    AfterEach {
        foreach ($name in 'response', 'TokenDomain', 'TokenUpn') {
            Remove-Variable -Scope Global -Name $name -ErrorAction SilentlyContinue
        }
    }

    It 'URL-decodes a 302 authorization code and exchanges it with CAE claims' {
        $redirectUrl = 'https://app.example/callback'
        $decodedCode = 'encoded+authorization/code=value'
        $claims = '{"access_token":{"xms_cc":{"values":["cp1"]}}}'

        Mock -ModuleName TokenTactics Invoke-WebRequest { throw "Unexpected web request: $Method $Uri" }
        Mock -ModuleName TokenTactics Invoke-WebRequest {
            [PSCustomObject]@{ StatusCode = 200; RawContent = ''; Headers = @{} }
        } -ParameterFilter {
            $UseBasicParsing -and
            -not $SkipHttpErrorCheck -and
            $MaximumRedirection -eq 0 -and
            "$ErrorAction" -eq 'SilentlyContinue' -and
            $WebSession -is [Microsoft.PowerShell.Commands.WebRequestSession] -and
            "$Method" -eq 'Get' -and
            "$Uri" -eq 'https://login.microsoftonline.com/error'
        }
        Mock -ModuleName TokenTactics Invoke-WebRequest {
            [PSCustomObject]@{
                StatusCode = 302
                RawContent = ''
                Headers    = @{
                    Location = [string[]]@(
                        'https://app.example/callback?code=encoded%2Bauthorization%2Fcode%3Dvalue&state=returned-state'
                    )
                }
            }
        } -ParameterFilter {
            $parsedUri = [Uri]$Uri
            $query = [System.Web.HttpUtility]::ParseQueryString($parsedUri.Query)
            $UseBasicParsing -and
            $SkipHttpErrorCheck -and
            $MaximumRedirection -eq 0 -and
            "$ErrorAction" -eq 'SilentlyContinue' -and
            $WebSession -is [Microsoft.PowerShell.Commands.WebRequestSession] -and
            "$Method" -eq 'Get' -and
            $parsedUri.Scheme -eq 'https' -and
            $parsedUri.Host -eq 'login.microsoftonline.com' -and
            $parsedUri.AbsolutePath -eq '/common/oauth2/v2.0/authorize' -and
            $Headers -is [System.Collections.IDictionary] -and
            $Headers.Count -eq 1 -and
            $Headers['User-Agent'] -eq 'TokenTactics-Test/1.0' -and
            $query.Count -eq 6 -and
            $query['response_type'] -eq 'code' -and
            $query['client_id'] -eq 'cookie-client-id' -and
            $query['scope'] -eq 'openid offline_access' -and
            $query['redirect_uri'] -eq 'https://app.example/callback' -and
            $query['state'] -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -and
            $query['claims'] -eq '{"access_token":{"xms_cc":{"values":["cp1"]}}}'
        }
        Mock -ModuleName TokenTactics Invoke-RestMethod { throw "Unexpected REST request: $Method $Uri" }
        Mock -ModuleName TokenTactics Invoke-RestMethod { $script:TokenResponse } -ParameterFilter {
            $UseBasicParsing -and
            "$Method" -eq 'Post' -and
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/v2.0/token' -and
            $Headers -is [System.Collections.IDictionary] -and
            $Headers.Count -eq 1 -and
            $Headers['User-Agent'] -eq 'TokenTactics-Test/1.0' -and
            $Body -is [System.Collections.IDictionary] -and
            $Body.Count -eq 6 -and
            $Body['client_id'] -eq 'cookie-client-id' -and
            $Body['grant_type'] -eq 'authorization_code' -and
            $Body['redirect_uri'] -eq 'https://app.example/callback' -and
            $Body['code'] -eq 'encoded+authorization/code=value' -and
            $Body['scope'] -eq 'openid offline_access' -and
            $Body['claims'] -eq '{"access_token":{"xms_cc":{"values":["cp1"]}}}'
        }

        Get-EntraIDTokenFromCookie `
            -CookieType ESTSAUTHPERSISTENT `
            -CookieValue 'test-cookie-value' `
            -ClientID 'cookie-client-id' `
            -Resource 'https://graph.microsoft.com' `
            -Scope 'openid offline_access' `
            -RedirectUrl $redirectUrl `
            -CustomUserAgent $script:TestUserAgent `
            -UseCAE

        $global:response.access_token | Should -Be $script:FakeAccessToken
        $global:TokenDomain | Should -Be 'contoso.com'
        $global:TokenUpn | Should -Be 'test.user@contoso.com'
        Should -Invoke Invoke-WebRequest -ModuleName TokenTactics -Exactly -Scope It -Times 2
        Should -Invoke Invoke-WebRequest -ModuleName TokenTactics -Exactly -Scope It -Times 1 -ParameterFilter {
            $UseBasicParsing -and
            -not $SkipHttpErrorCheck -and
            $MaximumRedirection -eq 0 -and
            "$ErrorAction" -eq 'SilentlyContinue' -and
            "$Method" -eq 'Get' -and
            "$Uri" -eq 'https://login.microsoftonline.com/error'
        }
        Should -Invoke Invoke-WebRequest -ModuleName TokenTactics -Exactly -Scope It -Times 1 -ParameterFilter {
            $parsedUri = [Uri]$Uri
            $query = [System.Web.HttpUtility]::ParseQueryString($parsedUri.Query)
            $UseBasicParsing -and
            $SkipHttpErrorCheck -and
            $MaximumRedirection -eq 0 -and
            "$ErrorAction" -eq 'SilentlyContinue' -and
            "$Method" -eq 'Get' -and
            $parsedUri.Host -eq 'login.microsoftonline.com' -and
            $parsedUri.AbsolutePath -eq '/common/oauth2/v2.0/authorize' -and
            $Headers.Count -eq 1 -and
            $Headers['User-Agent'] -eq 'TokenTactics-Test/1.0' -and
            $query.Count -eq 6 -and
            $query['response_type'] -eq 'code' -and
            $query['client_id'] -eq 'cookie-client-id' -and
            $query['scope'] -eq 'openid offline_access' -and
            $query['redirect_uri'] -eq 'https://app.example/callback' -and
            $query['state'] -match '^[0-9a-f-]{36}$' -and
            $query['claims'] -eq '{"access_token":{"xms_cc":{"values":["cp1"]}}}'
        }
        Should -Invoke Invoke-RestMethod -ModuleName TokenTactics -Exactly -Scope It -Times 1
        Should -Invoke Invoke-RestMethod -ModuleName TokenTactics -Exactly -Scope It -Times 1 -ParameterFilter {
            $UseBasicParsing -and
            "$Method" -eq 'Post' -and
            "$Uri" -eq 'https://login.microsoftonline.com/common/oauth2/v2.0/token' -and
            $Headers.Count -eq 1 -and
            $Headers['User-Agent'] -eq 'TokenTactics-Test/1.0' -and
            $Body.Count -eq 6 -and
            $Body['client_id'] -eq 'cookie-client-id' -and
            $Body['grant_type'] -eq 'authorization_code' -and
            $Body['redirect_uri'] -eq $redirectUrl -and
            $Body['code'] -eq $decodedCode -and
            $Body['scope'] -eq 'openid offline_access' -and
            $Body['claims'] -eq $claims
        }
    }
}

Describe 'Cookie convenience wrappers' {
    BeforeEach {
        foreach ($name in 'response', 'TokenDomain', 'TokenUpn') {
            Remove-Variable -Scope Global -Name $name -ErrorAction SilentlyContinue
        }
    }

    AfterEach {
        foreach ($name in 'response', 'TokenDomain', 'TokenUpn') {
            Remove-Variable -Scope Global -Name $name -ErrorAction SilentlyContinue
        }
    }

    It 'passes the exact ESTS cookie, client, user-agent, proxy, and resource arguments' {
        Mock -ModuleName TokenTactics Get-EntraIDTokenFromCookie { throw 'Unexpected delegation arguments' }
        Mock -ModuleName TokenTactics Get-EntraIDTokenFromCookie {} -ParameterFilter {
            $CookieType -eq 'ESTSAUTH' -and
            $CookieValue -eq 'ests-cookie-value' -and
            $ClientID -eq 'custom-ests-client' -and
            $CustomUserAgent -eq 'Delegation-Agent/2.0' -and
            $Proxy -eq 'http://127.0.0.1:8080' -and
            $Resource -eq 'https://resource.example' -and
            $Scope -eq 'api://resource/.default' -and
            $RedirectUrl -eq 'https://app.example/ests-callback' -and
            $null -eq $Device -and
            $null -eq $Browser
        }

        Get-EntraIDTokenFromESTSCookie `
            -CookieValue 'ests-cookie-value' `
            -ESTSCookieType ESTSAUTH `
            -Client Custom `
            -ClientID 'custom-ests-client' `
            -CustomUserAgent 'Delegation-Agent/2.0' `
            -Proxy 'http://127.0.0.1:8080' `
            -Resource 'https://resource.example' `
            -Scope 'api://resource/.default' `
            -RedirectUrl 'https://app.example/ests-callback'

        Should -Invoke Get-EntraIDTokenFromCookie -ModuleName TokenTactics -Exactly -Scope It -Times 1
        Should -Invoke Get-EntraIDTokenFromCookie -ModuleName TokenTactics -Exactly -Scope It -Times 1 -ParameterFilter {
            $CookieType -eq 'ESTSAUTH' -and
            $CookieValue -eq 'ests-cookie-value' -and
            $ClientID -eq 'custom-ests-client' -and
            $CustomUserAgent -eq 'Delegation-Agent/2.0' -and
            $Proxy -eq 'http://127.0.0.1:8080' -and
            $Resource -eq 'https://resource.example' -and
            $Scope -eq 'api://resource/.default' -and
            $RedirectUrl -eq 'https://app.example/ests-callback' -and
            $null -eq $Device -and
            $null -eq $Browser
        }
    }

    It 'passes the exact refresh-token credential cookie type, value, and client arguments' {
        Mock -ModuleName TokenTactics Get-EntraIDTokenFromCookie { throw 'Unexpected delegation arguments' }
        Mock -ModuleName TokenTactics Get-EntraIDTokenFromCookie {} -ParameterFilter {
            $CookieType -eq 'x-ms-RefreshTokenCredential' -and
            $CookieValue -eq 'refresh-token-credential-value' -and
            $ClientID -eq 'custom-refresh-client' -and
            $CustomUserAgent -eq 'Refresh-Agent/3.0' -and
            $Resource -eq 'https://graph.microsoft.com' -and
            $Scope -eq 'openid offline_access' -and
            $RedirectUrl -eq 'https://app.example/refresh-callback' -and
            $null -eq $Proxy -and
            $null -eq $Device -and
            $null -eq $Browser
        }

        Get-EntraIDTokenFromRefreshTokenCredentialCookie `
            -RefreshTokenCredential 'refresh-token-credential-value' `
            -Client Custom `
            -ClientID 'custom-refresh-client' `
            -CustomUserAgent 'Refresh-Agent/3.0' `
            -RedirectUrl 'https://app.example/refresh-callback'

        Should -Invoke Get-EntraIDTokenFromCookie -ModuleName TokenTactics -Exactly -Scope It -Times 1
        Should -Invoke Get-EntraIDTokenFromCookie -ModuleName TokenTactics -Exactly -Scope It -Times 1 -ParameterFilter {
            $CookieType -eq 'x-ms-RefreshTokenCredential' -and
            $CookieValue -eq 'refresh-token-credential-value' -and
            $ClientID -eq 'custom-refresh-client' -and
            $CustomUserAgent -eq 'Refresh-Agent/3.0' -and
            $Resource -eq 'https://graph.microsoft.com' -and
            $Scope -eq 'openid offline_access' -and
            $RedirectUrl -eq 'https://app.example/refresh-callback' -and
            $null -eq $Proxy -and
            $null -eq $Device -and
            $null -eq $Browser
        }
    }
}

Describe 'Get-EntraIDAuthorizationCode URL construction' {
    BeforeEach {
        foreach ($name in 'response', 'TokenDomain', 'TokenUpn') {
            Remove-Variable -Scope Global -Name $name -ErrorAction SilentlyContinue
        }
        Mock -ModuleName TokenTactics Start-Process { throw 'Browser operation was not expected' }
        Mock -ModuleName TokenTactics Set-Clipboard { throw 'Clipboard operation was not expected' }
    }

    AfterEach {
        Should -Invoke Start-Process -ModuleName TokenTactics -Exactly -Scope It -Times 0
        Should -Invoke Set-Clipboard -ModuleName TokenTactics -Exactly -Scope It -Times 0
        foreach ($name in 'response', 'TokenDomain', 'TokenUpn') {
            Remove-Variable -Scope Global -Name $name -ErrorAction SilentlyContinue
        }
    }

    It 'constructs the exact custom-client v2 URL' {
        $output = @(Get-EntraIDAuthorizationCode `
                -Client Custom `
                -ClientID 'custom-client' `
                -Scope 'api://custom/.default offline_access' `
                -RedirectUrl 'https://app.example/callback' `
                -AuthorizationCodeState 'fixed-state')

        $output[0] | Should -Be 'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?response_type=code&redirect_uri=https://app.example/callback&state=fixed-state&scope=api://custom/.default%20offline_access&client_id=custom-client'
    }

    It 'constructs the exact v1 URL with its resource' {
        $output = @(Get-EntraIDAuthorizationCode `
                -Client MSGraph `
                -ClientID 'v1-client' `
                -RedirectUrl 'https://app.example/v1-callback' `
                -AuthorizationCodeState 'v1-state' `
                -UseV1Endpoint `
                -Resource 'https://resource.example')

        $output[0] | Should -Be 'https://login.microsoftonline.com/organizations/oauth2/authorize?response_type=code&redirect_uri=https://app.example/v1-callback&state=v1-state&resource=https://resource.example&scope=https://graph.microsoft.com/.default%20offline_access%20openid&client_id=v1-client'
        $output[-1] | Should -Match 'Get-EntraIDTokenFromAuthorizationCode.*-Resource "https://resource\.example" -UseV1Endpoint$'
    }

    It 'constructs the exact CAE URL with the cp1 claim' {
        $output = @(Get-EntraIDAuthorizationCode `
                -Client MSGraph `
                -ClientID 'cae-client' `
                -RedirectUrl 'https://app.example/cae-callback' `
                -AuthorizationCodeState 'cae-state' `
                -UseCAE)

        $output[0] | Should -Be 'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?response_type=code&redirect_uri=https://app.example/cae-callback&state=cae-state&scope=https://graph.microsoft.com/.default%20offline_access%20openid&client_id=cae-client&claims=%7B%22access_token%22:%7B%22xms_cc%22:%7B%22values%22:[%22cp1%22]%7D%7D%7D'
    }

    It 'constructs the exact PKCE URL from deterministic verifier helpers' {
        Mock -ModuleName TokenTactics Get-TTCodeVerifier { 'fixed-code-verifier' }
        Mock -ModuleName TokenTactics Get-TTCodeChallenge { 'fixed-code-challenge' } -ParameterFilter {
            $CodeVerifier -eq 'fixed-code-verifier'
        }

        $output = @(Get-EntraIDAuthorizationCode `
                -Client MSGraph `
                -ClientID 'pkce-client' `
                -RedirectUrl 'https://app.example/pkce-callback' `
                -AuthorizationCodeState 'pkce-state' `
                -UseCodeVerifier)

        $output[0] | Should -Be 'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?response_type=code&redirect_uri=https://app.example/pkce-callback&state=pkce-state&code_challenge=fixed-code-challenge&code_challenge_method=S256&scope=https://graph.microsoft.com/.default%20offline_access%20openid&client_id=pkce-client'
        Should -Invoke Get-TTCodeVerifier -ModuleName TokenTactics -Exactly -Scope It -Times 1
        Should -Invoke Get-TTCodeChallenge -ModuleName TokenTactics -Exactly -Scope It -Times 1 -ParameterFilter {
            $CodeVerifier -eq 'fixed-code-verifier'
        }
    }
}
