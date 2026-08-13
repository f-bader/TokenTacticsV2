BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force

    $script:SessionInformation = [PSCustomObject]@{
        sFidoChallenge     = 'server-challenge-value'
        sFT                = 'flow-token'
        sCtx               = 'context'
        canary             = 'canary'
        correlationId      = 'correlation'
        urlPost            = '/post'
        urlPostAad         = '/post-aad'
        urlPostMsa         = '/post-msa'
        urlRefresh         = '/refresh'
        urlResume          = '/resume'
        UserPrincipalName  = 'user@contoso.com'
        RelyingParty       = 'login.microsoft.com'
        Origin             = 'https://login.microsoft.com'
        oGetCredTypeResult = [PSCustomObject]@{
            FlowToken   = 'credential-flow-token'
            Credentials = [PSCustomObject]@{
                HasFido    = $true
                FidoParams = [PSCustomObject]@{ AllowList = @('credential') }
            }
        }
    }

    $script:ResponseInformation = @{
        sCrossDomainCanary = 'cross-domain-canary'
        sessionId          = 'session-id'
        sCtx               = 'response-context'
        canary             = 'response-canary'
        sFT                = 'response-flow-token'
    } | ConvertTo-Json -Compress

    $script:Assertion = [PSCustomObject]@{
        id                = 'credential-id'
        clientDataJSON    = 'Y2xpZW50RGF0YQ'
        authenticatorData = 'YXV0aGVudGljYXRvckRhdGE'
        signature         = 'c2lnbmF0dXJl'
        userHandle        = 'dXNlckhhbmRsZQ'
    }

    $script:EstsCookieValue = '0.fake-ests-cookie-value-with-enough-length'
}

AfterAll {
    Remove-Variable -Scope Global -Name Fido2WebSession, Fido2FlowState, ESTSAUTH, webSession, response -ErrorAction SilentlyContinue
}

Describe 'New-EntraIDUserHandle' {
    It 'calculates the expected user handle for a known tenant and user id' {
        $result = New-EntraIDUserHandle -TenantId '00112233-4455-6677-8899-aabbccddeeff' -UserId 'ffeeddcc-bbaa-9988-7766-554433221100'

        $result.TenantId | Should -Be '00112233-4455-6677-8899-aabbccddeeff'
        $result.UserId | Should -Be 'ffeeddcc-bbaa-9988-7766-554433221100'
        $result.UserHandleBase64 | Should -Be 'T046MyIRAFVEd2aImaq7zN3u/+XL2v8mea6v5bMB3Jw5+rS+TeKZ6lehLC8UuwzR6I2C'
        $result.UserHandleBase64Url | Should -Be 'T046MyIRAFVEd2aImaq7zN3u_-XL2v8mea6v5bMB3Jw5-rS-TeKZ6lehLC8UuwzR6I2C'
        $result.UserHandle | Should -Be $result.UserHandleBase64Url
        $result.UserHandleHex | Should -Be '4f4e3a33221100554477668899aabbccddeeffe5cbdaff2679aeafe5b301dc9c39fab4be4de299ea57a12c2f14bb0cd1e88d82'
    }

    It 'throws when a GUID cannot be parsed' {
        { New-EntraIDUserHandle -TenantId 'not-a-guid' -UserId 'ffeeddcc-bbaa-9988-7766-554433221100' } | Should -Throw '*valid GUIDs*'
    }
}

Describe 'Get-EntraIDFido2Challenge' {
    BeforeEach {
        $script:CapturedUri = $null
        Mock -ModuleName TokenTactics Invoke-WebRequest {
            param($Uri)
            $script:CapturedUri = $Uri
            return [PSCustomObject]@{ Content = ($script:SessionInformation | ConvertTo-Json -Compress -Depth 10); StatusCode = 200 }
        }
    }

    AfterEach {
        Remove-Variable -Scope Global -Name Fido2WebSession, Fido2FlowState -ErrorAction SilentlyContinue
    }

    It 'returns structured flow state and saves the session state in global variables' {
        $result = Get-EntraIDFido2Challenge -UserPrincipalName 'user@contoso.com'

        $result.Challenge | Should -Be 'server-challenge-value'
        $result.OAuth.Client | Should -Be 'MSGraph'
        $result.OAuth.ClientID | Should -Be 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
        $result.OAuth.RedirectUrl | Should -Be 'ms-appx-web://Microsoft.AAD.BrokerPlugIn/S-1-15-2-1479478596-3248452454-924133441-2206841801-2812823084-3237817612-3652912309'
        $result.PostbackUrl | Should -Be '/post'

        $global:Fido2WebSession | Should -Not -BeNullOrEmpty
        $global:Fido2FlowState | Should -Not -BeNullOrEmpty
        $global:Fido2WebSession.Fido2SessionInfo | Should -Not -BeNullOrEmpty
        $global:Fido2WebSession.Fido2SessionInfo.UserPrincipalName | Should -Be 'user@contoso.com'
        $global:Fido2WebSession.Fido2SessionInfo.sFidoChallenge | Should -Be 'server-challenge-value'
    }

    It 'adds sso_reload and login_hint to the authorize request' {
        Get-EntraIDFido2Challenge -UserPrincipalName 'user@contoso.com'

        $script:CapturedUri | Should -Match 'sso_reload=true'
        $script:CapturedUri | Should -Match 'login_hint=user%40contoso\.com'
    }

    It 'parses an authorize response with a JavaScript config assignment and trailing semicolon' {
        Mock -ModuleName TokenTactics Invoke-WebRequest {
            $config = $script:SessionInformation | ConvertTo-Json -Compress -Depth 10
            return [PSCustomObject]@{
                Content = "<script>`$Config = $config;</script>"
                StatusCode = 200
            }
        }

        $result = Get-EntraIDFido2Challenge -UserPrincipalName 'user@contoso.com' -Client Outlook

        $result.Challenge | Should -Be 'server-challenge-value'
        $result.PostbackUrl | Should -Be '/post'
    }

    It 'throws when the user has no FIDO credentials registered' {
        Mock -ModuleName TokenTactics Invoke-WebRequest {
            $noFido = [PSCustomObject]@{
                oGetCredTypeResult = [PSCustomObject]@{
                    Credentials = [PSCustomObject]@{ HasFido = $false }
                }
            }
            return [PSCustomObject]@{ Content = ($noFido | ConvertTo-Json -Compress -Depth 10); StatusCode = 200 }
        }

        { Get-EntraIDFido2Challenge -UserPrincipalName 'user@contoso.com' } | Should -Throw '*FIDO*'
    }

    It 'throws when the auth URL is not a login.microsoftonline.com URL' {
        { Get-EntraIDFido2Challenge -UserPrincipalName 'user@contoso.com' -AuthUrl 'https://example.com/authorize?client_id=x&response_type=code&redirect_uri=y' } | Should -Throw '*login.microsoftonline.com*'
    }

    It 'builds OAuth URLs from the refresh-token client aliases and supports PKCE' {
        $result = Get-EntraIDFido2Challenge `
            -UserPrincipalName 'user@contoso.com' `
            -Client AzureManagement `
            -Tenant 'contoso.onmicrosoft.com' `
            -RedirectUrl 'https://app.example/callback' `
            -UseCodeVerifier `
            -CodeVerifier 'fixed-verifier'

        $result.OAuth.Client | Should -Be 'AzureManagement'
        $result.OAuth.ClientID | Should -Be 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
        $result.OAuth.CodeVerifier | Should -Be 'fixed-verifier'
        $result.OAuth.RedirectUrl | Should -Be 'https://app.example/callback'
        $script:CapturedUri | Should -Match 'organizations|contoso\.onmicrosoft\.com'
        $script:CapturedUri | Should -Match 'code_challenge_method=S256'
        $script:CapturedUri | Should -Match 'redirect_uri=https%3a%2f%2fapp.example%2fcallback'
    }

    It 'selects the registered redirect URI from the effective client ID' {
        $oauth = InModuleScope TokenTactics {
            New-TTEntraAuthorizationUrl `
                -Client Custom `
                -ClientID '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223' `
                -Scope 'openid'
        }

        $oauth.RedirectUrl | Should -Be 'ms-appx-web://Microsoft.AAD.BrokerPlugin/9ba1a5c7-f17a-4de9-a1f1-6178c8d51223'
    }

    It 'requires an explicit redirect URI for an unknown client ID' {
        {
            InModuleScope TokenTactics {
                New-TTEntraAuthorizationUrl -Client Custom -ClientID '00000000-0000-0000-0000-000000000001' -Scope 'openid'
            }
        } | Should -Throw '*Provide -RedirectUrl*'
    }
}

Describe 'ConvertFrom-TTUserSid' {
    It 'converts an Entra ID user SID to the correct object ID' {
        $result = InModuleScope TokenTactics {
            ConvertFrom-TTUserSid -Sid 'S-1-12-1-223508383-1125077638-3128705954-3034186293'
        }

        $result | Should -Be ([guid]'0d52779f-5286-430f-a243-7cba3502dab4')
    }

    It 'throws for a SID that is not an Entra ID user SID' {
        { InModuleScope TokenTactics { ConvertFrom-TTUserSid -Sid 'S-1-5-21-123456789-123456789-123456789-1001' } } | Should -Throw '*not a valid Entra ID user SID*'
    }
}

Describe 'Get-WindowsHelloFidoAssertion parameter validation' {
    It 'rejects a UserId that is not a GUID' {
        { Get-WindowsHelloFidoAssertion -Challenge 'challenge' -UserId 'katie.summer@contoso.com' } | Should -Throw '*object ID (GUID)*'
    }
}

Describe 'Get-WindowsHelloFidoAssertion platform guard' -Skip:($IsWindows) {
    It 'throws on non-Windows platforms' {
        { Get-WindowsHelloFidoAssertion -Challenge 'challenge' -UserId 'ffeeddcc-bbaa-9988-7766-554433221100' } | Should -Throw '*supported only on Windows*'
    }

    It 'throws on non-Windows platforms when UserId is omitted' {
        { Get-WindowsHelloFidoAssertion -Challenge 'challenge' } | Should -Throw '*supported only on Windows*'
    }
}

Describe 'Invoke-EntraIDPasskeyAssertionLogin' {
    BeforeEach {
        $script:Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $cookie = [System.Net.Cookie]::new('ESTSAUTH', $script:EstsCookieValue)
        $script:Session.Cookies.Add('https://login.microsoftonline.com/', $cookie)
        Add-Member -InputObject $script:Session -NotePropertyName 'Fido2SessionInfo' -NotePropertyValue $script:SessionInformation -Force

        Mock -ModuleName TokenTactics Invoke-WebRequest {
            param($Uri)
            if ($Uri -eq 'https://login.microsoft.com/common/fido/get?uiflavor=Web') {
                return [PSCustomObject]@{ Content = $script:ResponseInformation; StatusCode = 200 }
            }
            return [PSCustomObject]@{ Content = '{}'; StatusCode = 200; Error = $null }
        }
        Mock -ModuleName TokenTactics Get-EntraIDTokenFromESTSCookie { }
    }

    AfterEach {
        Remove-Variable -Scope Global -Name Fido2WebSession, ESTSAUTH, webSession, response -ErrorAction SilentlyContinue
    }

    It 'submits the assertion to the login endpoint using the saved global web session' {
        $global:Fido2WebSession = $script:Session

        Invoke-EntraIDPasskeyAssertionLogin -Assertion $script:Assertion

        Should -Invoke -ModuleName TokenTactics Invoke-WebRequest -Times 1 -Exactly -Scope It -ParameterFilter {
            if ($Uri -ne 'https://login.microsoftonline.com/post') {
                return $false
            }
            $assertion = $Body.assertion | ConvertFrom-Json
            $assertion.id -eq 'credential-id' -and
            $assertion.userHandle -eq 'dXNlckhhbmRsZQ' -and
            $Body.lmcCanary -eq 'cross-domain-canary' -and
            $Body.hpgrequestid -eq 'session-id'
        }
        Should -Invoke -ModuleName TokenTactics Invoke-WebRequest -Times 1 -Exactly -Scope It -ParameterFilter {
            $Uri -eq 'https://login.microsoftonline.com/post?sso_reload=true' -and
            $Body.ctx -eq 'context' -and
            $Body.canary -eq 'canary' -and
            $Body.flowToken -eq 'credential-flow-token'
        }
    }

    It 'accepts the assertion as a JSON string and uses the session username for the verify request' {
        Invoke-EntraIDPasskeyAssertionLogin -Assertion ($script:Assertion | ConvertTo-Json -Compress) -WebSession $script:Session -SessionInfo $script:SessionInformation

        Should -Invoke -ModuleName TokenTactics Invoke-WebRequest -Times 1 -Exactly -Scope It -ParameterFilter {
            $Uri -eq 'https://login.microsoft.com/common/fido/get?uiflavor=Web' -and
            $Body.username -eq 'user@contoso.com' -and
            $Body.credentialsJson -eq 'credential'
        }
    }

    It 'returns the ESTSAUTH cookie value when OutputType is ESTSAUTHCookie' {
        $result = Invoke-EntraIDPasskeyAssertionLogin -Assertion $script:Assertion -WebSession $script:Session -SessionInfo $script:SessionInformation -OutputType ESTSAUTHCookie

        $result | Should -Be $script:EstsCookieValue
        $global:ESTSAUTH | Should -Be $script:EstsCookieValue
        $global:webSession | Should -Be $script:Session
        Should -Invoke -ModuleName TokenTactics Get-EntraIDTokenFromESTSCookie -Times 0 -Exactly -Scope It
    }

    It 'exchanges the ESTSAUTH cookie for tokens by default' {
        Invoke-EntraIDPasskeyAssertionLogin -Assertion $script:Assertion -WebSession $script:Session -SessionInfo $script:SessionInformation

        Should -Invoke -ModuleName TokenTactics Get-EntraIDTokenFromESTSCookie -Times 1 -Exactly -Scope It -ParameterFilter {
            $CookieValue -eq $script:EstsCookieValue -and
            $ESTSCookieType -eq 'ESTSAUTH' -and
            $Client -eq 'Custom' -and
            $ClientID -eq 'd3590ed6-52b3-4102-aeff-aad2292ab01c' -and
            $Scope -eq 'https://graph.microsoft.com/.default offline_access openid'
        }
    }

    It 'tolerates the expected redirect error when the assertion is accepted' -ForEach @(
        'Operation is not valid due to the current state of the object.'
        'The maximum redirection count has been exceeded. To increase the number of redirections allowed, supply a higher value to the -MaximumRedirection parameter.'
    ) {
        $script:RedirectMessage = $_
        Mock -ModuleName TokenTactics Invoke-WebRequest {
            param($Uri)
            if ($Uri -eq 'https://login.microsoft.com/common/fido/get?uiflavor=Web') {
                return [PSCustomObject]@{ Content = $script:ResponseInformation; StatusCode = 200 }
            }
            if ($Uri -like 'https://login.microsoftonline.com/post*') {
                throw $script:RedirectMessage
            }
            return [PSCustomObject]@{ Content = '{}'; StatusCode = 200; Error = $null }
        }

        Invoke-EntraIDPasskeyAssertionLogin -Assertion $script:Assertion -WebSession $script:Session -SessionInfo $script:SessionInformation

        Should -Invoke -ModuleName TokenTactics Get-EntraIDTokenFromESTSCookie -Times 1 -Exactly -Scope It
    }

    It 'throws when the assertion is missing a required property' {
        $broken = [PSCustomObject]@{
            id                = 'credential-id'
            clientDataJSON    = 'Y2xpZW50RGF0YQ'
            authenticatorData = 'YXV0aGVudGljYXRvckRhdGE'
            signature         = 'c2lnbmF0dXJl'
        }

        { Invoke-EntraIDPasskeyAssertionLogin -Assertion $broken -WebSession $script:Session -SessionInfo $script:SessionInformation } | Should -Throw "*missing required property 'userHandle'*"
    }

    It 'throws when no web session is available' {
        Remove-Variable -Scope Global -Name Fido2WebSession, Fido2FlowState -ErrorAction SilentlyContinue

        { Invoke-EntraIDPasskeyAssertionLogin -Assertion $script:Assertion } | Should -Throw '*Get-EntraIDFido2Challenge*'
    }
}
