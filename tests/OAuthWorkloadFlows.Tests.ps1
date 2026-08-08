BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force
    $script:TokenResponse = [PSCustomObject]@{
        access_token = $script:FakeAccessToken
        token_type = 'Bearer'
        expires_in = 3600
    }
}

Describe 'OAuth workload flows' {
    BeforeEach {
        $script:LastTokenRequest = $null
        Mock -ModuleName TokenTactics Invoke-RestMethod {
            $script:LastTokenRequest = @{ Method = $Method; Uri = $Uri; Body = $Body }
            $script:TokenResponse
        }
    }

    It 'requests a client-credentials token with a plaintext secret' {
        Get-EntraIDTokenFromClientSecret -TenantId contoso -ClientId client-id -ClientSecret plaintext -Scope 'https://graph.microsoft.com/.default' | Out-Null

        $script:LastTokenRequest.Uri | Should -Be 'https://login.microsoftonline.com/contoso/oauth2/v2.0/token'
        $script:LastTokenRequest.Body.client_id | Should -Be 'client-id'
        $script:LastTokenRequest.Body.client_secret | Should -Be 'plaintext'
        $script:LastTokenRequest.Body.grant_type | Should -Be 'client_credentials'
    }

    It 'requests a client-credentials token with a secure-string secret' {
        $secret = ConvertTo-SecureString 'plaintext' -AsPlainText -Force
        Get-EntraIDTokenFromClientSecret -TenantId contoso -ClientId client-id -ClientSecretSecureString $secret | Out-Null

        $script:LastTokenRequest.Body.client_secret | Should -Be 'plaintext'
    }

    It 'writes useful verbose diagnostics without exposing client secrets or tokens' {
        $secret = 'super-secret-value'
        $verbose = @(Get-EntraIDTokenFromClientSecret -TenantId contoso -ClientId client-id -ClientSecret $secret -Verbose 4>&1 |
                Where-Object { $_ -is [System.Management.Automation.VerboseRecord] })
        $text = ($verbose | ForEach-Object Message) -join [Environment]::NewLine

        $text | Should -Match 'Starting client-credentials flow'
        $text | Should -Match 'POST token request'
        $text | Should -Match '<redacted length=18>'
        $text | Should -Not -Match [regex]::Escape($secret)
        $text | Should -Not -Match [regex]::Escape($script:FakeAccessToken)
    }

    It 'exchanges a generic federated assertion' {
        Get-EntraIDTokenFromFederatedCredential -TenantId contoso -ClientId client-id -FederatedToken 'external-assertion' | Out-Null

        $script:LastTokenRequest.Body.client_assertion | Should -Be 'external-assertion'
        $script:LastTokenRequest.Body.client_assertion_type | Should -Be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        $script:LastTokenRequest.Body.grant_type | Should -Be 'client_credentials'
    }

    It 'requests an on-behalf-of token with a middle-tier assertion' {
        $encode = {
            param([string]$Value)
            [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Value)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        }
        $assertion = "$(& $encode '{"alg":"none"}').$(& $encode '{"aud":"middle-tier"}').signature"

        Get-EntraIDTokenOnBehalfOf -TenantId contoso -ClientId middle-tier -ClientSecret plaintext -UserAssertion $assertion -Scope 'https://graph.microsoft.com/User.Read' | Out-Null

        $script:LastTokenRequest.Body.grant_type | Should -Be 'urn:ietf:params:oauth:grant-type:jwt-bearer'
        $script:LastTokenRequest.Body.requested_token_use | Should -Be 'on_behalf_of'
        $script:LastTokenRequest.Body.assertion | Should -Be $assertion
    }

    It 'obtains and exchanges the GitHub Actions runtime assertion' {
        $previousUrl = $env:ACTIONS_ID_TOKEN_REQUEST_URL
        $previousToken = $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN
        $env:ACTIONS_ID_TOKEN_REQUEST_URL = 'https://actions.example/token'
        $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN = 'runtime-request-token'
        try {
            Mock -ModuleName TokenTactics Invoke-RestMethod {
                if ("$Uri" -like 'https://actions.example/token*') {
                    [PSCustomObject]@{ value = 'github-oidc-assertion' }
                } else {
                    $script:LastTokenRequest = @{ Method = $Method; Uri = $Uri; Body = $Body }
                    $script:TokenResponse
                }
            }

            Get-EntraIDTokenFromGitHubActions -TenantId contoso -ClientId client-id | Out-Null
            $script:LastTokenRequest.Body.client_assertion | Should -Be 'github-oidc-assertion'
        } finally {
            $env:ACTIONS_ID_TOKEN_REQUEST_URL = $previousUrl
            $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN = $previousToken
        }
    }

    It 'completes the Azure Arc challenge-file handshake' {
        $previousEndpoint = $env:IDENTITY_ENDPOINT
        $challengePath = Join-Path $TestDrive 'arc-challenge.key'
        [IO.File]::WriteAllText($challengePath, 'arc-challenge-value')
        $env:IDENTITY_ENDPOINT = 'http://[::1]:40342/metadata/identity/oauth2/token'
        $script:ArcRequests = @()
        try {
            Mock -ModuleName TokenTactics Invoke-WebRequest {
                $capturedHeaders = @{}
                foreach ($headerName in $Headers.Keys) { $capturedHeaders[$headerName] = $Headers[$headerName] }
                $script:ArcRequests += [pscustomobject]@{ Uri = $Uri; Headers = $capturedHeaders }
                if ($null -eq $Headers.Authorization) {
                    [pscustomobject]@{
                        StatusCode = 401
                        Headers = @{ 'WWW-Authenticate' = "Basic realm=$challengePath" }
                        Content = ''
                    }
                } else {
                    [pscustomobject]@{
                        StatusCode = 200
                        Headers = @{}
                        Content = '{"access_token":"arc-access-token","token_type":"Bearer","expires_in":3600,"resource":"https://management.azure.com/"}'
                    }
                }
            }

            $result = Get-EntraIDTokenFromAzureArcManagedIdentity -Resource 'https://management.azure.com/'

            $result.access_token | Should -Be 'arc-access-token'
            $script:ArcRequests.Count | Should -Be 2
            $script:ArcRequests[0].Headers.Metadata | Should -Be 'True'
            $script:ArcRequests[1].Headers.Authorization | Should -Be 'Basic arc-challenge-value'
        } finally {
            $env:IDENTITY_ENDPOINT = $previousEndpoint
        }
    }

    It 'creates and parses an implicit access-token redirect with matching state' {
        $request = New-EntraIDImplicitAuthorizationUrl -TenantId organizations -ClientId client-id -RedirectUri 'https://app.example/callback' -Scope 'https://graph.microsoft.com/User.Read' -State expected-state
        $request.AuthorizationUrl | Should -Match 'response_type=token'
        $request.AuthorizationUrl | Should -Match 'response_mode=fragment'

        $result = ConvertFrom-EntraIDImplicitRedirect -RedirectUrl 'https://app.example/callback#access_token=token-value&token_type=Bearer&state=expected-state' -ExpectedState expected-state
        $result.AccessToken | Should -Be 'token-value'
        $result.TokenType | Should -Be 'Bearer'
    }

    It 'masks implicit-flow state and token values in verbose diagnostics' {
        $state = 'state-value-that-must-not-be-logged'
        $requestVerbose = @(New-EntraIDImplicitAuthorizationUrl -TenantId organizations -ClientId client-id -RedirectUri 'https://app.example/callback' -Scope 'https://graph.microsoft.com/User.Read' -State $state -Verbose 4>&1 |
                Where-Object { $_ -is [System.Management.Automation.VerboseRecord] })
        $redirectVerbose = @(ConvertFrom-EntraIDImplicitRedirect -RedirectUrl "https://app.example/callback#access_token=implicit-secret-token&token_type=Bearer&state=$state" -ExpectedState $state -Verbose 4>&1 |
                Where-Object { $_ -is [System.Management.Automation.VerboseRecord] })
        $text = (($requestVerbose + $redirectVerbose) | ForEach-Object Message) -join [Environment]::NewLine

        $text | Should -Match 'Implicit authorization URL built'
        $text | Should -Match '<redacted length='
        $text | Should -Not -Match [regex]::Escape($state)
        $text | Should -Not -Match 'implicit-secret-token'
    }

    It 'rejects an implicit redirect with the wrong state' {
        {
            ConvertFrom-EntraIDImplicitRedirect -RedirectUrl 'https://app.example/callback#access_token=token-value&state=wrong' -ExpectedState expected
        } | Should -Throw '*state value did not match*'
    }

    It 'rejects an implicit redirect without a fragment' {
        {
            ConvertFrom-EntraIDImplicitRedirect -RedirectUrl 'https://app.example/callback' -ExpectedState expected
        } | Should -Throw '*does not contain an implicit-flow response fragment*'
    }

    It 'always emits and returns a nonce when an ID token is requested' {
        $request = New-EntraIDImplicitAuthorizationUrl -TenantId organizations -ClientId client-id -RedirectUri 'https://app.example/callback' -Scope 'openid https://graph.microsoft.com/User.Read' -IncludeIdToken

        $request.Nonce | Should -Not -BeNullOrEmpty
        $request.AuthorizationUrl | Should -Match ([regex]::Escape("nonce=$($request.Nonce)"))
        $request.AuthorizationUrl | Should -Not -Match 'openid%20openid'
    }

    It 'rejects a client-credentials scope that is not a single /.default resource' {
        {
            Get-EntraIDTokenFromClientSecret -TenantId contoso -ClientId client-id -ClientSecret plaintext -Scope 'https://graph.microsoft.com/User.Read'
        } | Should -Throw '*Scope must contain exactly one resource*'
        {
            Get-EntraIDTokenFromClientSecret -TenantId contoso -ClientId client-id -ClientSecret plaintext -Scope 'https://graph.microsoft.com/.default https://management.azure.com/.default'
        } | Should -Throw '*Scope must contain exactly one resource*'
    }

    It 'rejects an on-behalf-of assertion issued to a different audience' {
        $encode = {
            param([string]$Value)
            [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Value)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        }
        $assertion = "$(& $encode '{"alg":"none"}').$(& $encode '{"aud":"someone-else"}').signature"

        {
            Get-EntraIDTokenOnBehalfOf -TenantId contoso -ClientId middle-tier -ClientSecret plaintext -UserAssertion $assertion -Scope 'https://graph.microsoft.com/User.Read'
        } | Should -Throw '*UserAssertion must be an access token issued to*'
    }

    It 'rejects a missing federated token file' {
        {
            Get-EntraIDTokenFromFederatedCredential -TenantId contoso -ClientId client-id -FederatedTokenPath (Join-Path $TestDrive 'missing.jwt')
        } | Should -Throw '*was not found*'
    }

    It 'surfaces the Entra error details when a token request fails' {
        Mock -ModuleName TokenTactics Invoke-RestMethod {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [Exception]::new('Response status code does not indicate success: 400 (Bad Request).'),
                'TokenRequestFailed', 'NotSpecified', $null
            )
            $errorRecord.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret is provided."}')
            throw $errorRecord
        }

        {
            Get-EntraIDTokenFromClientSecret -TenantId contoso -ClientId client-id -ClientSecret plaintext
        } | Should -Throw '*AADSTS7000215*'
    }

    It 'requires the GitHub Actions OIDC environment variables' {
        $previousUrl = $env:ACTIONS_ID_TOKEN_REQUEST_URL
        $previousToken = $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN
        $env:ACTIONS_ID_TOKEN_REQUEST_URL = $null
        $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN = $null
        try {
            { Get-EntraIDTokenFromGitHubActions -TenantId contoso -ClientId client-id } | Should -Throw '*environment variables are unavailable*'
        } finally {
            $env:ACTIONS_ID_TOKEN_REQUEST_URL = $previousUrl
            $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN = $previousToken
        }
    }

    It 'rejects a non-loopback Azure Arc identity endpoint' {
        $previousEndpoint = $env:IDENTITY_ENDPOINT
        $env:IDENTITY_ENDPOINT = 'http://169.254.169.254/metadata/identity/oauth2/token'
        try {
            { Get-EntraIDTokenFromAzureArcManagedIdentity } | Should -Throw '*loopback*'
        } finally {
            $env:IDENTITY_ENDPOINT = $previousEndpoint
        }
    }

    It 'fails the Azure Arc flow on a non-challenge error status' {
        $previousEndpoint = $env:IDENTITY_ENDPOINT
        $env:IDENTITY_ENDPOINT = 'http://127.0.0.1:40342/metadata/identity/oauth2/token'
        try {
            Mock -ModuleName TokenTactics Invoke-WebRequest {
                [pscustomobject]@{ StatusCode = 500; Headers = @{}; Content = 'server error' }
            }
            { Get-EntraIDTokenFromAzureArcManagedIdentity } | Should -Throw '*HTTP 500*'
        } finally {
            $env:IDENTITY_ENDPOINT = $previousEndpoint
        }
    }

    It 'fails the Azure Arc flow when the response contains no access token' {
        $previousEndpoint = $env:IDENTITY_ENDPOINT
        $env:IDENTITY_ENDPOINT = 'http://127.0.0.1:40342/metadata/identity/oauth2/token'
        try {
            Mock -ModuleName TokenTactics Invoke-WebRequest {
                [pscustomobject]@{ StatusCode = 200; Headers = @{}; Content = 'not-a-json-token-response' }
            }
            { Get-EntraIDTokenFromAzureArcManagedIdentity } | Should -Throw '*did not return an access token*'
        } finally {
            $env:IDENTITY_ENDPOINT = $previousEndpoint
        }
    }

    It 'generates public issuer metadata and a signed custom assertion from a PFX' {
        if (-not $IsWindows -and -not (Get-Command openssl -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because 'Cross-platform PFX generation requires OpenSSL.'
            return
        }

        $pfxPath = Join-Path $TestDrive 'issuer.pfx'
        $callerLocation = Join-Path $TestDrive 'caller'
        [IO.Directory]::CreateDirectory($callerLocation) | Out-Null
        $originalProcessLocation = [Environment]::CurrentDirectory
        try {
            Push-Location $callerLocation
            # PowerShell's provider location can differ from .NET's process location.
            [Environment]::CurrentDirectory = [IO.Path]::GetFullPath($TestDrive)
            $outputPath = './oidc-public'
            $certificateOutput = @(New-EntraIDFederatedSigningCertificate -PfxPath $pfxPath -PfxPassword 'test-password' -Verbose 4>&1)
            $certificateVerbose = @($certificateOutput | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] })
            $certificateVerboseText = ($certificateVerbose | ForEach-Object Message) -join [Environment]::NewLine
            $certificateVerboseText | Should -Match 'Federated signing certificate created'
            $certificateVerboseText | Should -Not -Match 'test-password'
            $metadata = New-EntraIDFederatedIssuerMetadata -Issuer 'https://issuer.example.test' -Subject workload -OutputPath $outputPath -PfxPath $pfxPath -PfxPassword 'test-password' -IncludeLocalConfig
            $assertion = New-EntraIDFederatedClientAssertion -Issuer 'https://issuer.example.test' -Subject workload -PfxPath $pfxPath -PfxPassword 'test-password'

            Test-Path (Join-Path $outputPath '.well-known/openid-configuration') | Should -BeTrue
            Test-Path (Join-Path $outputPath 'issuer-config.json') | Should -BeTrue
            $expectedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($outputPath)
            $metadata.OutputPath | Should -Be $expectedOutputPath
            $metadata.DiscoveryPath | Should -Be (Join-Path $expectedOutputPath '.well-known/openid-configuration')
            $metadata.GeneratedFiles.Count | Should -Be 3
            $discovery = Get-Content (Join-Path $outputPath '.well-known/openid-configuration') -Raw | ConvertFrom-Json
            $discovery.response_types_supported | Should -Contain 'id_token'
            $keys = Get-Content (Join-Path $outputPath 'keys.json') -Raw | ConvertFrom-Json
            $keys.keys.Count | Should -Be 1
            (ConvertFrom-JWTtoken -Token $assertion).iss | Should -Be 'https://issuer.example.test'

            # The local issuer configuration is opt-in; the web host only needs the
            # discovery document and the JWKS.
            $publicOnlyPath = './oidc-public-only'
            $publicOnly = New-EntraIDFederatedIssuerMetadata -Issuer 'https://issuer.example.test' -Subject workload -OutputPath $publicOnlyPath -PfxPath $pfxPath -PfxPassword 'test-password'
            $publicOnly.GeneratedFiles.Count | Should -Be 2
            $publicOnly.ConfigurationPath | Should -BeNullOrEmpty
            Test-Path (Join-Path $publicOnlyPath 'issuer-config.json') | Should -BeFalse
        } finally {
            Pop-Location
            [Environment]::CurrentDirectory = $originalProcessLocation
        }

        $decode = {
            param([string]$Value)
            $base64 = $Value.Replace('-', '+').Replace('_', '/')
            switch ($base64.Length % 4) {
                2 { $base64 += '==' }
                3 { $base64 += '=' }
            }
            [Convert]::FromBase64String($base64)
        }
        $rsa = [System.Security.Cryptography.RSA]::Create()
        try {
            $rsa.ImportParameters([System.Security.Cryptography.RSAParameters]@{
                Modulus = & $decode $keys.keys[0].n
                Exponent = & $decode $keys.keys[0].e
            })
            $parts = $assertion.Split('.')
            $rsa.VerifyData(
                [Text.Encoding]::UTF8.GetBytes("$($parts[0]).$($parts[1])"),
                (& $decode $parts[2]),
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            ) | Should -BeTrue
        } finally {
            $rsa.Dispose()
        }
    }
}
