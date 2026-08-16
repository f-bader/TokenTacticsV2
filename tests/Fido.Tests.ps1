BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force

    $curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
    $script:Ecdsa = [System.Security.Cryptography.ECDsa]::Create($curve)
    $script:PrivateKeyPem = -join [System.Security.Cryptography.PemEncoding]::Write('PRIVATE KEY', $script:Ecdsa.ExportPkcs8PrivateKey())
}

AfterAll {
    if ($script:Ecdsa) {
        $script:Ecdsa.Dispose()
    }
    Remove-Variable -Scope Global -Name ESTSAUTH, webSession -ErrorAction SilentlyContinue
}

Describe 'FIDO cryptographic helpers' {
    It 'constructs the exact 37-byte authenticator data layout' {
        $result = InModuleScope TokenTactics {
            New-FidoAuthenticatorData -RpId 'login.microsoft.com' -SignCount 0x01020304 -Flags 0x05
        }
        $expectedHash = [System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes('login.microsoft.com'))

        $result.Count | Should -Be 37
        [Convert]::ToHexString($result[0..31]) | Should -Be ([Convert]::ToHexString($expectedHash))
        $result[32] | Should -Be 0x05
        $result[33..36] | Should -Be ([byte[]](0x01, 0x02, 0x03, 0x04))
    }

    It 'creates WebAuthn client data and a verifiable DER ECDSA signature' {
        $authData = InModuleScope TokenTactics {
            New-FidoAuthenticatorData -RpId 'login.microsoft.com' -SignCount 7
        }
        $result = InModuleScope TokenTactics -Parameters @{
            AuthData = $authData
            KeyPem   = $script:PrivateKeyPem
        } {
            param($AuthData, $KeyPem)
            New-FidoSignature -Challenge 'server-challenge_123' -Origin 'https://login.microsoft.com' -AuthDataBytes $AuthData -PrivateKeyPem $KeyPem
        }

        $clientData = [Text.Encoding]::UTF8.GetString($result.ClientData) | ConvertFrom-Json
        $clientData.type | Should -Be 'webauthn.get'
        $clientData.challenge | Should -Be 'server-challenge_123'
        $clientData.origin | Should -Be 'https://login.microsoft.com'
        $clientData.crossOrigin | Should -BeFalse

        $clientHash = [System.Security.Cryptography.SHA256]::HashData($result.ClientData)
        $signedData = [byte[]]($authData + $clientHash)
        $script:Ecdsa.VerifyData(
            $signedData,
            $result.Signature,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence
        ) | Should -BeTrue
    }
}

Describe 'Invoke-EntraIDPasskeyLogin' {
    BeforeEach {
        $script:ServerChallenge = 'server-challenge-value'
        $sessionInformation = @{
            sFidoChallenge     = $script:ServerChallenge
            sFT                = 'flow-token'
            sCtx               = 'context'
            canary             = 'canary'
            correlationId      = 'correlation'
            urlPost            = '/post'
            urlPostAad         = '/post-aad'
            urlPostMsa         = '/post-msa'
            urlRefresh         = '/refresh'
            urlResume          = '/resume'
            oGetCredTypeResult = @{
                FlowToken  = 'credential-flow-token'
                Credentials = @{
                    HasFido    = $true
                    FidoParams = @{ AllowList = @('credential') }
                }
            }
        } | ConvertTo-Json -Compress -Depth 10
        $responseInformation = @{
            sCrossDomainCanary = 'cross-domain-canary'
            sessionId          = 'session-id'
            sCtx               = 'response-context'
            canary             = 'response-canary'
            sFT                = 'response-flow-token'
        } | ConvertTo-Json -Compress

        Mock -ModuleName TokenTactics ConvertTo-PEMPrivateKey { 'valid-pem' }
        Mock -ModuleName TokenTactics New-FidoAuthenticatorData { [byte[]](0..36) }
        Mock -ModuleName TokenTactics New-FidoSignature {
            [PSCustomObject]@{
                ClientData = [Text.Encoding]::UTF8.GetBytes('{}')
                Signature  = [byte[]](1, 2, 3)
            }
        }
        Mock -ModuleName TokenTactics Invoke-WebRequest {
            param($Uri)
            if ($Uri -match '/organizations/oauth2/v2\.0/authorize') {
                return [PSCustomObject]@{ Content = $sessionInformation; StatusCode = 200 }
            }
            if ($Uri -eq 'https://login.microsoft.com/common/fido/get?uiflavor=Web') {
                return [PSCustomObject]@{ Content = $responseInformation; StatusCode = 200 }
            }
            return [PSCustomObject]@{ Content = '{}'; StatusCode = 200; Error = $null }
        }
    }

    It 'Base64URL-encodes the server challenge bytes and uses normalized assertion values' {
        $credentialId = '00112233-4455-6677-8899-aabbccddeeff'
        $credentialBytes = [Convert]::FromHexString($credentialId.Replace('-', ''))
        $expectedCredentialId = [Convert]::ToBase64String($credentialBytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
        $expectedChallenge = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($script:ServerChallenge)).Replace('+', '-').Replace('/', '_').TrimEnd('=')

        Invoke-EntraIDPasskeyLogin -UserPrincipalName 'user@contoso.com' -UserHandle 'user-handle' -CredentialId $credentialId -PrivateKey 'raw-key'

        Should -Invoke -ModuleName TokenTactics New-FidoSignature -Times 1 -Exactly -Scope It -ParameterFilter {
            $Challenge -eq $expectedChallenge -and
            $Origin -eq 'https://login.microsoft.com' -and
            $PrivateKeyPem -eq 'valid-pem'
        }
        Should -Invoke -ModuleName TokenTactics Invoke-WebRequest -Times 1 -Exactly -Scope It -ParameterFilter {
            if ($Uri -ne 'https://login.microsoftonline.com/common/login') {
                return $false
            }
            $assertion = $Body.assertion | ConvertFrom-Json
            $assertion.id -eq $expectedCredentialId -and $assertion.userHandle -eq 'user-handle'
        }
        Should -Invoke -ModuleName TokenTactics Invoke-WebRequest -Times 1 -Exactly -Scope It -ParameterFilter {
            $Uri -eq 'https://login.microsoftonline.com/common/login?sso_reload=true' -and
            $Body.lmcCanary -eq 'cross-domain-canary' -and
            $Body.hpgrequestid -eq 'session-id' -and
            $Body.ctx -eq 'context' -and
            $Body.canary -eq 'canary' -and
            $Body.flowToken -eq 'credential-flow-token'
        }
        Should -Invoke -ModuleName TokenTactics Invoke-WebRequest -Times 1 -Exactly -Scope It -ParameterFilter {
            $Uri -match 'redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient' -and
            $Uri -match 'client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46'
        }
    }

    It 'throws instead of terminating the PowerShell host when the key file is missing' {
        { Invoke-EntraIDPasskeyLogin -KeyFilePath (Join-Path $TestDrive 'missing.json') } | Should -Throw '*not found*'
        Should -Invoke -ModuleName TokenTactics Invoke-WebRequest -Times 0 -Exactly -Scope It
    }

    It 'continues quietly when finalization reaches the intentional redirect limit' {
        Mock -ModuleName TokenTactics Invoke-WebRequest {
            param($Uri, $WebSession)
            $cookie = [System.Net.Cookie]::new('ESTSAUTH', 'redirect-limit-cookie-value-1234567890')
            $WebSession.Cookies.Add('https://login.microsoftonline.com/', $cookie)
            throw [System.InvalidOperationException]::new('The maximum redirection count has been exceeded. To increase the number of redirections allowed, supply a higher value to the -MaximumRedirection parameter.')
        } -ParameterFilter {
            $Uri -like 'https://login.microsoftonline.com/common/login*'
        }

        { Invoke-EntraIDPasskeyLogin -UserPrincipalName 'user@contoso.com' -UserHandle 'user-handle' -CredentialId 'credential-id' -PrivateKey 'raw-key' -ErrorAction Stop } | Should -Not -Throw
        $global:ESTSAUTH | Should -Be 'redirect-limit-cookie-value-1234567890'
        Remove-Variable -Name ESTSAUTH, webSession -Scope Global -ErrorAction SilentlyContinue
    }

    It 'continues quietly when PowerShell reports the redirect stop as an invalid state' {
        Mock -ModuleName TokenTactics Invoke-WebRequest {
            param($Uri, $WebSession)
            $cookie = [System.Net.Cookie]::new('ESTSAUTH', 'invalid-state-cookie-value-1234567890')
            $WebSession.Cookies.Add('https://login.microsoftonline.com/', $cookie)
            throw [System.InvalidOperationException]::new('Operation is not valid due to the current state of the object.')
        } -ParameterFilter {
            $Uri -like 'https://login.microsoftonline.com/common/login*'
        }

        { Invoke-EntraIDPasskeyLogin -UserPrincipalName 'user@contoso.com' -UserHandle 'user-handle' -CredentialId 'credential-id' -PrivateKey 'raw-key' -ErrorAction Stop } | Should -Not -Throw
        $global:ESTSAUTH | Should -Be 'invalid-state-cookie-value-1234567890'
        Remove-Variable -Name ESTSAUTH, webSession -Scope Global -ErrorAction SilentlyContinue
    }

    It 'does not index missing ConvergedSignIn session metadata' {
        Mock -ModuleName TokenTactics Invoke-WebRequest {
            [PSCustomObject]@{
                Content  = '{"pgid":"ConvergedSignIn","urlLogin":null}'
                StatusCode = 200
                Error = $null
            }
        } -ParameterFilter {
            $Uri -like 'https://login.microsoftonline.com/common/login*'
        }

        { Invoke-EntraIDPasskeyLogin -UserPrincipalName 'user@contoso.com' -UserHandle 'user-handle' -CredentialId 'credential-id' -PrivateKey 'raw-key' -ErrorAction Stop } | Should -Not -Throw
        Should -Invoke -ModuleName TokenTactics Invoke-WebRequest -Times 0 -Exactly -Scope It -ParameterFilter {
            $Uri -like '*sessionid=*'
        }
    }
}
