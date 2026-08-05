BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force

    $script:OriginalOS = $env:OS
    $env:OS = 'Windows_NT'
    $script:PrivateKey = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=TokenTactics-Test',
        $script:PrivateKey,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $script:Certificate = $request.CreateSelfSigned(
        [DateTimeOffset]::UtcNow.AddMinutes(-1),
        [DateTimeOffset]::UtcNow.AddMinutes(30)
    )
    $script:TokenResponse = [PSCustomObject]@{
        access_token = $script:FakeAccessToken
        token_type   = 'Bearer'
        expires_in   = 3600
    }
    $script:ConvertFromTestBase64Url = {
        param([string]$Value)

        $base64 = $Value.Replace('-', '+').Replace('_', '/')
        switch ($base64.Length % 4) {
            2 { $base64 += '==' }
            3 { $base64 += '=' }
        }

        [Convert]::FromBase64String($base64)
    }
}

AfterAll {
    $script:Certificate.Dispose()
    $script:PrivateKey.Dispose()
    $env:OS = $script:OriginalOS
}

Describe 'Get-EntraIDTokenFromCertificate' {
    BeforeEach {
        $script:LastTokenRequest = $null
        Mock -ModuleName TokenTactics Get-Item { $script:Certificate }
        Mock -ModuleName TokenTactics Invoke-RestMethod {
            $script:LastTokenRequest = @{
                Method = $Method
                Uri    = $Uri
                Body   = $Body
            }
            $script:TokenResponse
        }
    }

    AfterEach {
        Remove-Variable -Scope Global -Name response -ErrorAction SilentlyContinue
    }

    It 'returns and stores the token response' {
        $result = Get-EntraIDTokenFromCertificate `
            -TenantId 'contoso.onmicrosoft.com' `
            -ClientId '11111111-2222-3333-4444-555555555555' `
            -CertificateThumbprint $script:Certificate.Thumbprint

        $result | Should -Be $script:TokenResponse
        $global:response | Should -Be $script:TokenResponse
    }

    It 'sends a signed client-credentials request to the tenant v2 endpoint' {
        $clientId = '11111111-2222-3333-4444-555555555555'
        $scope = 'api://token-tactics/.default'
        Get-EntraIDTokenFromCertificate `
            -TenantId 'contoso.onmicrosoft.com' `
            -ClientId $clientId `
            -CertificateThumbprint $script:Certificate.Thumbprint `
            -Scope $scope | Out-Null

        $script:LastTokenRequest.Method | Should -Be 'Post'
        $script:LastTokenRequest.Uri | Should -Be 'https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token'
        $script:LastTokenRequest.Body['client_id'] | Should -Be $clientId
        $script:LastTokenRequest.Body['scope'] | Should -Be $scope
        $script:LastTokenRequest.Body['grant_type'] | Should -Be 'client_credentials'
        $script:LastTokenRequest.Body['client_assertion_type'] |
            Should -Be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    }

    It 'builds an RS256 assertion with the certificate thumbprint and valid signature' {
        $clientId = '11111111-2222-3333-4444-555555555555'
        Get-EntraIDTokenFromCertificate `
            -TenantId 'contoso.onmicrosoft.com' `
            -ClientId $clientId `
            -CertificateThumbprint $script:Certificate.Thumbprint | Out-Null

        $parts = $script:LastTokenRequest.Body['client_assertion'].Split('.')
        $parts.Count | Should -Be 3
        $header = [System.Text.Encoding]::UTF8.GetString((& $script:ConvertFromTestBase64Url -Value $parts[0])) | ConvertFrom-Json
        $payload = [System.Text.Encoding]::UTF8.GetString((& $script:ConvertFromTestBase64Url -Value $parts[1])) | ConvertFrom-Json

        $header.alg | Should -Be 'RS256'
        $header.typ | Should -Be 'JWT'
        $header.x5t | Should -Be ([Convert]::ToBase64String($script:Certificate.GetCertHash()).Replace('+', '-').Replace('/', '_').TrimEnd('='))
        $payload.aud | Should -Be 'https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token'
        $payload.iss | Should -Be $clientId
        $payload.sub | Should -Be $clientId
        $payload.exp | Should -BeGreaterThan $payload.nbf

        $publicKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($script:Certificate)
        try {
            $publicKey.VerifyData(
                [System.Text.Encoding]::UTF8.GetBytes("$($parts[0]).$($parts[1])"),
                (& $script:ConvertFromTestBase64Url -Value $parts[2]),
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            ) | Should -BeTrue
        } finally {
            $publicKey.Dispose()
        }
    }

    It 'rejects a malformed certificate thumbprint before accessing the store' {
        { Get-EntraIDTokenFromCertificate `
                -TenantId 'contoso.onmicrosoft.com' `
                -ClientId '11111111-2222-3333-4444-555555555555' `
                -CertificateThumbprint 'not-a-thumbprint' } |
            Should -Throw '*not valid hexadecimal*'

        Should -Invoke -ModuleName TokenTactics Get-Item -Times 0
    }

    It 'reports a missing certificate' {
        Mock -ModuleName TokenTactics Get-Item { throw 'item not found' }

        { Get-EntraIDTokenFromCertificate `
                -TenantId 'contoso.onmicrosoft.com' `
                -ClientId '11111111-2222-3333-4444-555555555555' `
                -CertificateThumbprint $script:Certificate.Thumbprint } |
            Should -Throw '*was not found*'
    }

    It 'propagates token endpoint failures' {
        Mock -ModuleName TokenTactics Invoke-RestMethod { throw 'network error' }

        { Get-EntraIDTokenFromCertificate `
                -TenantId 'contoso.onmicrosoft.com' `
                -ClientId '11111111-2222-3333-4444-555555555555' `
                -CertificateThumbprint $script:Certificate.Thumbprint } |
            Should -Throw '*network error*'
    }

    It 'rejects non-Windows certificate stores' {
        $env:OS = 'Unix'
        try {
            { Get-EntraIDTokenFromCertificate `
                    -TenantId 'contoso.onmicrosoft.com' `
                    -ClientId '11111111-2222-3333-4444-555555555555' `
                    -CertificateThumbprint $script:Certificate.Thumbprint } |
                Should -Throw '*requires a Windows certificate store*'
        } finally {
            $env:OS = 'Windows_NT'
        }
    }
}
