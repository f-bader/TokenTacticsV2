BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force

    $curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
    $script:Ecdsa = [System.Security.Cryptography.ECDsa]::Create($curve)
    $script:Pkcs8Bytes = $script:Ecdsa.ExportPkcs8PrivateKey()
    $script:RawBase64 = [Convert]::ToBase64String($script:Pkcs8Bytes)
    $script:RawBase64Url = $script:RawBase64.Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

AfterAll {
    if ($script:Ecdsa) {
        $script:Ecdsa.Dispose()
    }
}

Describe 'ConvertTo-PEMPrivateKey' {
    It 'returns an existing PEM value unchanged' {
        $pem = -join [System.Security.Cryptography.PemEncoding]::Write('PRIVATE KEY', $script:Pkcs8Bytes)
        ConvertTo-PEMPrivateKey -PrivateKey $pem | Should -BeExactly $pem
    }

    It 'converts unpadded Base64URL PKCS#8 data into importable PEM' {
        $pem = ConvertTo-PEMPrivateKey -PrivateKey $script:RawBase64Url
        $imported = [System.Security.Cryptography.ECDsa]::Create()
        try {
            $imported.ImportFromPem($pem)
            $data = [Text.Encoding]::UTF8.GetBytes('TokenTactics test')
            $signature = $imported.SignData($data, [Security.Cryptography.HashAlgorithmName]::SHA256)
            $script:Ecdsa.VerifyData($data, $signature, [Security.Cryptography.HashAlgorithmName]::SHA256) | Should -BeTrue
        } finally {
            $imported.Dispose()
        }
    }

    It 'wraps content lines at no more than 64 characters' {
        $pem = ConvertTo-PEMPrivateKey -PrivateKey $script:RawBase64
        $contentLines = $pem -split "`n" | Where-Object { $_ -notmatch '^-----' -and $_ }

        $contentLines.Count | Should -BeGreaterThan 1
        $contentLines | ForEach-Object { $_.Length | Should -BeLessOrEqual 64 }
    }

    It 'accepts valid key data from the pipeline' {
        $pem = $script:RawBase64Url | ConvertTo-PEMPrivateKey
        $pem | Should -Match '^-----BEGIN PRIVATE KEY-----'
        $pem | Should -Match '-----END PRIVATE KEY-----$'
    }

    It 'rejects malformed Base64 data' {
        { ConvertTo-PEMPrivateKey -PrivateKey 'not-a-private-key!' } | Should -Throw '*valid Base64*'
    }
}
