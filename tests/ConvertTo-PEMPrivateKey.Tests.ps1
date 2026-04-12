BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force
}

Describe "ConvertTo-PEMPrivateKey" {
    Context "Input already in PEM format" {
        It "Returns the input unchanged when it already has PEM headers" {
            $pemKey = "-----BEGIN PRIVATE KEY-----`nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg`n-----END PRIVATE KEY-----"
            $result = ConvertTo-PEMPrivateKey -PrivateKey $pemKey
            $result | Should -Be $pemKey
        }
    }

    Context "Raw Base64 key" {
        It "Wraps the key with PEM BEGIN and END headers" {
            $rawKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgtest1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"
            $result = ConvertTo-PEMPrivateKey -PrivateKey $rawKey
            $result | Should -Match "^-----BEGIN PRIVATE KEY-----"
            $result | Should -Match "-----END PRIVATE KEY-----$"
        }

        It "Wraps lines at 64 characters" {
            $rawKey = "A" * 128  # 128 chars -> 2 lines of 64
            $result = ConvertTo-PEMPrivateKey -PrivateKey $rawKey
            $lines = $result -split "`n"
            # Lines between BEGIN and END should each be <= 64 characters
            $contentLines = $lines | Where-Object { $_ -notmatch "-----" -and $_.Length -gt 0 }
            $contentLines | ForEach-Object { $_.Length | Should -BeLessOrEqual 64 }
        }

        It "Replaces dashes with plus and underscores with slash" {
            # Input with URL-safe Base64 characters (- -> +, _ -> /)
            $rawKey = "AAAA-AAAA_AAAA"
            $result = ConvertTo-PEMPrivateKey -PrivateKey $rawKey
            # Only check the content lines (skip PEM header/footer lines)
            $contentLines = ($result -split "`n") | Where-Object { $_ -notmatch "^-----" -and $_.Trim() -ne "" }
            $contentLines | ForEach-Object { $_ | Should -Not -Match "-" }
            $contentLines | ForEach-Object { $_ | Should -Not -Match "_" }
        }

        It "Accepts input from pipeline" {
            $rawKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgABCDEFGH"
            $result = $rawKey | ConvertTo-PEMPrivateKey
            $result | Should -Match "-----BEGIN PRIVATE KEY-----"
        }
    }
}
