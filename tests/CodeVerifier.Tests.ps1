BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force
}

Describe "CodeVerifier (PKCE helpers)" {
    Context "Get-TTCodeVerifier" {
        It "Returns a non-empty string" {
            InModuleScope TokenTactics {
                $result = Get-TTCodeVerifier
                $result | Should -Not -BeNullOrEmpty
                $result.Length | Should -Be 43
            }
        }

        It "Does not contain URL-unsafe characters" {
            InModuleScope TokenTactics {
                $result = Get-TTCodeVerifier
                $result | Should -Not -Match '\+'
                $result | Should -Not -Match '/'
                $result | Should -Not -Match '='
            }
        }

        It "Returns a different value on each call" {
            InModuleScope TokenTactics {
                $first  = Get-TTCodeVerifier
                $second = Get-TTCodeVerifier
                $first | Should -Not -Be $second
            }
        }
    }

    Context "Get-TTCodeChallenge" {
        It "Returns a non-empty string" {
            InModuleScope TokenTactics {
                $verifier = Get-TTCodeVerifier
                $result = Get-TTCodeChallenge -codeVerifier $verifier
                $result | Should -Not -BeNullOrEmpty
            }
        }

        It "Does not contain URL-unsafe characters" {
            InModuleScope TokenTactics {
                $verifier = Get-TTCodeVerifier
                $result = Get-TTCodeChallenge -codeVerifier $verifier
                $result | Should -Not -Match '\+'
                $result | Should -Not -Match '/'
                $result | Should -Not -Match '='
            }
        }

        It "Produces the correct SHA-256 Base64URL challenge for a known verifier" {
            InModuleScope TokenTactics {
                # Known S256 challenge for verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                # SHA-256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") base64url = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
                $verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                $expected  = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
                $result    = Get-TTCodeChallenge -codeVerifier $verifier
                $result | Should -Be $expected
            }
        }

        It "Returns the same challenge for the same verifier" {
            InModuleScope TokenTactics {
                $verifier = Get-TTCodeVerifier
                $first  = Get-TTCodeChallenge -codeVerifier $verifier
                $second = Get-TTCodeChallenge -codeVerifier $verifier
                $first | Should -Be $second
            }
        }
    }
}
