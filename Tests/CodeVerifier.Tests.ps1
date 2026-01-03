BeforeAll {
    # Dot-source the function file directly for faster test execution
    . "$PSScriptRoot/../modules/CodeVerifier.ps1"
}

Describe "CodeVerifier Functions" {
    Context "Get-TTCodeVerifier" {
        It "Should generate a code verifier" {
            $result = Get-TTCodeVerifier
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [string]
        }

        It "Should generate a code verifier with correct length (43 characters)" {
            $result = Get-TTCodeVerifier
            
            $result.Length | Should -Be 43
        }

        It "Should generate URL-safe base64 string (no +, /, or =)" {
            $result = Get-TTCodeVerifier
            
            $result | Should -Not -Match '\+'
            $result | Should -Not -Match '/'
            $result | Should -Not -Match '='
        }

        It "Should contain valid URL-safe characters (alphanumeric, -, _)" {
            $result = Get-TTCodeVerifier
            
            $result | Should -Match '^[A-Za-z0-9\-_]+$'
        }

        It "Should generate different values on multiple calls" {
            $result1 = Get-TTCodeVerifier
            $result2 = Get-TTCodeVerifier
            
            $result1 | Should -Not -Be $result2
        }
    }

    Context "Get-TTCodeChallenge" {
        It "Should generate a code challenge from a code verifier" {
            $codeVerifier = Get-TTCodeVerifier
            
            $result = Get-TTCodeChallenge -codeVerifier $codeVerifier
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [string]
        }

        It "Should require codeVerifier parameter" {
            { Get-TTCodeChallenge -codeVerifier $null -ErrorAction Stop } | Should -Throw
        }

        It "Should generate URL-safe base64 string (no +, /, or =)" {
            $codeVerifier = Get-TTCodeVerifier
            
            $result = Get-TTCodeChallenge -codeVerifier $codeVerifier
            
            $result | Should -Not -Match '\+'
            $result | Should -Not -Match '/'
            $result | Should -Not -Match '='
        }

        It "Should contain valid URL-safe characters (alphanumeric, -, _)" {
            $codeVerifier = Get-TTCodeVerifier
            
            $result = Get-TTCodeChallenge -codeVerifier $codeVerifier
            
            $result | Should -Match '^[A-Za-z0-9\-_]+$'
        }

        It "Should generate consistent code challenge for same code verifier" {
            $codeVerifier = Get-TTCodeVerifier
            
            $result1 = Get-TTCodeChallenge -codeVerifier $codeVerifier
            $result2 = Get-TTCodeChallenge -codeVerifier $codeVerifier
            
            $result1 | Should -Be $result2
        }

        It "Should generate different code challenges for different code verifiers" {
            $codeVerifier1 = Get-TTCodeVerifier
            $codeVerifier2 = Get-TTCodeVerifier
            
            $result1 = Get-TTCodeChallenge -codeVerifier $codeVerifier1
            $result2 = Get-TTCodeChallenge -codeVerifier $codeVerifier2
            
            $result1 | Should -Not -Be $result2
        }

        It "Should generate code challenge with correct length (43 characters)" {
            $codeVerifier = Get-TTCodeVerifier
            
            $result = Get-TTCodeChallenge -codeVerifier $codeVerifier
            
            $result.Length | Should -Be 43
        }
    }

    Context "Integration Test" {
        It "Should work together - verifier generation and challenge creation" {
            # Generate a code verifier
            $codeVerifier = Get-TTCodeVerifier
            
            # Generate code challenge from the verifier
            $codeChallenge = Get-TTCodeChallenge -codeVerifier $codeVerifier
            
            # Both should be valid
            $codeVerifier | Should -Not -BeNullOrEmpty
            $codeChallenge | Should -Not -BeNullOrEmpty
            
            # Both should be 43 characters
            $codeVerifier.Length | Should -Be 43
            $codeChallenge.Length | Should -Be 43
            
            # Both should be URL-safe
            $codeVerifier | Should -Match '^[A-Za-z0-9\-_]+$'
            $codeChallenge | Should -Match '^[A-Za-z0-9\-_]+$'
        }
    }
}
