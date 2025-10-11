BeforeAll {
    # Dot-source the function file directly for faster test execution
    . "$PSScriptRoot/../modules/ConvertFrom-JWTtoken.ps1"
}

Describe "ConvertFrom-JWTtoken" {
    Context "Valid JWT Token Parsing" {
        It "Should parse a valid JWT token successfully" {
            # This is a sample JWT token (header.payload.signature)
            # Header: {"alg":"HS256","typ":"JWT"}
            # Payload: {"sub":"1234567890","name":"Test User","iat":1516239022,"exp":1916239022,"nbf":1516239022}
            $token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxOTE2MjM5MDIyLCJuYmYiOjE1MTYyMzkwMjJ9.signature"
            
            $result = ConvertFrom-JWTtoken -token $token
            
            $result | Should -Not -BeNullOrEmpty
            $result.sub | Should -Be "1234567890"
            $result.name | Should -Be "Test User"
            $result.iat | Should -Be 1516239022
            $result.exp | Should -Be 1916239022
            $result.nbf | Should -Be 1516239022
        }

        It "Should add IssuedAt property when iat claim exists" {
            $token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxOTE2MjM5MDIyLCJuYmYiOjE1MTYyMzkwMjJ9.signature"
            
            $result = ConvertFrom-JWTtoken -token $token
            
            $result.IssuedAt | Should -Not -BeNullOrEmpty
            $result.IssuedAt | Should -BeOfType [DateTime]
        }

        It "Should add NotBefore property when nbf claim exists" {
            $token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxOTE2MjM5MDIyLCJuYmYiOjE1MTYyMzkwMjJ9.signature"
            
            $result = ConvertFrom-JWTtoken -token $token
            
            $result.NotBefore | Should -Not -BeNullOrEmpty
            $result.NotBefore | Should -BeOfType [DateTime]
        }

        It "Should add ExpirationDate property when exp claim exists" {
            $token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxOTE2MjM5MDIyLCJuYmYiOjE1MTYyMzkwMjJ9.signature"
            
            $result = ConvertFrom-JWTtoken -token $token
            
            $result.ExpirationDate | Should -Not -BeNullOrEmpty
            $result.ExpirationDate | Should -BeOfType [DateTime]
        }

        It "Should add ValidForHours property when IssuedAt exists" {
            $token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxOTE2MjM5MDIyLCJuYmYiOjE1MTYyMzkwMjJ9.signature"
            
            $result = ConvertFrom-JWTtoken -token $token
            
            $result.ValidForHours | Should -Not -BeNullOrEmpty
            $result.ValidForHours | Should -BeOfType [Double]
        }

        It "Should work with access_token parameter alias" {
            $token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxOTE2MjM5MDIyLCJuYmYiOjE1MTYyMzkwMjJ9.signature"
            
            $result = ConvertFrom-JWTtoken -access_token $token
            
            $result | Should -Not -BeNullOrEmpty
            $result.sub | Should -Be "1234567890"
        }

        It "Should work with id_token parameter alias" {
            $token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxOTE2MjM5MDIyLCJuYmYiOjE1MTYyMzkwMjJ9.signature"
            
            $result = ConvertFrom-JWTtoken -id_token $token
            
            $result | Should -Not -BeNullOrEmpty
            $result.sub | Should -Be "1234567890"
        }
    }

    Context "Invalid Token Handling" {
        It "Should throw error for token without dots" {
            { ConvertFrom-JWTtoken -token "invalidtoken" } | Should -Throw
        }

        It "Should throw error for token not starting with eyJ" {
            { ConvertFrom-JWTtoken -token "invalid.token.format" } | Should -Throw
        }

        It "Should throw error for empty token" {
            { ConvertFrom-JWTtoken -token "" } | Should -Throw
        }
    }

    Context "Pipeline Support" {
        It "Should accept token from pipeline" {
            $token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxOTE2MjM5MDIyLCJuYmYiOjE1MTYyMzkwMjJ9.signature"
            
            $result = $token | ConvertFrom-JWTtoken
            
            $result | Should -Not -BeNullOrEmpty
            $result.sub | Should -Be "1234567890"
        }
    }
}
