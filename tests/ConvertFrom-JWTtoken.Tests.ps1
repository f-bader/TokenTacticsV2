BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force
}

Describe "ConvertFrom-JWTtoken" {
    Context "Valid token" {
        It "Decodes the upn claim" {
            $result = ConvertFrom-JWTtoken -token $script:TestJWT
            $result.upn | Should -Be "test.user@contoso.com"
        }

        It "Decodes the aud claim" {
            $result = ConvertFrom-JWTtoken -token $script:TestJWT
            $result.aud | Should -Be "https://graph.microsoft.com"
        }

        It "Decodes the tid claim" {
            $result = ConvertFrom-JWTtoken -token $script:TestJWT
            $result.tid | Should -Be "00000000-0000-0000-0000-000000000001"
        }

        It "Decodes the scp claim" {
            $result = ConvertFrom-JWTtoken -token $script:TestJWT
            $result.scp | Should -Be "User.Read"
        }

        It "Adds the IssuedAt computed property from iat" {
            $result = ConvertFrom-JWTtoken -token $script:TestJWT
            $result.IssuedAt | Should -BeOfType [DateTime]
            # epoch 1700000000 = 2023-11-14T22:13:20Z
            $result.IssuedAt.ToUniversalTime().Year | Should -Be 2023
        }

        It "Adds the NotBefore computed property from nbf" {
            $result = ConvertFrom-JWTtoken -token $script:TestJWT
            $result.NotBefore | Should -BeOfType [DateTime]
        }

        It "Adds the ExpirationDate computed property from exp" {
            $result = ConvertFrom-JWTtoken -token $script:TestJWT
            $result.ExpirationDate | Should -BeOfType [DateTime]
        }

        It "Adds the ValidForHours computed property (1 hour)" {
            $result = ConvertFrom-JWTtoken -token $script:TestJWT
            $result.ValidForHours | Should -Be 1.0
        }

        It "Accepts token via pipeline" {
            $result = $script:TestJWT | ConvertFrom-JWTtoken
            $result.upn | Should -Be "test.user@contoso.com"
        }

        It "Accepts token via -access_token alias" {
            $obj = [PSCustomObject]@{ access_token = $script:TestJWT }
            $result = $obj | ConvertFrom-JWTtoken
            $result.upn | Should -Be "test.user@contoso.com"
        }
    }

    Context "Invalid token" {
        It "Throws on a string without dots" {
            { ConvertFrom-JWTtoken -token "notavalidtoken" } | Should -Throw
        }

        It "Throws on a string that does not start with eyJ" {
            { ConvertFrom-JWTtoken -token "abc.def.ghi" } | Should -Throw
        }
    }
}
