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
            $result.IssuedAt | Should -Be ([DateTime]::Parse('2023-11-14T22:13:20Z').ToUniversalTime())
            $result.IssuedAt.Kind | Should -Be ([DateTimeKind]::Utc)
        }

        It "Adds the NotBefore computed property from nbf" {
            $result = ConvertFrom-JWTtoken -token $script:TestJWT
            $result.NotBefore | Should -BeOfType [DateTime]
        }

        It "Adds the ExpirationDate computed property from exp" {
            $result = ConvertFrom-JWTtoken -token $script:TestJWT
            $result.ExpirationDate | Should -BeOfType [DateTime]
            $result.ExpirationDate | Should -Be ([DateTime]::Parse('2023-11-14T23:13:20Z').ToUniversalTime())
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

        It "decodes UTF-8 claims without data loss" {
            $headerJson = '{"alg":"none","typ":"JWT"}'
            $payloadJson = @{ name = 'Jorg: Jorg; Japanese: Tokyo'; iat = 0; exp = 3600 } | ConvertTo-Json -Compress
            $payloadJson = $payloadJson.Replace('Jorg: Jorg; Japanese: Tokyo', "J$([char]0x00F6)rg $([char]0x6771)$([char]0x4EAC)")
            $encode = {
                param([string]$Value)
                [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Value)).Replace('+', '-').Replace('/', '_').TrimEnd('=')
            }
            $token = "$(& $encode $headerJson).$(& $encode $payloadJson).signature"

            $result = ConvertFrom-JWTtoken -Token $token

            $result.name | Should -Be "J$([char]0x00F6)rg $([char]0x6771)$([char]0x4EAC)"
            $result.IssuedAt | Should -Be ([DateTime]::UnixEpoch)
            $result.ValidForHours | Should -Be 1
        }

        It "does not calculate ValidForHours when exp is absent" {
            $header = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"alg":"none"}')).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"iat":1700000000}')).TrimEnd('=').Replace('+', '-').Replace('/', '_')

            $result = ConvertFrom-JWTtoken -Token "$header.$payload.signature"

            $result.IssuedAt | Should -Not -BeNullOrEmpty
            $result.PSObject.Properties.Name | Should -Not -Contain 'ValidForHours'
        }
    }

    Context "Invalid token" {
        It "Throws on a string without dots" {
            { ConvertFrom-JWTtoken -token "notavalidtoken" } | Should -Throw
        }

        It "Throws on a string that does not start with eyJ" {
            { ConvertFrom-JWTtoken -token "abc.def.ghi" } | Should -Throw
        }

        It "throws when the token has the wrong number of segments" {
            { ConvertFrom-JWTtoken -Token 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0' } | Should -Throw
            { ConvertFrom-JWTtoken -Token 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.sig.extra' } | Should -Throw
        }

        It "throws for malformed Base64 or JSON" {
            { ConvertFrom-JWTtoken -Token 'eyJ.invalid!.signature' } | Should -Throw
            { ConvertFrom-JWTtoken -Token 'eyJub3QtanNvbg.e25vdC1qc29u.signature' } | Should -Throw
        }
    }
}
