BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force
}

Describe "ConvertTo-Base64Url" {
    It "Encodes a simple byte array without padding characters" {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes("hello")
        InModuleScope TokenTactics {
            $result = ConvertTo-Base64Url -Bytes ([System.Text.Encoding]::UTF8.GetBytes("hello"))
            $result | Should -Not -Match '\+'
            $result | Should -Not -Match '/'
            $result | Should -Not -Match '='
        }
    }

    It "Produces the expected Base64URL output for a known input" {
        # "hello" in standard Base64 is "aGVsbG8=" -> Base64URL is "aGVsbG8"
        InModuleScope TokenTactics {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes("hello")
            $result = ConvertTo-Base64Url -Bytes $bytes
            $result | Should -Be "aGVsbG8"
        }
    }

    It "Replaces + with - and / with _ compared to standard Base64" {
        # Byte sequence that produces + and / in standard Base64: bytes 0xFB, 0xFF (standard: +//x -> -__x in Base64URL)
        InModuleScope TokenTactics {
            $bytes = [byte[]](0xFB, 0xFF)
            $standard = [Convert]::ToBase64String($bytes)  # "+/8="
            $result = ConvertTo-Base64Url -Bytes $bytes
            $result | Should -Be ($standard.Replace('+', '-').Replace('/', '_').TrimEnd('='))
        }
    }
}
