BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force
}

Describe "ConvertTo-URLParameters" {
    It "Parses a simple query string into a hashtable" {
        InModuleScope TokenTactics {
            $result = ConvertTo-URLParameters -RequestURL "https://example.com/callback?code=abc123&state=xyz"
            $result['code'] | Should -Be "abc123"
            $result['state'] | Should -Be "xyz"
        }
    }

    It "Returns a hashtable with correct key count" {
        InModuleScope TokenTactics {
            $result = ConvertTo-URLParameters -RequestURL "https://example.com/callback?code=abc&state=def&session_state=ghi"
            $result.Count | Should -Be 3
        }
    }

    It "Handles a URL with a single parameter" {
        InModuleScope TokenTactics {
            $result = ConvertTo-URLParameters -RequestURL "https://example.com/callback?code=singlecode"
            $result['code'] | Should -Be "singlecode"
        }
    }

    It "Returns an empty hashtable for a URL with no query string" {
        InModuleScope TokenTactics {
            $result = ConvertTo-URLParameters -RequestURL "https://example.com/callback"
            $result | Should -BeOfType [hashtable]
        }
    }
}
