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
            $result.Count | Should -Be 0
        }
    }

    It "URL-decodes names and values without corrupting embedded equals signs" {
        InModuleScope TokenTactics {
            $result = ConvertTo-URLParameters -RequestURL "https://example.com/callback?authorization%20code=abc%2Bdef%2Fghi%3D%3D&state=a=b=c"
            $result['authorization code'] | Should -Be 'abc+def/ghi=='
            $result['state'] | Should -Be 'a=b=c'
        }
    }

    It "handles empty values, parameters without equals signs, and fragments" {
        InModuleScope TokenTactics {
            $result = ConvertTo-URLParameters -RequestURL "https://example.com/callback?empty=&flag&code=value#ignored=true"
            $result.Count | Should -Be 3
            $result['empty'] | Should -Be ''
            $result['flag'] | Should -Be ''
            $result['code'] | Should -Be 'value'
        }
    }
}
