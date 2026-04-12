BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force
}

Describe "Get-TenantID" {
    BeforeAll {
        # Build a fake openid-configuration response where the tenant GUID is embedded
        # in the authorization_endpoint path segment.
        $script:FakeTenantId = "aaaabbbb-cccc-dddd-eeee-ffffaaaabbbb"
        $script:FakeOpenIdConfig = [PSCustomObject]@{
            authorization_endpoint = "https://login.microsoftonline.com/$($script:FakeTenantId)/oauth2/authorize"
        }
    }

    It "Returns the tenant GUID extracted from authorization_endpoint" {
        Mock -ModuleName TokenTactics Invoke-RestMethod {
            return $script:FakeOpenIdConfig
        }
        $result = Get-TenantID -domain "contoso.com"
        $result | Should -Be $script:FakeTenantId
    }

    It "Calls the correct openid-configuration URL for the supplied domain" {
        Mock -ModuleName TokenTactics Invoke-RestMethod {
            return $script:FakeOpenIdConfig
        } -Verifiable
        Get-TenantID -domain "fabrikam.com"
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
            $Uri -match "fabrikam\.com"
        } -Times 1
    }
}
