BeforeAll {
    # Dot-source the function file directly for faster test execution
    . "$PSScriptRoot/../modules/Get-TenantId.ps1"
}

Describe "Get-TenantID" {
    Context "Valid Domain" {
        BeforeAll {
            # Mock the Invoke-RestMethod to avoid actual REST calls
            Mock Invoke-RestMethod {
                return [PSCustomObject]@{
                    authorization_endpoint = "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/oauth2/v2.0/authorize"
                    token_endpoint = "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/oauth2/v2.0/token"
                }
            }
        }

        It "Should return tenant ID for valid domain" {
            $result = Get-TenantID -domain "contoso.com"
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -Be "12345678-1234-1234-1234-123456789abc"
        }

        It "Should call Invoke-RestMethod with correct URL" {
            Get-TenantID -domain "contoso.com"
            
            Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
                $Uri -eq "https://login.microsoftonline.com/contoso.com/.well-known/openid-configuration"
            }
        }

        It "Should handle different domain names" {
            Get-TenantID -domain "fabrikam.com"
            
            Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
                $Uri -eq "https://login.microsoftonline.com/fabrikam.com/.well-known/openid-configuration"
            }
        }
    }

    Context "Error Handling" {
        BeforeAll {
            Mock Invoke-RestMethod {
                throw "Error: Domain not found"
            }
        }

        It "Should propagate errors from Invoke-RestMethod" {
            { Get-TenantID -domain "invalid-domain.com" } | Should -Throw
        }
    }

    Context "Parameter Validation" {
        It "Should require domain parameter" {
            { Get-TenantID -domain $null -ErrorAction Stop } | Should -Throw
        }
    }
}
