BeforeAll {
    # Dot-source the required function files
    . "$PSScriptRoot/../modules/TokenHandler.ps1"
    . "$PSScriptRoot/../modules/Get-ForgedUserAgent.ps1"
    . "$PSScriptRoot/../modules/Get-TenantId.ps1"
    . "$PSScriptRoot/../modules/CodeVerifier.ps1"
    . "$PSScriptRoot/../modules/ConvertFrom-JWTtoken.ps1"
}

Describe "Get-AzureToken" {
    BeforeAll {
        # Mock external dependencies
        Mock Get-ForgedUserAgent { return "Mocked-UserAgent" }
        Mock Invoke-RestMethod {
            param($Uri, $Method, $Headers, $Body)
            
            if ($Uri -like "*devicecode*") {
                return [PSCustomObject]@{
                    device_code      = "mock_device_code"
                    user_code        = "MOCK123"
                    verification_uri = "https://microsoft.com/devicelogin"
                    expires_in       = 900
                    interval         = 5
                    message          = "Mock message"
                }
            } else {
                return [PSCustomObject]@{
                    token_type    = "Bearer"
                    scope         = "mock_scope"
                    expires_in    = 3600
                    access_token  = "******"
                    refresh_token = "mock_refresh_token"
                }
            }
        }
        Mock Write-Output {}
        Mock ConvertFrom-JWTtoken {
            return [PSCustomObject]@{
                upn = "test@example.com"
            }
        }
    }

    Context "Client Parameter Validation" {
        It "Should use default client ID for Outlook client" {
            Mock Invoke-RestMethod {
                param($Body)
                $Body["client_id"] | Should -Be "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                $Body["scope"] | Should -BeLike "*outlook.office365.com*"
                return [PSCustomObject]@{
                    device_code = "mock"
                    user_code = "MOCK"
                    verification_uri = "https://test"
                    expires_in = 900
                    interval = 5
                }
            }
            
            Get-AzureToken -Client Outlook 6>&1 | Out-Null
            
            Should -Invoke Invoke-RestMethod -Times 1
        }

        It "Should use correct scope for Substrate client" {
            Mock Invoke-RestMethod {
                param($Body)
                $Body["scope"] | Should -BeLike "*substrate.office.com*"
                return [PSCustomObject]@{
                    device_code = "mock"
                    user_code = "MOCK"
                    verification_uri = "https://test"
                    expires_in = 900
                    interval = 5
                }
            }
            
            Get-AzureToken -Client Substrate 6>&1 | Out-Null
            
            Should -Invoke Invoke-RestMethod -Times 1
        }

        It "Should require ClientID and Scope for Custom client" {
            Mock Write-Error {}
            
            Get-AzureToken -Client Custom -ClientID "" 6>&1 | Out-Null
            
            Should -Invoke Write-Error -AtLeast 1
        }
    }

    Context "User Agent Handling" {
        It "Should call Get-ForgedUserAgent when using Device parameter" {
            Mock Get-ForgedUserAgent { return "Mock-Device-UA" }
            
            Get-AzureToken -Device "Windows" 6>&1 | Out-Null
            
            Should -Invoke Get-ForgedUserAgent -Times 1
        }

        It "Should call Get-ForgedUserAgent when using Browser parameter" {
            Mock Get-ForgedUserAgent { return "Mock-Browser-UA" }
            
            Get-AzureToken -Browser "Chrome" 6>&1 | Out-Null
            
            Should -Invoke Get-ForgedUserAgent -Times 1
        }
    }
}

Describe "Get-AzureAuthorizationCode" {
    Context "URL Generation" {
        It "Should generate authorization URL with default parameters" {
            $output = Get-AzureAuthorizationCode 6>&1
            $url = $output[0]
            
            $url | Should -Not -BeNullOrEmpty
            $url | Should -BeLike "*login.microsoftonline.com*"
            $url | Should -BeLike "*response_type=code*"
        }

        It "Should include MSGraph scope when MSGraph client specified" {
            $output = Get-AzureAuthorizationCode -Client MSGraph 6>&1
            $url = $output[0]
            
            $url | Should -BeLike "*graph.microsoft.com*"
        }

        It "Should include Graph scope when Graph client specified" {
            $output = Get-AzureAuthorizationCode -Client Graph 6>&1
            $url = $output[0]
            
            $url | Should -BeLike "*graph.windows.net*"
        }

        It "Should include custom scope when Custom client specified" {
            $output = Get-AzureAuthorizationCode -Client Custom -ClientID "test-client" -Scope "custom.scope" 6>&1
            $url = $output[0]
            
            $url | Should -BeLike "*custom.scope*"
        }

        It "Should include code verifier parameters when UseCodeVerifier is set" {
            Mock Get-TTCodeVerifier { return "mock_verifier" }
            Mock Get-TTCodeChallenge { return "mock_challenge" }
            
            $output = Get-AzureAuthorizationCode -UseCodeVerifier 6>&1
            $url = $output[0]
            
            $url | Should -BeLike "*code_challenge=*"
            $url | Should -BeLike "*code_challenge_method=S256*"
        }

        It "Should include CAE claims when UseCAE is set" {
            $output = Get-AzureAuthorizationCode -UseCAE 6>&1
            $url = $output[0]
            
            $url | Should -BeLike "*claims=*"
            $url | Should -BeLike "*xms_cc*"
        }

        It "Should use v1 endpoint when UseV1Endpoint is set" {
            $output = Get-AzureAuthorizationCode -UseV1Endpoint -Resource "https://test.resource" 6>&1
            $url = $output[0]
            
            $url | Should -BeLike "*oauth2/authorize*"
            $url | Should -Not -BeLike "*v2.0*"
            $url | Should -BeLike "*resource=*"
        }

        It "Should include login_hint when Username is provided" {
            $output = Get-AzureAuthorizationCode -Username "test@example.com" 6>&1
            $url = $output[0]
            
            $url | Should -BeLike "*login_hint=test@example.com*"
        }

        It "Should require ClientID and Scope for Custom client" {
            Mock Write-Error {}
            
            Get-AzureAuthorizationCode -Client Custom 6>&1 | Out-Null
            
            Should -Invoke Write-Error -Times 1
        }
    }
}

Describe "Invoke-RefreshToToken" {
    BeforeAll {
        Mock Get-ForgedUserAgent { return "Mocked-UserAgent" }
        Mock Get-TenantID { return "mock-tenant-id" }
        Mock Invoke-RestMethod {
            return [PSCustomObject]@{
                token_type    = "Bearer"
                scope         = "mock_scope"
                expires_in    = 3600
                access_token  = "mock_access_token"
                refresh_token = "mock_refresh_token"
            }
        }
    }

    Context "Token Refresh" {
        It "Should refresh token with required parameters" {
            $result = Invoke-RefreshToToken -Domain "test.com" -refreshToken "mock_refresh" -ClientID "mock_client" -Scope "mock_scope"
            
            $result | Should -Not -BeNullOrEmpty
            $result.access_token | Should -Be "mock_access_token"
        }

        It "Should call Get-TenantID with domain" {
            Invoke-RefreshToToken -Domain "test.com" -refreshToken "mock_refresh" -ClientID "mock_client" -Scope "mock_scope"
            
            Should -Invoke Get-TenantID -Times 1 -ParameterFilter { $domain -eq "test.com" }
        }

        It "Should call Invoke-RestMethod with correct parameters" {
            Invoke-RefreshToToken -Domain "test.com" -refreshToken "test_refresh" -ClientID "test_client" -Scope "test_scope"
            
            Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
                $Method -eq "Post" -and
                $Body["grant_type"] -eq "refresh_token" -and
                $Body["refresh_token"] -eq "test_refresh" -and
                $Body["client_id"] -eq "test_client" -and
                $Body["scope"] -eq "test_scope"
            }
        }

        It "Should use v2.0 endpoint by default" {
            Invoke-RefreshToToken -Domain "test.com" -refreshToken "mock_refresh" -ClientID "mock_client" -Scope "mock_scope"
            
            Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
                $Uri -like "*/oauth2/v2.0/token"
            }
        }

        It "Should use v1 endpoint when UseV1Endpoint is set" {
            Invoke-RefreshToToken -Domain "test.com" -refreshToken "mock_refresh" -ClientID "mock_client" -Scope "mock_scope" -UseV1Endpoint
            
            Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
                $Uri -like "*/oauth2/token" -and $Uri -notlike "*/v2.0/*"
            }
        }

        It "Should include CAE claims when UseCAE is set" {
            Invoke-RefreshToToken -Domain "test.com" -refreshToken "mock_refresh" -ClientID "mock_client" -Scope "mock_scope" -UseCAE
            
            Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
                $Body["claims"] -like "*xms_cc*"
            }
        }

        It "Should use DoD endpoint when UseDoD is set" {
            Invoke-RefreshToToken -Domain "test.com" -refreshToken "mock_refresh" -ClientID "mock_client" -Scope "mock_scope" -UseDoD
            
            Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
                $Uri -like "https://login.microsoftonline.us/*"
            }
        }

        It "Should include resource parameter when provided" {
            Invoke-RefreshToToken -Domain "test.com" -refreshToken "mock_refresh" -ClientID "mock_client" -Scope "mock_scope" -Resource "https://test.resource"
            
            Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
                $Body["resource"] -eq "https://test.resource"
            }
        }

        It "Should use custom user agent when provided" {
            Invoke-RefreshToToken -Domain "test.com" -refreshToken "mock_refresh" -ClientID "mock_client" -Scope "mock_scope" -CustomUserAgent "Custom/1.0"
            
            Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
                $Headers["User-Agent"] -eq "Custom/1.0"
            }
        }
    }
}
