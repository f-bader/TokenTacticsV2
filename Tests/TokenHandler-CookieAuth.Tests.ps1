BeforeAll {
    # Dot-source the required function files
    . "$PSScriptRoot/../modules/TokenHandler.ps1"
    . "$PSScriptRoot/../modules/Get-ForgedUserAgent.ps1"
    . "$PSScriptRoot/../modules/CodeVerifier.ps1"
    . "$PSScriptRoot/../modules/ConvertFrom-JWTtoken.ps1"
}

Describe "Get-AzureTokenFromCookie" {
    BeforeAll {
        Mock Get-ForgedUserAgent { return "Mocked-UserAgent" }
        Mock Get-TTCodeVerifier { return "mock_verifier_12345678901234567890123456789012" }
        Mock Get-TTCodeChallenge { return "mock_challenge_1234567890123456789012345678901" }
        Mock Invoke-WebRequest {
            param($Uri, $Method, $WebSession)
            
            # Mock the response based on URI
            if ($Uri -like "*authorize*") {
                $response = [PSCustomObject]@{
                    Headers = @{
                        Location = "mock://redirect?code=mock_auth_code&state=mock_state"
                    }
                    StatusCode = 302
                }
                return $response
            }
            return [PSCustomObject]@{ StatusCode = 200 }
        }
        Mock Invoke-RestMethod {
            return [PSCustomObject]@{
                token_type    = "Bearer"
                scope         = "mock_scope"
                expires_in    = 3600
                access_token  = "******"
                refresh_token = "mock_refresh_token"
                id_token      = "******"
            }
        }
        Mock ConvertFrom-JWTtoken {
            return [PSCustomObject]@{
                upn = "test@example.com"
            }
        }
    }

    Context "Cookie Authentication" {
        It "Should accept cookie parameters" {
            { Get-AzureTokenFromCookie -CookieType "ESTSAUTHPERSISTENT" -CookieValue "test_cookie" -ClientID "test_client" -Scope "test_scope" -RedirectUrl "https://test" } | Should -Not -Throw
        }

        It "Should create web session with cookie" {
            Mock Invoke-WebRequest {
                param($WebSession)
                $WebSession | Should -Not -BeNullOrEmpty
                return [PSCustomObject]@{
                    Headers = @{ Location = "mock://redirect?code=test&state=test" }
                    StatusCode = 302
                }
            }
            
            { Get-AzureTokenFromCookie -CookieType "ESTSAUTH" -CookieValue "test" -ClientID "test" -Scope "test" -RedirectUrl "https://test" } | Should -Not -Throw
        }

        It "Should use custom user agent when provided" {
            $customUA = "Custom/1.0"
            Mock Invoke-WebRequest {
                param($Headers)
                $Headers["User-Agent"] | Should -Be $customUA
                return [PSCustomObject]@{
                    Headers = @{ Location = "mock://redirect?code=test&state=test" }
                    StatusCode = 302
                }
            }
            
            Get-AzureTokenFromCookie -CookieType "ESTSAUTH" -CookieValue "test" -ClientID "test" -Scope "test" -RedirectUrl "https://test" -CustomUserAgent $customUA
            
            Should -Invoke Get-ForgedUserAgent -Times 0
        }

        It "Should call Get-ForgedUserAgent when device/browser specified" {
            Get-AzureTokenFromCookie -CookieType "ESTSAUTH" -CookieValue "test" -ClientID "test" -Scope "test" -RedirectUrl "https://test" -Device "iPhone" -Browser "Safari"
            
            Should -Invoke Get-ForgedUserAgent -Times 1
        }

        It "Should use v2.0 endpoint by default" {
            Mock Invoke-WebRequest {
                param($Uri)
                $Uri | Should -BeLike "*v2.0/authorize*"
                return [PSCustomObject]@{
                    Headers = @{ Location = "mock://redirect?code=test&state=test" }
                    StatusCode = 302
                }
            }
            
            Get-AzureTokenFromCookie -CookieType "ESTSAUTH" -CookieValue "test" -ClientID "test" -Scope "test" -RedirectUrl "https://test"
        }

        It "Should use v1 endpoint when UseV1Endpoint specified" {
            Mock Invoke-WebRequest {
                param($Uri)
                $Uri | Should -BeLike "*oauth2/authorize*"
                $Uri | Should -Not -BeLike "*v2.0*"
                return [PSCustomObject]@{
                    Headers = @{ Location = "mock://redirect?code=test&state=test" }
                    StatusCode = 302
                }
            }
            
            Get-AzureTokenFromCookie -CookieType "ESTSAUTH" -CookieValue "test" -ClientID "test" -Scope "test" -RedirectUrl "https://test" -UseV1Endpoint -Resource "https://test.resource"
        }

        It "Should include code verifier parameters when UseCodeVerifier specified" {
            Mock Invoke-WebRequest {
                param($Uri)
                $Uri | Should -BeLike "*code_challenge=*"
                return [PSCustomObject]@{
                    Headers = @{ Location = "mock://redirect?code=test&state=test" }
                    StatusCode = 302
                }
            }
            
            Get-AzureTokenFromCookie -CookieType "ESTSAUTH" -CookieValue "test" -ClientID "test" -Scope "test" -RedirectUrl "https://test" -UseCodeVerifier
            
            Should -Invoke Get-TTCodeVerifier -Times 1
            Should -Invoke Get-TTCodeChallenge -Times 1
        }
    }
}

Describe "Get-AzureTokenFromESTSCookie" {
    BeforeAll {
        Mock Get-AzureTokenFromCookie {
            return [PSCustomObject]@{
                token_type    = "Bearer"
                access_token  = "mock_token"
                refresh_token = "mock_refresh"
            }
        }
        Mock Get-ForgedUserAgent { return "Mocked-UserAgent" }
    }

    Context "ESTS Cookie Wrapper" {
        It "Should call Get-AzureTokenFromCookie with ESTSAUTHPERSISTENT cookie type" {
            Get-AzureTokenFromESTSCookie -ESTSAuthPersistentCookie "test_cookie"
            
            Should -Invoke Get-AzureTokenFromCookie -Times 1 -ParameterFilter {
                $CookieType -eq "ESTSAUTHPERSISTENT"
            }
        }

        It "Should use default MSGraph client parameters" {
            Get-AzureTokenFromESTSCookie -ESTSAuthPersistentCookie "test_cookie"
            
            Should -Invoke Get-AzureTokenFromCookie -Times 1 -ParameterFilter {
                $ClientID -eq "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
            }
        }

        It "Should accept Client parameter" {
            Get-AzureTokenFromESTSCookie -ESTSAuthPersistentCookie "test_cookie" -Client "Graph"
            
            Should -Invoke Get-AzureTokenFromCookie -Times 1 -ParameterFilter {
                $ClientID -eq "1b730954-1685-4b74-9bfd-dac224a7b894"
            }
        }

        It "Should propagate device and browser parameters" {
            Get-AzureTokenFromESTSCookie -ESTSAuthPersistentCookie "test_cookie" -Device "iPhone" -Browser "Safari"
            
            Should -Invoke Get-AzureTokenFromCookie -Times 1 -ParameterFilter {
                $Device -eq "iPhone" -and $Browser -eq "Safari"
            }
        }

        It "Should propagate resource parameter when specified" {
            Get-AzureTokenFromESTSCookie -ESTSAuthPersistentCookie "test_cookie" -Resource "https://test.resource"
            
            Should -Invoke Get-AzureTokenFromCookie -Times 1 -ParameterFilter {
                $Resource -eq "https://test.resource"
            }
        }
    }
}

Describe "Get-AzureTokenFromAuthorizationCode" {
    BeforeAll {
        Mock Get-ForgedUserAgent { return "Mocked-UserAgent" }
        Mock Invoke-RestMethod {
            return [PSCustomObject]@{
                token_type    = "Bearer"
                scope         = "mock_scope"
                expires_in    = 3600
                access_token  = "******"
                refresh_token = "mock_refresh_token"
                id_token      = "******"
            }
        }
        Mock ConvertFrom-JWTtoken {
            return [PSCustomObject]@{
                upn = "test@example.com"
            }
        }
    }

    Context "Authorization Code Flow" {
        It "Should accept authorization code parameter" {
            { Get-AzureTokenFromAuthorizationCode -AuthorizationCode "test_code" } | Should -Not -Throw
        }

        It "Should use default MSGraph client" {
            Mock Invoke-RestMethod {
                param($Body)
                $Body["client_id"] | Should -Be "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
                return [PSCustomObject]@{
                    token_type = "Bearer"
                    access_token = "mock_token"
                }
            }
            
            Get-AzureTokenFromAuthorizationCode -AuthorizationCode "test_code"
        }

        It "Should accept Graph client parameter" {
            Mock Invoke-RestMethod {
                param($Body)
                $Body["client_id"] | Should -Be "1b730954-1685-4b74-9bfd-dac224a7b894"
                return [PSCustomObject]@{
                    token_type = "Bearer"
                    access_token = "mock_token"
                }
            }
            
            Get-AzureTokenFromAuthorizationCode -Client "Graph" -AuthorizationCode "test_code"
        }

        It "Should accept DeviceRegistration client parameter" {
            Mock Invoke-RestMethod {
                param($Body)
                $Body["client_id"] | Should -Be "b90d5b8f-5503-4153-b545-b31cecfaece2"
                return [PSCustomObject]@{
                    token_type = "Bearer"
                    access_token = "mock_token"
                }
            }
            
            Get-AzureTokenFromAuthorizationCode -Client "DeviceRegistration" -AuthorizationCode "test_code"
        }

        It "Should extract code from full URL when RequestURL parameter used" {
            Mock Invoke-RestMethod {
                param($Body)
                $Body["code"] | Should -Be "test_auth_code"
                return [PSCustomObject]@{
                    token_type = "Bearer"
                    access_token = "mock_token"
                }
            }
            
            Get-AzureTokenFromAuthorizationCode -RequestURL "https://redirect?code=test_auth_code&state=test"
        }

        It "Should use v2.0 endpoint by default" {
            Mock Invoke-RestMethod {
                param($Uri)
                $Uri | Should -BeLike "*v2.0/token*"
                return [PSCustomObject]@{
                    token_type = "Bearer"
                    access_token = "mock_token"
                }
            }
            
            Get-AzureTokenFromAuthorizationCode -AuthorizationCode "test_code"
        }

        It "Should include code verifier when provided" {
            Mock Invoke-RestMethod {
                param($Body)
                $Body["code_verifier"] | Should -Be "test_verifier"
                return [PSCustomObject]@{
                    token_type = "Bearer"
                    access_token = "mock_token"
                }
            }
            
            Get-AzureTokenFromAuthorizationCode -AuthorizationCode "test_code" -CodeVerifier "test_verifier"
        }

        It "Should set global response variable" {
            Get-AzureTokenFromAuthorizationCode -AuthorizationCode "test_code"
            
            $global:response | Should -Not -BeNullOrEmpty
        }

        It "Should set global TokenDomain and TokenUpn variables" {
            Get-AzureTokenFromAuthorizationCode -AuthorizationCode "test_code"
            
            $global:TokenDomain | Should -Be "example.com"
            $global:TokenUpn | Should -Be "test@example.com"
        }
    }
}

Describe "Get-AzureTokenFromRefreshTokenCredentialCookie" {
    BeforeAll {
        Mock Invoke-WebRequest {
            return [PSCustomObject]@{
                Content = '{"access_token":"mock_access_token","refresh_token":"mock_refresh_token"}'
                StatusCode = 200
            }
        }
        Mock Get-ForgedUserAgent { return "Mocked-UserAgent" }
    }

    Context "Refresh Token Credential Cookie" {
        It "Should accept cookie parameter" {
            { Get-AzureTokenFromRefreshTokenCredentialCookie -CookieValue "test_cookie" } | Should -Not -Throw
        }

        It "Should make POST request to appverify endpoint" {
            Mock Invoke-WebRequest {
                param($Uri, $Method)
                $Uri | Should -BeLike "*appverify*"
                $Method | Should -Be "Post"
                return [PSCustomObject]@{
                    Content = '{"access_token":"test","refresh_token":"test"}'
                }
            }
            
            Get-AzureTokenFromRefreshTokenCredentialCookie -CookieValue "test_cookie"
        }

        It "Should set global response variable" {
            Get-AzureTokenFromRefreshTokenCredentialCookie -CookieValue "test_cookie"
            
            $global:response | Should -Not -BeNullOrEmpty
        }

        It "Should use custom user agent when provided" {
            $customUA = "Custom/1.0"
            Mock Invoke-WebRequest {
                param($Headers)
                $Headers["User-Agent"] | Should -Be $customUA
                return [PSCustomObject]@{
                    Content = '{"access_token":"test","refresh_token":"test"}'
                }
            }
            
            Get-AzureTokenFromRefreshTokenCredentialCookie -CookieValue "test_cookie" -CustomUserAgent $customUA
        }
    }
}
