BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force

    $script:FakeSCCAuth = "fakeSCCauthcookie"
    $script:FakeXSRF    = "fakeXSRFtoken"

    # Fake token response returned by the XDR API
    $script:FakeXdrToken = [PSCustomObject]@{
        token     = "eyFakeAccessToken"
        tokenType = "Bearer"
    }
}

Describe "Get-EntraIDTokenFromSCCAUTHCookie" {
    Context "XSRF provided by caller" {
        BeforeAll {
            Mock -ModuleName TokenTactics Invoke-WebRequest {} # not called when XSRF is supplied
            Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeXdrToken }
        }

        It "Does not call Invoke-WebRequest when XSRF is provided" {
            Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth $script:FakeSCCAuth -XSRF $script:FakeXSRF -ResourceName "MicrosoftGraph"
            Should -Invoke -ModuleName TokenTactics Invoke-WebRequest -Times 0
        }

        It "Calls the token endpoint and returns the response" {
            $result = Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth $script:FakeSCCAuth -XSRF $script:FakeXSRF -ResourceName "MicrosoftGraph"
            $result | Should -Not -BeNullOrEmpty
        }

        It "Uses the MicrosoftGraph resource URL" {
            Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth $script:FakeSCCAuth -XSRF $script:FakeXSRF -ResourceName "MicrosoftGraph"
            Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
                $Uri -match "graph\.microsoft\.com"
            } -Times 1
        }

        It "Uses the Azure resource URL for ResourceName Azure" {
            Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth $script:FakeSCCAuth -XSRF $script:FakeXSRF -ResourceName "Azure"
            Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
                $Uri -match "management\.core\.windows\.net"
            } -Times 1
        }

        It "Uses the LogAnalytics resource GUID" {
            Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth $script:FakeSCCAuth -XSRF $script:FakeXSRF -ResourceName "LogAnalytics"
            Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
                $Uri -match "ca7f3f0b"
            } -Times 1
        }

        It "Uses the MicrosoftOffice resource URL" {
            Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth $script:FakeSCCAuth -XSRF $script:FakeXSRF -ResourceName "MicrosoftOffice"
            Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
                $Uri -match "portal\.office\.com"
            } -Times 1
        }

        It "Uses a custom resource URL when -Resource is specified" {
            Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth $script:FakeSCCAuth -XSRF $script:FakeXSRF -Resource "https://custom.example.com/"
            Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
                $Uri -match "custom\.example\.com"
            } -Times 1
        }

        It "Includes the serviceType query parameter when it is set (Purview)" {
            Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth $script:FakeSCCAuth -XSRF $script:FakeXSRF -ResourceName "Purview"
            Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
                $Uri -match "serviceType=73c2949e"
            } -Times 1
        }

        It "Sets the X-XSRF-TOKEN request header" {
            Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth $script:FakeSCCAuth -XSRF $script:FakeXSRF -ResourceName "MicrosoftGraph"
            Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -ParameterFilter {
                $Headers -is [hashtable] -and $Headers.ContainsKey("X-XSRF-TOKEN")
            } -Times 1
        }
    }

    Context "XSRF obtained automatically" {
        BeforeAll {
            # Simulate Invoke-WebRequest adding an xsrf-token cookie to the session
            Mock -ModuleName TokenTactics Invoke-WebRequest {
                param($WebSession, $Uri)
                $cookie = [System.Net.Cookie]::new("xsrf-token", $script:FakeXSRF, "/", "security.microsoft.com")
                $WebSession.Cookies.Add([Uri]"https://security.microsoft.com/", $cookie)
                return [PSCustomObject]@{ StatusCode = 200 }
            }
            Mock -ModuleName TokenTactics Invoke-RestMethod { return $script:FakeXdrToken }
        }

        It "Calls Invoke-WebRequest to obtain the XSRF token" {
            Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth $script:FakeSCCAuth -ResourceName "MicrosoftGraph"
            Should -Invoke -ModuleName TokenTactics Invoke-WebRequest -Times 1
        }

        It "Calls the token endpoint after obtaining XSRF automatically" {
            $result = Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth $script:FakeSCCAuth -ResourceName "MicrosoftGraph"
            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context "XSRF cookie not returned (failure path)" {
        BeforeAll {
            # Simulate Invoke-WebRequest NOT adding the xsrf-token cookie
            Mock -ModuleName TokenTactics Invoke-WebRequest {
                return [PSCustomObject]@{ StatusCode = 200 }
            }
        }

        It "Throws when XSRF cookie cannot be obtained" {
            { Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth $script:FakeSCCAuth -ResourceName "MicrosoftGraph" } | Should -Throw
        }
    }
}
