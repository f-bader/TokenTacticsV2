$resourceCases = @(
    @{ ResourceName = 'Azure'; Resource = 'https://management.core.windows.net/'; ServiceType = $null }
    @{ ResourceName = 'LogAnalytics'; Resource = 'ca7f3f0b-7d91-482c-8e09-c5d840d0eac5'; ServiceType = $null }
    @{ ResourceName = 'MATP'; Resource = 'MATP'; ServiceType = $null }
    @{ ResourceName = 'MCAS'; Resource = 'MCAS'; ServiceType = $null }
    @{ ResourceName = 'MicrosoftGraph'; Resource = 'https://graph.microsoft.com/'; ServiceType = $null }
    @{ ResourceName = 'MicrosoftOffice'; Resource = 'https://portal.office.com'; ServiceType = $null }
    @{ ResourceName = 'Purview'; Resource = 'https://api.purview-service.microsoft.com'; ServiceType = '73c2949e-da2d-457a-9607-fcc665198967' }
    @{ ResourceName = 'ThreatIntelligencePortal'; Resource = '478d8d1a-326f-49da-a58e-8f576faa4b5e'; ServiceType = $null }
)

BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force

    $script:FakeSCCAuth = 'fake-sccauth-cookie'
    $script:FakeXSRF = 'fake%2Bxsrf%2Ftoken'
    $script:DecodedXSRF = 'fake+xsrf/token'
    $script:FakeXdrToken = [PSCustomObject]@{ token = 'fake-access-token'; tokenType = 'Bearer' }
}

Describe 'Get-EntraIDTokenFromSCCAUTHCookie' {
    BeforeEach {
        Mock -ModuleName TokenTactics Invoke-WebRequest { throw 'Unexpected bootstrap request' }
        Mock -ModuleName TokenTactics Invoke-RestMethod { $script:FakeXdrToken }
    }

    It 'maps <ResourceName> to the exact XDR token request' -ForEach $resourceCases {
        $result = Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth $script:FakeSCCAuth -XSRF $script:FakeXSRF -ResourceName $ResourceName

        $result | Should -Be $script:FakeXdrToken
        Should -Invoke -ModuleName TokenTactics Invoke-WebRequest -Times 0 -Exactly -Scope It
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -Times 1 -Exactly -Scope It -ParameterFilter {
            $parsedUri = [Uri]$Uri
            $query = [System.Web.HttpUtility]::ParseQueryString($parsedUri.Query)
            $parsedUri.Scheme -eq 'https' -and
            $parsedUri.Host -eq 'security.microsoft.com' -and
            $parsedUri.AbsolutePath -eq '/api/Auth/getToken' -and
            $query['resource'] -eq $Resource -and
            $query['serviceType'] -eq $ServiceType -and
            $ContentType -eq 'application/json' -and
            $WebSession -is [Microsoft.PowerShell.Commands.WebRequestSession] -and
            $Headers.Count -eq 1 -and
            $Headers['X-XSRF-TOKEN'] -eq 'fake+xsrf/token'
        }
    }

    It 'uses exact custom resource, service type, tenant headers, and decoded XSRF value' {
        Get-EntraIDTokenFromSCCAUTHCookie `
            -SCCAuth $script:FakeSCCAuth `
            -XSRF $script:FakeXSRF `
            -Resource 'api://custom-resource' `
            -ServiceType 'custom-service' `
            -TenantId 'tenant-id'

        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -Times 1 -Exactly -Scope It -ParameterFilter {
            $parsedUri = [Uri]$Uri
            $query = [System.Web.HttpUtility]::ParseQueryString($parsedUri.Query)
            $query['resource'] -eq 'api://custom-resource' -and
            $query['serviceType'] -eq 'custom-service' -and
            $Headers.Count -eq 3 -and
            $Headers['X-XSRF-TOKEN'] -eq 'fake+xsrf/token' -and
            $Headers['x-tid'] -eq 'tenant-id' -and
            $Headers['tenant-id'] -eq 'tenant-id'
        }
    }

    It 'constructs the PurviewACC resource from an explicitly supplied tenant' {
        Get-EntraIDTokenFromSCCAUTHCookie `
            -SCCAuth $script:FakeSCCAuth `
            -XSRF $script:FakeXSRF `
            -ResourceName PurviewACC `
            -TenantId 'tenant-id'

        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -Times 1 -Exactly -Scope It -ParameterFilter {
            $query = [System.Web.HttpUtility]::ParseQueryString(([Uri]$Uri).Query)
            $query['resource'] -eq 'https://tenant-id-api.purview-service.microsoft.com' -and
            $query['serviceType'] -eq '73c2949e-da2d-457a-9607-fcc665198967' -and
            $Headers['x-tid'] -eq 'tenant-id' -and
            $Headers['tenant-id'] -eq 'tenant-id'
        }
    }

    It 'retrieves the tenant before requesting a PurviewACC token when none is supplied' {
        Mock -ModuleName TokenTactics Invoke-RestMethod { throw "Unexpected REST request: $Uri" }
        Mock -ModuleName TokenTactics Invoke-RestMethod {
            [PSCustomObject]@{ AuthInfo = [PSCustomObject]@{ TenantId = 'discovered-tenant' } }
        } -ParameterFilter { $Uri -match '/TenantContext\?realTime=true$' }
        Mock -ModuleName TokenTactics Invoke-RestMethod { $script:FakeXdrToken } -ParameterFilter {
            $query = [System.Web.HttpUtility]::ParseQueryString(([Uri]$Uri).Query)
            $query['resource'] -eq 'https://discovered-tenant-api.purview-service.microsoft.com'
        }

        $result = Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth $script:FakeSCCAuth -XSRF $script:FakeXSRF -ResourceName PurviewACC

        $result | Should -Be $script:FakeXdrToken
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -Times 2 -Exactly -Scope It
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -Times 1 -Exactly -Scope It -ParameterFilter {
            $Uri -eq 'https://security.microsoft.com/apiproxy/mtp/sccManagement/mgmt/TenantContext?realTime=true'
        }
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -Times 1 -Exactly -Scope It -ParameterFilter {
            $query = [System.Web.HttpUtility]::ParseQueryString(([Uri]$Uri).Query)
            $query['resource'] -eq 'https://discovered-tenant-api.purview-service.microsoft.com' -and
            $Headers['x-tid'] -eq 'discovered-tenant' -and
            $Headers['tenant-id'] -eq 'discovered-tenant'
        }
    }

    It 'bootstraps XSRF exactly once when the caller does not provide it' {
        Mock -ModuleName TokenTactics Invoke-WebRequest {
            param($WebSession)
            $cookie = [System.Net.Cookie]::new('xsrf-token', $script:FakeXSRF, '/', 'security.microsoft.com')
            $WebSession.Cookies.Add([Uri]'https://security.microsoft.com/', $cookie)
            [PSCustomObject]@{ StatusCode = 200 }
        }

        Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth $script:FakeSCCAuth -ResourceName MicrosoftGraph

        Should -Invoke -ModuleName TokenTactics Invoke-WebRequest -Times 1 -Exactly -Scope It -ParameterFilter {
            $UseBasicParsing -and
            "$ErrorAction" -eq 'SilentlyContinue' -and
            "$Method" -eq 'Get' -and
            $Uri -eq 'https://security.microsoft.com/' -and
            $WebSession -is [Microsoft.PowerShell.Commands.WebRequestSession]
        }
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -Times 1 -Exactly -Scope It -ParameterFilter {
            $Headers['X-XSRF-TOKEN'] -eq 'fake+xsrf/token'
        }
    }

    It 'throws when XSRF bootstrapping does not return the cookie' {
        Mock -ModuleName TokenTactics Invoke-WebRequest { [PSCustomObject]@{ StatusCode = 200 } }

        { Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth $script:FakeSCCAuth -ResourceName MicrosoftGraph } |
            Should -Throw '*Failed to obtain XSRF-TOKEN*'
        Should -Invoke -ModuleName TokenTactics Invoke-RestMethod -Times 0 -Exactly -Scope It
    }

    It 'propagates token endpoint failures' {
        Mock -ModuleName TokenTactics Invoke-RestMethod { throw 'XDR token request failed' }

        { Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth $script:FakeSCCAuth -XSRF $script:FakeXSRF -ResourceName MicrosoftGraph } |
            Should -Throw '*XDR token request failed*'
    }
}
