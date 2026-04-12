BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force
}

Describe "Clear-Token" {
    BeforeEach {
        # Pre-set all global token variables
        $global:response              = [PSCustomObject]@{ access_token = "fake" }
        $global:OutlookToken          = [PSCustomObject]@{ access_token = "fake" }
        $global:MSTeamsToken          = [PSCustomObject]@{ access_token = "fake" }
        $global:GraphToken            = [PSCustomObject]@{ access_token = "fake" }
        $global:AzureCoreManagementToken = [PSCustomObject]@{ access_token = "fake" }
        $global:OfficeManagementToken = [PSCustomObject]@{ access_token = "fake" }
        $global:MSGraphToken          = [PSCustomObject]@{ access_token = "fake" }
        $global:DODMSGraphToken       = [PSCustomObject]@{ access_token = "fake" }
        $global:CustomToken           = [PSCustomObject]@{ access_token = "fake" }
        $global:SubstrateToken        = [PSCustomObject]@{ access_token = "fake" }
        $global:SharePointToken       = [PSCustomObject]@{ access_token = "fake" }
        $global:YammerToken           = [PSCustomObject]@{ access_token = "fake" }
        $global:DeviceRegistrationToken = [PSCustomObject]@{ access_token = "fake" }
    }

    AfterEach {
        # Clean up any remaining global variables
        Remove-Variable -Scope Global -Name response              -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name OutlookToken          -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name MSTeamsToken          -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name GraphToken            -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name AzureCoreManagementToken -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name OfficeManagementToken -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name MSGraphToken          -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name DODMSGraphToken       -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name CustomToken           -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name SubstrateToken        -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name SharePointToken       -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name YammerToken           -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name DeviceRegistrationToken -ErrorAction SilentlyContinue
    }

    Context "Clear-Token -Token All" {
        It "Removes the `$response global variable" {
            Clear-Token -Token All
            { Get-Variable -Scope Global -Name response -ErrorAction Stop } | Should -Throw
        }

        It "Removes the `$MSTeamsToken global variable" {
            Clear-Token -Token All
            { Get-Variable -Scope Global -Name MSTeamsToken -ErrorAction Stop } | Should -Throw
        }

        It "Removes the `$MSGraphToken global variable" {
            Clear-Token -Token All
            { Get-Variable -Scope Global -Name MSGraphToken -ErrorAction Stop } | Should -Throw
        }

        It "Removes the `$SubstrateToken global variable" {
            Clear-Token -Token All
            { Get-Variable -Scope Global -Name SubstrateToken -ErrorAction Stop } | Should -Throw
        }
    }

    Context "Clear-Token -Token specific" {
        It "Removes only `$MSTeamsToken when -Token MSTeams is specified" {
            Clear-Token -Token MSTeams
            { Get-Variable -Scope Global -Name MSTeamsToken -ErrorAction Stop } | Should -Throw
            # Other tokens should still exist
            $global:response | Should -Not -BeNullOrEmpty
        }

        It "Removes only `$response when -Token Response is specified" {
            Clear-Token -Token Response
            { Get-Variable -Scope Global -Name response -ErrorAction Stop } | Should -Throw
            $global:MSTeamsToken | Should -Not -BeNullOrEmpty
        }

        It "Removes only `$MSGraphToken when -Token MSGraph is specified" {
            Clear-Token -Token MSGraph
            { Get-Variable -Scope Global -Name MSGraphToken -ErrorAction Stop } | Should -Throw
            $global:response | Should -Not -BeNullOrEmpty
        }

        It "Removes only `$OutlookToken when -Token Outlook is specified" {
            Clear-Token -Token Outlook
            { Get-Variable -Scope Global -Name OutlookToken -ErrorAction Stop } | Should -Throw
            $global:response | Should -Not -BeNullOrEmpty
        }

        It "Removes only `$GraphToken when -Token Graph is specified" {
            Clear-Token -Token Graph
            { Get-Variable -Scope Global -Name GraphToken -ErrorAction Stop } | Should -Throw
            $global:response | Should -Not -BeNullOrEmpty
        }

        It "Removes only `$SharePointToken when -Token SharePoint is specified" {
            Clear-Token -Token SharePoint
            { Get-Variable -Scope Global -Name SharePointToken -ErrorAction Stop } | Should -Throw
            $global:response | Should -Not -BeNullOrEmpty
        }

        It "Does not throw when the variable does not already exist" {
            Remove-Variable -Scope Global -Name MSTeamsToken -ErrorAction SilentlyContinue
            { Clear-Token -Token MSTeams } | Should -Not -Throw
        }
    }
}
