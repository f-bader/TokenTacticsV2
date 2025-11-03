BeforeAll {
    # Dot-source the function file directly for faster test execution
    . "$PSScriptRoot/../modules/TokenHandler.ps1"
}

Describe "Clear-Token" {
    Context "Clear All Tokens" {
        BeforeEach {
            # Set up some global variables to test clearing
            $global:response = "test_response"
            $global:OutlookToken = "test_outlook"
            $global:MSTeamsToken = "test_msteams"
            $global:GraphToken = "test_graph"
            $global:MSGraphToken = "test_msgraph"
            $global:SubstrateToken = "test_substrate"
            $global:SharePointToken = "test_sharepoint"
        }

        It "Should clear all token variables when Token is 'All'" {
            Clear-Token -Token All
            
            # Verify variables are removed
            { Get-Variable -Name response -Scope Global -ErrorAction Stop } | Should -Throw
            { Get-Variable -Name OutlookToken -Scope Global -ErrorAction Stop } | Should -Throw
            { Get-Variable -Name MSTeamsToken -Scope Global -ErrorAction Stop } | Should -Throw
            { Get-Variable -Name GraphToken -Scope Global -ErrorAction Stop } | Should -Throw
            { Get-Variable -Name MSGraphToken -Scope Global -ErrorAction Stop } | Should -Throw
            { Get-Variable -Name SubstrateToken -Scope Global -ErrorAction Stop } | Should -Throw
        }
    }

    Context "Clear Individual Tokens" {
        BeforeEach {
            # Set up some global variables to test clearing
            $global:response = "test_response"
            $global:OutlookToken = "test_outlook"
            $global:MSTeamsToken = "test_msteams"
            $global:GraphToken = "test_graph"
        }

        It "Should clear only Response token when Token is 'Response'" {
            Clear-Token -Token Response
            
            { Get-Variable -Name response -Scope Global -ErrorAction Stop } | Should -Throw
            { Get-Variable -Name OutlookToken -Scope Global -ErrorAction Stop } | Should -Not -Throw
        }

        It "Should clear only Outlook token when Token is 'Outlook'" {
            Clear-Token -Token Outlook
            
            { Get-Variable -Name OutlookToken -Scope Global -ErrorAction Stop } | Should -Throw
            { Get-Variable -Name response -Scope Global -ErrorAction Stop } | Should -Not -Throw
        }

        It "Should clear only MSTeams token when Token is 'MSTeams'" {
            Clear-Token -Token MSTeams
            
            { Get-Variable -Name MSTeamsToken -Scope Global -ErrorAction Stop } | Should -Throw
            { Get-Variable -Name response -Scope Global -ErrorAction Stop } | Should -Not -Throw
        }

        It "Should clear only Graph token when Token is 'Graph'" {
            Clear-Token -Token Graph
            
            { Get-Variable -Name GraphToken -Scope Global -ErrorAction Stop } | Should -Throw
            { Get-Variable -Name response -Scope Global -ErrorAction Stop } | Should -Not -Throw
        }

        It "Should clear only MSGraph token when Token is 'MSGraph'" {
            $global:MSGraphToken = "test_msgraph"
            
            Clear-Token -Token MSGraph
            
            { Get-Variable -Name MSGraphToken -Scope Global -ErrorAction Stop } | Should -Throw
        }

        It "Should clear only Substrate token when Token is 'Substrate'" {
            $global:SubstrateToken = "test_substrate"
            
            Clear-Token -Token Substrate
            
            { Get-Variable -Name SubstrateToken -Scope Global -ErrorAction Stop } | Should -Throw
        }

        It "Should clear only SharePoint token when Token is 'SharePoint'" {
            $global:SharePointToken = "test_sharepoint"
            
            Clear-Token -Token SharePoint
            
            { Get-Variable -Name SharePointToken -Scope Global -ErrorAction Stop } | Should -Throw
        }

        It "Should clear only OneDrive token when Token is 'OneDrive'" {
            $global:OneDriveToken = "test_onedrive"
            
            Clear-Token -Token OneDrive
            
            { Get-Variable -Name OneDriveToken -Scope Global -ErrorAction Stop } | Should -Throw
        }

        It "Should clear only Yammer token when Token is 'Yammer'" {
            $global:YammerToken = "test_yammer"
            
            Clear-Token -Token Yammer
            
            { Get-Variable -Name YammerToken -Scope Global -ErrorAction Stop } | Should -Throw
        }
    }

    Context "Parameter Validation" {
        It "Should require Token parameter" {
            { Clear-Token -Token $null -ErrorAction Stop } | Should -Throw
        }

        It "Should validate Token parameter against ValidateSet" {
            { Clear-Token -Token "InvalidToken" } | Should -Throw
        }
    }

    Context "Idempotency" {
        It "Should not throw error when clearing non-existent token" {
            # Ensure token doesn't exist
            Remove-Variable -Name OutlookToken -Scope Global -ErrorAction SilentlyContinue
            
            # Should not throw
            { Clear-Token -Token Outlook } | Should -Not -Throw
        }

        It "Should not throw error when clearing all tokens when none exist" {
            # Clear all first
            Clear-Token -Token All
            
            # Should not throw when calling again
            { Clear-Token -Token All } | Should -Not -Throw
        }
    }
}
