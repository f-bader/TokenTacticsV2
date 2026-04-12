BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force
}

Describe "Invoke-EntraErrorHandling" {
    Context "Error code 50058 (session information not sufficient)" {
        It "Outputs a message referencing error code 50058" {
            $output = InModuleScope TokenTactics {
                Invoke-EntraErrorHandling -AppConfig ([PSCustomObject]@{ sErrorCode = "50058" })
            }
            ($output -join "`n") | Should -Match "50058"
        }

        It "Outputs a message about session information" {
            $output = InModuleScope TokenTactics {
                Invoke-EntraErrorHandling -AppConfig ([PSCustomObject]@{ sErrorCode = "50058" })
            }
            ($output -join "`n") | Should -Match "session"
        }
    }

    Context "Error code 53003 (Conditional Access block)" {
        It "Outputs a message referencing error code 53003" {
            $output = InModuleScope TokenTactics {
                Invoke-EntraErrorHandling -AppConfig ([PSCustomObject]@{ sErrorCode = "53003" })
            }
            ($output -join "`n") | Should -Match "53003"
        }

        It "Mentions Conditional Access" {
            $output = InModuleScope TokenTactics {
                Invoke-EntraErrorHandling -AppConfig ([PSCustomObject]@{
                    sErrorCode             = "53003"
                    urlTokenBindingLearnMore = $null
                })
            }
            ($output -join "`n") | Should -Match "Conditional Access"
        }
    }

    Context "Generic error code with title and description" {
        It "Outputs a message containing the error code" {
            $output = InModuleScope TokenTactics {
                Invoke-EntraErrorHandling -AppConfig ([PSCustomObject]@{
                    sErrorCode        = "70011"
                    iErrorTitle       = 1
                    iErrorDescription = 1
                })
            }
            ($output -join "`n") | Should -Match "70011"
        }
    }

    Context "No error code - strMainMessage present" {
        It "Outputs the strMainMessage value" {
            $output = InModuleScope TokenTactics {
                Invoke-EntraErrorHandling -AppConfig ([PSCustomObject]@{
                    sErrorCode              = ""
                    strMainMessage          = "Custom error occurred"
                    strServiceExceptionMessage = "Details here"
                })
            }
            ($output -join "`n") | Should -Match "Custom error occurred"
        }
    }

    Context "No error code and no main message" {
        It "Outputs a fallback 'No error code received' message" {
            $output = InModuleScope TokenTactics {
                Invoke-EntraErrorHandling -AppConfig ([PSCustomObject]@{
                    sErrorCode     = ""
                    strMainMessage = ""
                })
            }
            ($output -join "`n") | Should -Match "No error code"
        }
    }

    Context "Optional diagnostic fields" {
        It "Outputs Device Id when sDeviceId is present" {
            $output = InModuleScope TokenTactics {
                Invoke-EntraErrorHandling -AppConfig ([PSCustomObject]@{
                    sErrorCode  = "50058"
                    sDeviceId   = "device-abc-123"
                })
            }
            ($output -join "`n") | Should -Match "device-abc-123"
        }

        It "Outputs Correlation Id when correlationId is present" {
            $output = InModuleScope TokenTactics {
                Invoke-EntraErrorHandling -AppConfig ([PSCustomObject]@{
                    sErrorCode    = "50058"
                    correlationId = "corr-123"
                })
            }
            ($output -join "`n") | Should -Match "corr-123"
        }
    }
}
