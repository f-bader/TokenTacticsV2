BeforeAll {
    # Dot-source the required function files
    . "$PSScriptRoot/../modules/TokenHandler.ps1"
    . "$PSScriptRoot/../modules/Get-ForgedUserAgent.ps1"
    . "$PSScriptRoot/../modules/Get-TenantId.ps1"
    . "$PSScriptRoot/../modules/ConvertFrom-JWTtoken.ps1"
}

Describe "Invoke-RefreshTo* Functions" {
    BeforeAll {
        # Mock the core dependencies
        Mock Get-ForgedUserAgent { return "Mocked-UserAgent" }
        Mock Invoke-RefreshToToken {
            return [PSCustomObject]@{
                token_type    = "Bearer"
                scope         = "mock_scope"
                expires_in    = 3600
                access_token  = "mock_access_token"
                refresh_token = "mock_refresh_token"
            }
        }
        Mock ConvertFrom-JWTtoken {
            return [PSCustomObject]@{
                upn = "test@example.com"
            }
        }
        Mock Write-Output {}
        Mock Format-List {}
    }

    Context "Invoke-RefreshToMSGraphToken" {
        It "Should call Invoke-RefreshToToken with correct scope" {
            Mock Write-Output {}
            
            Invoke-RefreshToMSGraphToken -Domain "test.com" -refreshToken "mock_refresh" 6>&1 | Out-Null
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Scope -like "*graph.microsoft.com*"
            }
        }

        It "Should use default MS Teams client ID" {
            Mock Write-Output {}
            
            Invoke-RefreshToMSGraphToken -Domain "test.com" -refreshToken "mock_refresh" 6>&1 | Out-Null
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $ClientID -eq "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
            }
        }

        It "Should set global MSGraphToken variable" {
            Mock Write-Output {}
            
            Invoke-RefreshToMSGraphToken -Domain "test.com" -refreshToken "mock_refresh" 6>&1 | Out-Null
            
            $global:MSGraphToken | Should -Not -BeNullOrEmpty
            $global:MSGraphToken.access_token | Should -Be "mock_access_token"
        }
    }

    Context "Invoke-RefreshToGraphToken" {
        It "Should call Invoke-RefreshToToken with correct scope" {
            Invoke-RefreshToGraphToken -Domain "test.com" -refreshToken "mock_refresh"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Scope -like "*graph.windows.net*"
            }
        }

        It "Should set global GraphToken variable" {
            Invoke-RefreshToGraphToken -Domain "test.com" -refreshToken "mock_refresh"
            
            $global:GraphToken | Should -Not -BeNullOrEmpty
        }
    }

    Context "Invoke-RefreshToOutlookToken" {
        It "Should call Invoke-RefreshToToken with Outlook scope" {
            Invoke-RefreshToOutlookToken -Domain "test.com" -refreshToken "mock_refresh"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Scope -like "*outlook.office365.com*"
            }
        }

        It "Should set global OutlookToken variable" {
            Invoke-RefreshToOutlookToken -Domain "test.com" -refreshToken "mock_refresh"
            
            $global:OutlookToken | Should -Not -BeNullOrEmpty
        }
    }

    Context "Invoke-RefreshToMSTeamsToken" {
        It "Should call Invoke-RefreshToToken with Teams scope" {
            Invoke-RefreshToMSTeamsToken -Domain "test.com" -refreshToken "mock_refresh"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Scope -like "*api.spaces.skype.com*"
            }
        }

        It "Should set global MSTeamsToken variable" {
            Invoke-RefreshToMSTeamsToken -Domain "test.com" -refreshToken "mock_refresh"
            
            $global:MSTeamsToken | Should -Not -BeNullOrEmpty
        }
    }

    Context "Invoke-RefreshToSubstrateToken" {
        It "Should call Invoke-RefreshToToken with Substrate scope" {
            Invoke-RefreshToSubstrateToken -Domain "test.com" -refreshToken "mock_refresh"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Scope -like "*substrate.office.com*"
            }
        }

        It "Should set global SubstrateToken variable" {
            Invoke-RefreshToSubstrateToken -Domain "test.com" -refreshToken "mock_refresh"
            
            $global:SubstrateToken | Should -Not -BeNullOrEmpty
        }
    }

    Context "Invoke-RefreshToOfficeManagementToken" {
        It "Should call Invoke-RefreshToToken with Office Management scope" {
            Invoke-RefreshToOfficeManagementToken -Domain "test.com" -refreshToken "mock_refresh"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Scope -like "*manage.office.com*"
            }
        }

        It "Should set global OfficeManagementToken variable" {
            Invoke-RefreshToOfficeManagementToken -Domain "test.com" -refreshToken "mock_refresh"
            
            $global:OfficeManagementToken | Should -Not -BeNullOrEmpty
        }
    }

    Context "Invoke-RefreshToOfficeAppsToken" {
        It "Should call Invoke-RefreshToToken with Office Apps scope" {
            Invoke-RefreshToOfficeAppsToken -Domain "test.com" -refreshToken "mock_refresh"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Scope -like "*officeapps.live.com*"
            }
        }

        It "Should set global OfficeAppsToken variable" {
            Invoke-RefreshToOfficeAppsToken -Domain "test.com" -refreshToken "mock_refresh"
            
            $global:OfficeAppsToken | Should -Not -BeNullOrEmpty
        }
    }

    Context "Invoke-RefreshToAzureCoreManagementToken" {
        It "Should call Invoke-RefreshToToken with Azure Core Management scope" {
            Invoke-RefreshToAzureCoreManagementToken -Domain "test.com" -refreshToken "mock_refresh"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Scope -like "*management.core.windows.net*"
            }
        }

        It "Should set global AzureCoreManagementToken variable" {
            Invoke-RefreshToAzureCoreManagementToken -Domain "test.com" -refreshToken "mock_refresh"
            
            $global:AzureCoreManagementToken | Should -Not -BeNullOrEmpty
        }
    }

    Context "Invoke-RefreshToAzureManagementToken" {
        It "Should call Invoke-RefreshToToken with Azure Management scope" {
            Invoke-RefreshToAzureManagementToken -Domain "test.com" -refreshToken "mock_refresh"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Scope -like "*management.azure.com*"
            }
        }

        It "Should set global AzureManagementToken variable" {
            Invoke-RefreshToAzureManagementToken -Domain "test.com" -refreshToken "mock_refresh"
            
            $global:AzureManagementToken | Should -Not -BeNullOrEmpty
        }
    }

    Context "Invoke-RefreshToAzureStorageToken" {
        It "Should call Invoke-RefreshToToken with Azure Storage scope" {
            Invoke-RefreshToAzureStorageToken -Domain "test.com" -refreshToken "mock_refresh"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Scope -like "*storage.azure.com*"
            }
        }

        It "Should set global AzureStorageToken variable" {
            Invoke-RefreshToAzureStorageToken -Domain "test.com" -refreshToken "mock_refresh"
            
            $global:AzureStorageToken | Should -Not -BeNullOrEmpty
        }
    }

    Context "Invoke-RefreshToAzureKeyVaultToken" {
        It "Should call Invoke-RefreshToToken with Azure Key Vault scope" {
            Invoke-RefreshToAzureKeyVaultToken -Domain "test.com" -refreshToken "mock_refresh"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Scope -like "*vault.azure.net*"
            }
        }

        It "Should set global AzureKeyVaultToken variable" {
            Invoke-RefreshToAzureKeyVaultToken -Domain "test.com" -refreshToken "mock_refresh"
            
            $global:AzureKeyVaultToken | Should -Not -BeNullOrEmpty
        }
    }

    Context "Invoke-RefreshToMAMToken" {
        It "Should call Invoke-RefreshToToken with MAM scope" {
            Invoke-RefreshToMAMToken -Domain "test.com" -refreshToken "mock_refresh"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Scope -like "*mam.manage.microsoft.com*"
            }
        }

        It "Should set global MAMToken variable" {
            Invoke-RefreshToMAMToken -Domain "test.com" -refreshToken "mock_refresh"
            
            $global:MAMToken | Should -Not -BeNullOrEmpty
        }
    }

    Context "Invoke-RefreshToMSManageToken" {
        It "Should call Invoke-RefreshToToken with MS Manage scope" {
            Invoke-RefreshToMSManageToken -Domain "test.com" -refreshToken "mock_refresh"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Scope -like "*microsoft.com//.default*"
            }
        }

        It "Should set global MSManageToken variable" {
            Invoke-RefreshToMSManageToken -Domain "test.com" -refreshToken "mock_refresh"
            
            $global:MSManageToken | Should -Not -BeNullOrEmpty
        }
    }

    Context "Invoke-RefreshToDODMSGraphToken" {
        It "Should call Invoke-RefreshToToken with DoD flag" {
            Invoke-RefreshToDODMSGraphToken -Domain "test.com" -refreshToken "mock_refresh"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $UseDoD -eq $true
            }
        }

        It "Should set global DODMSGraphToken variable" {
            Invoke-RefreshToDODMSGraphToken -Domain "test.com" -refreshToken "mock_refresh"
            
            $global:DODMSGraphToken | Should -Not -BeNullOrEmpty
        }
    }

    Context "Invoke-RefreshToSharePointToken" {
        It "Should call Invoke-RefreshToToken with SharePoint scope" {
            Invoke-RefreshToSharePointToken -Domain "test.com" -refreshToken "mock_refresh" -SharePointTenantName "contoso" 6>&1 | Out-Null
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Scope -like "*sharepoint.com*"
            }
        }

        It "Should set global SharePointToken variable" {
            Invoke-RefreshToSharePointToken -Domain "test.com" -refreshToken "mock_refresh" -SharePointTenantName "contoso" 6>&1 | Out-Null
            
            $global:SharePointToken | Should -Not -BeNullOrEmpty
        }
    }

    Context "Invoke-RefreshToOneDriveToken" {
        It "Should call Invoke-RefreshToToken with OneDrive scope" {
            Invoke-RefreshToOneDriveToken -Domain "test.com" -refreshToken "mock_refresh"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Scope -like "*onedrive.com*"
            }
        }

        It "Should set global OneDriveToken variable" {
            Invoke-RefreshToOneDriveToken -Domain "test.com" -refreshToken "mock_refresh"
            
            $global:OneDriveToken | Should -Not -BeNullOrEmpty
        }
    }

    Context "Invoke-RefreshToYammerToken" {
        It "Should call Invoke-RefreshToToken with Yammer resource" {
            Invoke-RefreshToYammerToken -Domain "test.com" -refreshToken "mock_refresh"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Resource -like "*yammer.com*"
            }
        }

        It "Should set global YammerToken variable" {
            Invoke-RefreshToYammerToken -Domain "test.com" -refreshToken "mock_refresh"
            
            $global:YammerToken | Should -Not -BeNullOrEmpty
        }
    }

    Context "Invoke-RefreshToDeviceRegistrationToken" {
        It "Should call Invoke-RefreshToToken with Device Registration resource" {
            Invoke-RefreshToDeviceRegistrationToken -Domain "test.com" -refreshToken "mock_refresh"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Resource -like "*device.registration*"
            }
        }

        It "Should set global DeviceRegistrationToken variable" {
            Invoke-RefreshToDeviceRegistrationToken -Domain "test.com" -refreshToken "mock_refresh"
            
            $global:DeviceRegistrationToken | Should -Not -BeNullOrEmpty
        }
    }

    Context "Parameter Propagation" {
        It "Should propagate CustomUserAgent parameter" {
            Invoke-RefreshToMSGraphToken -Domain "test.com" -refreshToken "mock_refresh" -CustomUserAgent "Custom/1.0"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $CustomUserAgent -eq "Custom/1.0"
            }
        }

        It "Should propagate Device parameter" {
            Invoke-RefreshToMSGraphToken -Domain "test.com" -refreshToken "mock_refresh" -Device "iPhone"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Device -eq "iPhone"
            }
        }

        It "Should propagate Browser parameter" {
            Invoke-RefreshToMSGraphToken -Domain "test.com" -refreshToken "mock_refresh" -Browser "Safari"
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $Browser -eq "Safari"
            }
        }

        It "Should propagate UseCAE parameter" {
            Invoke-RefreshToMSGraphToken -Domain "test.com" -refreshToken "mock_refresh" -UseCAE
            
            Should -Invoke Invoke-RefreshToToken -Times 1 -ParameterFilter {
                $UseCAE -eq $true
            }
        }
    }
}
