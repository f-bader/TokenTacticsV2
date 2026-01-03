if ( [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace.Name -match "^PSTask" ) {
    # Skip all information messages when running in a task
    $OutputMessages = $false
} else {
    # Set the default behavior to show information messages
    $OutputMessages = $true
}
if ( $OutputMessages ) {
    # Print the welcome message
    $manifest = Import-PowerShellDataFile "$PSScriptRoot\TokenTactics.psd1"
    $version = $manifest.ModuleVersion
    $host.ui.RawUI.WindowTitle = "TokenTactics $version"

    # Font. Slant
    $banner = @"
  ______      __                 __             __  _                     ___ 
 /_  __/___  / /_____  ____     / /_____ ______/ /_(_)_________   _   __ |__ \
  / / / __ \/ //_/ _ \/ __ \   / __/ __ ``/ ___/ __/ / ___/ ___/  | | / / __/ /
 / / / /_/ / ,< /  __/ / / /  / /_/ /_/ / /__/ /_/ / /__(__  )   | |/ / / __/ 
/_/  \____/_/|_|\___/_/ /_/   \__/\__,_/\___/\__/_/\___/____/    |___(_)____/                                                               
"@
    Write-Host $banner -ForegroundColor Red
}

# Load the .ps1 scripts
#$scripts = @(Get-ChildItem -Path $PSScriptRoot\*.ps1 -ErrorAction SilentlyContinue)
$scripts = @(Get-ChildItem -Path $PSScriptRoot\modules\*.ps1 -ErrorAction SilentlyContinue)
$c = 0
foreach ($script in $scripts) {
    if ( $OutputMessages ) {
        Write-Progress -Activity "Importing script" -Status $script -PercentComplete (($c++ / $scripts.count) * 100) 
    }
    try {
        . $script.FullName
    } catch {
        Write-Error "Failed to import $($script.FullName): $_"
    }
}
# Export functions
$functions = @(
    "Clear-Token"
    "ConvertFrom-JWTtoken"
    "ConvertTo-PEMPrivateKey"
    "Get-EntraIDAuthorizationCode"
    "Get-EntraIDToken"
    "Get-EntraIDTokenFromAuthorizationCode"
    "Get-EntraIDTokenFromCookie"
    "Get-EntraIDTokenFromESTSCookie"
    "Get-EntraIDTokenFromRefreshTokenCredentialCookie"
    "Get-ForgedUserAgent"
    "Get-TenantID"
    "Invoke-EntraIDPasskeyLogin"
    "Invoke-RefreshToAzureCoreManagementToken"
    "Invoke-RefreshToAzureKeyVaultToken"
    "Invoke-RefreshToAzureManagementToken"
    "Invoke-RefreshToAzureStorageToken"
    "Invoke-RefreshToDeviceRegistrationToken"
    "Invoke-RefreshToDODMSGraphToken"
    "Invoke-RefreshToGraphToken"
    "Invoke-RefreshToMAMToken"
    "Invoke-RefreshToMSGraphToken"
    "Invoke-RefreshToMSManageToken"
    "Invoke-RefreshToMSTeamsToken"
    "Invoke-RefreshToOfficeAppsToken"
    "Invoke-RefreshToOfficeManagementToken"
    "Invoke-RefreshToOneDriveToken"
    "Invoke-RefreshToOutlookToken"
    "Invoke-RefreshToSharePointToken"
    "Invoke-RefreshToSubstrateToken"
)

$c = 0
foreach ($function in $functions) {
    if ( $OutputMessages ) {
        Write-Progress -Activity "Exporting function" -Status $function -PercentComplete (($c++ / $functions.count) * 100)
    }
    Export-ModuleMember -Function $function
}

# Add backward compatibility aliases
New-Alias -Name Parse-JWTtoken -Value ConvertFrom-JWTtoken
New-Alias -Name Forge-UserAgent -Value Get-ForgedUserAgent
New-Alias -Name RefreshTo-SubstrateToken -Value Invoke-RefreshToSubstrateToken
New-Alias -Name RefreshTo-MSManageToken -Value Invoke-RefreshToMSManageToken
New-Alias -Name RefreshTo-MSTeamsToken -Value Invoke-RefreshToMSTeamsToken
New-Alias -Name RefreshTo-OfficeManagementToken -Value Invoke-RefreshToOfficeManagementToken
New-Alias -Name RefreshTo-OutlookToken -Value Invoke-RefreshToOutlookToken
New-Alias -Name RefreshTo-MSGraphToken -Value Invoke-RefreshToMSGraphToken
New-Alias -Name RefreshTo-GraphToken -Value Invoke-RefreshToGraphToken
New-Alias -Name RefreshTo-OfficeAppsToken -Value Invoke-RefreshToOfficeAppsToken
New-Alias -Name RefreshTo-AzureCoreManagementToken -Value Invoke-RefreshToAzureCoreManagementToken
New-Alias -Name RefreshTo-AzureManagementToken -Value Invoke-RefreshToAzureManagementToken
New-Alias -Name RefreshTo-MAMToken -Value Invoke-RefreshToMAMToken
New-Alias -Name RefreshTo-DODMSGraphToken -Value Invoke-RefreshToDODMSGraphToken
New-Alias -Name RefreshTo-SharePointToken -Value Invoke-RefreshToSharePointToken
New-Alias -Name RefreshTo-OneDriveToken -Value Invoke-RefreshToOneDriveToken
New-Alias -Name RefreshTo-YammerToken -Value Invoke-RefreshToYammerToken
New-Alias -Name RefreshTo-AzureStorageToken -Value Invoke-RefreshToAzureStorageToken
New-Alias -Name RefreshTo-AzureKeyVaultToken -Value Invoke-RefreshToAzureKeyVaultToken
New-Alias -Name RefreshTo-DeviceRegistrationToken -Value Invoke-RefreshToDeviceRegistrationToken
New-Alias -Name Get-AzureToken -Value Get-EntraIDToken
New-Alias -Name Get-AzureTokenFromESTSCookie -Value Get-EntraIDTokenFromESTSCookie
New-Alias -Name Get-AzureTokenFromAuthorizationCode -Value Get-EntraIDTokenFromAuthorizationCode
New-Alias -Name Get-AzureAuthorizationCode -Value Get-EntraIDAuthorizationCode
New-Alias -Name Get-AzureTokenFromCookie -Value Get-EntraIDTokenFromCookie
New-Alias -Name Get-AzureTokenFromRefreshTokenCredentialCookie -Value Get-EntraIDTokenFromRefreshTokenCredentialCookie

Export-ModuleMember -Alias * -Function *
