# Print the welcome message
$manifest = Import-PowerShellDataFile "$PSScriptRoot\TokenTactics.psd1"
$version = $manifest.ModuleVersion
$host.ui.RawUI.WindowTitle = "TokenTactics $version"

$banner = @"
_______    _                _______         _   _                 ___  
|__   __|  | |              |__   __|       | | (_)               |__ \ 
   | | ___ | | _____ _ __      | | __ _  ___| |_ _  ___ ___  __   __ ) |
   | |/ _ \| |/ / _ \ '_ \     | |/ _` |/ __| __| |/ __/ __| \ \ / // / 
   | | (_) |   <  __/ | | |    | | (_| | (__| |_| | (__\__ \  \ V // /_ 
   |_|\___/|_|\_\___|_| |_|    |_|\__,_|\___|\__|_|\___|___/   \_/|____|
                                                                        
                                                                        
"@
Write-Host $banner -ForegroundColor Red

# Load the .ps1 scripts
#$scripts = @(Get-ChildItem -Path $PSScriptRoot\*.ps1 -ErrorAction SilentlyContinue)
$scripts = @(Get-ChildItem -Path $PSScriptRoot\modules\*.ps1 -ErrorAction SilentlyContinue)
$c = 0
foreach ($script in $scripts) {
    Write-Progress -Activity "Importing script" -Status $script -PercentComplete (($c++ / $scripts.count) * 100) 
    try {
        . $script.FullName
    } catch {
        Write-Error "Failed to import $($script.FullName): $_"
    }
}
# Export functions
$functions = @(
    "ConvertFrom-JWTtoken"
    "Get-TenantID"
    "Get-AzureToken"
    "Invoke-RefreshToAzureCoreManagementToken"
    "Invoke-RefreshToAzureManagementToken"
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
    "Clear-Token"
    "Get-ForgedUserAgent"
)

$c = 0
foreach ($function in $functions) {
    Write-Progress -Activity "Exporting function" -Status $function -PercentComplete (($c++ / $functions.count) * 100)
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

Export-ModuleMember -Alias * -Function *
