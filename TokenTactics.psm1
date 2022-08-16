# Print the welcome message
$manifest = Import-PowerShellDataFile "$PSScriptRoot\TokenTactics.psd1"
$version = $manifest.ModuleVersion
$host.ui.RawUI.WindowTitle="TokenTactics $version"

$banner=@"
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
    Write-Progress -Activity "Importing script" -Status $script -PercentComplete (($c++/$scripts.count)*100) 
    try {
        . $script.FullName
    } catch {
        Write-Error "Failed to import $($script.FullName): $_"
    }
}
# Export functions
$functions=@(
    "Parse-JWTtoken"
    "Get-TenantID"
    "Get-AzureToken"
    "RefreshTo-AzureCoreManagementToken"
    "RefreshTo-AzureManagementToken"
    "RefreshTo-DODMSGraphToken"
    "RefreshTo-GraphToken"
    "RefreshTo-MAMToken"
    "RefreshTo-MSGraphToken"
    "RefreshTo-MSManageToken"
    "RefreshTo-MSTeamsToken"
    "RefreshTo-OfficeAppsToken"
    "RefreshTo-OfficeManagementToken"
    "RefreshTo-OneDriveToken"
    "RefreshTo-OutlookToken"
    "RefreshTo-SharePointToken"
    "RefreshTo-SubstrateToken"
    "Clear-Token"
    "Forge-UserAgent"
)
$c = 0
foreach($function in $functions)
{
    Write-Progress -Activity "Exporting function" -Status $function -PercentComplete (($c++/$functions.count)*100)
    Export-ModuleMember -Function $function
}
