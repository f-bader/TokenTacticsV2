[CmdletBinding()]
param()

$requiredVersion = [version]'5.7.1'
$pester = Get-Module -ListAvailable Pester |
    Where-Object Version -EQ $requiredVersion |
    Select-Object -First 1

if (-not $pester) {
    throw "Pester $requiredVersion is required. Install it with: Install-Module Pester -RequiredVersion $requiredVersion -Scope CurrentUser"
}

Import-Module $pester.Path -Force
$settings = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'PesterConfiguration.psd1')
$configuration = New-PesterConfiguration -Hashtable $settings
$result = Invoke-Pester -Configuration $configuration

if ($result.Result -ne 'Passed') {
    throw "Pester run failed: $($result.FailedCount) test(s) failed."
}
