# TokenTactics v2

This is an updated version of [TokenTactics](https://github.com/rvrsh3ll/TokenTactics) originally written by Stephan Borosh [@rvrsh3ll](https://github.com/rvrsh3ll) & Bobby Cooke [@0xBoku](https://github.com/boku7).

## New Features in v2

* Switched to `v2.0` of the Azure AD OAuth2 endpoint
* Support for [continuous access evaluation](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/concept-continuous-access-evaluation) using the new `-UseCAE` switch
* Made `ClientId` a parameter
* Changed `client_id` for MSTeams
* Added support for OneDrive and SharePoint
* Added `IssuedAt`, `NotBefore`, `ExpirationDate` and `ValidForHours` in `Parse-JWTtoken` output in human readable format
* Refactored the codebase to have less redudant code and make it easier to extend
* Support for Linux as a device platform (2023-07-21)
* Support for OS/2 as a device platform (2023-07-21) :grin:

## Azure JSON Web Token ("JWT") Manipulation Toolset

Azure access tokens allow you to authenticate to certain endpoints as a user who signs in with a device code. If you are in possesion of a [FOCI (Family of Client IDs)](https://github.com/secureworks/family-of-client-ids-research) capable refresh token you can use it to get access tokens to all known [FOCI capable endpoints](https://github.com/secureworks/family-of-client-ids-research/blob/main/known-foci-clients.csv). Since the refresh-token also contains the infomration if the user has done multi-factor authentication you can use this. Once you have a user's access token, it may be possible to access certain apps such as Outlook, SharePoint, OneDrive, MSTeams and more. 

For instance, if you have a Graph or MSGraph refresh token, you can then connect to Azure and dump users, groups, etc. You could then, depending on conditional access policies, switch to an Azure Core Management token and run [AzureHound](https://github.com/BloodHoundAD/AzureHound). Then, get an Outlook access token and read/send emails or MS Teams and read/send teams messages!

For more on Azure token types [Microsoft identity platform access tokens](https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens)

There are some example requests to endpoints in the resources folder. There is also an example phishing template for device code phishing.

You may also use these tokens with [AAD Internals](https://o365blog.com/aadinternals/) as well. We strongly recommended to check this amazing tool out.

## Installation and Usage

```powershell
Import-Module .\TokenTactics.psd1
Get-Help Get-AzureToken
RefreshTo-SubstrateToken -Domain "myclient.org"
```

### Get refresh token using Device Code flow

```powershell
Get-AzureToken -Client MSGraph
```

Once the user has logged in, you'll be presented with the JWT and it will be saved in the `$response` variable. To access the access token use ```$response.access_token``` from your PowerShell window to display the token. You may also display the refresh token with ```$response.refresh_token```. Hint: You'll want the refresh token to keep refreshing to new tokens!

#### DOD/Mil Device Code

```powershell
Get-AzureToken -Client DODMSGraph
```

### Refresh to new access token

If you do not specify a refresh token the cmdlets will use `$response.refresh_token` as a default.

```powershell
RefreshTo-OutlookToken -domain "myclient.org"

$OutlookToken.access_token
```

### Connect to AzureAD using access token

```powershell
Connect-AzureAD -AadAccessToken $response.access_token -AccountId user@myclient.org
```

### Connect to MgGraph using access token

```powershell
RefreshTo-MSGraphToken -Domain "myclient.org"
Connect-MgGraph -AccessToken $MSGraphToken.access_token -Scopes "User.Read.All","Group.ReadWrite.All"
```

### Clear tokens

This will remove any token variables.

```powershell
Clear-Token -Token All
```

### Continuous Access Evaluation

With [continuous access evaluation](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/concept-continuous-access-evaluation) Microsoft implements addition security measures, but also extend the maximum livetime of an access token to 24 hours. Certain CAE capable service like MSGraph, Exchange, Teams and SharePoint can blocke access tokens based on certain events triggered by Azure AD. Currently those critical events are:

* User Account is deleted or disabled
* Password for a user is changed or reset
* Multi-factor authentication is enabled for the user
* Administrator explicitly revokes all refresh tokens for a user
* High user risk detected by Azure AD Identity Protection (not in Teams and SharePoint Online)

```powershell
RefreshTo-MSGraphToken -Domain "myclient.org" -UseCAE
if ( $global:MSGraphTokenValidForHours -gt 23) { "MSGraph token is CAE capable" }
```

### Use with AAD Internals

If you have AADInternals installed as well you can use the created access tokens.

```powershell
RefreshTo-MSTeamsToken -UseCAE -Domain "myclient.org"
Set-AADIntTeamsStatusMessage -Message "My cool status message" -AccessToken $MSTeamsToken.access_token -Verbose
```

### Commands

```powershell
Get-Command -Module TokenTactics

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Clear-Token                                        0.2.0      TokenTactics
Function        Forge-UserAgent                                    0.2.0      TokenTactics
Function        Get-AzureToken                                     0.2.0      TokenTactics
Function        Get-TenantID                                       0.2.0      TokenTactics
Function        Parse-JWTtoken                                     0.2.0      TokenTactics
Function        RefreshTo-AzureCoreManagementToken                 0.2.0      TokenTactics
Function        RefreshTo-AzureManagementToken                     0.2.0      TokenTactics
Function        RefreshTo-DODMSGraphToken                          0.2.0      TokenTactics
Function        RefreshTo-GraphToken                               0.2.0      TokenTactics
Function        RefreshTo-MAMToken                                 0.2.0      TokenTactics
Function        RefreshTo-MSGraphToken                             0.2.0      TokenTactics
Function        RefreshTo-MSManageToken                            0.2.0      TokenTactics
Function        RefreshTo-MSTeamsToken                             0.2.0      TokenTactics
Function        RefreshTo-OfficeAppsToken                          0.2.0      TokenTactics
Function        RefreshTo-OfficeManagementToken                    0.2.0      TokenTactics
Function        RefreshTo-OneDriveToken                            0.2.0      TokenTactics
Function        RefreshTo-OutlookToken                             0.2.0      TokenTactics
Function        RefreshTo-SharePointToken                          0.2.0      TokenTactics
Function        RefreshTo-SubstrateToken                           0.2.0      TokenTactics
```

## Authors and contributors
- [@rvrsh3ll](https://github.com/rvrsh3ll)
- [@0xBoku](https://github.com/boku7) co-author and researcher.
- [@f-bader](https://github.com/f-bader) updated CAE capable version

TokenTactic's methods are highly influenced by the great research of Dr Nestori Syynimaa at https://o365blog.com/.
