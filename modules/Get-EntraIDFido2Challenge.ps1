<#
.SYNOPSIS
    Retrieves a FIDO2 sign-in challenge from Entra ID for a given user.

.DESCRIPTION
    Starts an Entra ID authorization flow for the specified user, validates that the user
    has FIDO2 credentials registered and returns the server-issued FIDO2 challenge string
    (sFidoChallenge).

    A structured flow state is returned and saved as $global:Fido2FlowState. The web session is
    also saved as $global:Fido2WebSession with the legacy Fido2SessionInfo property attached, so
    Invoke-EntraIDPasskeyAssertionLogin can complete the sign-in in the same PowerShell session.
    The challenge itself is session-bound and cannot be replayed against a different session.

    The challenge string can be transferred to another machine (e.g. a Windows client with a
    Windows Hello for Business key) to create a signed assertion with
    Get-WindowsHelloFidoAssertion.

.PARAMETER UserPrincipalName
    The user principal name of the target user.

.PARAMETER RelyingParty
    The relying party identifier (RP ID). Defaults to "login.microsoft.com".

.PARAMETER AuthUrl
    Optional complete OAuth2 authorize URL. When omitted, the URL is built from Client and the
    OAuth parameters below.

.PARAMETER Client
    Built-in OAuth client name. Names mirror Invoke-RefreshToToken.ps1, including MSGraph,
    Graph, MSTeams, AzureManagement, SharePoint and DeviceRegistration.

.PARAMETER ClientID
    Overrides the client ID associated with Client. Required with Client Custom.

.PARAMETER Tenant
    Entra tenant segment used in the authorize URL. Defaults to organizations.

.PARAMETER Authority
    Login authority host. Defaults to login.microsoftonline.com.

.PARAMETER RedirectUrl
    OAuth redirect URI. When omitted, the helper selects the preferred registered redirect URI
    for the effective client ID. An explicit value overrides the client mapping.

.PARAMETER Scope
    Custom OAuth scope. Built-in clients get their scope from Client.

.PARAMETER Resource
    OAuth v1 resource value. Used with -UseV1Endpoint.

.PARAMETER UseV1Endpoint
    Uses the v1 authorize endpoint and resource parameter.

.PARAMETER UseCAE
    Adds the cp1 claims request to a v2 authorize URL.

.PARAMETER UseCodeVerifier
    Adds a PKCE S256 challenge to the authorize URL and stores the verifier in the flow state.

.PARAMETER CodeVerifier
    Optional PKCE verifier. If omitted with -UseCodeVerifier, one is generated.

.PARAMETER AuthorizationCodeState
    OAuth state value. A GUID is generated when omitted.

.PARAMETER OutputType
    FlowState (default) returns the structured flow state. Challenge returns only the challenge
    string for compatibility with older scripts.

.PARAMETER UserAgent
    The user agent string used for the web session.

.PARAMETER Proxy
    Optional proxy URL used for all web requests.

.EXAMPLE
    $flow = Get-EntraIDFido2Challenge -UserPrincipalName "user@contoso.com" -Client MSGraph
    Retrieves structured FIDO2 flow state and saves the web session.

.EXAMPLE
    (Get-EntraIDFido2Challenge -UserPrincipalName "user@contoso.com").Challenge | Set-Clipboard
    Retrieves a FIDO2 challenge and copies it to the clipboard for use on another machine.

.NOTES
    Part of TokenTacticsV2
    https://github.com/f-bader/TokenTacticsV2
#>
function Get-TTJsonObjectCandidates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Content
    )

    # Locate balanced JSON objects instead of using a greedy regex. The
    # authorize response is commonly emitted as `$Config = {...};` and may be
    # wrapped in a script block or HTML.
    for ($start = 0; $start -lt $Content.Length; $start++) {
        if ($Content[$start] -ne '{') { continue }

        $depth = 0
        $inString = $false
        $escaped = $false
        for ($index = $start; $index -lt $Content.Length; $index++) {
            $character = $Content[$index]
            if ($inString) {
                if ($escaped) {
                    $escaped = $false
                } elseif ($character -eq '\') {
                    $escaped = $true
                } elseif ($character -eq '"') {
                    $inString = $false
                }
                continue
            }

            if ($character -eq '"') {
                $inString = $true
            } elseif ($character -eq '{') {
                $depth++
            } elseif ($character -eq '}') {
                $depth--
                if ($depth -eq 0) {
                    $Content.Substring($start, $index - $start + 1)
                    break
                }
            }
        }
    }
}

function ConvertFrom-TTEntraFidoResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Content
    )

    $fallback = $null
    $candidates = @($Content.Trim()) + @(Get-TTJsonObjectCandidates -Content $Content)
    foreach ($candidate in $candidates) {
        try {
            $parsed = $candidate.Trim().TrimEnd(';').Trim() | ConvertFrom-Json -Depth 100 -ErrorAction Stop
        } catch {
            continue
        }

        if ($parsed.sFidoChallenge -or $parsed.oGetCredTypeResult -or $parsed.urlPost) {
            return $parsed
        }
        if (-not $fallback) { $fallback = $parsed }
    }

    if ($fallback) { return $fallback }
    throw 'The authorize response did not contain a valid Entra FIDO configuration object.'
}

function Get-EntraIDFido2Challenge {
    [CmdletBinding()]
    param (
        [Alias('UserName')]
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $false)]
        [string]$RelyingParty = "login.microsoft.com",

        [Parameter(Mandatory = $false)]
        [string]$AuthUrl,

        [ValidateSet('Substrate','MSManage','MSTeams','OfficeManagement','Outlook','MSGraph','Graph','OfficeApps','AzureCoreManagement','AzureStorage','AzureKeyVault','AzureManagement','AzurePowerShell','AzureCLI','MAM','DODMSGraph','SharePoint','OneDrive','Yammer','DeviceRegistration','Custom')]
        [string]$Client = 'MSGraph',

        [string]$ClientID,

        [string]$Tenant = 'organizations',

        [string]$Authority = 'login.microsoftonline.com',

        [string]$RedirectUrl,

        [string]$Scope,

        [string]$Resource,

        [string]$SharePointTenantName,

        [switch]$SharePointUseAdmin,

        [switch]$UseV1Endpoint,

        [switch]$UseCAE,

        [switch]$UseCodeVerifier,

        [string]$CodeVerifier,

        [Alias('State')]
        [string]$AuthorizationCodeState,

        [ValidateSet('FlowState', 'Challenge')]
        [string]$OutputType = 'FlowState',

        [Parameter(Mandatory = $false)]
        $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0',

        [Parameter(Mandatory = $false)]
        [string]$Proxy
    )

    # Configure Default Parameters
    $PSDefaultParameterValues = @{}
    $PSDefaultParameterValues.Add('Invoke-WebRequest:Verbose', $false)

    if ($Proxy) {
        Write-Verbose "$([char]0x2718) Setting proxy to $Proxy"
        $PSDefaultParameterValues.Add('Invoke-WebRequest:Proxy', $Proxy)
    }

    $rpId = $RelyingParty
    $origin = "https://$($rpId)"

    # Configure Session
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = $UserAgent

    $oauth = New-TTEntraAuthorizationUrl `
        -Client $Client `
        -ClientID $ClientID `
        -Tenant $Tenant `
        -Authority $Authority `
        -RedirectUrl $RedirectUrl `
        -Scope $Scope `
        -Resource $Resource `
        -SharePointTenantName $SharePointTenantName `
        -SharePointUseAdmin:$SharePointUseAdmin `
        -UseV1Endpoint:$UseV1Endpoint `
        -UseCAE:$UseCAE `
        -UseCodeVerifier:$UseCodeVerifier `
        -CodeVerifier $CodeVerifier `
        -AuthorizationCodeState $AuthorizationCodeState `
        -Username $UserPrincipalName `
        -AuthUrl $AuthUrl
    $AuthUrl = $oauth.Url
    Write-Verbose "$([char]0x2718) Auth URL: $AuthUrl"

    # This sets the initial ESTS cookies and flow state.
    Write-Host "$([char]0x2718) Warming up session on login.microsoftonline.com (Authorize)..." -ForegroundColor Cyan
    try {
        $InitialResponse = Invoke-WebRequest -UseBasicParsing -Uri $AuthUrl -Method Get -WebSession $session -ErrorAction Stop
        $SessionInformation = ConvertFrom-TTEntraFidoResponse -Content ([string]$InitialResponse.Content)
    } catch {
        throw "Could not retrieve or parse the Entra FIDO challenge response. $($_.Exception.Message)"
    }

    # Validate Credential Type
    Write-Host "$([char]0x2718) Validate FIDO2 Credential Type..." -ForegroundColor Cyan
    if (-not $SessionInformation.oGetCredTypeResult.Credentials.HasFido) {
        throw "User does not have FIDO credentials registered."
    }

    if (-not $SessionInformation.sFidoChallenge) {
        throw "No FIDO challenge received from server."
    }

    Write-Host "$([char]0x2714) Challenge Received." -ForegroundColor Green
    Write-Host "$([char]0x2714) User:   $UserPrincipalName" -ForegroundColor Gray
    Write-Host "$([char]0x2714) RP ID:  $rpId" -ForegroundColor Gray
    Write-Host "$([char]0x2714) Origin: $origin" -ForegroundColor Gray

    $flowState = [PSCustomObject]@{
        PSTypeName         = 'TokenTactics.EntraIDFido2FlowState'
        Challenge          = [string]$SessionInformation.sFidoChallenge
        UserPrincipalName  = $UserPrincipalName
        RelyingParty       = $rpId
        Origin             = $origin
        OAuth              = $oauth
        SessionInformation = $SessionInformation
        PostbackUrl        = [string]$SessionInformation.urlPost
        CreatedAt          = [DateTimeOffset]::UtcNow
        WebSession         = $session
    }

    # Enrich session information with the flow context needed by Invoke-EntraIDPasskeyAssertionLogin
    Add-Member -InputObject $SessionInformation -NotePropertyName 'UserPrincipalName' -NotePropertyValue $UserPrincipalName -Force
    # Save session state for Invoke-EntraIDPasskeyAssertionLogin (session info travels with the session)
    Add-Member -InputObject $session -NotePropertyName 'Fido2SessionInfo' -NotePropertyValue $SessionInformation -Force
    $global:Fido2WebSession = $session
    $global:Fido2FlowState = $flowState
    Write-Host "$([char]0x26BF) Flow state saved as `$global:Fido2FlowState and web session as `$global:Fido2WebSession." -ForegroundColor Gray

    if ($OutputType -eq 'Challenge') {
        return $flowState.Challenge
    }
    return $flowState
}
