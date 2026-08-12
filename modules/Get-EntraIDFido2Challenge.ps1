<#
.SYNOPSIS
    Retrieves a FIDO2 sign-in challenge from Entra ID for a given user.

.DESCRIPTION
    Starts an Entra ID authorization flow for the specified user, validates that the user
    has FIDO2 credentials registered and returns the server-issued FIDO2 challenge string
    (sFidoChallenge).

    The web session is saved as $global:Fido2WebSession (with the parsed session information
    attached as property Fido2SessionInfo) so that Invoke-EntraIDPasskeyAssertionLogin can
    complete the sign-in in the same PowerShell session. The challenge itself is
    session-bound and cannot be replayed against a different session.

    The challenge string can be transferred to another machine (e.g. a Windows client with a
    Windows Hello for Business key) to create a signed assertion with
    Get-WindowsHelloFidoAssertion.

.PARAMETER UserPrincipalName
    The user principal name of the target user.

.PARAMETER RelyingParty
    The relying party identifier (RP ID). Defaults to "login.microsoft.com".

.PARAMETER AuthUrl
    The OAuth2 authorize URL used to start the flow. Must contain client_id, response_type
    and redirect_uri. Defaults to the Azure AD v2.0 authorize endpoint for the Microsoft
    Azure CLI client.

.PARAMETER UserAgent
    The user agent string used for the web session.

.PARAMETER Proxy
    Optional proxy URL used for all web requests.

.EXAMPLE
    $challenge = Get-EntraIDFido2Challenge -UserPrincipalName "user@contoso.com"
    Retrieves a FIDO2 challenge and saves the web session for Invoke-EntraIDPasskeyAssertionLogin.

.EXAMPLE
    Get-EntraIDFido2Challenge -UserPrincipalName "user@contoso.com" | Set-Clipboard
    Retrieves a FIDO2 challenge and copies it to the clipboard for use on another machine.

.NOTES
    Part of TokenTacticsV2
    https://github.com/f-bader/TokenTacticsV2
#>
function Get-EntraIDFido2Challenge {
    [CmdletBinding()]
    param (
        [Alias('UserName')]
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $false)]
        $RelyingParty = "login.microsoft.com",

        [Parameter(Mandatory = $false)]
        $AuthUrl = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?response_type=code&redirect_uri=msauth.com.msauth.unsignedapp://auth&scope=https://graph.microsoft.com/.default&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46",

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

    # Add mandatory fields to URI
    # Get all existing query parameters
    try {
        $uriBuilder = [System.UriBuilder]$AuthUrl
        $query = [System.Web.HttpUtility]::ParseQueryString($uriBuilder.Query)
    } catch {
        throw "Invalid auth URL format. $($_.Exception.Message)"
    }
    if ( $AuthUrl -notmatch "^https://login.microsoftonline.com/" ) {
        throw "Auth URL must start with 'https://login.microsoftonline.com/'"
    }
    # Check if required parameters are already present
    # scope
    # client_id
    # response_type
    # redirect_uri
    $RequiredParams = @("client_id", "response_type", "redirect_uri")
    foreach ($param in $RequiredParams) {
        if (-not $query.Get($param)) {
            throw "Missing required parameter '$param' in auth URL."
        }
    }
    # Add additional required parameters if missing
    # sso_reload=true
    # login_hint=$UserPrincipalName
    if (-not $query.Get("sso_reload")) {
        $AuthUrl = "$AuthUrl&sso_reload=true"
    }
    if (-not $query.Get("login_hint")) {
        $AuthUrl = "$AuthUrl&login_hint=$UserPrincipalName"
    }
    Write-Verbose "$([char]0x2718) Auth URL: $AuthUrl"

    # This sets the initial ESTS cookies and flow state.
    Write-Host "$([char]0x2718) Warming up session on login.microsoftonline.com (Authorize)..." -ForegroundColor Cyan
    try {
        $InitialResponse = Invoke-WebRequest -UseBasicParsing -Uri $AuthUrl -Method Get -WebSession $session
        $InitialResponse.Content -match '{(.*)}' | Out-Null
        $SessionInformation = $Matches[0] | ConvertFrom-Json
    } catch {
        # It's expected to redirect or fail if we don't follow the full HTML flow,
        # but we just need the Cookies in $session.
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

    # Enrich session information with the flow context needed by Invoke-EntraIDPasskeyAssertionLogin
    Add-Member -InputObject $SessionInformation -NotePropertyName 'UserPrincipalName' -NotePropertyValue $UserPrincipalName -Force

    # Save session state for Invoke-EntraIDPasskeyAssertionLogin (session info travels with the session)
    Add-Member -InputObject $session -NotePropertyName 'Fido2SessionInfo' -NotePropertyValue $SessionInformation -Force
    $global:Fido2WebSession = $session
    Write-Host "$([char]0x26BF) Web session saved as `$global:Fido2WebSession for use with Invoke-EntraIDPasskeyAssertionLogin." -ForegroundColor Gray

    # Output only the challenge (portable to another machine for assertion signing)
    return $SessionInformation.sFidoChallenge
}
