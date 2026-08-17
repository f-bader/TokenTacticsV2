<#
.SYNOPSIS
    Completes an Entra ID passkey (FIDO2) sign-in using a signed assertion.

.DESCRIPTION
    Submits a signed FIDO2 assertion (e.g. created with Get-WindowsHelloFidoAssertion) to
    Entra ID and completes the sign-in flow, including interrupt handling (CMSI, KMSI and
    ConvergedSignIn).

    The command accepts the structured flow state returned by Get-EntraIDFido2Challenge or falls
    back to the legacy $global:Fido2WebSession state. Postback URLs are taken from the Entra flow
    state instead of being hard-coded.

    By default the resulting ESTSAUTH cookie is exchanged for an access token and refresh
    token (OutputType 'Token'). Use -OutputType ESTSAUTHCookie to return the raw ESTSAUTH
    cookie value instead.

.PARAMETER Assertion
    The signed FIDO2 assertion as an object (id, clientDataJSON, authenticatorData,
    signature, userHandle) or as a JSON string, e.g. from Get-WindowsHelloFidoAssertion.

.PARAMETER WebSession
    The web request session that requested the FIDO2 challenge.
    Defaults to $global:Fido2WebSession.

.PARAMETER SessionInfo
    The parsed session information created by Get-EntraIDFido2Challenge.
    Defaults to the Fido2SessionInfo property of the web session.

.PARAMETER FlowState
    Structured flow state returned by Get-EntraIDFido2Challenge. Its session, OAuth settings and
    session information take precedence over global state.

.PARAMETER UserPrincipalName
    The user principal name of the target user.
    Defaults to the value stored in the session information.

.PARAMETER OutputType
    'Token' (default) exchanges the ESTSAUTH cookie for an access token and refresh token.
    'ESTSAUTHCookie' returns the raw ESTSAUTH cookie value.

.PARAMETER Client
    The built-in client used for the OAuth/token exchange. Names mirror Invoke-RefreshToToken.ps1.

.PARAMETER ClientID
    A custom client ID used for the token exchange (Client 'Custom').

.PARAMETER Resource
    The resource for the token exchange. Defaults to "https://graph.microsoft.com".

.PARAMETER Scope
    The scope for the token exchange. Defaults to "openid offline_access".

.PARAMETER RedirectUrl
    The redirect URL for the token exchange. When omitted, the preferred registered redirect URI
    for the effective client ID is selected; an explicit value overrides it.

.PARAMETER Tenant
    Tenant segment used by the OAuth flow.

.PARAMETER Authority
    Login authority host. Defaults to login.microsoftonline.com.

.PARAMETER UseV1Endpoint
    Use the v1 OAuth token model and resource parameter.

.PARAMETER UseCAE
    Request the CAE cp1 claim for v2 OAuth.

.PARAMETER UseCodeVerifier
    Enable PKCE for the OAuth flow.

.PARAMETER CodeVerifier
    PKCE verifier to use when redeeming an authorization code.

.PARAMETER Proxy
    Optional proxy URL used for all web requests.

.EXAMPLE
    $flow = Get-EntraIDFido2Challenge -UserPrincipalName "user@contoso.com"
    $assertion = Get-WindowsHelloFidoAssertion -Challenge $flow.Challenge -UserId "00000000-0000-0000-0000-000000000002"
    Invoke-EntraIDPasskeyAssertionLogin -FlowState $flow -Assertion $assertion
    Completes the passkey sign-in and returns an access token and refresh token.

.EXAMPLE
    Invoke-EntraIDPasskeyAssertionLogin -Assertion $assertion -OutputType ESTSAUTHCookie
    Completes the passkey sign-in and returns the ESTSAUTH cookie value.

.NOTES
    Part of TokenTacticsV2
    https://github.com/f-bader/TokenTacticsV2
#>
function Invoke-EntraIDPasskeyAssertionLogin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $Assertion,

        [Parameter(Mandatory = $false)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter(Mandatory = $false)]
        $SessionInfo,

        [Parameter(Mandatory = $false)]
        $FlowState,

        [Alias('UserName')]
        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Token', 'ESTSAUTHCookie')]
        [string]$OutputType = 'Token',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Substrate','MSManage','MSTeams','OfficeManagement','Outlook','MSGraph','Graph','OfficeApps','AzureCoreManagement','AzureStorage','AzureKeyVault','AzureManagement','AzurePowerShell','AzureCLI','MAM','DODMSGraph','SharePoint','OneDrive','Yammer','DeviceRegistration','Custom')]
        [string]$Client = "MSGraph",

        [Parameter(Mandatory = $false)]
        [string]$ClientID,

        [Parameter(Mandatory = $false)]
        [string]$Resource = "https://graph.microsoft.com",

        [Parameter(Mandatory = $false)]
        [string]$Scope,

        [Parameter(Mandatory = $false)]
        [string]$RedirectUrl,

        [Parameter(Mandatory = $false)]
        [string]$Tenant = 'organizations',

        [Parameter(Mandatory = $false)]
        [string]$Authority = 'login.microsoftonline.com',

        [Parameter(Mandatory = $false)]
        [switch]$UseV1Endpoint,

        [Parameter(Mandatory = $false)]
        [switch]$UseCAE,

        [Parameter(Mandatory = $false)]
        [switch]$UseCodeVerifier,

        [Parameter(Mandatory = $false)]
        [string]$CodeVerifier,

        [Parameter(Mandatory = $false)]
        [string]$Proxy
    )

    process {
        # Normalize the assertion input (object or JSON string)
        if ($Assertion -is [string]) {
            try {
                $Assertion = $Assertion | ConvertFrom-Json
            } catch {
                throw "Assertion could not be parsed as JSON. $($_.Exception.Message)"
            }
        }
        foreach ($property in @('id', 'clientDataJSON', 'authenticatorData', 'signature', 'userHandle')) {
            if ([string]::IsNullOrWhiteSpace($Assertion.$property)) {
                throw "Assertion is missing required property '$property'."
            }
        }
        $assertionJson = $Assertion | ConvertTo-Json -Compress -Depth 10

        if ($FlowState) {
            if (-not $WebSession) { $WebSession = $FlowState.WebSession }
            if (-not $SessionInfo) { $SessionInfo = $FlowState.SessionInformation }
            if (-not $SessionInfo) { $SessionInfo = $FlowState.SessionInfo }
            if ($FlowState.OAuth) {
                if ([string]::IsNullOrWhiteSpace($ClientID)) { $ClientID = $FlowState.OAuth.ClientID }
                if ([string]::IsNullOrWhiteSpace($Scope)) { $Scope = $FlowState.OAuth.Scope }
                if ($FlowState.OAuth.Resource) { $Resource = $FlowState.OAuth.Resource }
                if ([string]::IsNullOrWhiteSpace($RedirectUrl)) { $RedirectUrl = $FlowState.OAuth.RedirectUrl }
                if ($FlowState.OAuth.UseV1Endpoint) { $UseV1Endpoint = $true }
                if ($FlowState.OAuth.UseCAE) { $UseCAE = $true }
                if ($FlowState.OAuth.UseCodeVerifier) { $UseCodeVerifier = $true }
                if ([string]::IsNullOrWhiteSpace($CodeVerifier)) { $CodeVerifier = $FlowState.OAuth.CodeVerifier }
            }
        }
        if (-not $WebSession) { $WebSession = $global:Fido2WebSession }
        if (-not $SessionInfo -and $WebSession) { $SessionInfo = $WebSession.Fido2SessionInfo }

        if (-not $WebSession) {
            throw "No web session available. Run Get-EntraIDFido2Challenge first or provide -WebSession."
        }
        if (-not $SessionInfo) {
            throw "No session information available. Run Get-EntraIDFido2Challenge first or provide -SessionInfo."
        }

        $effectiveClient = $Client
        if ($FlowState -and $FlowState.OAuth -and $FlowState.OAuth.Client) {
            $effectiveClient = $FlowState.OAuth.Client
        }
        $resolvedOAuth = Resolve-TTEntraOAuthClient `
            -Client $effectiveClient `
            -ClientID $ClientID `
            -Scope $Scope `
            -Resource $Resource `
            -RedirectUrl $RedirectUrl `
            -UseV1Endpoint:$UseV1Endpoint
        if ([string]::IsNullOrWhiteSpace($ClientID)) { $ClientID = $resolvedOAuth.ClientID }
        if ([string]::IsNullOrWhiteSpace($Scope)) { $Scope = $resolvedOAuth.Scope }
        if ([string]::IsNullOrWhiteSpace($Scope)) { $Scope = 'openid offline_access' }
        if ($resolvedOAuth.Resource) { $Resource = $resolvedOAuth.Resource }
        if ($resolvedOAuth.UseV1Endpoint) { $UseV1Endpoint = $true }
        if ([string]::IsNullOrWhiteSpace($RedirectUrl)) { $RedirectUrl = $resolvedOAuth.RedirectUrl }
        if ([string]::IsNullOrWhiteSpace($RedirectUrl)) {
            throw "No redirect URI is known for client ID '$ClientID'. Provide -RedirectUrl for this app registration."
        }

        # Note: an unbound [string] parameter is an empty string, not $null, so ?? cannot be used here
        $targetUser = $UserPrincipalName
        if ([string]::IsNullOrWhiteSpace($targetUser)) {
            $targetUser = $SessionInfo.UserPrincipalName
        }
        if ([string]::IsNullOrWhiteSpace($targetUser)) {
            throw "UserPrincipalName not found. Provide -UserPrincipalName or run Get-EntraIDFido2Challenge first."
        }

        # Configure Default Parameters
        $PSDefaultParameterValues = @{}
        $PSDefaultParameterValues.Add('Invoke-WebRequest:Verbose', $false)

        if ($Proxy) {
            Write-Verbose "$([char]0x2718) Setting proxy to $Proxy"
            $PSDefaultParameterValues.Add('Invoke-WebRequest:Proxy', $Proxy)
        }

        $session = $WebSession
        $flowAuthority = $Authority
        if ($FlowState -and $FlowState.OAuth -and $FlowState.OAuth.Authority) {
            $flowAuthority = $FlowState.OAuth.Authority
        }
        $credentialsJson = $SessionInfo.oGetCredTypeResult.Credentials.FidoParams.AllowList -join ','

        Write-Host "$([char]0x2718) Get required pre-information from microsoft.com..." -ForegroundColor Cyan
        $verifyUrl = "https://login.microsoft.com/common/fido/get?uiflavor=Web"

        # The fidoAssertion must be a JSON string *inside* the body
        $bodyVerify = @{
            allowedIdentities = 2
            canary            = $SessionInfo.sFT
            ServerChallenge   = $SessionInfo.sFT
            postBackUrl       = $SessionInfo.urlPost
            postBackUrlAad    = $SessionInfo.urlPostAad
            postBackUrlMsa    = $SessionInfo.urlPostMsa
            cancelUrl         = $SessionInfo.urlRefresh
            resumeUrl         = $SessionInfo.urlResume
            correlationId     = $SessionInfo.correlationId
            credentialsJson   = $credentialsJson
            ctx               = $SessionInfo.sCtx
            username          = $targetUser
            loginCanary       = $SessionInfo.canary
        }

        try {
            Write-Verbose "$([char]0x2718) Submitting verification request ..."
            Write-Debug "$($bodyVerify | ConvertTo-Json -Depth 10)"
            $respVerify = Invoke-WebRequest -UseBasicParsing -Uri $verifyUrl -Method Post -Body $bodyVerify -WebSession $session

            # Extract config from response headers/cookies
            $respVerify.Content -match '{(.*)}' | Out-Null
            $ResponseInformation = $Matches[0] | ConvertFrom-Json
        } catch {
            throw "Verification request failed: $($_.Exception.Message)"
        }

        $postbackUrl = $SessionInfo.urlPost
        if ($FlowState -and $FlowState.PostbackUrl) { $postbackUrl = $FlowState.PostbackUrl }
        $LoginUri = Resolve-TTEntraPostbackUri -PostbackUrl $postbackUrl -Authority $flowAuthority
        $Payload = @{
            type         = 23
            ps           = 23
            assertion    = $assertionJson
            lmcCanary    = $ResponseInformation.sCrossDomainCanary
            hpgrequestid = $ResponseInformation.sessionId
            ctx          = $ResponseInformation.sCtx
            canary       = $ResponseInformation.canary
            flowToken    = $ResponseInformation.sFT
        }

        try {
            Write-Host "$([char]0x2718) Submitting FIDO2 assertion to microsoftonline.com ..." -ForegroundColor Cyan
            Write-Debug ($Payload | ConvertTo-Json -Depth 10)
            $respFinalize = Invoke-WebRequest -UseBasicParsing -Uri $LoginUri -Method Post -Body $Payload -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction Stop
            if ($respFinalize.Content -match '{(.*)}') {
                $Debug = $Matches[0] | ConvertFrom-Json | ConvertTo-Json -Depth 10
                Write-Debug "$([char]0x2718) Finalization Response: $Debug"
            }
        } catch {
            # A redirect is an expected response when the assertion was accepted; the ESTS
            # cookies are set on the session. Depending on the platform this surfaces as a
            # redirection count error or an InvalidOperationException. Anything else is a
            # real failure.
            # Note: [regex]::IsMatch is used instead of -notmatch to avoid populating $Matches.
            if (-not [regex]::IsMatch($_.Exception.Message, 'maximum redirection count|current state of the object')) {
                throw "Finalization request failed: $($_.Exception.Message)"
            }
            Write-Verbose "$([char]0x2714) Assertion accepted (server responded with a redirect)."
        }

        $LoginUri = Add-TTUriQueryParameter -Uri $LoginUri -Name 'sso_reload' -Value 'true'
        $Payload = @{
            type         = 23
            ps           = 23
            assertion    = $assertionJson
            lmcCanary    = $ResponseInformation.sCrossDomainCanary
            hpgrequestid = $ResponseInformation.sessionId
            ctx          = $SessionInfo.sCtx
            canary       = $SessionInfo.canary
            flowToken    = $SessionInfo.oGetCredTypeResult.FlowToken
        }

        try {
            Write-Host "$([char]0x2718) Submitting FIDO2 assertion to microsoftonline.com with sso_reload=true ..." -ForegroundColor Cyan
            $respFinalize = Invoke-WebRequest -UseBasicParsing -Uri $LoginUri -Method Post -Body $Payload -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction Stop
        } catch {
            # A redirect is an expected response when the assertion was accepted; the ESTS
            # cookies are set on the session. Depending on the platform this surfaces as a
            # redirection count error or an InvalidOperationException. Anything else is a
            # real failure.
            # Note: [regex]::IsMatch is used instead of -notmatch to avoid populating $Matches.
            if (-not [regex]::IsMatch($_.Exception.Message, 'maximum redirection count|current state of the object')) {
                throw "Finalization request failed: $($_.Exception.Message)"
            }
            Write-Verbose "$([char]0x2714) Assertion accepted (server responded with a redirect)."
        }

        # $respFinalize can be null here if both submissions were answered with a redirect
        $Debug = $null
        if ($respFinalize.Content -match '{(.*)}') {
            $Debug = $Matches[0] | ConvertFrom-Json
        }
        if ($Debug.pgid) {
            Write-Host "$([char]0x2718) PageID: $($Debug.pgid)"
            $CurrentPageId = $Debug.pgid
        }
        Write-Debug "$([char]0x2718) Finalization Response: $($Debug | ConvertTo-Json -Depth 10)"

        # Interrupt Handling
        $LoopCount = 0
        while ($Debug.pgid -in @("CmsiInterrupt", "KmsiInterrupt", "ConvergedSignIn")) {
            # Cleanup variables
            Remove-Variable -Name respFinalize -ErrorAction SilentlyContinue
            # Prevent infinite loops
            if ($CurrentPageId -eq $LastPageId) {
                Write-Warning "Stuck in interrupt loop on PageID: $($Debug.pgid). Exiting."
                break
            }
            $LastPageId = $CurrentPageId

            # Display debug info only on first loop
            if ($LoopCount -eq 0) {
                if ( -not [string]::IsNullOrWhiteSpace($Debug.sDeviceId)) {
                    Write-Host "$([char]0x2718)  Device Id: $($Debug.sDeviceId)"
                }
                if ( -not [string]::IsNullOrWhiteSpace($Debug.correlationId)) {
                    Write-Host "$([char]0x2718)  Correlation Id: $($Debug.correlationId)"
                }
                if ( -not [string]::IsNullOrWhiteSpace($Debug.sessionId)) {
                    Write-Host "$([char]0x2718)  Session Id: $($Debug.sessionId)"
                }
                if ( -not [string]::IsNullOrWhiteSpace($Debug.sPOST_Username)) {
                    Write-Host "$([char]0x2718)  Username: $($Debug.sPOST_Username)"
                }
            }
            $LoopCount++

            if ($LoopCount -gt 10) {
                Write-Warning "Exceeded maximum interrupt handling attempts. Exiting."
                break
            }

            # CMSI (consent) interrupt
            if ($Debug.pgid -eq "CmsiInterrupt") {
                Write-Host "$([char]0x2718)  AADSTS50199: CmsiInterrupt"
                Write-Host "   For security reasons, user confirmation is required for this application: $($Debug.sAppName)."
                Write-Host "$([char]0x2718)  urlPost URL: $($Debug.urlPost)"
                $Uri = "https://login.microsoftonline.com/appverify"
                $Payload = @{
                    "ContinueAuth"    = "true"
                    "i19"             = "$(Get-Random -Minimum 1000 -Maximum 9999)"
                    "canary"          = $Debug.canary
                    "iscsrfspeedbump" = "false"
                    "flowToken"       = $Debug.sFT
                    "hpgrequestid"    = $Debug.correlationId
                    "ctx"             = $Debug.sCtx
                }

                try {
                    Write-Host "$([char]0x2718) Submitting CMSI response to microsoftonline.com ..." -ForegroundColor Cyan
                    $respFinalize = Invoke-WebRequest -UseBasicParsing -Uri $Uri -Method Post -Body $Payload -WebSession $session -SkipHttpErrorCheck -MaximumRedirection 10
                } catch {
                    Write-Warning "CMSI request failed; checking previous response for success. Error: $($_.Exception.Message)"
                }
            }

            # KMSI (keep me signed in) interrupt
            if ($Debug.pgid -eq "KmsiInterrupt") {
                Write-Host "$([char]0x2718) Handling KMSI prompt..." -ForegroundColor Cyan
                $PayloadKMSI = @{
                    LoginOptions = 1
                    type         = 28
                    ctx          = $Debug.sCtx
                    hpgrequestid = $Debug.correlationId
                    flowToken    = $Debug.sFT
                    canary       = $Debug.canary
                    i19          = 4130
                }

                try {
                    $Uri = "https://login.microsoftonline.com/kmsi"
                    Write-Host "$([char]0x2718) Submitting KMSI response to microsoftonline.com ..." -ForegroundColor Cyan
                    $respFinalize = Invoke-WebRequest -UseBasicParsing -Uri $Uri -Method Post -Body $PayloadKMSI -WebSession $session
                    Write-Debug "$([char]0x2718) KMSI Response: $($respFinalize | Out-String )"
                } catch {
                    Write-Warning "KMSI request failed; checking previous response for success. Error: $($_.Exception.Message)"
                }
            }

            # ConvergedSignIn interrupt
            if ($Debug.pgid -eq "ConvergedSignIn") {
                Write-Output "$([char]0x2718)  ConvergedSignIn - Attempting to continue sign-in flow"
                $SessionId = $($Debug.arrSessions[0].id) ?? $Debug.sessionId
                try {
                    $Uri = $Debug.urlLogin + "&sessionid=$($SessionId)"
                    Write-Host "$([char]0x2718) Submitting ConvergedSignIn request to microsoftonline.com ..." -ForegroundColor Cyan
                    Write-Verbose "$([char]0x2718) ConvergedSignIn URL: $Uri"
                    $respFinalize = Invoke-WebRequest -UseBasicParsing -Uri $Uri -Method Get -WebSession $session
                } catch {
                    Write-Warning "ConvergedSignIn request failed; checking previous response for success. Error: $($_.Exception.Message)"
                }
            }

            Remove-Variable -Name Debug -ErrorAction SilentlyContinue
            if ( $respFinalize.Content -match '{(.*)}' ) {
                try {
                    $Debug = $Matches[0] | ConvertFrom-Json
                } catch {
                    Write-Warning "Failed to parse JSON response during interrupt handling. Exiting loop."
                    break
                }
                if ($Debug.pgid) {
                    Write-Host "$([char]0x2718) PageID: $($Debug.pgid)"
                    $CurrentPageId = $Debug.pgid
                }
                Write-Debug "$([char]0x2718) Full Response: $($Debug | ConvertTo-Json -Depth 10)"
            } else {
                Write-Debug "$([char]0x2718) No JSON response received; exiting interrupt handling loop."
                Write-Debug "$([char]0x2718) Last Response: $($respFinalize) ..."
                break
            }
        }

        if ($respFinalize.Error) {
            Write-Error "Login Error: $($respFinalize.Error.Message)"
        } elseif ( $session.Cookies.GetCookies("https://login.microsoftonline.com") | Where-Object Name -Like "ESTS*") {
            Write-Host "$([char]0x2714) Login Successful!" -ForegroundColor Green
            $ESTSAUTH = $session.Cookies.GetCookies("https://login.microsoftonline.com") | Where-Object Name -EQ "ESTSAUTH"
            $ESTSAUTHPERSISTENT = $session.Cookies.GetCookies("https://login.microsoftonline.com") | Where-Object Name -EQ "ESTSAUTHPERSISTENT"
            $ESTSAUTHLIGHT = $session.Cookies.GetCookies("https://login.microsoftonline.com") | Where-Object Name -EQ "ESTSAUTHLIGHT"
            # Get  ESTS cookie with longest value (usually ESTSAUTH or ESTSAUTHPERSISTENT)
            $ests = @($ESTSAUTH, $ESTSAUTHPERSISTENT, $ESTSAUTHLIGHT) | Sort-Object { $_.Value.Length } -Descending | Select-Object -First 1
            if (-not $ests) {
                throw "Login succeeded but no ESTSAUTH cookie was found in the session."
            }

            if ($OutputType -eq 'ESTSAUTHCookie') {
                Write-Host "$([char]0x26BF) ESTSAUTH Cookie: $($ests.Value.Substring(0, 20))... saved as `$global:ESTSAUTH" -ForegroundColor Gray
                $global:ESTSAUTH = $ests.Value
                Write-Host "$([char]0x26BF) Session saved as `$global:webSession for reuse in other functions." -ForegroundColor Gray
                $global:webSession = $session
                return $ests.Value
            }

            # Default: exchange the ESTSAUTH cookie for an access token and refresh token
            $exchangeClient = $Client
            $supportedCookieClients = @('MSTeams', 'MSEdge', 'AzurePowershell', 'AzureManagement', 'DeviceComplianceBypass', 'Custom')
            if ($FlowState -or $exchangeClient -notin $supportedCookieClients) {
                $exchangeClient = 'Custom'
            }
            $TokenParameters = @{
                CookieValue = $ests.Value
                Resource    = $Resource
                Scope       = $Scope
                RedirectUrl = $RedirectUrl
                Client      = $exchangeClient
                Verbose     = $VerbosePreference
            }
            if ($ests.Name -in @('ESTSAUTH', 'ESTSAUTHPERSISTENT')) {
                $TokenParameters.Add('ESTSCookieType', $ests.Name)
            }
            if ($ClientID) {
                $TokenParameters.Add('ClientID', $ClientID)
            }
            if ($Proxy) {
                $TokenParameters.Add('Proxy', $Proxy)
            }
            if ($UseV1Endpoint) { $TokenParameters.Add('UseV1Endpoint', $true) }
            if ($UseCAE) { $TokenParameters.Add('UseCAE', $true) }
            if ($UseCodeVerifier) {
                $TokenParameters.Add('UseCodeVerifier', $true)
                if ($CodeVerifier) { $TokenParameters.Add('CodeVerifier', $CodeVerifier) }
            }
            Get-EntraIDTokenFromESTSCookie @TokenParameters
            return $global:response
        } else {
            Write-Warning "Flow finished but success state is unclear. Saved session for inspection as `$global:webSession."
            if ($respFinalize.Content -match '{(.*)}') {
                $Matches[0] | ConvertFrom-Json | ConvertTo-Json -Depth 10
            }
            $global:webSession = $session
        }
    }
}
