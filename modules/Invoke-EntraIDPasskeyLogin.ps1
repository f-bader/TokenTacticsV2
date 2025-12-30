function Invoke-EntraIDPasskeyLogin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string]$KeyFilePath,

        [Alias('UserName')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Path')]
        [Parameter(Mandatory, ParameterSetName = 'Manual')]
        [string]$UserPrincipalName,

        [Parameter(Mandatory, ParameterSetName = 'Manual')]
        [string]$UserHandle,

        [Parameter(Mandatory, ParameterSetName = 'Manual')]
        [string]$CredentialId,

        [Parameter(Mandatory, ParameterSetName = 'Manual')]
        [string]$PrivateKey,

        [Parameter(Mandatory = $false)]
        $RelyingParty = "login.microsoft.com",

        [Parameter(Mandatory = $false)]
        $authUrl = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?response_type=code&redirect_uri=msauth.com.msauth.unsignedapp://auth&scope=https://graph.microsoft.com/.default&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46",

        [Parameter(Mandatory = $false)]
        $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0',

        [Parameter(Mandatory = $false)]
        [string]$Proxy
    )

    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Error "This function requires PowerShell 7 (Core) for ECDsa PEM support."
        exit 1
    }

    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        if (-not (Test-Path $KeyFilePath)) {
            Write-Error "Key file '$KeyFilePath' not found."
            exit 1
        }

        # Load Key Data
        Write-Host "$([char]0x2718) Loading key data from file: $KeyFilePath" -ForegroundColor Cyan
        try {
            $keyData = Get-Content $KeyFilePath -Raw | ConvertFrom-Json
        } catch {
            Write-Error "Invalid JSON in key file."
            exit 1
        }
    }

    # Configure Default Parameters
    $PSDefaultParameterValues = @{}
    $PSDefaultParameterValues.Add('Invoke-WebRequest:Verbose', $false)

    if ($Proxy) {
        Write-Verbose "$([char]0x2718) Setting proxy to $Proxy"
        $PSDefaultParameterValues.Add('Invoke-WebRequest:Proxy', $Proxy)
    }

    # Determine Target User
    $targetUser = $keyData.username ?? $UserPrincipalName
    if (-not $targetUser) {
        Write-Error "Username not found in JSON or arguments."
        exit 1
    }

    # Determine FIDO Parameters from JSON (Critical for the HAR flow)
    $rpId = $keyData.relyingParty ?? $RelyingParty
    $origin = $keyData.url ?? "https://$($rpId)"
    # Make sure origin is just scheme + host
    $origin = [uri]"$origin" | Select-Object -ExpandProperty Host
    $origin = "https://$($origin)"

    $userHandle = $keyData.userHandle ?? $UserHandle
    if (-not $userHandle) {
        Write-Error "UserHandle not found in JSON or arguments."
        exit 1
    }
    $credentialId = $keyData.credentialId ?? $CredentialId
    if (-not $credentialId) {
        Write-Error "CredentialId not found in JSON or arguments."
        exit 1
    }

    Write-Host "$([char]0x2714) User:       $targetUser" -ForegroundColor Gray
    Write-Host "$([char]0x2714) RP ID:      $rpId" -ForegroundColor Gray
    Write-Host "$([char]0x2714) Origin:     $origin" -ForegroundColor Gray
    Write-Host "$([char]0x2714) CredID:     $credentialId" -ForegroundColor Gray
    Write-Host "$([char]0x2714) UserHandle: $userHandle" -ForegroundColor Gray

    # Private Key and Sign Count
    [int]$SignCount = $keyData.signCount ?? 0
    $PrivateKeyPem = $keyData.privateKey ?? $PrivateKey
    $PrivateKeyPem = ConvertTo-PEMPrivateKey -PrivateKey $PrivateKeyPem
    if (-not $PrivateKeyPem) {
        Write-Error "Private key not found in JSON or arguments."
        exit 1
    }

    #region Authentication Flow
    # Configure Session
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = $UserAgent

    # Add mandatory fields to URI
    # Get all existing query parameters
    try {
        $uriBuilder = [System.UriBuilder]$authUrl
        $query = [System.Web.HttpUtility]::ParseQueryString($uriBuilder.Query)
    } catch {
        Write-Error "Invalid auth URL format. $($_.Exception.Message)"
        exit 1
    }
    if ( $authUrl -notmatch "^https://login.microsoftonline.com/" ) {
        Write-Error "Auth URL must start with 'https://login.microsoftonline.com/'"
        exit 1
    }
    # Check if required parameters are already present
    # scope
    # client_id
    # response_type
    # redirect_uri
    $RequiredParams = @("client_id", "response_type", "redirect_uri")
    foreach ($param in $RequiredParams) {
        if (-not $query.Get($param)) {
            Write-Error "$([char]0x2718) Missing required parameter '$param' in auth URL."
            exit 1
        }
    }
    # Add additional required parameters if missing
    # sso_reload=true
    # login_hint=$targetUser
    if (-not $query.Get("sso_reload")) {
        $authUrl = "$authUrl&sso_reload=true"
    }
    if (-not $query.Get("login_hint")) {
        $authUrl = "$authUrl&login_hint=$targetUser"
    }
    Write-Verbose "$([char]0x2718) Auth URL: $authUrl"

    # This sets the initial ESTS cookies and flow state.
    Write-Host "$([char]0x2718) Warming up session on login.microsoftonline.com (Authorize)..." -ForegroundColor Cyan
    try {
        $InitialResponse = Invoke-WebRequest -UseBasicParsing -Uri $authUrl -Method Get -WebSession $session
        $InitialResponse.Content -match '{(.*)}' | Out-Null
        $SessionInformation = $Matches[0] | ConvertFrom-Json
    } catch {
        # It's expected to redirect or fail if we don't follow the full HTML flow,
        # but we just need the Cookies in $session.
    }

    # B. Validate Credential Type
    Write-Host "$([char]0x2718) Validate FIDO2 Credential Type..." -ForegroundColor Cyan
    if (-not $SessionInformation.oGetCredTypeResult.Credentials.HasFido) {
        Write-Error "User does not have FIDO credentials registered."
        exit 1
    }

    if (-not $SessionInformation.sFidoChallenge) {
        Write-Error "No FIDO challenge received from server."
        exit 1
    }

    $serverChallenge = [System.Text.Encoding]::ASCII.GetBytes( $SessionInformation.sFidoChallenge ) # Base64Url challenge from session info
    Write-Host "$([char]0x2714) Challenge Received." -ForegroundColor Green

    # C. Local Signing (The "Page 4" equivalent)
    Write-Host "$([char]0x2718) Generating FIDO Assertion locally..." -ForegroundColor Cyan

    try {
        $authData = New-FidoAuthenticatorData -RpId $rpId -SignCount $SignCount
        $FidoSignatureParameters = @{
            Challenge     = (ConvertTo-Base64Url $serverChallenge)
            Origin        = $origin
            AuthDataBytes = $authData
            PrivateKeyPem = $PrivateKeyPem
        }
        $crypto = New-FidoSignature @FidoSignatureParameters

        # Construct the payload structure Microsoft expects
        $fidoPayload = [ordered]@{
            id                = $CredentialId
            clientDataJSON    = (ConvertTo-Base64Url $crypto.ClientData)
            authenticatorData = (ConvertTo-Base64Url $authData)
            signature         = (ConvertTo-Base64Url $crypto.Signature)
            userHandle        = $UserHandle
        }

        $credentialsJson = $SessionInformation.oGetCredTypeResult.Credentials.FidoParams.AllowList -join ','
    } catch {
        Write-Error "FIDO Assertion generation failed: $($_.Exception.Message)"
        exit 1
    }

    Write-Host "$([char]0x2718) Get required pre-information from microsoft.com..." -ForegroundColor Cyan
    $verifyUrl = "https://login.microsoft.com/common/fido/get?uiflavor=Web"

    # The fidoAssertion must be a JSON string *inside* the body
    $bodyVerify = @{
        allowedIdentities = 2
        canary            = $SessionInformation.sFT
        ServerChallenge   = $SessionInformation.sFT
        postBackUrl       = $SessionInformation.urlPost
        postBackUrlAad    = $SessionInformation.urlPostAad
        postBackUrlMsa    = $SessionInformation.urlPostMsa
        cancelUrl         = $SessionInformation.urlRefresh
        resumeUrl         = $SessionInformation.urlResume
        correlationId     = $SessionInformation.correlationId
        credentialsJson   = $credentialsJson
        ctx               = $SessionInformation.sCtx
        username          = $targetUser
        loginCanary       = $SessionInformation.canary
    }

    try {
        Write-Verbose "$([char]0x2718) Submitting verification request ..."
        Write-Debug "$($bodyVerify | ConvertTo-Json -Depth 10)"
        $respVerify = Invoke-WebRequest -UseBasicParsing -Uri $verifyUrl -Method Post -Body $bodyVerify -WebSession $session

        # Extract config from response headers/cookies
        $respVerify.Content -match '{(.*)}' | Out-Null
        $ResponseInformation = $Matches[0] | ConvertFrom-Json
    } catch {
        Write-Warning "Verification request failed: $($_.Exception.Message)"
        exit 1
    }

    $LoginUri = "https://login.microsoftonline.com/common/login"
    $Payload = @{
        type         = 23
        ps           = 23
        assertion    = ($fidoPayload | ConvertTo-Json -Compress -Depth 10)
        lmcCanary    = $ResponseInformation.sCrossDomainCanary
        hpgrequestid = $ResponseInformation.sessionId
        ctx          = $ResponseInformation.sCtx
        canary       = $ResponseInformation.canary
        flowToken    = $ResponseInformation.sFT
    }

    try {
        Write-Host "$([char]0x2718) Submitting FIDO2 assertion to microsoftonline.com ..." -ForegroundColor Cyan
        Write-Debug ($Payload | ConvertTo-Json -Depth 10)
        $respFinalize = Invoke-WebRequest -UseBasicParsing -Uri $LoginUri -Method Post -Body $Payload -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck
        $respFinalize.Content -match '{(.*)}' | Out-Null
        $Debug = $Matches[0] | ConvertFrom-Json | ConvertTo-Json -Depth 10
        Write-Debug "$([char]0x2718) Finalization Response: $Debug"
    } catch {
        Write-Warning "Finalization request failed; checking previous response for success. Error: $($_.Exception.Message)"
        Write-Debug "$([char]0x2718) Last Response: $($respFinalize | ConvertTo-Json -Depth 10 )"
        exit 1
    }

    $LoginUri = "https://login.microsoftonline.com/common/login?sso_reload=true"
    $Payload = @{
        type         = 23
        ps           = 23
        assertion    = ($fidoPayload | ConvertTo-Json -Compress -Depth 10)
        lmcCanary    = $lmcCanary.Value
        hpgrequestid = $hpgrequestid
        ctx          = $SessionInformation.sCtx
        canary       = $SessionInformation.canary
        flowToken    = $SessionInformation.oGetCredTypeResult.FlowToken
    }

    try {
        Write-Host "$([char]0x2718) Submitting FIDO2 assertion to microsoftonline.com with sso_reload=true ..." -ForegroundColor Cyan
        $respFinalize = Invoke-WebRequest -UseBasicParsing -Uri $LoginUri -Method Post -Body $Payload -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck
    } catch {
        Write-Warning "Finalization request failed; checking previous response for success. Error: $($_.Exception.Message)"
        Write-Debug "$([char]0x2718) Last Response: $($respFinalize)"
        exit 1
    }

    $respFinalize.Content -match '{(.*)}' | Out-Null
    $Debug = $Matches[0] | ConvertFrom-Json
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
            $Debug = $Matches[0] | ConvertFrom-Json
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
        if ($ests) {
            Write-Host "$([char]0x26BF) ESTSAUTH Cookie: $($ests.Value.Substring(0, 20))... saved as `$global:ESTSAUTH" -ForegroundColor Gray
            $global:ESTSAUTH = $ests.Value
            Write-Host "$([char]0x26BF) Session saved as `$global:webSession for reuse in other functions." -ForegroundColor Gray
            $global:webSession = $session
        }
    } else {
        Write-Warning "Flow finished but success state is unclear. Saved session for inspection as `$global:webSession."
        $respFinalize.Content -match '{(.*)}' | Out-Null
        $Matches[0] | ConvertFrom-Json | ConvertTo-Json -Depth 10
        $global:webSession = $session
    }
}