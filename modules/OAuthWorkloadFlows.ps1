function ConvertFrom-TTSecureValue {
    param([Parameter(Mandatory = $true)][object]$Value)
    if ($Value -is [System.Security.SecureString]) {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
        try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    }
    return [string]$Value
}

function Get-TTMaskedValue {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '<null>' }
    $text = [string]$Value
    "<redacted length=$($text.Length)>"
}

function Get-TTTokenRequestSummary {
    param([Parameter(Mandatory = $true)][hashtable]$Body)
    $parts = foreach ($entry in $Body.GetEnumerator()) {
        if ($entry.Key -match '^(client_secret|client_assertion|assertion|refresh_token|access_token|id_token)$') {
            '{0}={1}' -f $entry.Key, (Get-TTMaskedValue -Value $entry.Value)
        } else {
            '{0}={1}' -f $entry.Key, $entry.Value
        }
    }
    ($parts | Sort-Object) -join '; '
}

function Get-TTResponseSummary {
    param([AllowNull()][object]$Response)
    if ($null -eq $Response) { return '<null response>' }
    $parts = foreach ($property in $Response.PSObject.Properties) {
        $normalizedName = ($property.Name -replace '[_-]', '').ToLowerInvariant()
        if ($normalizedName -in @('accesstoken', 'idtoken', 'refreshtoken', 'clientsecret', 'clientassertion', 'assertion', 'secret', 'password', 'authorization', 'privatekey', 'state') -or $normalizedName -match '(secret|password|authorization|privatekey|assertion)$') {
            '{0}={1}' -f $property.Name, (Get-TTMaskedValue -Value $property.Value)
        } else {
            '{0}={1}' -f $property.Name, $property.Value
        }
    }
    ($parts | Sort-Object) -join '; '
}

function Get-TTTokenEndpoint {
    param([Parameter(Mandatory = $true)][string]$TenantId)
    "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
}

function Assert-TTDefaultScope {
    param([Parameter(Mandatory = $true)][string]$Scope)
    $parts = @($Scope -split '\s+' | Where-Object { $_ })
    if ($parts.Count -ne 1 -or $parts[0] -notmatch '^.+/\.default$') {
        throw "Scope must contain exactly one resource with the '/.default' suffix."
    }
}

function Invoke-TTTokenEndpoint {
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][hashtable]$Body
    )
    $endpoint = Get-TTTokenEndpoint -TenantId $TenantId
    Write-Verbose ("POST token request: endpoint={0}; body={1}" -f $endpoint, (Get-TTTokenRequestSummary -Body $Body))
    try {
        $global:response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $endpoint -Body $Body -ErrorAction Stop
        Write-Verbose ("Token response received: {0}" -f (Get-TTResponseSummary -Response $global:response))
        $global:response
    } catch {
        # Do not include the request body here: it can contain client credentials.
        throw "Entra token request failed: $($_.Exception.Message)"
    }
}

function Get-TTOpenSslPfxMaterial {
    param([Parameter(Mandatory = $true)][string]$PfxPath, [Parameter(Mandatory = $true)][string]$Password)
    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if ($null -eq $openssl) { throw 'The PFX could not be loaded by .NET and OpenSSL is unavailable.' }
    Write-Verbose ("Loading PFX with OpenSSL fallback: path={0}" -f $PfxPath)
    $temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ("tokentactics-pfx-" + [guid]::NewGuid().ToString('N'))
    $certificatePem = Join-Path $temporaryDirectory 'certificate.pem'
    $certificateDer = Join-Path $temporaryDirectory 'certificate.der'
    $privateKey = Join-Path $temporaryDirectory 'key.pem'
    [IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null
    $previousPassword = $env:TT_OAUTH_PFX_PASSWORD
    $env:TT_OAUTH_PFX_PASSWORD = $Password
    try {
        & $openssl.Source pkcs12 -in $PfxPath -clcerts -nokeys -out $certificatePem -passin env:TT_OAUTH_PFX_PASSWORD 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'OpenSSL could not extract the PFX certificate.' }
        & $openssl.Source pkcs12 -in $PfxPath -nocerts -nodes -out $privateKey -passin env:TT_OAUTH_PFX_PASSWORD 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'OpenSSL could not extract the PFX private key.' }
        & $openssl.Source x509 -in $certificatePem -out $certificateDer -outform DER 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'OpenSSL could not convert the PFX certificate.' }
        $publicKey = & $openssl.Source x509 -in $certificatePem -pubkey -noout
        if ($LASTEXITCODE -ne 0) { throw 'OpenSSL could not export the PFX public key.' }
        [pscustomobject]@{
            TTOpenSslMaterial = $true
            RawData = [IO.File]::ReadAllBytes($certificateDer)
            PrivateKeyPath = $privateKey
            PublicKeyPem = ($publicKey -join [Environment]::NewLine)
            TemporaryDirectory = $temporaryDirectory
        }
    } catch {
        if (Test-Path -LiteralPath $temporaryDirectory) { Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force }
        throw
    } finally {
        $env:TT_OAUTH_PFX_PASSWORD = $previousPassword
    }
}

function Remove-TTCertificate {
    param($Certificate)
    if ($null -eq $Certificate) { return }
    if ($Certificate.PSObject.Properties['TTOpenSslMaterial'] -and $Certificate.TTOpenSslMaterial) {
        if (Test-Path -LiteralPath $Certificate.TemporaryDirectory) { Remove-Item -LiteralPath $Certificate.TemporaryDirectory -Recurse -Force }
    } elseif ($Certificate -is [IDisposable]) {
        $Certificate.Dispose()
    }
}

function Get-TTCertificate {
    param(
        [string]$CertificateThumbprint,
        [ValidateSet('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')][string]$CertStoreLocation = 'Cert:\CurrentUser\My',
        [string]$PfxPath,
        [object]$PfxPassword
    )
    if ($PfxPath) {
        $passwordInput = if ($null -ne $PfxPassword) { 'provided' } else { 'not provided' }
        Write-Verbose ("Loading signing certificate from PFX: path={0}; password={1}" -f $PfxPath, $passwordInput)
        if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) { throw "PFX file '$PfxPath' was not found." }
        $password = if ($null -ne $PfxPassword) { ConvertFrom-TTSecureValue -Value $PfxPassword } else { '' }
        try {
            if ($IsMacOS) { return Get-TTOpenSslPfxMaterial -PfxPath $PfxPath -Password $password }
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $PfxPath, $password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
            )
        } catch {
            return Get-TTOpenSslPfxMaterial -PfxPath $PfxPath -Password $password
        } finally { $password = $null }
    }
    if ($env:OS -ne 'Windows_NT') {
        throw 'Certificate thumbprint lookup requires a Windows certificate store. Use -PfxPath on this platform.'
    }
    Write-Verbose ("Loading signing certificate from Windows certificate store: location={0}; thumbprint={1}" -f $CertStoreLocation, $CertificateThumbprint)
    $thumbprint = ($CertificateThumbprint -replace '\s', '').ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($thumbprint) -or $thumbprint -notmatch '^[0-9A-F]+$') { throw 'CertificateThumbprint must be hexadecimal.' }
    try { return Get-Item -Path "$CertStoreLocation\$thumbprint" -ErrorAction Stop }
    catch { throw "Certificate '$thumbprint' was not found at '$CertStoreLocation'." }
}

function Assert-TTCertificate {
    param([Parameter(Mandatory = $true)]$Certificate)
    if ($Certificate.PSObject.Properties['TTOpenSslMaterial'] -and $Certificate.TTOpenSslMaterial) { return }
    if (-not $Certificate.HasPrivateKey) { throw 'The selected certificate does not have an accessible private key.' }
    $now = [DateTimeOffset]::UtcNow
    if ($Certificate.NotBefore.ToUniversalTime() -gt $now.UtcDateTime -or $Certificate.NotAfter.ToUniversalTime() -lt $now.UtcDateTime) {
        throw 'The selected certificate is not currently valid.'
    }
}

function New-TTRsaJwt {
    param(
        [Parameter(Mandatory = $true)]$Certificate,
        [Parameter(Mandatory = $true)][System.Collections.Specialized.OrderedDictionary]$Payload,
        [ValidateSet('RS256', 'PS256')][string]$Algorithm = 'RS256'
    )
    Assert-TTCertificate -Certificate $Certificate
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try { $kid = ConvertTo-Base64Url -Bytes ($sha256.ComputeHash($Certificate.RawData)) } finally { $sha256.Dispose() }
    $header = [ordered]@{ alg = $Algorithm; typ = 'JWT'; 'x5t#S256' = $kid }
    $headerBytes = [Text.Encoding]::UTF8.GetBytes(($header | ConvertTo-Json -Compress))
    $payloadBytes = [Text.Encoding]::UTF8.GetBytes(($Payload | ConvertTo-Json -Compress))
    $unsigned = "$(ConvertTo-Base64Url -Bytes $headerBytes).$(ConvertTo-Base64Url -Bytes $payloadBytes)"
    if ($Certificate.PSObject.Properties['TTOpenSslMaterial'] -and $Certificate.TTOpenSslMaterial) {
        if ($Algorithm -eq 'PS256') { throw 'PFX signing with PS256 requires a .NET certificate provider. Use a Windows certificate store or a platform where the PFX loads natively.' }
        $unsignedPath = Join-Path $Certificate.TemporaryDirectory 'unsigned.bin'
        $signaturePath = Join-Path $Certificate.TemporaryDirectory 'signature.bin'
        [IO.File]::WriteAllBytes($unsignedPath, [Text.Encoding]::UTF8.GetBytes($unsigned))
        $openssl = Get-Command openssl -ErrorAction Stop
        & $openssl.Source dgst -sha256 -sign $Certificate.PrivateKeyPath -out $signaturePath $unsignedPath | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'OpenSSL could not sign the JWT.' }
        return "$unsigned.$(ConvertTo-Base64Url -Bytes ([IO.File]::ReadAllBytes($signaturePath)))"
    }
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if ($null -eq $rsa) { throw 'The selected certificate does not expose an RSA private key.' }
    try {
        $padding = if ($Algorithm -eq 'PS256') { [System.Security.Cryptography.RSASignaturePadding]::Pss } else { [System.Security.Cryptography.RSASignaturePadding]::Pkcs1 }
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($unsigned), [System.Security.Cryptography.HashAlgorithmName]::SHA256, $padding)
        "$unsigned.$(ConvertTo-Base64Url -Bytes $signature)"
    } finally { $rsa.Dispose() }
}

function New-TTClientCertificateAssertion {
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true)]$Certificate
    )
    $now = [DateTimeOffset]::UtcNow
    $payload = [ordered]@{
        aud = Get-TTTokenEndpoint -TenantId $TenantId; iss = $ClientId; sub = $ClientId; jti = [guid]::NewGuid().ToString()
        nbf = $now.ToUnixTimeSeconds(); exp = $now.AddMinutes(10).ToUnixTimeSeconds()
    }
    New-TTRsaJwt -Certificate $Certificate -Payload $payload -Algorithm RS256
}

function Get-EntraIDTokenFromClientSecret {
    [CmdletBinding(DefaultParameterSetName = 'PlaintextSecret')]
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true, ParameterSetName = 'PlaintextSecret')][string]$ClientSecret,
        [Parameter(Mandatory = $true, ParameterSetName = 'SecureStringSecret')][securestring]$ClientSecretSecureString,
        [string]$Scope = 'https://graph.microsoft.com/.default'
    )
    Write-Verbose ("Starting client-credentials flow: tenant={0}; client_id={1}; scope={2}; credential_input={3}" -f $TenantId, $ClientId, $Scope, $PSCmdlet.ParameterSetName)
    Assert-TTDefaultScope -Scope $Scope
    $secret = if ($PSCmdlet.ParameterSetName -eq 'SecureStringSecret') { ConvertFrom-TTSecureValue $ClientSecretSecureString } else { $ClientSecret }
    try {
        Write-Verbose ("Client secret accepted: value={0}; submitting to token endpoint" -f (Get-TTMaskedValue -Value $secret))
        Invoke-TTTokenEndpoint -TenantId $TenantId -Body @{
            client_id = $ClientId; client_secret = $secret; scope = $Scope; grant_type = 'client_credentials'
        }
    } finally {
        $secret = $null
        Write-Verbose 'Client secret cleared from the working variable.'
    }
}

function Get-EntraIDTokenOnBehalfOf {
    [CmdletBinding(DefaultParameterSetName = 'PlaintextSecret')]
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true)][string]$UserAssertion,
        [Parameter(Mandatory = $true)][string]$Scope,
        [Parameter(Mandatory = $true, ParameterSetName = 'PlaintextSecret')][string]$ClientSecret,
        [Parameter(Mandatory = $true, ParameterSetName = 'SecureStringSecret')][securestring]$ClientSecretSecureString,
        [Parameter(Mandatory = $true, ParameterSetName = 'CertificateStore')][string]$CertificateThumbprint,
        [Parameter(ParameterSetName = 'CertificateStore')][ValidateSet('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')][string]$CertStoreLocation = 'Cert:\CurrentUser\My',
        [Parameter(Mandatory = $true, ParameterSetName = 'PfxPlaintext')]
        [Parameter(Mandatory = $true, ParameterSetName = 'PfxSecureString')]
        [string]$PfxPath,
        [Parameter(ParameterSetName = 'PfxPlaintext')][string]$PfxPassword,
        [Parameter(Mandatory = $true, ParameterSetName = 'PfxSecureString')][securestring]$PfxPasswordSecureString
    )
    Write-Verbose ("Starting on-behalf-of flow: tenant={0}; client_id={1}; scope={2}; credential_input={3}; user_assertion={4}" -f $TenantId, $ClientId, $Scope, $PSCmdlet.ParameterSetName, (Get-TTMaskedValue -Value $UserAssertion))
    $claims = ConvertFrom-JWTtoken -token $UserAssertion
    Write-Verbose ("Decoded user assertion claims: audience={0}" -f (@($claims.aud) -join ', '))
    if (@($claims.aud) -notcontains $ClientId) { throw 'UserAssertion must be an access token issued to the requesting middle-tier ClientId.' }
    Write-Verbose 'User assertion audience matches the middle-tier client ID.'
    $body = @{ client_id = $ClientId; scope = $Scope; grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer'; assertion = $UserAssertion; requested_token_use = 'on_behalf_of' }
    $certificate = $null
    $secret = $null
    try {
        if ($PSCmdlet.ParameterSetName -like '*Secret') {
            $secret = if ($PSCmdlet.ParameterSetName -eq 'SecureStringSecret') { ConvertFrom-TTSecureValue $ClientSecretSecureString } else { $ClientSecret }
            $body.client_secret = $secret
            Write-Verbose ("Using client secret credential: value={0}" -f (Get-TTMaskedValue -Value $secret))
        } else {
            if ($PSCmdlet.ParameterSetName -eq 'CertificateStore') { $certificate = Get-TTCertificate -CertificateThumbprint $CertificateThumbprint -CertStoreLocation $CertStoreLocation }
            elseif ($PSCmdlet.ParameterSetName -eq 'PfxPlaintext') { $certificate = Get-TTCertificate -PfxPath $PfxPath -PfxPassword $PfxPassword }
            else { $certificate = Get-TTCertificate -PfxPath $PfxPath -PfxPassword $PfxPasswordSecureString }
            Write-Verbose 'Using certificate credential to create a client assertion.'
            $body.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            $body.client_assertion = New-TTClientCertificateAssertion -TenantId $TenantId -ClientId $ClientId -Certificate $certificate
            Write-Verbose ("Client certificate assertion created: value={0}" -f (Get-TTMaskedValue -Value $body.client_assertion))
        }
        Invoke-TTTokenEndpoint -TenantId $TenantId -Body $body
    } finally {
        Remove-TTCertificate -Certificate $certificate
        $secret = $null
        Write-Verbose 'On-behalf-of credential material cleared and certificate disposed.'
    }
}

function Get-EntraIDTokenFromFederatedCredential {
    [CmdletBinding(DefaultParameterSetName = 'PlaintextToken')]
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true, ParameterSetName = 'PlaintextToken')][string]$FederatedToken,
        [Parameter(Mandatory = $true, ParameterSetName = 'SecureStringToken')][securestring]$FederatedTokenSecureString,
        [Parameter(Mandatory = $true, ParameterSetName = 'TokenFile')][string]$FederatedTokenPath,
        [string]$Scope = 'https://graph.microsoft.com/.default'
    )
    Write-Verbose ("Starting federated-credential flow: tenant={0}; client_id={1}; scope={2}; assertion_input={3}" -f $TenantId, $ClientId, $Scope, $PSCmdlet.ParameterSetName)
    Assert-TTDefaultScope -Scope $Scope
    $assertion = switch ($PSCmdlet.ParameterSetName) {
        'SecureStringToken' { ConvertFrom-TTSecureValue $FederatedTokenSecureString; break }
        'TokenFile' {
            if (-not (Test-Path -LiteralPath $FederatedTokenPath -PathType Leaf)) { throw "Federated token file '$FederatedTokenPath' was not found." }
            Write-Verbose ("Reading federated assertion from file: path={0}" -f $FederatedTokenPath)
            (Get-Content -LiteralPath $FederatedTokenPath -Raw).Trim(); break
        }
        default { $FederatedToken }
    }
    try {
        Write-Verbose ("Federated assertion accepted: value={0}; submitting exchange" -f (Get-TTMaskedValue -Value $assertion))
        Invoke-TTTokenEndpoint -TenantId $TenantId -Body @{
            client_id = $ClientId; scope = $Scope; grant_type = 'client_credentials'
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'; client_assertion = $assertion
        }
    } finally {
        $assertion = $null
        Write-Verbose 'Federated assertion cleared from the working variable.'
    }
}

function Get-EntraIDTokenFromGitHubActions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [string]$Scope = 'https://graph.microsoft.com/.default',
        [string]$Audience = 'api://AzureADTokenExchange'
    )
    Write-Verbose ("Starting GitHub Actions OIDC flow: tenant={0}; client_id={1}; scope={2}; audience={3}" -f $TenantId, $ClientId, $Scope, $Audience)
    if ([string]::IsNullOrWhiteSpace($env:ACTIONS_ID_TOKEN_REQUEST_URL) -or [string]::IsNullOrWhiteSpace($env:ACTIONS_ID_TOKEN_REQUEST_TOKEN)) {
        throw 'GitHub Actions OIDC environment variables are unavailable. Run this command in a workflow with id-token: write permission.'
    }
    $separator = if ($env:ACTIONS_ID_TOKEN_REQUEST_URL.Contains('?')) { '&' } else { '?' }
    $uri = "$($env:ACTIONS_ID_TOKEN_REQUEST_URL)$separator" + 'audience=' + [Uri]::EscapeDataString($Audience)
    $githubEndpoint = [Uri]$uri
    Write-Verbose ("Requesting GitHub OIDC assertion: endpoint={0}{1}; runtime bearer token={2}" -f $githubEndpoint.Host, $githubEndpoint.AbsolutePath, (Get-TTMaskedValue -Value $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN))
    $githubResponse = Invoke-RestMethod -UseBasicParsing -Method Get -Uri $uri -Headers @{ Authorization = "Bearer $($env:ACTIONS_ID_TOKEN_REQUEST_TOKEN)" } -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($githubResponse.value)) { throw 'GitHub Actions did not return an OIDC token.' }
    Write-Verbose ("GitHub OIDC assertion received: value={0}; exchanging with Entra" -f (Get-TTMaskedValue -Value $githubResponse.value))
    Get-EntraIDTokenFromFederatedCredential -TenantId $TenantId -ClientId $ClientId -FederatedToken $githubResponse.value -Scope $Scope
}

function Get-EntraIDTokenFromAzureArcManagedIdentity {
    [CmdletBinding()]
    param(
        [string]$Resource = 'https://management.azure.com/',
        [string]$ApiVersion = '2020-06-01'
    )
    Write-Verbose ("Starting Azure Arc managed-identity flow: resource={0}; api_version={1}" -f $Resource, $ApiVersion)
    if ([string]::IsNullOrWhiteSpace($env:IDENTITY_ENDPOINT)) { throw 'IDENTITY_ENDPOINT is not set. This command must run on an Azure Arc-enabled machine with a managed identity.' }
    $endpoint = [Uri]$env:IDENTITY_ENDPOINT
    if ($endpoint.Host -notin @('localhost', '127.0.0.1', '::1')) { throw 'IDENTITY_ENDPOINT must be a loopback endpoint.' }
    Write-Verbose ("Using loopback identity endpoint: host={0}; port={1}; path={2}" -f $endpoint.Host, $endpoint.Port, $endpoint.AbsolutePath)
    $separator = if ($env:IDENTITY_ENDPOINT.Contains('?')) { '&' } else { '?' }
    $uri = "$($env:IDENTITY_ENDPOINT)$separator" + "resource=$([Uri]::EscapeDataString($Resource))&api-version=$([Uri]::EscapeDataString($ApiVersion))"
    $headers = @{ Metadata = 'True' }
    try {
        Write-Verbose 'Sending the initial Azure Arc managed-identity request with Metadata=True.'
        $identityResponse = Invoke-RestMethod -UseBasicParsing -Method Get -Uri $uri -Headers $headers -ErrorAction Stop
        Write-Verbose ("Azure Arc identity response received: {0}" -f (Get-TTResponseSummary -Response $identityResponse))
        return $identityResponse
    }
    catch {
        $challenge = $_.Exception.Response.Headers['WWW-Authenticate']
        if ([string]::IsNullOrWhiteSpace($challenge) -or $challenge -notmatch 'Basic realm=(.+)$') { throw "Azure Arc managed identity request failed: $($_.Exception.Message)" }
        $secretFile = $Matches[1].Trim('"')
        if (-not (Test-Path -LiteralPath $secretFile -PathType Leaf)) { throw 'Azure Arc returned an inaccessible challenge secret file.' }
        Write-Verbose ("Azure Arc requested Basic authentication; reading challenge secret file: path={0}" -f $secretFile)
        $secret = (Get-Content -LiteralPath $secretFile -Raw).Trim()
        try {
            $headers.Authorization = "Basic $secret"
            Write-Verbose ("Retrying Azure Arc request with challenge secret: value={0}" -f (Get-TTMaskedValue -Value $secret))
            $identityResponse = Invoke-RestMethod -UseBasicParsing -Method Get -Uri $uri -Headers $headers -ErrorAction Stop
            Write-Verbose ("Azure Arc identity response received: {0}" -f (Get-TTResponseSummary -Response $identityResponse))
            return $identityResponse
        } finally {
            $secret = $null
            Write-Verbose 'Azure Arc challenge secret cleared from the working variable.'
        }
    }
}

function New-EntraIDImplicitAuthorizationUrl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true)][string]$RedirectUri,
        [Parameter(Mandatory = $true)][string]$Scope,
        [string]$State,
        [switch]$IncludeIdToken
    )
    $stateWasProvided = -not [string]::IsNullOrWhiteSpace($State)
    if (-not $stateWasProvided) { $State = [guid]::NewGuid().ToString('N') }
    $responseType = if ($IncludeIdToken) { 'token id_token' } else { 'token' }
    $stateSource = if ($stateWasProvided) { 'provided' } else { 'generated' }
    $maskedState = Get-TTMaskedValue -Value $State
    Write-Verbose ("Building implicit authorization request: tenant={0}; client_id={1}; redirect_uri={2}; scope={3}; response_type={4}; state_source={5}; state={6}" -f $TenantId, $ClientId, $RedirectUri, $Scope, $responseType, $stateSource, $maskedState)
    $parts = [ordered]@{ client_id = $ClientId; response_type = $responseType; redirect_uri = $RedirectUri; response_mode = 'fragment'; scope = $Scope; state = $State }
    if ($IncludeIdToken -and $Scope -notmatch '(^|\s)openid(\s|$)') {
        $parts.scope = "$Scope openid"
        $parts.nonce = [guid]::NewGuid().ToString('N')
        Write-Verbose 'Added openid scope and generated a nonce because IncludeIdToken was requested.'
    }
    $query = @($parts.GetEnumerator() | ForEach-Object { "$($_.Key)=$([Uri]::EscapeDataString([string]$_.Value))" }) -join '&'
    Write-Verbose ("Implicit authorization URL built: authority=login.microsoftonline.com; path=/oauth2/v2.0/authorize; query_parameters={0}; state={1}" -f (($parts.Keys -join ',') , (Get-TTMaskedValue -Value $State)))
    [pscustomobject]@{ AuthorizationUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?$query"; State = $State }
}

function ConvertFrom-EntraIDImplicitRedirect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RedirectUrl,
        [Parameter(Mandatory = $true)][string]$ExpectedState
    )
    $uri = [Uri]$RedirectUrl
    $fragment = $uri.Fragment.TrimStart('#')
    if ([string]::IsNullOrWhiteSpace($fragment)) { throw 'The redirect URL does not contain an implicit-flow response fragment.' }
    Write-Verbose ("Parsing implicit redirect: host={0}; path={1}; fragment_length={2}; expected_state={3}" -f $uri.Host, $uri.AbsolutePath, $fragment.Length, (Get-TTMaskedValue -Value $ExpectedState))
    $values = @{}
    foreach ($part in $fragment -split '&') {
        $pair = $part -split '=', 2
        $values[[Uri]::UnescapeDataString($pair[0])] = if ($pair.Count -gt 1) { [Uri]::UnescapeDataString($pair[1]) } else { '' }
    }
    Write-Verbose ("Implicit redirect parameters parsed: names={0}" -f (($values.Keys | Sort-Object) -join ', '))
    if ($values.state -cne $ExpectedState) { throw 'The implicit-flow state value did not match the expected value.' }
    Write-Verbose 'Implicit redirect state matches the expected value.'
    $result = [pscustomobject]@{
        AccessToken = $values.access_token; IdToken = $values.id_token; TokenType = $values.token_type; ExpiresIn = $values.expires_in
        Scope = $values.scope; State = $values.state; Error = $values.error; ErrorDescription = $values.error_description
    }
    Write-Verbose ("Implicit redirect result: {0}" -f (Get-TTResponseSummary -Response $result))
    $result
}

function New-TTFederatedSigningCertificate {
    [CmdletBinding(DefaultParameterSetName = 'PlaintextPassword')]
    param(
        [Parameter(Mandatory = $true)][string]$PfxPath,
        [Parameter(Mandatory = $true, ParameterSetName = 'PlaintextPassword')][string]$PfxPassword,
        [Parameter(Mandatory = $true, ParameterSetName = 'SecureStringPassword')][securestring]$PfxPasswordSecureString,
        [string]$Subject = 'CN=TokenTactics Federated Issuer',
        [ValidateSet(2048, 3072, 4096)][int]$KeyLength = 2048,
        [datetime]$NotAfter = (Get-Date).AddYears(1),
        [string]$PublicCertificatePath
    )
    Write-Verbose ("Creating federated signing certificate: pfx_path={0}; public_certificate_path={1}; subject={2}; key_length={3}; not_after={4}; password_input={5}" -f $PfxPath, $PublicCertificatePath, $Subject, $KeyLength, $NotAfter.ToUniversalTime().ToString('o'), $PSCmdlet.ParameterSetName)
    if ($NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) { throw 'NotAfter must be in the future.' }
    $parent = Split-Path -Parent $PfxPath
    if ($parent) { [IO.Directory]::CreateDirectory($parent) | Out-Null }
    $publicParent = if ($PublicCertificatePath) { Split-Path -Parent $PublicCertificatePath } else { $null }
    if ($publicParent) { [IO.Directory]::CreateDirectory($publicParent) | Out-Null }
    $password = if ($PSCmdlet.ParameterSetName -eq 'SecureStringPassword') { ConvertFrom-TTSecureValue $PfxPasswordSecureString } else { $PfxPassword }
    $certificate = $null
    $rsa = [System.Security.Cryptography.RSA]::Create($KeyLength)
    try {
        try {
            if ($IsMacOS) { throw 'Use the OpenSSL fallback on macOS.' }
            Write-Verbose 'Generating the self-signed certificate with the .NET certificate provider.'
            $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($Subject, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $false))
            $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]$NotAfter)
            [IO.File]::WriteAllBytes($PfxPath, $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password))
            if ($PublicCertificatePath) { [IO.File]::WriteAllBytes($PublicCertificatePath, $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)) }
        } catch {
            # Some macOS/Linux crypto providers cannot create self-signed certificates
            # through CertificateRequest. Fall back to OpenSSL when it is available.
            if ($certificate) { $certificate.Dispose(); $certificate = $null }
            $openssl = Get-Command openssl -ErrorAction SilentlyContinue
            if ($null -eq $openssl) { throw "Unable to create a self-signed PFX with .NET and OpenSSL is unavailable. $($_.Exception.Message)" }
            Write-Verbose 'The .NET certificate provider could not create the certificate; using the OpenSSL fallback.'
            $temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ("tokentactics-pfx-" + [guid]::NewGuid().ToString('N'))
            $temporaryKey = Join-Path $temporaryDirectory 'key.pem'
            $temporaryCertificate = Join-Path $temporaryDirectory 'certificate.pem'
            [IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null
            $opensslSubject = '/' + ($Subject -replace ',', '/' -replace '^CN=', 'CN=')
            $days = [Math]::Max(1, [Math]::Ceiling(($NotAfter.ToUniversalTime() - [DateTime]::UtcNow).TotalDays))
            $previousPassword = $env:TT_OAUTH_PFX_PASSWORD
            $env:TT_OAUTH_PFX_PASSWORD = $password
            try {
                & $openssl.Source req -x509 -newkey "rsa:$KeyLength" -keyout $temporaryKey -out $temporaryCertificate -days $days -nodes -subj $opensslSubject 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'OpenSSL failed to create the signing certificate.' }
                & $openssl.Source pkcs12 -export -out $PfxPath -inkey $temporaryKey -in $temporaryCertificate -passout env:TT_OAUTH_PFX_PASSWORD 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'OpenSSL failed to create the PFX.' }
                if ($PublicCertificatePath) {
                    & $openssl.Source x509 -in $temporaryCertificate -out $PublicCertificatePath -outform DER 2>&1 | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw 'OpenSSL failed to export the public certificate.' }
                }
                $certificate = Get-TTOpenSslPfxMaterial -PfxPath $PfxPath -Password $password
            } finally {
                $env:TT_OAUTH_PFX_PASSWORD = $previousPassword
                if (Test-Path -LiteralPath $temporaryDirectory) { Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force }
            }
        }
        if ($certificate.PSObject.Properties['TTOpenSslMaterial'] -and $certificate.TTOpenSslMaterial) {
            $sha1 = [System.Security.Cryptography.SHA1]::Create()
            try { $thumbprint = ([BitConverter]::ToString($sha1.ComputeHash($certificate.RawData))).Replace('-', '') } finally { $sha1.Dispose() }
            $certificateNotAfter = $NotAfter
        } else {
            $thumbprint = $certificate.Thumbprint
            $certificateNotAfter = $certificate.NotAfter
        }
        Write-Verbose ("Federated signing certificate created: thumbprint={0}; pfx_path={1}; public_certificate_path={2}; not_after={3}" -f $thumbprint, $PfxPath, $PublicCertificatePath, $certificateNotAfter.ToUniversalTime().ToString('o'))
        [pscustomobject]@{ Thumbprint = $thumbprint; PfxPath = $PfxPath; PublicCertificatePath = $PublicCertificatePath; NotAfter = $certificateNotAfter }
    } finally {
        Remove-TTCertificate -Certificate $certificate
        $rsa.Dispose()
        $password = $null
        Write-Verbose 'Federated signing certificate password cleared and temporary certificate material disposed.'
    }
}

function New-TTFederatedIssuerMetadata {
    [CmdletBinding(DefaultParameterSetName = 'PfxPlaintext')]
    param(
        [Parameter(Mandatory = $true)][Uri]$Issuer,
        [Parameter(Mandatory = $true)][string]$Subject,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [string]$Audience = 'api://AzureADTokenExchange',
        [Parameter(Mandatory = $true, ParameterSetName = 'CertificateStore')][string]$CertificateThumbprint,
        [Parameter(ParameterSetName = 'CertificateStore')][ValidateSet('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')][string]$CertStoreLocation = 'Cert:\CurrentUser\My',
        [Parameter(Mandatory = $true, ParameterSetName = 'PfxPlaintext')]
        [Parameter(Mandatory = $true, ParameterSetName = 'PfxSecureString')]
        [string]$PfxPath,
        [Parameter(ParameterSetName = 'PfxPlaintext')][string]$PfxPassword,
        [Parameter(Mandatory = $true, ParameterSetName = 'PfxSecureString')][securestring]$PfxPasswordSecureString
    )
    Write-Verbose ("Generating federated issuer metadata: issuer={0}; subject={1}; audience={2}; output_path={3}; certificate_input={4}" -f $Issuer.AbsoluteUri, $Subject, $Audience, $OutputPath, $PSCmdlet.ParameterSetName)
    if ($Issuer.Scheme -ne 'https') { throw 'Issuer must be an HTTPS URL.' }
    if ([string]::IsNullOrWhiteSpace($OutputPath)) { throw 'OutputPath must not be empty.' }
    # Resolve through PowerShell's provider path so a relative path follows the
    # caller's Get-Location, not a potentially stale process working directory.
    $outputDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    Write-Verbose ("Resolved metadata output directory: path={0}" -f $outputDirectory)
    $certificate = $null
    try {
        if ($PSCmdlet.ParameterSetName -eq 'CertificateStore') { $certificate = Get-TTCertificate -CertificateThumbprint $CertificateThumbprint -CertStoreLocation $CertStoreLocation }
        elseif ($PSCmdlet.ParameterSetName -eq 'PfxSecureString') { $certificate = Get-TTCertificate -PfxPath $PfxPath -PfxPassword $PfxPasswordSecureString }
        else { $certificate = Get-TTCertificate -PfxPath $PfxPath -PfxPassword $PfxPassword }
        Write-Verbose 'Loaded the signing certificate and exporting its public RSA key to JWK form.'
        if ($certificate.PSObject.Properties['TTOpenSslMaterial'] -and $certificate.TTOpenSslMaterial) {
            $rsa = [System.Security.Cryptography.RSA]::Create()
            $rsa.ImportFromPem($certificate.PublicKeyPem)
        } else {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
        }
        if ($null -eq $rsa) { throw 'The selected certificate does not expose an RSA public key.' }
        try {
            $parameters = $rsa.ExportParameters($false)
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            try { $kid = ConvertTo-Base64Url -Bytes ($sha256.ComputeHash($certificate.RawData)) } finally { $sha256.Dispose() }
            $issuerText = $Issuer.AbsoluteUri.TrimEnd('/')
            $jwk = [ordered]@{ kty = 'RSA'; use = 'sig'; alg = 'RS256'; kid = $kid; n = ConvertTo-Base64Url -Bytes $parameters.Modulus; e = ConvertTo-Base64Url -Bytes $parameters.Exponent; x5c = @([Convert]::ToBase64String($certificate.RawData)) }
            $discovery = [ordered]@{
                issuer = $issuerText
                jwks_uri = "$issuerText/keys.json"
                response_types_supported = @('id_token')
                subject_types_supported = @('public')
                id_token_signing_alg_values_supported = @('RS256')
            }
            $wellKnown = Join-Path $outputDirectory '.well-known'
            [IO.Directory]::CreateDirectory($wellKnown) | Out-Null
            $discoveryPath = Join-Path $wellKnown 'openid-configuration'
            $jwksPath = Join-Path $outputDirectory 'keys.json'
            $configurationPath = Join-Path $outputDirectory 'issuer-config.json'
            [IO.File]::WriteAllText($discoveryPath, ($discovery | ConvertTo-Json -Depth 5), [Text.Encoding]::UTF8)
            [IO.File]::WriteAllText($jwksPath, (@{ keys = @($jwk) } | ConvertTo-Json -Depth 8), [Text.Encoding]::UTF8)
            [IO.File]::WriteAllText($configurationPath, ([ordered]@{ issuer = $issuerText; subject = $Subject; audience = $Audience; kid = $kid } | ConvertTo-Json), [Text.Encoding]::UTF8)
            Write-Verbose ("Generated issuer metadata files: discovery={0}; jwks={1}; configuration={2}" -f $discoveryPath, $jwksPath, $configurationPath)
            [pscustomobject]@{
                Issuer = $issuerText
                Subject = $Subject
                Audience = $Audience
                KeyId = $kid
                OutputPath = $outputDirectory
                DiscoveryPath = $discoveryPath
                JwksPath = $jwksPath
                ConfigurationPath = $configurationPath
                GeneratedFiles = @($discoveryPath, $jwksPath, $configurationPath)
            }
        } finally { $rsa.Dispose() }
    } finally {
        Remove-TTCertificate -Certificate $certificate
        Write-Verbose 'Issuer metadata certificate material disposed.'
    }
}

function New-TTFederatedClientAssertion {
    [CmdletBinding(DefaultParameterSetName = 'PfxPlaintext')]
    param(
        [Parameter(Mandatory = $true)][Uri]$Issuer,
        [Parameter(Mandatory = $true)][string]$Subject,
        [string]$Audience = 'api://AzureADTokenExchange',
        [ValidateRange(1, 10)][int]$LifetimeMinutes = 5,
        [Parameter(Mandatory = $true, ParameterSetName = 'CertificateStore')][string]$CertificateThumbprint,
        [Parameter(ParameterSetName = 'CertificateStore')][ValidateSet('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')][string]$CertStoreLocation = 'Cert:\CurrentUser\My',
        [Parameter(Mandatory = $true, ParameterSetName = 'PfxPlaintext')]
        [Parameter(Mandatory = $true, ParameterSetName = 'PfxSecureString')]
        [string]$PfxPath,
        [Parameter(ParameterSetName = 'PfxPlaintext')][string]$PfxPassword,
        [Parameter(Mandatory = $true, ParameterSetName = 'PfxSecureString')][securestring]$PfxPasswordSecureString
    )
    Write-Verbose ("Creating federated client assertion: issuer={0}; subject={1}; audience={2}; lifetime_minutes={3}; certificate_input={4}" -f $Issuer.AbsoluteUri, $Subject, $Audience, $LifetimeMinutes, $PSCmdlet.ParameterSetName)
    if ($Issuer.Scheme -ne 'https') { throw 'Issuer must be an HTTPS URL.' }
    $certificate = $null
    try {
        if ($PSCmdlet.ParameterSetName -eq 'CertificateStore') { $certificate = Get-TTCertificate -CertificateThumbprint $CertificateThumbprint -CertStoreLocation $CertStoreLocation }
        elseif ($PSCmdlet.ParameterSetName -eq 'PfxSecureString') { $certificate = Get-TTCertificate -PfxPath $PfxPath -PfxPassword $PfxPasswordSecureString }
        else { $certificate = Get-TTCertificate -PfxPath $PfxPath -PfxPassword $PfxPassword }
        $now = [DateTimeOffset]::UtcNow
        $payload = [ordered]@{
            iss = $Issuer.AbsoluteUri.TrimEnd('/'); sub = $Subject; aud = $Audience; iat = $now.ToUnixTimeSeconds()
            nbf = $now.ToUnixTimeSeconds(); exp = $now.AddMinutes($LifetimeMinutes).ToUnixTimeSeconds(); jti = [guid]::NewGuid().ToString()
        }
        Write-Verbose ("Signing assertion with time window: not_before={0}; expires={1}" -f $payload.nbf, $payload.exp)
        $assertion = New-TTRsaJwt -Certificate $certificate -Payload $payload
        Write-Verbose ("Federated client assertion created: value={0}" -f (Get-TTMaskedValue -Value $assertion))
        $assertion
    } finally {
        Remove-TTCertificate -Certificate $certificate
        Write-Verbose 'Client assertion certificate material disposed.'
    }
}
