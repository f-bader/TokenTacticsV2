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

function ConvertFrom-TTHttpJsonResponse {
    param([AllowNull()][object]$Response)
    if ($null -eq $Response) { return $null }
    if (-not $Response.PSObject.Properties['Content']) { return $Response }
    $content = [string]$Response.Content
    if ([string]::IsNullOrWhiteSpace($content)) { return $null }
    try { return ConvertFrom-Json -InputObject $content -ErrorAction Stop }
    catch { return $content }
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
        # The service response body carries the Entra error code and description and
        # never contains the submitted credentials, so surface it for troubleshooting.
        $message = "Entra token request failed: $($_.Exception.Message)"
        $detail = $_.ErrorDetails.Message
        if (-not [string]::IsNullOrWhiteSpace($detail)) { $message += " Response: $detail" }
        throw $message
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
    # The extracted private key is unencrypted; keep the directory owner-only.
    if ($env:OS -ne 'Windows_NT') { & chmod 700 $temporaryDirectory | Out-Null }
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
        # Resolve through PowerShell's provider location before validation and
        # filesystem/external-process access. .NET and OpenSSL use the process
        # working directory for relative paths, which may differ from the
        # caller's PowerShell location.
        $PfxPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PfxPath)
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
    if ($Certificate.PSObject.Properties['TTOpenSslMaterial'] -and $Certificate.TTOpenSslMaterial) {
        if (-not (Test-Path -LiteralPath $Certificate.PrivateKeyPath -PathType Leaf)) { throw 'The extracted private key is not accessible.' }
        $publicCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Certificate.RawData)
        try {
            $now = [DateTimeOffset]::UtcNow
            if ($publicCertificate.NotBefore.ToUniversalTime() -gt $now.UtcDateTime -or $publicCertificate.NotAfter.ToUniversalTime() -lt $now.UtcDateTime) {
                throw 'The selected certificate is not currently valid.'
            }
        } finally { $publicCertificate.Dispose() }
        return
    }
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
    # Emit the RFC 7515 key id so relying parties can select the key from the JWKS
    # (and so key rollover with multiple published keys keeps working). It matches
    # the JWK 'kid'; x5t#S256 is retained for Entra certificate credentials.
    $header = [ordered]@{ alg = $Algorithm; typ = 'JWT'; kid = $kid; 'x5t#S256' = $kid }
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
    <#
    .SYNOPSIS
        Acquires an Entra ID application token with a client secret.

    .DESCRIPTION
        Requests an app-only access token through the OAuth 2.0 client credentials
        grant. The scope must name exactly one resource with the '/.default' suffix.
        Verbose diagnostics redact the secret and the returned tokens.

    .PARAMETER TenantId
        The Microsoft Entra tenant ID or domain.

    .PARAMETER ClientId
        The application (client) ID registered in Microsoft Entra ID.

    .PARAMETER ClientSecret
        The plaintext client-secret value.

    .PARAMETER ClientSecretSecureString
        The client secret as a SecureString.

    .PARAMETER Scope
        The application permission scope to request. Must use the .default suffix.
        Defaults to 'https://graph.microsoft.com/.default'.

    .EXAMPLE
        Get-EntraIDTokenFromClientSecret -TenantId 'contoso.onmicrosoft.com' -ClientId '00000000-0000-0000-0000-000000000000' -ClientSecret 'secret-value'

    .NOTES
        Treat the client secret as a credential. Prefer SecureString input or a
        federated credential for automation.
    #>
    [CmdletBinding(DefaultParameterSetName = 'PlaintextSecret')]
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true, ParameterSetName = 'PlaintextSecret')][string]$ClientSecret,
        [Parameter(Mandatory = $true, ParameterSetName = 'SecureStringSecret')][securestring]$ClientSecretSecureString,
        [string]$Scope
    )
    if ([string]::IsNullOrWhiteSpace($Scope)) { $Scope = Get-TTEntraOAuthDefaultScope -Client MSGraph }
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
    <#
    .SYNOPSIS
        Exchanges a user access token for a downstream API token (on-behalf-of).

    .DESCRIPTION
        Performs the OAuth 2.0 on-behalf-of grant: a middle-tier API exchanges an
        incoming user access token whose audience is the middle-tier client ID for a
        delegated downstream token. The middle tier authenticates with a client
        secret or an RSA certificate (Windows store or PFX).

    .PARAMETER TenantId
        The Microsoft Entra tenant ID or domain.

    .PARAMETER ClientId
        The application (client) ID of the middle-tier API.

    .PARAMETER UserAssertion
        The incoming user access token issued to the middle-tier application.

    .PARAMETER Scope
        Space-delimited delegated scopes for the downstream API.

    .PARAMETER ClientSecret
        The plaintext middle-tier client-secret value.

    .PARAMETER ClientSecretSecureString
        The middle-tier client secret as a SecureString.

    .PARAMETER CertificateThumbprint
        Thumbprint of an RSA certificate in a Windows certificate store.

    .PARAMETER CertStoreLocation
        The personal certificate store containing the certificate.

    .PARAMETER PfxPath
        Path to a PFX containing an accessible RSA private key.

    .PARAMETER PfxPassword
        Plaintext PFX password.

    .PARAMETER PfxPasswordSecureString
        PFX password as a SecureString.

    .EXAMPLE
        Get-EntraIDTokenOnBehalfOf -TenantId 'contoso.onmicrosoft.com' -ClientId $middleTierId -ClientSecret $secret -UserAssertion $incomingToken -Scope 'https://graph.microsoft.com/User.Read'

    .NOTES
        The user assertion, client secret, and certificate assertion are credentials;
        keep them out of logs, transcripts, and source control.
    #>
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
    <#
    .SYNOPSIS
        Exchanges an external OIDC JWT for an Entra ID application token.

    .DESCRIPTION
        Sends an externally issued JWT as a client assertion through the OAuth 2.0
        client credentials grant. An Entra federated identity credential whose
        issuer, subject, and audience exactly match the JWT must exist on the app
        registration. The scope must name one resource with the '/.default' suffix.

    .PARAMETER TenantId
        The Microsoft Entra tenant ID or domain.

    .PARAMETER ClientId
        The application (client) ID configured with the federated credential.

    .PARAMETER FederatedToken
        The plaintext external JWT.

    .PARAMETER FederatedTokenSecureString
        The external JWT as a SecureString.

    .PARAMETER FederatedTokenPath
        Path to a file containing the external JWT.

    .PARAMETER Scope
        The application permission scope to request. Must use the .default suffix.
        Defaults to 'https://graph.microsoft.com/.default'.

    .EXAMPLE
        Get-EntraIDTokenFromFederatedCredential -TenantId 'contoso.onmicrosoft.com' -ClientId $clientId -FederatedToken $externalJwt -Scope 'https://management.azure.com/.default'

    .NOTES
        The external JWT is exchangeable while valid; do not log or commit it.
    #>
    [CmdletBinding(DefaultParameterSetName = 'PlaintextToken')]
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true, ParameterSetName = 'PlaintextToken')][string]$FederatedToken,
        [Parameter(Mandatory = $true, ParameterSetName = 'SecureStringToken')][securestring]$FederatedTokenSecureString,
        [Parameter(Mandatory = $true, ParameterSetName = 'TokenFile')][string]$FederatedTokenPath,
        [string]$Scope
    )
    if ([string]::IsNullOrWhiteSpace($Scope)) { $Scope = Get-TTEntraOAuthDefaultScope -Client MSGraph }
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
    <#
    .SYNOPSIS
        Acquires an Entra ID application token inside a GitHub Actions workflow.

    .DESCRIPTION
        Requests an OIDC token from the GitHub Actions runtime and exchanges it for
        an Entra application access token through workload identity federation. The
        job must run with 'id-token: write' permission and the app registration must
        trust the repository, ref, or environment via a federated credential.

    .PARAMETER TenantId
        The Microsoft Entra tenant ID or domain.

    .PARAMETER ClientId
        The application (client) ID configured with the GitHub federated credential.

    .PARAMETER Scope
        The application permission scope to request. Must use the .default suffix.
        Defaults to 'https://graph.microsoft.com/.default'.

    .PARAMETER Audience
        The audience requested from GitHub's OIDC endpoint. Defaults to
        'api://AzureADTokenExchange' and must match the federated credential.

    .EXAMPLE
        Get-EntraIDTokenFromGitHubActions -TenantId $env:AZURE_TENANT_ID -ClientId $env:AZURE_CLIENT_ID -Scope 'https://management.azure.com/.default'

    .NOTES
        Only runs where ACTIONS_ID_TOKEN_REQUEST_URL and
        ACTIONS_ID_TOKEN_REQUEST_TOKEN are present.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [string]$Scope,
        [string]$Audience = 'api://AzureADTokenExchange'
    )
    if ([string]::IsNullOrWhiteSpace($Scope)) { $Scope = Get-TTEntraOAuthDefaultScope -Client MSGraph }
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
    <#
    .SYNOPSIS
        Acquires a token from an Azure Arc-enabled machine's managed identity.

    .DESCRIPTION
        Requests a resource token from the local Azure Arc identity endpoint,
        completing the endpoint's challenge-file protocol: the initial request
        receives a 401 with a WWW-Authenticate challenge naming a local secret file,
        whose content authorizes the retry. The endpoint must be a loopback address.

    .PARAMETER Resource
        The Azure resource URI to request a token for. Defaults to
        'https://management.azure.com/'.

    .PARAMETER ApiVersion
        The Arc managed-identity endpoint API version. Defaults to '2020-06-01'.

    .EXAMPLE
        Get-EntraIDTokenFromAzureArcManagedIdentity -Resource 'https://management.azure.com/'

    .NOTES
        Only runs on Azure Arc-enabled Windows or Linux servers where
        IDENTITY_ENDPOINT is present. The challenge secret is never returned or
        persisted.
    #>
    [CmdletBinding()]
    param(
        [string]$Resource = 'https://management.azure.com/',
        [string]$ApiVersion = '2020-06-01'
    )
    Write-Verbose ("Starting Azure Arc managed-identity flow: resource={0}; api_version={1}" -f $Resource, $ApiVersion)
    if ([string]::IsNullOrWhiteSpace($env:IDENTITY_ENDPOINT)) { throw 'IDENTITY_ENDPOINT is not set. This command must run on an Azure Arc-enabled machine with a managed identity.' }
    $endpoint = [Uri]$env:IDENTITY_ENDPOINT
    if ($endpoint.DnsSafeHost -notin @('localhost', '127.0.0.1', '::1')) { throw 'IDENTITY_ENDPOINT must be a loopback endpoint.' }
    Write-Verbose ("Using loopback identity endpoint: host={0}; port={1}; path={2}" -f $endpoint.Host, $endpoint.Port, $endpoint.AbsolutePath)
    $separator = if ($env:IDENTITY_ENDPOINT.Contains('?')) { '&' } else { '?' }
    $uri = "$($env:IDENTITY_ENDPOINT)$separator" + "resource=$([Uri]::EscapeDataString($Resource))&api-version=$([Uri]::EscapeDataString($ApiVersion))"
    $headers = @{ Metadata = 'True' }
    try {
        Write-Verbose 'Sending the initial Azure Arc managed-identity request with Metadata=True.'
        # Arc deliberately responds with HTTP 401 and a WWW-Authenticate challenge
        # before a caller can read the challenge file and retry. Invoke-RestMethod's
        # exception response does not expose that header consistently across PS7/.NET
        # versions, so capture the non-success response explicitly.
        $initialResponse = Invoke-WebRequest -UseBasicParsing -Method Get -Uri $uri -Headers $headers -SkipHttpErrorCheck -ErrorAction Stop
    }
    catch {
        throw "Azure Arc managed identity request failed: $($_.Exception.Message)"
    }

    $statusCode = [int]$initialResponse.StatusCode
    Write-Verbose ("Azure Arc initial response received: status={0}" -f $statusCode)
    if ($statusCode -ge 200 -and $statusCode -lt 300) {
        $identityResponse = ConvertFrom-TTHttpJsonResponse -Response $initialResponse
        if ($null -eq $identityResponse -or [string]::IsNullOrWhiteSpace([string]$identityResponse.access_token)) {
            throw 'Azure Arc managed identity endpoint did not return an access token.'
        }
        Write-Verbose ("Azure Arc identity response received: {0}" -f (Get-TTResponseSummary -Response $identityResponse))
        return $identityResponse
    }
    if ($statusCode -ne 401) {
        throw "Azure Arc managed identity request failed: HTTP $statusCode."
    }

    $challenge = [string]$initialResponse.Headers['WWW-Authenticate']
    if ([string]::IsNullOrWhiteSpace($challenge) -or $challenge -notmatch '(?i)Basic\s+realm=(.+)$') {
        throw 'Azure Arc managed identity request returned 401 without a parseable WWW-Authenticate challenge.'
    }
    $secretFile = $Matches[1].Trim().Trim('"')
    if (-not (Test-Path -LiteralPath $secretFile -PathType Leaf)) { throw 'Azure Arc returned an inaccessible challenge secret file.' }
    Write-Verbose ("Azure Arc requested Basic authentication; reading challenge secret file: path={0}" -f $secretFile)
    $secret = (Get-Content -LiteralPath $secretFile -Raw).Trim()
    try {
        $headers.Authorization = "Basic $secret"
        Write-Verbose ("Retrying Azure Arc request with challenge secret: value={0}" -f (Get-TTMaskedValue -Value $secret))
        try {
            $retryResponse = Invoke-WebRequest -UseBasicParsing -Method Get -Uri $uri -Headers $headers -SkipHttpErrorCheck -ErrorAction Stop
        }
        catch {
            throw "Azure Arc managed identity challenge retry failed: $($_.Exception.Message)"
        }
        $retryStatusCode = [int]$retryResponse.StatusCode
        if ($retryStatusCode -lt 200 -or $retryStatusCode -ge 300) {
            throw "Azure Arc managed identity challenge retry failed: HTTP $retryStatusCode."
        }
        $identityResponse = ConvertFrom-TTHttpJsonResponse -Response $retryResponse
        if ($null -eq $identityResponse -or [string]::IsNullOrWhiteSpace([string]$identityResponse.access_token)) {
            throw 'Azure Arc managed identity endpoint did not return an access token.'
        }
        Write-Verbose ("Azure Arc identity response received: {0}" -f (Get-TTResponseSummary -Response $identityResponse))
        return $identityResponse
    } finally {
        $secret = $null
        $headers.Authorization = $null
        Write-Verbose 'Azure Arc challenge secret cleared from the working variable.'
    }
}

function New-EntraIDImplicitAuthorizationUrl {
    <#
    .SYNOPSIS
        Builds an Entra OAuth 2.0 implicit-flow authorization URL.

    .DESCRIPTION
        Constructs a v2 /authorize URL for the implicit grant (response_mode
        fragment) and returns it together with the state value needed to validate
        the redirect. Implicit flow is a compatibility feature; prefer
        authorization code flow with PKCE for new applications.

    .PARAMETER TenantId
        The Microsoft Entra tenant ID, domain, or selector such as 'organizations'.

    .PARAMETER ClientId
        The application (client) ID of the interactive application.

    .PARAMETER RedirectUri
        The exact registered redirect URI that receives the fragment response.

    .PARAMETER Scope
        Space-delimited delegated scopes, for example
        'https://graph.microsoft.com/User.Read'.

    .PARAMETER State
        Caller-provided CSRF/correlation value. A random value is generated when
        omitted.

    .PARAMETER IncludeIdToken
        Requests both an access token and an ID token (response_type
        'token id_token'). Ensures the openid scope is present and adds a nonce,
        which is returned for later validation.

    .EXAMPLE
        $request = New-EntraIDImplicitAuthorizationUrl -TenantId 'organizations' -ClientId $clientId -RedirectUri 'https://app.example/callback' -Scope 'https://graph.microsoft.com/User.Read'

    .OUTPUTS
        PSCustomObject with AuthorizationUrl, State, and Nonce properties.

    .NOTES
        Access-token implicit grant must be enabled on the app registration. Treat
        the resulting redirect URL as sensitive: its fragment contains bearer tokens.
    #>
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
    $nonce = $null
    if ($IncludeIdToken) {
        # Entra requires a nonce whenever the response type includes id_token,
        # even if the caller already included the openid scope.
        if ($Scope -notmatch '(^|\s)openid(\s|$)') {
            $parts.scope = "$Scope openid"
            Write-Verbose 'Added openid scope because IncludeIdToken was requested.'
        }
        $nonce = [guid]::NewGuid().ToString('N')
        $parts.nonce = $nonce
        Write-Verbose ("Generated a nonce for the ID token request: value={0}" -f (Get-TTMaskedValue -Value $nonce))
    }
    $query = @($parts.GetEnumerator() | ForEach-Object { "$($_.Key)=$([Uri]::EscapeDataString([string]$_.Value))" }) -join '&'
    Write-Verbose ("Implicit authorization URL built: authority=login.microsoftonline.com; path=/oauth2/v2.0/authorize; query_parameters={0}; state={1}" -f (($parts.Keys -join ',') , (Get-TTMaskedValue -Value $State)))
    [pscustomobject]@{ AuthorizationUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?$query"; State = $State; Nonce = $nonce }
}

function ConvertFrom-EntraIDImplicitRedirect {
    <#
    .SYNOPSIS
        Parses an Entra implicit-flow redirect URL and validates its state.

    .DESCRIPTION
        Extracts the access token, ID token, and related fields from the fragment of
        the final browser redirect URL. The comparison against ExpectedState is
        exact and case-sensitive; a mismatch throws before any result is returned.
        The command parses only: it does not validate JWT signatures or claims.

    .PARAMETER RedirectUrl
        The complete final redirect URL, including the portion after '#'.

    .PARAMETER ExpectedState
        The exact state value paired with the authorization request.

    .EXAMPLE
        $result = ConvertFrom-EntraIDImplicitRedirect -RedirectUrl $browserUrl -ExpectedState $request.State

    .OUTPUTS
        PSCustomObject with AccessToken, IdToken, TokenType, ExpiresIn, Scope,
        State, Error, and ErrorDescription properties.

    .NOTES
        Check the Error property before using AccessToken. The redirect URL and the
        returned tokens are credentials; keep them out of logs and history.
    #>
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

function New-EntraIDFederatedSigningCertificate {
    <#
    .SYNOPSIS
        Creates a self-signed RSA signing certificate for a custom OIDC issuer.

    .DESCRIPTION
        Generates a digital-signature RSA certificate and exports it as a
        password-protected PFX, optionally exporting the public certificate as DER.
        The PFX is the private signing material for New-EntraIDFederatedClientAssertion;
        only the public key is published through the OIDC metadata. Uses .NET
        cryptography where supported and falls back to OpenSSL.

    .PARAMETER PfxPath
        Destination PFX file. Parent directories are created when absent.

    .PARAMETER PfxPassword
        Plaintext PFX export password.

    .PARAMETER PfxPasswordSecureString
        PFX export password as a SecureString.

    .PARAMETER Subject
        Certificate subject. Defaults to 'CN=TokenTactics Federated Issuer'.

    .PARAMETER KeyLength
        RSA key size: 2048 (default), 3072, or 4096.

    .PARAMETER NotAfter
        Certificate expiry. Defaults to one year from creation and must be in the
        future.

    .PARAMETER PublicCertificatePath
        Optional path for a DER-encoded public certificate export.

    .EXAMPLE
        $password = Read-Host 'PFX password' -AsSecureString
        New-EntraIDFederatedSigningCertificate -PfxPath './issuer-signing.pfx' -PfxPasswordSecureString $password -PublicCertificatePath './issuer-signing.cer'

    .OUTPUTS
        PSCustomObject with Thumbprint, PfxPath, PublicCertificatePath, and NotAfter
        properties.

    .NOTES
        Keep the PFX in a private, access-controlled location and rotate it before
        expiry. Never publish the PFX or its private key.
    #>
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
    # Resolve through PowerShell's provider location before creating parent
    # directories or passing paths to .NET/OpenSSL.
    $PfxPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PfxPath)
    if ($PublicCertificatePath) {
        $PublicCertificatePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PublicCertificatePath)
    }
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
            if ($env:OS -ne 'Windows_NT') { & chmod 600 $PfxPath | Out-Null }
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
            if ($env:OS -ne 'Windows_NT') { & chmod 700 $temporaryDirectory | Out-Null }
            $opensslSubject = '/' + (($Subject -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join '/')
            $days = [Math]::Max(1, [Math]::Ceiling(($NotAfter.ToUniversalTime() - [DateTime]::UtcNow).TotalDays))
            $previousPassword = $env:TT_OAUTH_PFX_PASSWORD
            $env:TT_OAUTH_PFX_PASSWORD = $password
            try {
                & $openssl.Source req -x509 -newkey "rsa:$KeyLength" -keyout $temporaryKey -out $temporaryCertificate -days $days -nodes -subj $opensslSubject 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'OpenSSL failed to create the signing certificate.' }
                & $openssl.Source pkcs12 -export -out $PfxPath -inkey $temporaryKey -in $temporaryCertificate -passout env:TT_OAUTH_PFX_PASSWORD 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'OpenSSL failed to create the PFX.' }
                if ($env:OS -ne 'Windows_NT') { & chmod 600 $PfxPath | Out-Null }
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

function New-EntraIDFederatedIssuerMetadata {
    <#
    .SYNOPSIS
        Generates public OIDC discovery metadata for a custom federated issuer.

    .DESCRIPTION
        Writes the public OpenID Connect discovery document
        (.well-known/openid-configuration) and JWKS (keys.json) for a
        certificate-backed custom issuer into OutputPath, ready to be hosted at the
        issuer URL. With -IncludeLocalConfig, also writes issuer-config.json, a
        local convenience record that must not be published.

    .PARAMETER Issuer
        The stable HTTPS issuer URL. Must match the Entra federated credential and
        every assertion's iss claim.

    .PARAMETER Subject
        The workload subject that must match the federated credential.

    .PARAMETER OutputPath
        Directory that receives the generated metadata files.

    .PARAMETER Audience
        The assertion audience. Defaults to 'api://AzureADTokenExchange'.

    .PARAMETER CertificateThumbprint
        Thumbprint of an RSA certificate in a Windows certificate store.

    .PARAMETER CertStoreLocation
        The personal certificate store containing the certificate.

    .PARAMETER PfxPath
        Path to an existing RSA PFX.

    .PARAMETER PfxPassword
        Plaintext PFX password.

    .PARAMETER PfxPasswordSecureString
        PFX password as a SecureString.

    .PARAMETER IncludeLocalConfig
        Also write issuer-config.json (issuer, subject, audience, key ID) for local
        reference. Not required by the web host; do not publish it.

    .EXAMPLE
        New-EntraIDFederatedIssuerMetadata -Issuer 'https://oidc.example.com' -Subject 'build-workload' -OutputPath './oidc-public' -PfxPath './issuer-signing.pfx' -PfxPasswordSecureString $password

    .OUTPUTS
        PSCustomObject with Issuer, Subject, Audience, KeyId, OutputPath,
        DiscoveryPath, JwksPath, ConfigurationPath, and GeneratedFiles properties.

    .NOTES
        Publish only the discovery document and the JWKS, anonymously reachable over
        HTTPS. Keep the PFX and private key outside the public directory.
    #>
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
        [Parameter(Mandatory = $true, ParameterSetName = 'PfxSecureString')][securestring]$PfxPasswordSecureString,
        [switch]$IncludeLocalConfig
    )
    Write-Verbose ("Generating federated issuer metadata: issuer={0}; subject={1}; audience={2}; output_path={3}; certificate_input={4}; local_config={5}" -f $Issuer.AbsoluteUri, $Subject, $Audience, $OutputPath, $PSCmdlet.ParameterSetName, $IncludeLocalConfig.IsPresent)
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
            $utf8NoBom = [Text.UTF8Encoding]::new($false)
            [IO.File]::WriteAllText($discoveryPath, ($discovery | ConvertTo-Json -Depth 5), $utf8NoBom)
            [IO.File]::WriteAllText($jwksPath, (@{ keys = @($jwk) } | ConvertTo-Json -Depth 8), $utf8NoBom)
            # issuer-config.json is a local convenience record that the web host does
            # not need, so it is only written when explicitly requested.
            $configurationPath = $null
            if ($IncludeLocalConfig) {
                $configurationPath = Join-Path $outputDirectory 'issuer-config.json'
                [IO.File]::WriteAllText($configurationPath, ([ordered]@{ issuer = $issuerText; subject = $Subject; audience = $Audience; kid = $kid } | ConvertTo-Json), $utf8NoBom)
            }
            $generatedFiles = @($discoveryPath, $jwksPath)
            if ($configurationPath) { $generatedFiles += $configurationPath }
            Write-Verbose ("Generated issuer metadata files: {0}" -f ($generatedFiles -join '; '))
            [pscustomobject]@{
                Issuer = $issuerText
                Subject = $Subject
                Audience = $Audience
                KeyId = $kid
                OutputPath = $outputDirectory
                DiscoveryPath = $discoveryPath
                JwksPath = $jwksPath
                ConfigurationPath = $configurationPath
                GeneratedFiles = $generatedFiles
            }
        } finally { $rsa.Dispose() }
    } finally {
        Remove-TTCertificate -Certificate $certificate
        Write-Verbose 'Issuer metadata certificate material disposed.'
    }
}

function New-EntraIDFederatedClientAssertion {
    <#
    .SYNOPSIS
        Signs a short-lived OIDC JWT for exchange through a custom federated credential.

    .DESCRIPTION
        Creates an RS256-signed JWT with the supplied issuer, subject, and audience
        from a local PFX or Windows certificate-store/TPM key. Exchange the
        assertion with Get-EntraIDTokenFromFederatedCredential. The issuer's public
        discovery and JWKS metadata must be published and the Entra federated
        credential must match before the exchange can succeed.

    .PARAMETER Issuer
        The HTTPS issuer URL. A trailing slash is removed before signing.

    .PARAMETER Subject
        The workload subject. Must exactly match the federated credential.

    .PARAMETER Audience
        The assertion audience. Defaults to 'api://AzureADTokenExchange'.

    .PARAMETER LifetimeMinutes
        Assertion lifetime in minutes (1-10). Defaults to 5.

    .PARAMETER CertificateThumbprint
        Thumbprint of an RSA certificate in a Windows certificate store.

    .PARAMETER CertStoreLocation
        The personal certificate store containing the certificate.

    .PARAMETER PfxPath
        Path to a PFX containing an accessible RSA private key.

    .PARAMETER PfxPassword
        Plaintext PFX password.

    .PARAMETER PfxPasswordSecureString
        PFX password as a SecureString.

    .EXAMPLE
        $assertion = New-EntraIDFederatedClientAssertion -Issuer 'https://oidc.example.com' -Subject 'build-workload' -PfxPath './issuer-signing.pfx' -PfxPasswordSecureString $password

    .OUTPUTS
        System.String. The compact signed JWT.

    .NOTES
        The assertion is a bearer credential until it expires; do not log, persist,
        or commit it.
    #>
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
